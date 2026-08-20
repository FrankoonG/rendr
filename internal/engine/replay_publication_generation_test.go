package engine

import (
	"testing"
	"time"
)

func TestReplayPublicationBarrierRejectsStaleSameFrontierCompletion(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })

	const frontier = uint64(17)
	first := e.installReplayPublicationBarrier(frontier)
	if !first.valid() {
		t.Fatal("first publication barrier was not installed")
	}
	_, firstWake := replayPublicationBarrierTestState(e)

	completionEntered := make(chan struct{})
	releaseCompletion := make(chan struct{})
	e.replayPublicationBeforeComplete = func(barrier replayPublicationBarrierToken) {
		if barrier != first {
			return
		}
		close(completionEntered)
		<-releaseCompletion
	}
	completionDone := make(chan struct{})
	go func() {
		e.completeReplayPublicationBarrierForReplay(first, frontier)
		close(completionDone)
	}()
	publicationBarrierTestWait(t, completionEntered, "old replay completion")

	second := e.installReplayPublicationBarrier(frontier)
	if !second.valid() || second.generation <= first.generation {
		t.Fatalf("replacement barrier=%+v, first=%+v", second, first)
	}
	if second.frontier != first.frontier {
		t.Fatalf("replacement frontier=%d want same frontier %d", second.frontier, first.frontier)
	}

	close(releaseCompletion)
	publicationBarrierTestWait(t, completionDone, "released old replay completion")
	current, currentWake := replayPublicationBarrierTestState(e)
	if current != second {
		t.Fatalf("old replay completion cleared replacement barrier: got=%+v want=%+v", current, second)
	}
	if currentWake != firstWake {
		t.Fatal("same-frontier replacement unexpectedly changed the waiter generation")
	}
	publicationBarrierTestRequireOpen(t, firstWake, "replacement barrier wake")

	e.completeReplayPublicationBarrierForReplay(second, frontier)
	current, _ = replayPublicationBarrierTestState(e)
	if current.valid() {
		t.Fatalf("current replay completion left barrier active: %+v", current)
	}
	publicationBarrierTestRequireClosed(t, firstWake, "completed barrier wake")
}

func TestReplayPublicationBarrierACKCompletesCurrentGeneration(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })

	const frontier = uint64(23)
	first := e.installReplayPublicationBarrier(frontier)
	second := e.installReplayPublicationBarrier(frontier)
	if !first.valid() || !second.valid() || second.generation <= first.generation {
		t.Fatalf("barrier generations first=%+v second=%+v", first, second)
	}
	_, wake := replayPublicationBarrierTestState(e)

	// A claimed frontier is not ACK proof unless the cumulative ACK state has
	// actually reached it.
	e.sendAckNext.Store(frontier - 1)
	e.completeReplayPublicationBarrier(frontier)
	if current, _ := replayPublicationBarrierTestState(e); current != second {
		t.Fatalf("unproved ACK cleared current barrier: got=%+v want=%+v", current, second)
	}

	e.sendAckNext.Store(frontier)
	e.completeReplayPublicationBarrier(frontier)
	if current, _ := replayPublicationBarrierTestState(e); current.valid() {
		t.Fatalf("cumulative ACK left barrier active: %+v", current)
	}
	publicationBarrierTestRequireClosed(t, wake, "ACK-completed barrier wake")

	// Both replay completions are stale after the independent ACK completion.
	e.completeReplayPublicationBarrierForReplay(first, frontier)
	e.completeReplayPublicationBarrierForReplay(second, frontier)
}

func TestReplayPublicationBarrierCloseInvalidatesCompletionToken(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	const frontier = uint64(31)
	barrier := e.installReplayPublicationBarrier(frontier)
	if !barrier.valid() {
		t.Fatal("publication barrier was not installed")
	}
	_, wake := replayPublicationBarrierTestState(e)

	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if current, _ := replayPublicationBarrierTestState(e); current.valid() {
		t.Fatalf("Close left publication barrier active: %+v", current)
	}
	publicationBarrierTestRequireClosed(t, wake, "Close-released barrier wake")

	// A replay finishing after Close owns no live publication generation.
	e.completeReplayPublicationBarrierForReplay(barrier, frontier)
	if resurrected := e.installReplayPublicationBarrier(frontier); resurrected.valid() {
		t.Fatalf("Close allowed publication barrier resurrection: %+v", resurrected)
	}
}

func TestReplayQueueCoalescingKeepsNewestPublicationBarrier(t *testing.T) {
	e := &Engine{}
	const frontier = uint64(41)
	first := e.installReplayPublicationBarrier(frontier)
	second := e.installReplayPublicationBarrier(frontier)

	e.queueReplay(replayRequest{
		nextSeq:            1,
		target:             frontier,
		kind:               replayRequestBounded,
		publicationBarrier: first,
	})
	e.queueReplay(replayRequest{nextSeq: 0, kind: replayRequestFull})
	e.queueReplay(replayRequest{
		nextSeq:            2,
		target:             frontier,
		kind:               replayRequestBounded,
		publicationBarrier: second,
	})

	request, ok := e.takeReplayRequest()
	if !ok {
		t.Fatal("coalesced replay request is missing")
	}
	if request.publicationBarrier != second {
		t.Fatalf("coalesced barrier=%+v want newest=%+v", request.publicationBarrier, second)
	}
}

func replayPublicationBarrierTestState(e *Engine) (replayPublicationBarrierToken, <-chan struct{}) {
	e.replayMu.Lock()
	defer e.replayMu.Unlock()
	return e.replayPublicationBarrier, e.replayPublicationWake
}

func publicationBarrierTestWait(t *testing.T, ch <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func publicationBarrierTestRequireOpen(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s is closed", name)
	default:
	}
}

func publicationBarrierTestRequireClosed(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	default:
		t.Fatalf("%s is open", name)
	}
}
