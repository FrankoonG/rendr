package engine

import (
	"sync"
	"testing"
)

func TestApplicationDispatchWaiterCompletionAndAbandonmentAreSingleOwner(t *testing.T) {
	for iteration := 0; iteration < 1000; iteration++ {
		waiter := acquireApplicationDispatchWaiter()
		start := make(chan struct{})
		completed := make(chan struct{})
		go func() {
			<-start
			completeApplicationDispatchWaiter(waiter, pathDispatchResult{})
			close(completed)
		}()
		close(start)
		abandonApplicationDispatchWaiter(waiter)
		<-completed
	}

	waiter := acquireApplicationDispatchWaiter()
	completeApplicationDispatchWaiter(waiter, pathDispatchResult{})
	<-waiter.done
	releaseApplicationDispatchWaiter(waiter)
}

func TestDispatchStallGenerationClearsForEitherCompletionOrder(t *testing.T) {
	for iteration := 0; iteration < 1000; iteration++ {
		slot := &pathSlot{}
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			slot.markDispatchStalled(1)
		}()
		go func() {
			defer wait.Done()
			<-start
			slot.completeDispatch(1)
		}()
		close(start)
		wait.Wait()
		if slot.dispatchStalled.Load() || slot.dispatchStallGen.Load() != 0 {
			t.Fatalf("iteration %d retained completed stalled generation", iteration)
		}
	}
}

func TestOlderDispatchCompletionCannotClearNewerStall(t *testing.T) {
	slot := &pathSlot{}
	slot.completeDispatch(1)
	slot.markDispatchStalled(2)
	slot.completeDispatch(1)
	if !slot.dispatchStalled.Load() || slot.dispatchStallGen.Load() != 2 {
		t.Fatal("older completion cleared newer stalled generation")
	}
	slot.completeDispatch(2)
	if slot.dispatchStalled.Load() || slot.dispatchStallGen.Load() != 0 {
		t.Fatal("matching completion did not clear stalled generation")
	}
}

func TestDispatchCompletionFrontierCannotRegress(t *testing.T) {
	slot := &pathSlot{}
	slot.completeDispatch(2)
	slot.completeDispatch(1)
	if got := slot.dispatchDoneGen.Load(); got != 2 {
		t.Fatalf("completion frontier=%d want 2", got)
	}
	slot.markDispatchStalled(2)
	if slot.dispatchStalled.Load() || slot.dispatchStallGen.Load() != 0 {
		t.Fatal("already-completed generation remained stalled after out-of-order completion")
	}
}
