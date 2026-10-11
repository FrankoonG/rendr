package carrier

import (
	"strings"
	"sync/atomic"
	"testing"
)

// TestDgNoteTopLevel (the race lane's harness lever, dgbatch_harness_test.go):
// a fakeIO pair built in a subtest, or for a fuzz target from its stack,
// records the top-level name the later settings' -test.run selects; a
// build no Test or Fuzz frame names is reported, so every test runs in
// every setting. Without -race nothing is recorded.
func TestDgNoteTopLevel(t *testing.T) {
	dgNotedMu.Lock()
	saved, savedLost := dgNoted, dgLost.Load()
	dgNoted = map[string]bool{}
	dgNotedMu.Unlock()
	defer func() {
		dgNotedMu.Lock()
		if dgNoted = saved; saved != nil {
			saved["TestDgNoteTopLevel"] = true
		}
		dgNotedMu.Unlock()
		if savedLost == nil {
			dgLost = atomic.Value{} // this test's own unnamed build is no reason to run every test
		}
	}()
	t.Run("sub/inner", func(t *testing.T) { newFakeIOPair(t, 1200) })
	newFakeIOPair(nil, 1200) // this test's own frame is on the stack
	done := make(chan struct{})
	go dgNoteNoFrame(done) // no Test frame
	<-done
	dgNotedMu.Lock()
	noted := dgNoted
	dgNotedMu.Unlock()
	lost, _ := dgLost.Load().(string)
	if !carrierRace {
		if len(noted) != 0 || (savedLost == nil && lost != "") {
			t.Fatalf("without -race: noted %v, lost %q", noted, lost)
		}
		return
	}
	if len(noted) != 1 || !noted["TestDgNoteTopLevel"] {
		t.Fatalf("noted %v, want only TestDgNoteTopLevel", noted)
	}
	if !strings.Contains(lost, "dgNoteNoFrame") {
		t.Fatalf("a build without a Test frame: lost %q, want its stack", lost)
	}
}

// dgNoteNoFrame builds a fakeIO pair on a goroutine no test function
// started directly, then closes done.
func dgNoteNoFrame(done chan struct{}) {
	defer close(done)
	newFakeIOPair(nil, 1200)
}
