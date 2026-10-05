package rendr

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestRejectedSessionEndsRejected_L50: a pending session this side's
// application rejects ends — in its EventSessionEnd — with an error that
// matches ErrRejected and names the code, not with the error of a second
// decision; a later Confirm or Reject still reports that second decision.
func TestRejectedSessionEndsRejected_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var ends []error
		rt := wpTestRuntime(t, Config{OnEvent: func(ev Event) {
			if ev.Kind == EventSessionEnd {
				mu.Lock()
				ends = append(ends, ev.Err)
				mu.Unlock()
			}
		}}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		d := wpConnect(t, ln, wpInst(0xa7), 1)
		d.hello(rt)
		d.send(wire.TypeOpen, 0, wpOpen(wpSID(1), wire.KindStream, 1, nil))
		pc, err := ln.Accept(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := pc.Reject(4242, "no route"); err != nil {
			t.Fatalf("Reject: %v", err)
		}
		d.expectOpenAck(wire.StatusRejected, 4242)
		d.drain()
		synctest.Wait()
		if err := pc.Reject(1, "again"); err == nil || errors.Is(err, ErrRejected) {
			t.Fatalf("a second Reject: %v, want the second-decision error", err)
		}
		rt.Close()
		synctest.Wait()
		mu.Lock()
		defer mu.Unlock()
		if len(ends) != 1 {
			t.Fatalf("%d session-end events, want 1: %v", len(ends), ends)
		}
		if err := ends[0]; !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "4242") {
			t.Fatalf("the rejected session's end error: %v, want one matching ErrRejected with code 4242", err)
		}
	})
}
