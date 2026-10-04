package rendr

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// rootErrors are the sentinel errors of plan §6 as exported by package
// rendr, with the internal values they must be identical to.
var rootErrors = []struct {
	name     string
	root, in error
}{
	{"ErrNoPath", ErrNoPath, session.ErrNoPath},
	{"ErrSessionLost", ErrSessionLost, session.ErrSessionLost},
	{"ErrAborted", ErrAborted, session.ErrAborted},
	{"ErrRejected", ErrRejected, session.ErrRejected},
	{"ErrCapacity", ErrCapacity, session.ErrCapacity},
	{"ErrVersion", ErrVersion, session.ErrVersion},
	{"ErrProtocol", ErrProtocol, session.ErrProtocol},
	{"ErrMetadataTooLarge", ErrMetadataTooLarge, session.ErrMetadataTooLarge},
	{"ErrIdleTimeout", ErrIdleTimeout, session.ErrIdleTimeout},
}

// TestErrorsMatch checks the error model of plan §6 and design §9 at the
// public surface: every sentinel is the exact value the core produces, is
// distinct from every other, matches errors.Is through %w wrapping
// (including the Dial form "ctx error (last carrier error: …)"), and is a
// net.Error with Timeout() == false — unlike a deadline, which is
// os.ErrDeadlineExceeded with Timeout() == true and is not one of them.
func TestErrorsMatch(t *testing.T) {
	for i, e := range rootErrors {
		if e.root != e.in {
			t.Errorf("%s is not the core's value", e.name)
		}
		if e.root.Error() == "" {
			t.Errorf("%s has no message", e.name)
		}
		for j, o := range rootErrors {
			if i != j && (e.root == o.root || errors.Is(e.root, o.root) || e.root.Error() == o.root.Error()) {
				t.Errorf("%s and %s are not distinct", e.name, o.name)
			}
		}
		var ne net.Error
		if !errors.As(e.root, &ne) || ne.Timeout() {
			t.Errorf("%s: net.Error %v, Timeout must be false", e.name, ne)
		}
		wrapped := fmt.Errorf("dial: %w", e.root)
		if !errors.Is(wrapped, e.root) || !errors.As(wrapped, &ne) || ne.Timeout() {
			t.Errorf("%s: lost through %%w wrapping", e.name)
		}
		dial := fmt.Errorf("%w (last carrier error: %w)", e.root, errLastCarrier)
		if !errors.Is(dial, e.root) || !errors.Is(dial, errLastCarrier) {
			t.Errorf("%s: lost in the two-error Dial form", e.name)
		}
		if errors.Is(e.root, os.ErrDeadlineExceeded) || errors.Is(e.root, net.ErrClosed) {
			t.Errorf("%s matches a deadline or net.ErrClosed", e.name)
		}
	}
	var ne net.Error
	if !errors.As(os.ErrDeadlineExceeded, &ne) || !ne.Timeout() {
		t.Error("os.ErrDeadlineExceeded must be a net.Error with Timeout() == true")
	}
}

// errLastCarrier stands in for the last carrier error a Dial wraps.
var errLastCarrier = errors.New("io: read/write on closed pipe")

// TestAbortAndRejectErrors checks the coded errors: *AbortError matches
// ErrAborted (and nothing else), yields Code/Msg/Remote through errors.As,
// also when wrapped, and is a net.Error that is not a timeout; *RejectError
// matches ErrRejected (and nothing else) and yields Code/Msg through
// errors.As, also when wrapped, while the sentinel ErrRejected itself is no
// *RejectError; the reserved abort codes equal the wire RST codes.
func TestAbortAndRejectErrors(t *testing.T) {
	ab := &AbortError{Code: AbortLinger, Msg: "linger expired", Remote: true}
	var err error = fmt.Errorf("read: %w", ab)
	if !errors.Is(err, ErrAborted) || errors.Is(err, ErrRejected) || errors.Is(err, ErrNoPath) {
		t.Fatal("AbortError matches the wrong sentinels")
	}
	var got *AbortError
	if !errors.As(err, &got) || got.Code != AbortLinger || got.Msg != "linger expired" || !got.Remote {
		t.Fatalf("errors.As AbortError: %+v", got)
	}
	var ne net.Error
	if !errors.As(err, &ne) || ne.Timeout() {
		t.Fatal("AbortError must be a net.Error with Timeout() == false")
	}
	local := &AbortError{Code: AbortExhausted}
	if local.Error() == ab.Error() || !errors.Is(local, ErrAborted) {
		t.Fatalf("local abort %q", local.Error())
	}

	rj := &RejectError{Code: 403, Msg: "forbidden"}
	err = fmt.Errorf("dial: %w", rj)
	if !errors.Is(err, ErrRejected) || errors.Is(err, ErrAborted) || errors.Is(err, ErrCapacity) {
		t.Fatal("RejectError matches the wrong sentinels")
	}
	var gr *RejectError
	if !errors.As(err, &gr) || gr.Code != 403 || gr.Msg != "forbidden" {
		t.Fatalf("errors.As RejectError: %+v", gr)
	}
	if errors.As(ErrRejected, &gr) {
		t.Fatal("the sentinel itself is not a *RejectError")
	}

	for _, c := range []struct {
		root AbortCode
		wire uint32
	}{
		{AbortClosed, wire.RstClosed}, {AbortLinger, wire.RstLinger}, {AbortGoingAway, wire.RstGoingAway},
		{AbortExhausted, wire.RstExhausted}, {AbortIdle, wire.RstIdle}, {AbortWithdrawn, wire.RstWithdrawn},
	} {
		if uint32(c.root) != c.wire {
			t.Errorf("abort code %d differs from the wire RST code %d", c.root, c.wire)
		}
	}
	if AbortClosed != 1 || AbortWithdrawn != 6 {
		t.Errorf("reserved abort codes moved: closed %d withdrawn %d", AbortClosed, AbortWithdrawn)
	}
}
