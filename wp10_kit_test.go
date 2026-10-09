package rendr

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The rendr mux integration kit (M3 WP10): dialer factories whose carriers
// run through a rendrtest.Tamper — its frame tap (Log) shows what each side
// placed for each handle, its Hold and Release stop and resume one
// direction —, factory call counts, and Runtime-level views of the shared
// trunks. Helpers of these tests start with "mx".

// mxTaps records the tampers of one factory's carriers, oldest first.
type mxTaps struct {
	mu    sync.Mutex
	tps   []*rendrtest.Tamper
	dials atomic.Int32 // factory calls
	fail  atomic.Bool  // factory calls fail at once (a dead path)
}

// mxErrDial is the error of a failing factory call.
var mxErrDial = &net.OpError{Op: "dial", Net: "test", Err: net.ErrClosed}

// mxTapCarrier returns a StreamCarrier over l whose every carrier passes
// through a new Tamper recorded in taps.
func mxTapCarrier(l *rendrtest.Link, taps *mxTaps) StreamCarrier {
	return StreamCarrier{Name: l.Name(), Dial: func(ctx context.Context) (net.Conn, error) {
		taps.dials.Add(1)
		if taps.fail.Load() {
			return nil, mxErrDial
		}
		c, err := l.Dial(ctx)
		if err != nil {
			return nil, err
		}
		a, a2 := net.Pipe()
		tp := rendrtest.NewTamper(a2, c)
		taps.mu.Lock()
		taps.tps = append(taps.tps, tp)
		taps.mu.Unlock()
		return a, nil
	}}
}

// tap returns the i-th tamper (its carrier the i-th factory call's).
func (m *mxTaps) tap(t testing.TB, i int) *rendrtest.Tamper {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if i >= len(m.tps) {
		t.Fatalf("tamper %d of %d", i, len(m.tps))
	}
	return m.tps[i]
}

// count returns the tampers made so far.
func (m *mxTaps) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tps)
}

// close closes every tamper (each ends its two pumps).
func (m *mxTaps) close() {
	m.mu.Lock()
	tps := m.tps
	m.mu.Unlock()
	for _, tp := range tps {
		tp.Close()
	}
}

// mxFrames returns the logged frames of direction d of tp of type typ for
// handle h (any handle when h is 0 and typ a session type; handle 0 for a
// carrier-level type).
func mxFrames(tp *rendrtest.Tamper, d rendrtest.Dir, typ rendrtest.FrameType, h uint32) []rendrtest.FrameRec {
	var out []rendrtest.FrameRec
	for _, r := range tp.Log(d) {
		if r.Type == typ && (h == 0 || r.Handle == h) {
			out = append(out, r)
		}
	}
	return out
}

// mxHandles returns the set of handles of frames of type typ in direction d.
func mxHandles(tp *rendrtest.Tamper, d rendrtest.Dir, typ rendrtest.FrameType) map[uint32]int {
	out := map[uint32]int{}
	for _, r := range tp.Log(d) {
		if r.Type == typ {
			out[r.Handle]++
		}
	}
	return out
}

// mxPeer returns a dialer Peer of e over the given factories.
func (e *e2ePair) mxPeer(cs ...Carrier) *Peer {
	e.t.Helper()
	p, err := e.d.NewPeer(PeerConfig{Carriers: cs})
	if err != nil {
		e.t.Fatalf("NewPeer: %v", err)
	}
	return p
}

// mxOpen dials p and confirms the session on ln (e2eOpen), returning both
// ends and the dialer's carrier of factory name.
func mxOpen(t testing.TB, p *Peer, ln *Listener, o DialOptions) (dc, pc *Conn) {
	t.Helper()
	return e2eOpen(t, p, ln, o)
}

// mxCarrier returns c's live carrier named name ("" on the passive: any).
func mxCarrier(t testing.TB, c *Conn, name string) CarrierStatus {
	t.Helper()
	for _, cs := range c.Status().Carriers {
		if cs.State != CarrierDead && (name == "" || cs.Name == name) {
			return cs
		}
	}
	t.Fatalf("no live carrier %q: %+v", name, c.Status().Carriers)
	return CarrierStatus{}
}

// mxHandleOf returns the handle of c's live carrier named name ("": any):
// its view's on the shared trunk, read from the session's own status (the
// carrier's Stats.Handle).
func mxHandleOf(t testing.TB, c *Conn, name string) uint32 {
	t.Helper()
	for _, cs := range c.s.Status().Carriers {
		if cs.State != session.LaneDead && (name == "" || cs.Name == name) {
			return cs.Stats.Handle
		}
	}
	t.Fatalf("no live carrier %q: %+v", name, c.Status().Carriers)
	return 0
}

// mxSessionCarriers returns the session-level carrier rows of c (dead ones
// included), with their handles.
func mxSessionCarriers(c *Conn) []session.CarrierStatus { return c.s.Status().Carriers }

// mxWait waits, at most within (virtual time), until cond holds.
func mxWait(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, within)
		}
		time.Sleep(time.Millisecond)
	}
}

// mxTrunkSet returns the passive trunk set's view-1 conns.
func mxTrunkSet(rt *Runtime) []*carrier.Conn {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return mapKeys(rt.trunks)
}
