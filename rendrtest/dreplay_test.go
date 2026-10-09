package rendrtest

import (
	"bytes"
	"net"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

// expectPanic fails t unless f panics.
func expectPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not panic", what)
		}
	}()
	f()
}

// TestDatagramLinkReplayInto: ReplayInto re-delivers exactly the n-th
// datagram the dialer of the link's newest carrier sent into another
// link's newest carrier (or its own), Up, from that carrier's dialer
// address, counted as Injected and Replayed; the first 16 and the latest
// 128 are kept, any other index panics, and a link without a live
// carrier gets nothing.
func TestDatagramLinkReplayInto(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ra := newDRig(t, DatagramLinkConfig{Name: "replay-a"})
		rb := newDRig(t, DatagramLinkConfig{Name: "replay-b"})
		rc := newDRig(t, DatagramLinkConfig{Name: "replay-c"})
		defer ra.l.Close()
		defer rb.l.Close()
		defer rc.l.Close()
		a, b := ra.dial(), rb.dial()
		h1 := dH1Session(1, false)
		a.up(t, h1)
		dRecv(t, a.srv)
		b.up(t, dH1Session(2, false))
		dRecv(t, b.srv)
		const n = 200
		for i := range n { // datagram i+1 of a's dialer
			a.up(t, []byte{'a', byte(i)})
			dRecv(t, a.srv)
		}
		cases := []struct {
			dst  *dRig
			k    int
			want []byte
			to   dCarrier
		}{
			{rb, 5, []byte{'a', 4}, b},
			{rb, 0, h1, b},
			{rb, 15, []byte{'a', 14}, b},          // the last of the first 16
			{rb, n + 1 - 128, []byte{'a', 72}, b}, // the oldest of the latest 128
			{ra, n, []byte{'a', n - 1}, a},        // into the carrier itself
		}
		for _, c := range cases {
			ra.l.ReplayInto(c.dst.l, c.k)
			got, from := dRecv(t, c.to.srv)
			if !bytes.Equal(got, c.want) || !sameAddr(from, c.to.cliAddr.(*net.UDPAddr)) {
				t.Fatalf("ReplayInto(%d): %x from %v, want %x from %v", c.k, got, from, c.want, c.to.cliAddr)
			}
		}
		for _, k := range []int{16, n - 128, n + 1, -1} {
			expectPanic(t, "ReplayInto of a datagram not kept", func() { ra.l.ReplayInto(rb.l, k) })
		}
		ra.l.ReplayInto(rc.l, 1) // no carrier on rc: nothing
		sa, sb, sc := ra.l.Stats(), rb.l.Stats(), rc.l.Stats()
		if sb.Replayed != 4 || sb.Session.Injected != 4 || sb.All.Injected != 4 {
			t.Fatalf("b: Replayed %d, Injected %d (session %d); want 4", sb.Replayed, sb.All.Injected, sb.Session.Injected)
		}
		if sa.Replayed != 1 || sa.Session.Injected != 1 || sc.Replayed != 0 || sc.All.Injected != 0 {
			t.Fatalf("a: Replayed %d, Injected %d; c: Replayed %d, Injected %d; want 1, 1, 0, 0",
				sa.Replayed, sa.Session.Injected, sc.Replayed, sc.All.Injected)
		}
		dNothing(t, b.srv, time.Second)
	})
}

// TestDatagramLinkSpliceFrom: SpliceFrom delivers, at this link's newest
// carrier, copies of the next n datagrams other's newest carrier sends
// instead of n of its own (those are lost); the source carrier delivers
// its own unchanged; Spliced, Injected and Lost count it. A splice that
// never gets its datagrams ends at Close (the bubble checks the goroutine).
func TestDatagramLinkSpliceFrom(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ra := newDRig(t, DatagramLinkConfig{Name: "splice-a"})
		rb := newDRig(t, DatagramLinkConfig{Name: "splice-b"})
		defer ra.l.Close()
		defer rb.l.Close()
		a, b := ra.dial(), rb.dial()
		a.up(t, dH1Session(1, false))
		dRecv(t, a.srv)
		b.up(t, dH1Session(2, false))
		dRecv(t, b.srv)
		ra.l.SpliceFrom(rb.l, 2)
		for _, s := range []string{"a1", "a2", "a3"} {
			a.up(t, []byte(s))
		}
		for _, s := range []string{"b1", "b2", "b3"} {
			b.up(t, []byte(s))
		}
		synctest.Wait()
		var atA, atB []string
		for range 3 {
			got, from := dRecv(t, a.srv)
			if !sameAddr(from, a.cliAddr.(*net.UDPAddr)) {
				t.Fatalf("%q arrived at a from %v, want a's dialer %v", got, from, a.cliAddr)
			}
			atA = append(atA, string(got))
			got, _ = dRecv(t, b.srv)
			atB = append(atB, string(got))
		}
		dNothing(t, a.srv, time.Second)
		slices.Sort(atA)
		if !slices.Equal(atA, []string{"a3", "b1", "b2"}) || !slices.Equal(atB, []string{"b1", "b2", "b3"}) {
			t.Fatalf("a received %q, b received %q; want [a3 b1 b2] and [b1 b2 b3]", atA, atB)
		}
		sa, sb := ra.l.Stats(), rb.l.Stats()
		if sa.Spliced != 2 || sa.Session.Injected != 2 || sa.Session.Lost != 2 || sa.Session.Sent != 4 {
			t.Fatalf("a: Spliced %d, Injected %d, Lost %d, Sent %d; want 2, 2, 2, 4",
				sa.Spliced, sa.Session.Injected, sa.Session.Lost, sa.Session.Sent)
		}
		if sb.Spliced != 0 || sb.All.Injected != 0 || sb.All.Lost != 0 {
			t.Fatalf("b counted the splice: %+v", sb)
		}
		ra.l.SpliceFrom(rb.l, 5) // never filled: Close ends it
		expectPanic(t, "SpliceFrom itself", func() { ra.l.SpliceFrom(ra.l, 1) })
	})
}

// TestDatagramHubReplayFlow: ReplayFlow re-delivers the datagrams one
// client sent with the flow header of another, from that client's
// address, counted as Injected and Replayed; an unknown client panics.
func TestDatagramHubReplayFlow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := NewDatagramHub(DatagramHubConfig{Name: "replayflow"})
		defer h.Close()
		sock := h.PacketConn()
		a, pa := hDial(t, h)
		b, pb := hDial(t, h)
		var wa [][]byte
		for _, d := range [][]byte{dH1Session(1, false), []byte("a1")} {
			dSend(t, a, d, pa)
			w, _ := dRecv(t, sock)
			wa = append(wa, w)
		}
		dSend(t, b, dH1Session(2, false), pb)
		wb, fromB := dRecv(t, sock)
		flowA, _ := hFlow(t, wa[0])
		flowB, _ := hFlow(t, wb)
		h.ReplayFlow(0, 1)
		for k := range wa {
			got, from := dRecv(t, sock)
			flow, rest := hFlow(t, got)
			_, orig := hFlow(t, wa[k])
			if flow != flowB || flow == flowA || !bytes.Equal(rest, orig) || !sameAddr(from, fromB.(*net.UDPAddr)) {
				t.Fatalf("replay %d: flow %x (b %x) from %v (b %v), payload equal %v", k, flow, flowB, from, fromB, bytes.Equal(rest, orig))
			}
		}
		dNothing(t, sock, time.Second)
		if s := h.Stats(); s.Replayed != 2 || s.Session.Injected != 2 || s.Spoofed != 0 {
			t.Fatalf("Replayed %d, Injected %d, Spoofed %d; want 2, 2, 0", s.Replayed, s.Session.Injected, s.Spoofed)
		}
		for _, bad := range [][2]int{{0, 2}, {-1, 0}, {2, 1}} {
			expectPanic(t, "ReplayFlow of an unknown client", func() { h.ReplayFlow(bad[0], bad[1]) })
		}
	})
}
