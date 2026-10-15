//go:build linux && (amd64 || arm64)

package carrier

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// M5 WP2 rows of the dialer reader over a real loopback socket that
// batches (recvmmsg through udpsocket.Reader).

// gateEP is a packet endpoint that holds the reader inside the delivery of
// DGRAM seq gate until open is closed, and counts every delivery.
type gateEP struct {
	dEP
	gate uint64
	at   chan struct{} // closed when the gated DGRAM arrives
	open chan struct{}
	got  atomic.Int64
}

func (e *gateEP) Datagram(c *Conn, seq uint64, p []byte, buf *Buf) error {
	if seq == e.gate {
		close(e.at)
		<-e.open
	}
	e.got.Add(1)
	return e.dEP.Datagram(c, seq, p, buf)
}

// wp2RealDialer returns a dialer carrier over rendr's own loopback socket
// toward a raw socket, unstarted, with MaxBatch 32, and that raw sender.
func wp2RealDialer(t *testing.T) (c *Conn, env *Env, raw *wp2Raw) {
	t.Helper()
	ru, _ := wp5Listen(t, "udp4")
	du, _ := wp5Listen(t, "udp4")
	o := NewOwnedUDPBatch(du, wp5AP(ru), wp5Flow, wp5MaxDatagram, 32)
	env = wp2Env()
	c = dgConn(env, o, 1200, true)
	raw = &wp2Raw{t: t, u: ru, dst: wp5AP(du), p: &rawPeer{fseq: env.Presets.firstFseq()}}
	t.Cleanup(func() {
		c.Kill(CauseLocalClose, "test end")
		<-c.Done()
		ru.Close()
	})
	return c, env, raw
}

// wp2Raw sends DGRAM datagrams with the flow's header to the dialer.
type wp2Raw struct {
	t   *testing.T
	u   *net.UDPConn
	dst netip.AddrPort
	p   *rawPeer
}

func (r *wp2Raw) send(from, n int) {
	for i := range n {
		d := append(wp5Header(wp5Flow), r.p.datagram(dgramFrame(uint64(from+i), 100))...)
		wp5Send(r.t, r.u, d, r.dst)
	}
}

// TestDgramReaderDrainsQueued_L54 (R1-7): 64 datagrams are queued on the
// dialer socket before its reader starts: it drains them in at most 7
// counted receive calls (depths 1, 2, 4, …, 32), the tail call that found
// datagrams queued keeps the depth, and a second burst of 20, queued while
// the reader is busy, is read in one call.
func TestDgramReaderDrainsQueued_L54(t *testing.T) {
	t.Cleanup(g10NoLeak(t)) // runs after wp2RealDialer's cleanup has ended the carrier
	c, env, raw := wp2RealDialer(t)
	ep := &gateEP{gate: 63, at: make(chan struct{}), open: make(chan struct{})}
	raw.send(0, 64)
	c.Start(ep, &hBell{}, StartOptions{})
	select {
	case <-ep.at:
	case <-time.After(10 * time.Second):
		t.Fatal("the 64th datagram never arrived")
	}
	_, _, calls, moved, _ := env.Dgram.IO.Load()
	if moved != 64 || calls > 7 {
		close(ep.open)
		t.Fatalf("%d datagrams in %d counted receive calls, want 64 in at most 7", moved, calls)
	}
	raw.send(64, 20) // queued while the reader is held inside the 64th delivery
	close(ep.open)
	waitFor(t, "84 deliveries", func() bool { return ep.got.Load() == 84 })
	_, _, calls2, moved2, _ := env.Dgram.IO.Load()
	if calls2-calls != 1 || moved2-moved != 20 {
		t.Fatalf("second burst: %d datagrams in %d calls, want 20 in 1", moved2-moved, calls2-calls)
	}
}

// TestDgramReaderIdleReleaseRealSocket (R1-5 with the kernel): after a
// burst the reader parks in recvmmsg holding its extras; the idle release
// returns them while it is parked and wakes it, and the reader goes on at
// depth 1 — a later datagram is delivered, nothing is charged beyond the
// baseline, the carrier lives.
func TestDgramReaderIdleReleaseRealSocket(t *testing.T) {
	t.Cleanup(g10NoLeak(t)) // runs after wp2RealDialer's cleanup has ended the carrier
	setIdleRelease(t, 50*time.Millisecond)
	c, env, raw := wp2RealDialer(t)
	ep := &gateEP{gate: ^uint64(0)}
	c.Start(ep, &hBell{}, StartOptions{Hold: true}) // held: the writer writes nothing, so the accounts hold the reader's alone
	sbase := 2 * slotSize()                         // the reader's buffer and the writer's scratch
	waitFor(t, "the reader's start", func() bool { return env.Stages.Used() == sbase })
	base := env.Budget.Used()
	raw.send(0, 64)
	waitFor(t, "64 deliveries", func() bool { return ep.got.Load() == 64 })
	if env.Budget.Used() == base {
		t.Fatal("no slot charged after a burst of 64: the reader did not batch")
	}
	waitFor(t, "the idle release", func() bool { return env.Budget.Used() == base && env.Stages.Used() == sbase })
	raw.send(64, 1)
	waitFor(t, "a datagram after the release", func() bool { return ep.got.Load() == 65 })
	if dead, cause, detail, _ := c.Death(); dead {
		t.Fatalf("carrier died: %v %q", cause, detail)
	}
}
