package lessons6

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPacketDeadlinesE2E_L06: the L06 table through PacketConn, end to end
// over two datagram links (selector), each row on a live session of two
// Runtimes:
//
//   - a 200-ms read deadline fires within 150–500 ms; the error is a
//     timeout (net.Error.Timeout and os.ErrDeadlineExceeded) and the
//     session survives;
//   - a 5-s deadline shortened to now + 100 ms while ReadFrom waits returns
//     within 300 ms;
//   - a deadline extended before it fired does not fire: the datagram that
//     arrives later is returned;
//   - five waiting readers are all woken by a deadline set in the past;
//   - a passed read deadline fails ReadFrom even with datagrams queued;
//     cleared, they are returned intact;
//   - a passed write deadline fails WriteTo with (0, timeout) and no side
//     effect (nothing sent, counted or delivered); a future one never
//     delays WriteTo; SetDeadline sets both;
//   - deadlines never affect control frames: with every deadline of both
//     ends in the past for 30 s the carrier keeps its PING/PONG and lives;
//   - a deadline spans a migration: a reader waiting across the death of
//     the active carrier returns its timeout at the deadline, no error at
//     the death;
//   - the session's end takes precedence: the peer's FIN gives io.EOF and
//     the local Close net.ErrClosed, whatever the deadlines.
func TestPacketDeadlinesE2E_L06(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const oneWay = 10 * time.Millisecond
		w := newWorld(t, worldOpts{}, "A", "B")
		for _, l := range w.links {
			for _, d := range bothDirs {
				l.SetDelay(d, oneWay, 0)
			}
		}
		dc, pc := w.open(w.peer(dgCarrier(w.links[0], 1400), dgCarrier(w.links[1], 1400)), rendr.DialOptions{})
		v := rendrtest.NewPacketVerifier(51)
		seq := uint64(0)
		wbuf := make([]byte, wire.MaxDatagram)
		send := func(c *rendr.PacketConn) {
			t.Helper()
			n := sizeOf(int(seq))
			if m, err := c.WriteTo(rendrtest.PacketPayload(wbuf, 51, seq, n, time.Now()), nil); m != n || err != nil {
				t.Fatalf("WriteTo of seq %d = %d, %v", seq, m, err)
			}
			seq++
		}
		rbuf := make([]byte, wire.MaxDatagram+1)
		recv := func(c *rendr.PacketConn, what string) {
			t.Helper()
			n, addr, err := c.ReadFrom(rbuf)
			if err != nil || addr != c.RemoteAddr() {
				t.Fatalf("%s: ReadFrom = %d, %v, %v", what, n, addr, err)
			}
			if err := v.Add(rbuf[:n], time.Now()); err != nil {
				t.Fatalf("%s: %v", what, err)
			}
		}
		timedOut := func(what string, n int, addr net.Addr, err error) {
			t.Helper()
			if n != 0 || addr != nil || !isTimeout(err) {
				t.Fatalf("%s: = %d, %v, %v; want 0, nil, a timeout", what, n, addr, err)
			}
		}
		alive := func(what string) {
			t.Helper()
			for _, c := range []*rendr.PacketConn{dc, pc} {
				if st := c.Status(); st.State == rendr.StateEnded {
					t.Fatalf("%s: the %v session ended: %v", what, st.Role, st.Err)
				}
			}
			received := v.Result().Unique
			send(dc)
			recv(pc, what+": the next datagram")
			if v.Result().Unique != received+1 {
				t.Fatalf("%s: the session did not deliver after the deadline", what)
			}
		}

		// A 200-ms read deadline.
		start := time.Now()
		if err := pc.SetReadDeadline(start.Add(200 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, addr, err := pc.ReadFrom(rbuf)
		timedOut("200 ms", n, addr, err)
		if d := time.Since(start); d < 150*time.Millisecond || d > 500*time.Millisecond {
			t.Fatalf("a 200-ms deadline fired after %v", d)
		}
		_ = pc.SetReadDeadline(time.Time{})
		alive("200 ms")

		// Shortened while waiting.
		start = time.Now()
		_ = pc.SetReadDeadline(start.Add(5 * time.Second))
		go func() {
			time.Sleep(100 * time.Millisecond)
			_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}()
		n, addr, err = pc.ReadFrom(rbuf)
		timedOut("shortened", n, addr, err)
		if d := time.Since(start); d > 300*time.Millisecond {
			t.Fatalf("the shortened deadline returned after %v, want within 300 ms", d)
		}
		_ = pc.SetReadDeadline(time.Time{})
		alive("shortened")

		// Extended before it fired: the old expiry does nothing.
		start = time.Now()
		_ = pc.SetReadDeadline(start.Add(100 * time.Millisecond))
		late := make(chan error, 1)
		go func() {
			time.Sleep(50 * time.Millisecond)
			_ = pc.SetReadDeadline(time.Now().Add(time.Second))
			time.Sleep(450 * time.Millisecond)
			b := rendrtest.PacketPayload(nil, 51, seq, sizeOf(int(seq)), time.Now())
			_, err := dc.WriteTo(b, nil)
			late <- err
		}()
		recv(pc, "extended")
		if err := <-late; err != nil {
			t.Fatalf("the late datagram's WriteTo: %v", err)
		}
		seq++
		if d := time.Since(start); d != 500*time.Millisecond+oneWay {
			t.Fatalf("after the extension ReadFrom returned at %v, want the datagram's arrival at %v", d, 500*time.Millisecond+oneWay)
		}
		_ = pc.SetReadDeadline(time.Time{})

		// Five waiting readers, one past deadline.
		var wg sync.WaitGroup
		errs := make([]error, 5)
		for i := range errs {
			wg.Go(func() { _, _, errs[i] = pc.ReadFrom(make([]byte, 2048)) })
		}
		synctest.Wait()
		_ = pc.SetReadDeadline(time.Now().Add(-time.Second))
		woken := make(chan struct{})
		go func() { wg.Wait(); close(woken) }()
		select {
		case <-woken:
		case <-time.After(time.Second):
			t.Fatalf("a past deadline did not wake the waiting readers within 1 s: %v", errs)
		}
		for i, err := range errs {
			if !isTimeout(err) {
				t.Fatalf("waiting reader %d: %v, want a timeout", i, err)
			}
		}

		// A passed deadline with datagrams queued.
		rx0 := pc.Status().Packet.Received
		for range 3 {
			send(dc)
		}
		waitFor(t, time.Second, "three queued datagrams", func() bool { return pc.Status().Packet.Received == rx0+3 })
		n, addr, err = pc.ReadFrom(rbuf)
		timedOut("queued datagrams past the deadline", n, addr, err)
		_ = pc.SetReadDeadline(time.Time{})
		for range 3 {
			recv(pc, "the queued datagrams")
		}

		// A passed write deadline: (0, timeout), no side effect.
		_ = dc.SetWriteDeadline(time.Now().Add(-time.Millisecond))
		before, rxBefore := dc.Status(), pc.Status().Packet.Received
		m, err := dc.WriteTo(rendrtest.PacketPayload(wbuf, 51, seq, 100, time.Now()), nil)
		if m != 0 || !isTimeout(err) {
			t.Fatalf("WriteTo past the write deadline = %d, %v; want 0, a timeout", m, err)
		}
		time.Sleep(time.Second)
		after := dc.Status()
		// PeerReceived is the peer's report (its PACK), not this side's.
		after.Packet.PeerReceived = before.Packet.PeerReceived
		if after.TxBytes != before.TxBytes || *after.Packet != *before.Packet || pc.Status().Packet.Received != rxBefore {
			t.Fatalf("a timed-out WriteTo had a side effect: TxBytes %d → %d, %+v → %+v, passive Received %d → %d",
				before.TxBytes, after.TxBytes, *before.Packet, *after.Packet, rxBefore, pc.Status().Packet.Received)
		}
		// A future write deadline never delays WriteTo.
		_ = dc.SetWriteDeadline(time.Now().Add(time.Millisecond))
		at := time.Now()
		send(dc)
		if d := time.Since(at); d != 0 {
			t.Fatalf("WriteTo with a future deadline took %v", d)
		}
		recv(pc, "after the write deadline moved")
		_ = dc.SetWriteDeadline(time.Time{})
		// SetDeadline sets both.
		_ = dc.SetDeadline(time.Now().Add(-time.Millisecond))
		if m, err := dc.WriteTo(wbuf[:100], nil); m != 0 || !isTimeout(err) {
			t.Fatalf("WriteTo after SetDeadline(past) = %d, %v", m, err)
		}
		n, addr, err = dc.ReadFrom(rbuf)
		timedOut("ReadFrom after SetDeadline(past)", n, addr, err)
		_ = dc.SetDeadline(time.Time{})
		alive("write deadline")

		// Control frames ignore deadlines: 30 s with every deadline past.
		a0, _ := activeOf(dc.Status())
		pongs0 := w.links[0].Stats().Session.Delivered + w.links[1].Stats().Session.Delivered
		for _, c := range []*rendr.PacketConn{dc, pc} {
			_ = c.SetDeadline(time.Now().Add(-time.Second))
		}
		time.Sleep(30 * time.Second)
		if evs := append(w.dev.of(rendr.EventCarrierDown), w.pev.of(rendr.EventCarrierDown)...); len(evs) != 0 {
			t.Fatalf("a carrier went down while every deadline was past: %+v", evs)
		}
		if a, _ := activeOf(dc.Status()); a.ID != a0.ID {
			t.Fatalf("the active carrier changed from %d to %d while idle", a0.ID, a.ID)
		}
		if pongs := w.links[0].Stats().Session.Delivered + w.links[1].Stats().Session.Delivered; pongs == pongs0 {
			t.Fatalf("stimulus: no control datagram crossed in 30 s")
		}
		for _, c := range []*rendr.PacketConn{dc, pc} {
			_ = c.SetDeadline(time.Time{})
		}
		alive("control frames")

		// A deadline across a migration: the active link dies 1 s into a
		// 3-s wait.
		var la *rendrtest.DatagramLink
		for _, l := range w.links {
			if l.Name() == a0.Name {
				la = l
			}
		}
		start = time.Now()
		_ = pc.SetReadDeadline(start.Add(3 * time.Second))
		go func() {
			time.Sleep(time.Second)
			la.Kill()
		}()
		n, addr, err = pc.ReadFrom(rbuf)
		timedOut("across the death", n, addr, err)
		if d := time.Since(start); d != 3*time.Second {
			t.Fatalf("the wait across the death returned after %v, want the deadline (3 s)", d)
		}
		_ = pc.SetReadDeadline(time.Time{})
		if m := dc.Status().Migrations; m.Death != 1 {
			t.Fatalf("stimulus: migrations %+v, want one death migration", m)
		}
		alive("across the death")

		// The end takes precedence over every deadline.
		_ = pc.SetDeadline(time.Now().Add(-time.Second))
		_ = dc.SetDeadline(time.Now().Add(-time.Second))
		if err := dc.Close(); err != nil {
			t.Fatal(err)
		}
		if m, err := dc.WriteTo(wbuf[:100], nil); m != 0 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("WriteTo after Close with a past deadline = %d, %v; want net.ErrClosed", m, err)
		}
		if _, _, err := dc.ReadFrom(rbuf); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom after Close with a past deadline: %v; want net.ErrClosed", err)
		}
		if err := dc.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("SetReadDeadline after Close: %v; want net.ErrClosed", err)
		}
		waitFor(t, 5*time.Second, "io.EOF through a past read deadline", func() bool {
			_, _, err := pc.ReadFrom(rbuf)
			if err != nil && !isTimeout(err) && err != io.EOF {
				t.Fatalf("the passive's ReadFrom: %v", err)
			}
			return err == io.EOF
		})
		if m, err := pc.WriteTo(wbuf[:100], nil); m != 0 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("the passive's WriteTo after the peer's FIN with a past deadline = %d, %v; want net.ErrClosed", m, err)
		}
		pc.Close()
		waitDone(t, 10*time.Second, dc, pc)
		res := v.Result()
		if res.Unique != seq || res.Duplicates+res.Corrupt+res.BadSize != 0 || len(res.Missing) != 0 {
			t.Fatalf("datagrams: %d written, %+v", seq, res)
		}
		w.noViolation()
		w.close()
	})
}
