package l4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestForwardPacketShortWrite_L42 (M6-D14, M6-D15; L42): a datagram write
// must be exactly complete. A local Write that returns fewer bytes than
// the datagram with a nil error (an embedder or hook conn that breaks
// io.Writer's contract; it sends nothing here) is an invalid count, as a
// Read's count outside its buffer is: the datagram is not counted
// delivered, the forward ends with LocalErr errBadDatagramCount and
// SessionErr net.ErrClosed, the peer reads io.EOF and local is closed
// once. The flow moved one datagram each way before. Through HandleUDP
// (no first datagram) the same write ends the flow Local and is not in
// UDPServerStatus.ToTarget.
func TestForwardPacketShortWrite_L42(t *testing.T) {
	t.Run("ForwardPacket", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPFWorld(t, pfOpts{})
			dc, pc := w.dial(rendr.DialOptions{})
			app, local := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
			short := &pfShortWrite{Conn: local, at: 2}
			spy := &spyConn{Conn: short}
			res := pfForward(context.Background(), dc, spy, FlowIdle{})
			up, down := pfData(40, 1), pfData(50, 2)
			pfSend(t, app, up)
			if got, err := pfRecvPC(t, pc); err != nil || !bytes.Equal(got, up) {
				t.Fatalf("before: passive read %d bytes, %v", len(got), err)
			}
			pc.WriteTo(down, nil)
			pfExpect(t, app, down)
			pc.WriteTo(pfData(70, 3), nil) // local's second Write reports 69 bytes and sends nothing
			var r PacketResult
			select {
			case r = <-res:
			case <-time.After(10 * time.Second):
				t.Fatal("the forward did not end at the short write")
			}
			if !errors.Is(r.LocalErr, errBadDatagramCount) || !errors.Is(r.SessionErr, net.ErrClosed) || r.ToLocal != 1 || r.ToSession != 1 {
				t.Fatalf("result %+v: want LocalErr errBadDatagramCount, SessionErr net.ErrClosed, ToLocal 1 and ToSession 1", r)
			}
			if _, err := pfRecvPC(t, pc); !errors.Is(err, io.EOF) {
				t.Fatalf("the peer reads %v, want io.EOF (the session closed)", err)
			}
			synctest.Wait()
			if _, _, closes, _ := spy.snapshot(); closes != 1 {
				t.Fatalf("local closed %d times, want once", closes)
			}
			w.shutdown()
		})
	})
	t.Run("HandleUDP", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSUWorld(t, suOpts{})
			ts := newSUTargets(rendrtest.DatagramPipeConfig{})
			ts.wrap = func(srv, _ *rendrtest.DatagramConn, _ Request) net.Conn { return &suShortWrite{DatagramConn: srv} }
			s := &Server{UDP: true, Dial: ts.dial}
			sv := suServe(w, s)
			pc := suDial(t, w, pfTarget, nil)
			app := ts.next(t, time.Minute)
			pc.WriteTo(pfData(60, 4), nil) // the forward's first Write reports 59 bytes and sends nothing
			waitFor(t, time.Minute, "the flow ends Local", func() bool { return s.Status().UDP.Ended.Local == 1 })
			if u := s.Status().UDP; u.ToTarget != 0 || u.Confirmed != 1 || u.Live != 0 {
				t.Fatalf("UDP status %+v: want ToTarget 0 (the short write is not delivered), one flow confirmed and ended", u)
			}
			if _, err := pfRecvPC(t, pc); !errors.Is(err, io.EOF) {
				t.Fatalf("the dialer reads %v, want io.EOF (the flow ended)", err)
			}
			if c := app.Counts(); c.In != 0 {
				t.Fatalf("the target read %d datagrams, want none", c.In)
			}
			pc.Close()
			sv.stop(t)
			suUnits(t, s)
			w.shutdown()
		})
	})
}

// pfShortWrite wraps a local conn: its at-th Write (from 1) reports one
// byte less than it was given, with no error, and sends nothing (an
// invalid count, L42); the others pass through.
type pfShortWrite struct {
	net.Conn
	at, n int // only the forward's caller goroutine writes
}

func (c *pfShortWrite) Write(b []byte) (int, error) {
	if c.n++; c.n == c.at {
		return len(b) - 1, nil
	}
	return c.Conn.Write(b)
}
