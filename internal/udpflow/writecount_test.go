package udpflow

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// countPC is a foreign conn (fakeConn) that misreports the counts of its
// next writes: each of them is sent — recorded as written — and then
// reports lies[0](len) instead of the datagram's length (nil: the true
// count; L42: an embedder conn that sent a datagram and returned
// (len+1, nil) or (0, nil)).
type countPC struct {
	*fakeConn
	lmu  sync.Mutex
	lies []func(n int) int
}

func (c *countPC) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.fakeConn.WriteTo(p, addr)
	c.lmu.Lock()
	defer c.lmu.Unlock()
	if err == nil && len(c.lies) > 0 {
		if lie := c.lies[0]; lie != nil {
			n = lie(n)
		}
		c.lies = c.lies[1:]
	}
	return n, err
}

// lie queues the counts of the next writes (nil: the true count).
func (c *countPC) lie(fs ...func(n int) int) {
	c.lmu.Lock()
	c.lies = append(c.lies, fs...)
	c.lmu.Unlock()
}

// TestFlowForeignWriteCount_L42 (L42; A3 of the second review wave): on the
// passive side, a flow of a foreign conn whose WriteTo sent the datagram
// and reported (len+1, nil) or (0, nil) returns an error matching
// carrier.ErrWriteCount — the identity by which the carrier's writer knows
// that the datagrams of the call may have left and hands none of them back
// (internal/carrier's TestDgramUnsentNotReturnedOnAdapterCount_L42) —
// neither noise nor a size refusal, so the carrier dies. Through
// WriteDatagrams the datagrams before it are counted written, the
// misreported one was sent, and the call's later datagrams were never
// given to the conn. Mutant: errWriteCount not wrapping
// carrier.ErrWriteCount.
func TestFlowForeignWriteCount_L42(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		pc := &countPC{fakeConn: newFakeConn()}
		s := NewSource(env, pc, Limits{})
		admitted := make(chan *Flow, 1)
		go s.Run(func(f *Flow) { admitted <- f })
		defer func() {
			s.Abort()
			<-s.Done()
		}()
		pc.send(h1(1, wire.TypeOpen, 1), udpAddr(2, 1000))
		synctest.Wait()
		var f *Flow
		select {
		case f = <-admitted:
		default:
			t.Fatal("no flow admitted")
		}
		defer f.Close()
		readOne(t, f, time.Second)
		f.Admitted()
		datagram := func(i byte) []byte {
			b := make([]byte, wire.FlowHeaderLen+20)
			b[wire.FlowHeaderLen] = i
			return b
		}
		lies := []struct {
			name string
			lie  func(n int) int
		}{
			{"(len+1, nil)", func(n int) int { return n + 1 }},
			{"(0, nil)", func(int) int { return 0 }},
		}
		for _, l := range lies {
			// One datagram, WriteDatagram's path.
			mark := len(pc.written())
			pc.lie(l.lie)
			err := f.WriteDatagram(datagram(1))
			if !errors.Is(err, carrier.ErrWriteCount) || errors.Is(err, carrier.ErrNoise) || errors.Is(err, wire.ErrDatagramTooLarge) {
				t.Fatalf("%s: WriteDatagram: %v, want an error matching carrier.ErrWriteCount (L42)", l.name, err)
			}
			if w := pc.written()[mark:]; len(w) != 1 || w[0].b[wire.FlowHeaderLen] != 1 {
				t.Fatalf("%s: stimulus: %d datagrams written, want the misreported one sent", l.name, len(w))
			}

			// A call of four, the second misreported.
			ds := [][]byte{datagram(10), datagram(11), datagram(12), datagram(13)}
			mark = len(pc.written())
			pc.lie(nil, l.lie)
			n, err := f.WriteDatagrams(ds)
			if n != 1 || !errors.Is(err, carrier.ErrWriteCount) {
				t.Fatalf("%s: WriteDatagrams of 4, the second misreported: %d, %v; want 1 and an error matching carrier.ErrWriteCount", l.name, n, err)
			}
			w := pc.written()[mark:]
			if len(w) != 2 || !bytes.Equal(w[0].b, ds[0]) || !bytes.Equal(w[1].b, ds[1]) {
				t.Fatalf("%s: %d datagrams written, want ds[0] and the misreported ds[1] (ds[2:] never given to the conn)", l.name, len(w))
			}
		}
	})
}

var _ net.PacketConn = (*countPC)(nil)
