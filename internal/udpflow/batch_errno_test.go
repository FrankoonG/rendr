//go:build !plan9 && !wasip1

// The errno rows of the batched Source and flows (§A6.4): the errors of
// rendr's own socket are errnos, which Plan 9 and WASI lack (errno_test.go's
// constraint), so these rows build everywhere else.

package udpflow

import (
	"errors"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestFlowWriteDatagramsNoise (§A4.5, §A6.4): the error of datagram n of a
// WriteDatagrams call is returned with n and classified as WriteDatagram's:
// an ICMP-class errno at datagram 2 is noise after two datagrams left (the
// errno row of TestFlowWriteDatagramsSeam).
func TestFlowWriteDatagramsNoise(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		c := newFakeSock(4)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		c.queue(apOf(2, 1000), h1(7, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		readOne(t, f, time.Second)
		ds := make([][]byte, 4)
		for i := range ds {
			ds[i] = make([]byte, wire.FlowHeaderLen+3)
		}
		c.mu.Lock()
		c.wErrs = []fakeWErr{{n: 2, err: opErr("write", syscall.ECONNREFUSED)}}
		c.mu.Unlock()
		if n, err := f.WriteDatagrams(ds); n != 2 || err != carrier.ErrNoise {
			t.Fatalf("noise at datagram 2: %d, %v", n, err)
		}
		if got := len(c.written()); got != 2 {
			t.Fatalf("%d datagrams written, want 2 (the two before the noise)", got)
		}
	})
}

// TestSourceOwnedErrnos_L58 (§A6.4): the errors of rendr's own socket —
// a udpsocket.Conn returns the socket's errnos — keep M2's classes on the
// batched paths: on a read, noise and an abort back off, a too-large error
// is a truncated datagram; on a write, too large is a refusal without a
// size, noise, a local filter's EPERM and an abort lose the datagram, and
// anything else ends the carrier.
func TestSourceOwnedErrnos_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		c := newFakeSock(32)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		peer := apOf(2, 1000)
		c.queue(peer, h1(1, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		readOne(t, f, time.Second)

		c.failRead(opErr("read", syscall.ECONNREFUSED))
		c.failRead(opErr("read", syscall.ECONNABORTED))
		c.failRead(opErr("read", 10040)) // WSAEMSGSIZE
		c.queue(peer, dg(1, pingFrame(2)))
		if _, _, ev := readOne(t, f, time.Second); ev != carrier.ReadOK {
			t.Fatalf("event %d", ev)
		}
		if st := h.s.Stats(); st.ReadErrors != 2 || st.Truncated != 1 || st.Flows != 1 {
			t.Fatalf("Stats %+v, want 2 read errors, 1 truncated, the flow alive", st)
		}

		b := make([]byte, wire.FlowHeaderLen+30)
		for _, tc := range []struct {
			err  error
			want error
		}{
			{opErr("write", syscall.EMSGSIZE), wire.ErrDatagramTooLarge},
			{opErr("write", syscall.ENOBUFS), carrier.ErrNoise},
			{opErr("write", syscall.EPERM), carrier.ErrNoise},
			{opErr("write", syscall.ECONNABORTED), carrier.ErrNoise},
			{opErr("write", syscall.EINVAL), syscall.EINVAL},
		} {
			c.mu.Lock()
			c.wErrs = []fakeWErr{{err: tc.err}}
			c.mu.Unlock()
			if err := f.WriteDatagram(b); !errors.Is(err, tc.want) {
				t.Errorf("%v: %v, want %v", tc.err, err, tc.want)
			}
		}
		c.failRead(opErr("read", syscall.EINVAL)) // permanent: this source stops
		synctest.Wait()
		if !h.s.killed.Load() {
			t.Fatal("a permanent read error did not stop the source")
		}
		if _, _, _, err := f.ReadDatagram(nil); err == nil {
			t.Fatal("a flow of a stopped source still reads")
		}
	})
}
