//go:build !plan9 && !wasip1

// The errno rows of a foreign conn's error table: carrier.ClassifyPacketErr
// matches the Windows numbers on every OS (R1-28, integration 1 D16); Plan 9
// and WASI have no errno table (pkterr_noerrno.go), hence the constraint.

package udpflow

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// opErr wraps errno as a UDP conn returns it.
func opErr(op string, errno syscall.Errno) error {
	return &net.OpError{Op: op, Net: "udp", Err: os.NewSyscallError("wsa"+op, errno)}
}

func TestSourceForeignErrnos_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		defer h.shutdown()
		h.c.send(h1(1, wire.TypeOpen, 1), udpAddr(2, 1000))
		synctest.Wait()
		f := h.last()
		readOne(t, f, time.Second)

		h.c.fail(opErr("read", 10054))                // WSAECONNRESET: noise (plan:638)
		h.c.fail(opErr("read", 10052))                // WSAENETRESET: noise
		h.c.fail(opErr("read", 10053))                // WSAECONNABORTED: noise on a shared listening socket (D16)
		h.c.fail(opErr("read", syscall.ECONNREFUSED)) // ICMP class: noise
		h.c.fail(opErr("read", 10040))                // WSAEMSGSIZE: a truncated datagram
		h.c.send(dg(1, pingFrame(2)), udpAddr(2, 1000))
		if _, _, ev := readOne(t, f, time.Second); ev != carrier.ReadOK {
			t.Fatalf("event %d", ev)
		}
		st := h.s.Stats()
		if st.ReadErrors != 4 || st.Truncated != 1 || st.Flows != 1 {
			t.Fatalf("Stats %+v, want 4 read errors, 1 truncated, the flow alive", st)
		}

		b := make([]byte, wire.FlowHeaderLen+30)
		h.c.mu.Lock()
		h.c.wErrs = []fakeWrite{{err: opErr("write", 10053)}, {err: opErr("write", 10054)}, {err: opErr("write", 10040)}}
		h.c.mu.Unlock()
		if err := f.WriteDatagram(b); err != carrier.ErrNoise {
			t.Fatalf("WSAECONNABORTED on a write: %v, want ErrNoise (shared socket)", err)
		}
		if err := f.WriteDatagram(b); err != carrier.ErrNoise {
			t.Fatalf("WSAECONNRESET on a write: %v, want ErrNoise", err)
		}
		if err := f.WriteDatagram(b); !errors.Is(err, wire.ErrDatagramTooLarge) {
			t.Fatalf("WSAEMSGSIZE on a write: %v, want too large", err)
		}
	})
}
