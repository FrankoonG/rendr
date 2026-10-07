//go:build !plan9 && !wasip1

package carrier

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// wbTemporary is an error that reports Temporary().
type wbTemporary struct{}

func (wbTemporary) Error() string   { return "temporary" }
func (wbTemporary) Temporary() bool { return true }

// TestPacketIOErrorClasses_L58: the embedder adapter maps its conn's
// results to the datagram I/O contract by ClassifyPacketErr's one table on
// every OS (M2 design §A6.4; R1-28; integration 1, D11, D13, D16): on a
// read, ICMP-class errnos, ENOBUFS, Temporary() and ErrNoise are noise,
// WSAEMSGSIZE a truncation, and an abort, EPERM, a closed conn, a panic and
// an invalid count end the carrier, while the caller's deadline comes back
// as itself; on a write, EPERM and the ICMP class are noise, EMSGSIZE a
// size refusal with no Max and the embedder's DatagramTooLargeError keeps
// its Max, and an abort, a panic, the deadline and every invalid count —
// short, long, negative, zero — are errors that are neither noise nor a
// size refusal (L42, L58).
func TestPacketIOErrorClasses_L58(t *testing.T) {
	env := dgEnv()
	peer := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2).To4(), Port: 4000}
	op := func(err error) error { return &net.OpError{Op: "read", Net: "udp", Err: err} }
	t.Run("read", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			r     wbRead
			ev    ReadEvent
			death bool // an error ends the carrier
			dl    bool // the error is the caller's deadline
		}{
			{"WSAECONNRESET", wbRead{err: op(pktWSAECONNRESET)}, ReadNoise, false, false},
			{"ECONNREFUSED", wbRead{err: op(syscall.ECONNREFUSED)}, ReadNoise, false, false},
			{"WSAENETRESET", wbRead{err: op(pktWSAENETRESET)}, ReadNoise, false, false},
			{"ENOBUFS", wbRead{err: op(syscall.ENOBUFS)}, ReadNoise, false, false},
			{"Temporary", wbRead{err: wbTemporary{}}, ReadNoise, false, false},
			{"ErrNoise", wbRead{err: fmt.Errorf("wrapped: %w", ErrNoise)}, ReadNoise, false, false},
			{"WSAEMSGSIZE", wbRead{n: 1501, err: op(pktWSAEMSGSIZE)}, ReadTruncated, false, false},
			{"WSAECONNABORTED", wbRead{err: op(pktWSAECONNABORTED)}, 0, true, false},
			{"ECONNABORTED", wbRead{err: op(syscall.ECONNABORTED)}, 0, true, false},
			{"EPERM", wbRead{err: op(syscall.EPERM)}, 0, true, false},
			{"closed", wbRead{err: net.ErrClosed}, 0, true, false},
			{"deadline", wbRead{err: os.ErrDeadlineExceeded}, 0, true, true},
			{"count -1", wbRead{n: -1, src: peer}, 0, true, false},
			{"count beyond the buffer", wbRead{n: 1502, src: peer}, 0, true, false},
			{"count filling the buffer", wbRead{n: 1501, src: peer}, ReadTruncated, false, false},
			{"empty", wbRead{n: 0, src: peer}, ReadEmpty, false, false},
		} {
			pc := newWBPC()
			io, err := NewPacketIO(env, pc, peer, 1500)
			if err != nil {
				t.Fatal(err)
			}
			pc.push(tc.r)
			_, _, ev, err := io.ReadDatagram(make([]byte, io.ReadSize()))
			switch {
			case tc.death && err == nil:
				t.Errorf("%s: no error (event %v), want the carrier's end", tc.name, ev)
			case !tc.death && (err != nil || ev != tc.ev):
				t.Errorf("%s: %v, %v; want event %v", tc.name, ev, err, tc.ev)
			case tc.death && errors.Is(err, os.ErrDeadlineExceeded) != tc.dl:
				t.Errorf("%s: %v: deadline %v, want %v", tc.name, err, !tc.dl, tc.dl)
			}
		}
		pp := &wbPanicPC{wbPC: newWBPC()}
		io, _ := NewPacketIO(env, pp, peer, 1500)
		if _, _, _, err := io.ReadDatagram(make([]byte, io.ReadSize())); err == nil {
			t.Errorf("a panicking ReadFrom is no error")
		}
	})
	t.Run("write", func(t *testing.T) {
		tooLarge := &wire.DatagramTooLargeError{Max: 900}
		for _, tc := range []struct {
			name string
			n    int // relative to len(p) when rel
			rel  bool
			err  error
			want string // noise, size, size900, death, deadline
		}{
			{"EPERM", 0, false, op(syscall.EPERM), "noise"},
			{"WSAECONNRESET", 0, false, op(pktWSAECONNRESET), "noise"},
			{"EHOSTUNREACH", 0, false, op(syscall.EHOSTUNREACH), "noise"},
			{"ErrNoise", 0, false, ErrNoise, "noise"},
			{"Temporary", 0, false, wbTemporary{}, "noise"},
			{"EMSGSIZE", 0, false, op(syscall.EMSGSIZE), "size"},
			{"WSAEMSGSIZE", 0, false, op(pktWSAEMSGSIZE), "size"},
			{"DatagramTooLargeError", 0, false, tooLarge, "size900"},
			{"WSAECONNABORTED", 0, false, op(pktWSAECONNABORTED), "death"},
			{"ECONNABORTED", 0, false, op(syscall.ECONNABORTED), "death"},
			{"closed", 0, false, net.ErrClosed, "death"},
			{"deadline", 0, false, os.ErrDeadlineExceeded, "deadline"},
			{"short", -3, true, nil, "death"},
			{"long", 1, true, nil, "death"},
			{"negative", -1, false, nil, "death"},
			{"zero", 0, false, nil, "death"},
		} {
			pc := newWBPC()
			pc.wfn = func(p []byte, _ net.Addr) (int, error) {
				if tc.rel {
					return len(p) + tc.n, tc.err
				}
				return tc.n, tc.err
			}
			io, _ := NewPacketIO(env, pc, peer, 1500)
			err := io.WriteDatagram(make([]byte, 100))
			var te *wire.DatagramTooLargeError
			size := errors.As(err, &te)
			noise := errors.Is(err, ErrNoise)
			switch tc.want {
			case "noise":
				if !noise || size {
					t.Errorf("%s: %v, want ErrNoise", tc.name, err)
				}
			case "size", "size900":
				want := 0
				if tc.want == "size900" {
					want = 900
				}
				if !size || te.Max != want || noise {
					t.Errorf("%s: %v, want a size refusal with Max %d", tc.name, err, want)
				}
			case "deadline":
				if !errors.Is(err, os.ErrDeadlineExceeded) || noise || size {
					t.Errorf("%s: %v, want the deadline", tc.name, err)
				}
			default:
				if err == nil || noise || size {
					t.Errorf("%s: %v, want an error that ends the carrier", tc.name, err)
				}
			}
		}
		pp := &wbPanicPC{wbPC: newWBPC()}
		io, _ := NewPacketIO(env, pp, peer, 1500)
		if err := io.WriteDatagram(make([]byte, 10)); err == nil || errors.Is(err, ErrNoise) {
			t.Errorf("a panicking WriteTo: %v, want an error that ends the carrier", err)
		}
	})
}

// wbPanicPC is a wbPC whose ReadFrom and WriteTo panic.
type wbPanicPC struct{ *wbPC }

func (*wbPanicPC) ReadFrom([]byte) (int, net.Addr, error) { panic("ReadFrom") }
func (*wbPanicPC) WriteTo([]byte, net.Addr) (int, error)  { panic("WriteTo") }
