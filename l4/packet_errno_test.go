//go:build !plan9

package l4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// pfErrno is a named errno of the l4 socket rows.
type pfErrno struct {
	name string
	err  error
}

// The Windows numbers (compared by number on every OS but plan9).
var (
	pfWSANoise = []pfErrno{
		{"WSAECONNRESET", syscall.Errno(10054)},
		{"WSAENETRESET", syscall.Errno(10052)},
		{"WSAENOBUFS", syscall.Errno(10055)},
		{"WSAEACCES", syscall.Errno(10013)},
		{"WSAENETDOWN", syscall.Errno(10050)},
		{"WSAEHOSTUNREACH", syscall.Errno(10065)},
		{"WSAENETUNREACH", syscall.Errno(10051)},
		{"WSAECONNREFUSED", syscall.Errno(10061)},
		{"WSAETIMEDOUT", syscall.Errno(10060)},
	}
	pfWSAFatal = []pfErrno{
		{"WSAENOTSOCK", syscall.Errno(10038)},
		{"WSAEINVAL", syscall.Errno(10022)},
		{"WSAEFAULT", syscall.Errno(10014)},
		{"WSAENOTCONN", syscall.Errno(10057)},
		{"WSAEDESTADDRREQ", syscall.Errno(10039)},
		{"WSAESHUTDOWN", syscall.Errno(10058)},
		{"WSAEOPNOTSUPP", syscall.Errno(10045)},
		{"WSAEBADF", syscall.Errno(10009)},
		{"WSAEISCONN", syscall.Errno(10056)},
	}
	pfWSASize = pfErrno{"WSAEMSGSIZE", syscall.Errno(10040)}
)

// pfNoiseErrnos are the noise rows of §A7.2 (R1-2): the Windows numbers
// and this OS's symbols.
func pfNoiseErrnos() []pfErrno { return append(append([]pfErrno(nil), pfWSANoise...), pfSymNoise()...) }

// pfFatalErrnos are the fatal set's rows.
func pfFatalErrnos() []pfErrno { return append(append([]pfErrno(nil), pfWSAFatal...), pfSymFatal()...) }

// pfSizeErrnos are the "message too long" rows.
func pfSizeErrnos() []pfErrno { return append([]pfErrno{pfWSASize}, pfSymSize()...) }

// pfWrapped returns e bare and as the net package returns it.
func pfWrapped(e pfErrno) []pfErrno {
	return []pfErrno{e, {e.name + " in OpError", &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", e.err)}}}
}

// TestErrClassTables (M6-D15, R1-2, R1-16; W1.3): errClass's tables. The
// size class: io.ErrShortBuffer (bare or wrapped), EMSGSIZE and
// WSAEMSGSIZE; the fatal set's errnos, and every error that is not an
// Errno (net.ErrClosed, io.EOF, a deadline, an embedder's timeout or own
// error), are fatal; every other errno, bare or wrapped as the net package
// returns it, is noise — also errnos no table names (ECONNRESET's kin,
// ETIMEDOUT, an unknown number).
func TestErrClassTables(t *testing.T) {
	var rows []struct {
		e    pfErrno
		want localClass
	}
	add := func(es []pfErrno, c localClass) {
		for _, e := range es {
			for _, w := range pfWrapped(e) {
				rows = append(rows, struct {
					e    pfErrno
					want localClass
				}{w, c})
			}
		}
	}
	add(pfNoiseErrnos(), classNoise)
	add([]pfErrno{{"an unknown number", syscall.Errno(4242)}}, classNoise)
	add(pfFatalErrnos(), classFatal)
	add(pfSizeErrnos(), classSize)
	add([]pfErrno{{"io.ErrShortBuffer", io.ErrShortBuffer}}, classSize)
	add([]pfErrno{
		{"net.ErrClosed", net.ErrClosed},
		{"io.EOF", io.EOF},
		{"os.ErrDeadlineExceeded", os.ErrDeadlineExceeded},
		{"an embedder's timeout", pfTimeoutErr{}},
		{"an embedder's error", errors.New("embedder")},
		{"rendr.ErrPacketTooLarge", rendr.ErrPacketTooLarge},
	}, classFatal)
	for _, r := range rows {
		if got := errClass(r.e.err); got != r.want {
			t.Errorf("errClass(%s) = %d, want %d", r.e.name, got, r.want)
		}
	}
}

// pfNoiseConn returns err from its next left Reads (counting every Read),
// then reads the wrapped conn.
type pfNoiseConn struct {
	net.Conn
	mu    sync.Mutex
	err   error
	left  int
	reads int
}

func (c *pfNoiseConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	c.reads++
	if c.left > 0 {
		c.left--
		c.mu.Unlock()
		return 0, c.err
	}
	c.mu.Unlock()
	return c.Conn.Read(b)
}

func (c *pfNoiseConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

// pfScriptConn returns its errors from its next Reads, one each, then
// reads the wrapped conn.
type pfScriptConn struct {
	net.Conn
	mu   sync.Mutex
	errs []error
}

func (c *pfScriptConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if len(c.errs) > 0 {
		err := c.errs[0]
		c.errs = c.errs[1:]
		c.mu.Unlock()
		return 0, err
	}
	c.mu.Unlock()
	return c.Conn.Read(b)
}

// TestForwardPacketNoise_L58_L73 (M6-D15, R1-2; L58, L73): every noise
// errno of §A7.2 (the OS's symbols and the Windows numbers, bare and
// wrapped) on a local Read and on a local Write is counted (LocalNoise)
// and ignored: the flow goes on, and the datagram after it is delivered
// (a Write's datagram is lost, as UDP's). EMSGSIZE and WSAEMSGSIZE on a
// Write are noise too (the size class is a read's). A local conn that
// fails every Read costs no spin: 10,000 consecutive noise errors take
// exactly 64 free reads and then the back-off (5 ms doubling to 100 ms):
// ≤ 64 + 5 + 100 reads in the first 10 virtual seconds, and the datagram
// behind them reaches the session after the sum of the waits (993.255 s).
// A size-class read (a datagram arrived, too long) ends a run: 64 noise
// errors, a WSAEMSGSIZE and 64 more cost no wait.
func TestForwardPacketNoise_L58_L73(t *testing.T) {
	var noise []pfErrno
	for _, e := range pfNoiseErrnos() {
		noise = append(noise, pfWrapped(e)...)
	}
	t.Run("each errno", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPFWorld(t, pfOpts{})
			dc, pc := w.dial(rendr.DialOptions{})
			app, local := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
			ctx, cancel := context.WithCancel(context.Background())
			res := pfForward(ctx, dc, local, FlowIdle{})
			writes := append(append([]pfErrno(nil), noise...), pfSizeErrnos()...)
			for i, e := range noise {
				local.Inject(e.err, false)
				d := pfData(30, byte(i))
				pfSend(t, app, d)
				if got, err := pfRecvPC(t, pc); err != nil || !bytes.Equal(got, d) {
					t.Fatalf("%s on Read: the next datagram %d bytes, %v", e.name, len(got), err)
				}
			}
			for i, e := range writes {
				local.InjectWrite(e.err, 1)
				pc.WriteTo(pfData(40, byte(i)), nil) // lost to the error
				next := pfData(41, byte(i))
				pc.WriteTo(next, nil)
				pfExpect(t, app, next)
			}
			cancel()
			r := <-res
			if r.LocalNoise != uint64(len(noise)+len(writes)) || r.LocalErr != nil || r.TooLarge != 0 ||
				r.ToSession != uint64(len(noise)) || r.ToLocal != uint64(len(writes)) || !errors.Is(r.SessionErr, context.Canceled) {
				t.Fatalf("result %+v: want %d noise errors counted, every next datagram moved, no end", r, len(noise)+len(writes))
			}
			if c := local.Counts(); c.Injected != uint64(len(noise)+len(writes)) {
				t.Fatalf("stimulus: %d injected errors returned, want %d", c.Injected, len(noise)+len(writes))
			}
			w.shutdown()
		})
	})
	t.Run("back-off", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPFWorld(t, pfOpts{})
			dc, pc := w.dial(rendr.DialOptions{})
			app, local := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
			const errs = 10000
			nc := &pfNoiseConn{Conn: local, err: noise[0].err, left: errs}
			d := pfData(30, 0x77)
			pfSend(t, app, d) // waits behind the errors
			t0 := time.Now()
			ctx, cancel := context.WithCancel(context.Background())
			res := pfForward(ctx, dc, nc, FlowIdle{Short: -1})
			time.Sleep(10 * time.Second)
			if n := nc.count(); n > noiseRunFree+5+100 || n < noiseRunFree+5+90 {
				t.Fatalf("%d reads in the first 10 s of a run of errors, want at most %d + 5 + 100 (the back-off) and at least %d", n, noiseRunFree, noiseRunFree+5+90)
			}
			pc.SetReadDeadline(time.Now().Add(time.Hour))
			buf := make([]byte, 64)
			n, _, err := pc.ReadFrom(buf)
			el := time.Since(t0)
			// The waits after errors 65 … 10,000: 5, 10, 20, 40, 80 ms, then
			// 100 ms each; then the read of d and the link's one way.
			want := 155*time.Millisecond + (errs-noiseRunFree-5)*noiseBackoffMax + pfOneWay
			if err != nil || !bytes.Equal(buf[:n], d) || el != want {
				t.Fatalf("the datagram behind %d errors arrived after %v (%d bytes, %v), want %v", errs, el, n, err, want)
			}
			if got := nc.count(); got != errs+2 {
				t.Fatalf("%d reads, want %d errors, the datagram's and the next (waiting)", got, errs)
			}
			cancel()
			if r := <-res; r.LocalNoise != errs || r.ToSession != 1 || r.LocalErr != nil {
				t.Fatalf("result %+v", r)
			}
			w.shutdown()
		})
	})
	t.Run("a size read ends the run", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPFWorld(t, pfOpts{})
			dc, pc := w.dial(rendr.DialOptions{})
			app, local := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
			var script []error
			for range 2 * noiseRunFree {
				script = append(script, noise[0].err)
			}
			script = slices.Insert(script, noiseRunFree, pfWSASize.err)
			sc := &pfScriptConn{Conn: local, errs: script}
			d := pfData(30, 0x78)
			pfSend(t, app, d) // waits behind the errors
			t0 := time.Now()
			ctx, cancel := context.WithCancel(context.Background())
			res := pfForward(ctx, dc, sc, FlowIdle{Short: -1})
			pc.SetReadDeadline(time.Now().Add(time.Hour))
			buf := make([]byte, 64)
			n, _, err := pc.ReadFrom(buf)
			if el := time.Since(t0); err != nil || !bytes.Equal(buf[:n], d) || el != pfOneWay {
				t.Fatalf("the datagram behind %d noise errors, a size error and %d more arrived after %v (%d bytes, %v), want %v: no back-off",
					noiseRunFree, noiseRunFree, el, n, err, pfOneWay)
			}
			cancel()
			if r := <-res; r.LocalNoise != 2*noiseRunFree || r.TooLarge != 1 || r.ToSession != 1 || r.LocalErr != nil {
				t.Fatalf("result %+v", r)
			}
			w.shutdown()
		})
	})
}

// TestForwardPacketTallyLive (W1.3; the passive's live UDPServerStatus
// counters): a forward given a packetTally counts into it as datagrams
// move — read while the flow runs — and its counts equal the
// PacketResult's at the end: datagrams each way, a dropped oversize one,
// a noise error.
func TestForwardPacketTallyLive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPFWorld(t, pfOpts{})
		dc, pc := w.dial(rendr.DialOptions{})
		app, local := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
		var tally packetTally
		ctx, cancel := context.WithCancel(context.Background())
		res := make(chan PacketResult, 1)
		go func() { res <- forwardPacket(ctx, dc, local, FlowIdle{}, flowSeed{}, &tally) }()
		for k := range 3 {
			pfSend(t, app, pfData(20, byte(k)))
			if _, err := pfRecvPC(t, pc); err != nil {
				t.Fatal(err)
			}
		}
		pfSend(t, app, pfData(dc.MaxPayload()+1, 9))
		local.Inject(pfWSANoise[0].err, false)
		for k := range 2 {
			pc.WriteTo(pfData(30, byte(k)), nil)
			pfRecv(t, app)
		}
		synctest.Wait()
		live := [4]uint64{tally.toSession.Load(), tally.toLocal.Load(), tally.tooLarge.Load(), tally.noise.Load()}
		if live != [4]uint64{3, 2, 1, 1} {
			t.Fatalf("live tally %v (to session, to local, too large, noise), want [3 2 1 1]", live)
		}
		cancel()
		r := <-res
		if got := [4]uint64{r.ToSession, r.ToLocal, r.TooLarge, r.LocalNoise}; got != live {
			t.Fatalf("result %+v, the tally %v", r, live)
		}
		w.shutdown()
	})
}
