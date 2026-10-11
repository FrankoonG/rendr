package l4

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The L4 forwarding benchmark (§A13.2; rendr-regress perf/l4-forward runs
// it from the pin's l4 test binary with -test.bench ^BenchmarkL4Forward$
// -test.cpu 8, and its variants once): BENCH-E2E-1's generator and CRC
// through the L4 path built from rendr's public API. A generator writes
// PRNG bytes to a loopback TCP ingress; the ingress l4.Dials one L4 session
// per accepted connection and Forwards it; the session runs over one
// carrier/tcp loopback carrier to an l4.Server, which dials a loopback TCP
// target and Forwards to it; the target counts the bytes and computes
// their CRC-32C, answering both at the generator's FIN. Against
// BENCH-E2E-1 each byte costs two Forward copies and four loopback socket
// syscalls more. One op is benchChunk bytes per session (b.SetBytes); the
// count and the CRC are checked at the end, so a benchmark that lost or
// damaged a byte fails.

// benchChunk is one op's bytes per session (one generator Write).
const benchChunk = 1 << 20

// BenchmarkL4Forward: one L4 session with Forward's 32-KiB buffer.
func BenchmarkL4Forward(b *testing.B) { benchL4Forward(b, 1) }

// BenchmarkL4ForwardVariants are the variants §A13.2 records once:
// Forward's buffer at 16, 32 and 64 KiB (bufPool, the unexported test
// variable), and 4 concurrent L4 sessions on the Peer's one MUX trunk.
func BenchmarkL4ForwardVariants(b *testing.B) {
	for _, kib := range []int{16, 32, 64} {
		b.Run(fmt.Sprintf("buf=%dKiB", kib), func(b *testing.B) {
			setBufPool(kib << 10)
			defer setBufPool(32 << 10)
			benchL4Forward(b, 1)
		})
	}
	b.Run("sessions=4", func(b *testing.B) { benchL4Forward(b, 4) })
}

// setBufPool gives Forward's pumps buffers of size bytes (no pump runs
// while it is called: every fixture of the benchmarks is closed by then).
func setBufPool(size int) {
	bufPool = sync.Pool{New: func() any { b := make([]byte, size); return &b }}
}

// benchL4Forward runs sessions concurrent generators of b.N chunks each
// through the fixture and checks every byte's arrival by count and CRC.
func benchL4Forward(b *testing.B, sessions int) {
	f := newBenchL4(b)
	defer f.close()
	src := make([]byte, benchChunk)
	if _, err := io.ReadFull(rendrtest.PRNG(13), src); err != nil {
		b.Fatal(err)
	}
	table := crc32.MakeTable(crc32.Castagnoli)
	conns := make([]net.Conn, sessions)
	for i := range conns {
		c, err := net.Dial("tcp", f.ingress.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		conns[i] = c
	}
	b.SetBytes(int64(sessions) * benchChunk)
	b.ResetTimer()
	errs := make(chan error, sessions)
	for _, c := range conns {
		go func() {
			var crc uint32
			for range b.N {
				if _, err := c.Write(src); err != nil {
					errs <- fmt.Errorf("generator Write: %w", err)
					return
				}
				crc = crc32.Update(crc, table, src)
			}
			if err := c.(*net.TCPConn).CloseWrite(); err != nil {
				errs <- fmt.Errorf("generator CloseWrite: %w", err)
				return
			}
			var res [12]byte
			if _, err := io.ReadFull(c, res[:]); err != nil {
				errs <- fmt.Errorf("the target's answer: %w", err)
				return
			}
			n, got := binary.BigEndian.Uint64(res[:8]), binary.BigEndian.Uint32(res[8:])
			if want := uint64(b.N) * benchChunk; n != want || got != crc {
				errs <- fmt.Errorf("the target counted %d bytes with CRC-32C %08x, want %d with %08x", n, got, want, crc)
				return
			}
			errs <- nil
		}()
	}
	for range conns {
		if err := <-errs; err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

// benchL4 is the benchmark's fixture: the dialer and passive Runtimes, the
// Peer's carrier/tcp loopback carrier, the l4.Server, the loopback target
// and the ingress.
type benchL4 struct {
	b               testing.TB
	d, p            *rendr.Runtime
	peer            *rendr.Peer
	target, ingress net.Listener
	cancel          context.CancelFunc
	served          chan error
	wg              sync.WaitGroup
}

func newBenchL4(b testing.TB) *benchL4 {
	b.Helper()
	f := &benchL4{b: b, served: make(chan error, 1)}
	var err error
	if f.d, err = rendr.NewRuntime(rendr.Config{}); err != nil {
		b.Fatal(err)
	}
	if f.p, err = rendr.NewRuntime(rendr.Config{}); err != nil {
		b.Fatal(err)
	}
	l, err := tcp.Listen("tcp", "127.0.0.1:0", tcp.Options{})
	if err != nil {
		b.Fatal(err)
	}
	ln, err := f.p.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(l)}})
	if err != nil {
		l.Close()
		b.Fatal(err)
	}
	if f.peer, err = f.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{tcp.Carrier("bench", "tcp", l.Addr().String(), tcp.Options{})}}); err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	srv := &Server{}
	go func() { f.served <- srv.Serve(ctx, ln) }()
	if f.target, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		b.Fatal(err)
	}
	f.wg.Go(func() { f.acceptLoop(f.target, benchTarget) })
	if f.ingress, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		b.Fatal(err)
	}
	f.wg.Go(func() {
		f.acceptLoop(f.ingress, func(c net.Conn) {
			sc, err := Dial(ctx, f.peer, f.target.Addr().String(), rendr.DialOptions{})
			if err != nil {
				c.Close()
				return
			}
			Forward(ctx, sc, c)
		})
	})
	return f
}

// acceptLoop serves every connection of l on its own goroutine until l
// closes.
func (f *benchL4) acceptLoop(l net.Listener, serve func(net.Conn)) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		f.wg.Go(func() { serve(c) })
	}
}

// benchTarget reads c to its FIN, then answers the byte count and the
// CRC-32C of what it read (12 bytes, big-endian) and closes.
func benchTarget(c net.Conn) {
	defer c.Close()
	table := crc32.MakeTable(crc32.Castagnoli)
	buf := make([]byte, 64<<10)
	var n uint64
	var crc uint32
	for {
		k, err := c.Read(buf)
		n += uint64(k)
		crc = crc32.Update(crc, table, buf[:k])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return
		}
	}
	var res [12]byte
	binary.BigEndian.PutUint64(res[:8], n)
	binary.BigEndian.PutUint32(res[8:], crc)
	c.Write(res[:])
}

// close ends the fixture: the listeners, the Peer and both Runtimes, then
// Serve and every connection goroutine.
func (f *benchL4) close() {
	f.ingress.Close()
	f.target.Close()
	f.peer.Close()
	f.d.Close()
	f.p.Close()
	select {
	case <-f.served:
	case <-time.After(10 * time.Second):
		f.b.Errorf("l4.Server.Serve did not return within 10 s of Runtime.Close")
	}
	f.cancel()
	f.wg.Wait()
}
