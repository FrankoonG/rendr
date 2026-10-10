package realsock

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The EarlyReturn row of the real-socket group (M4 design §A12.4, M4-D4,
// M4-D9, plan:663; WP12): the first flight of an EarlyReturn session over
// carrier/tcp, which has no DialEarly, as the passive's socket receives
// it. Helpers carry the ef prefix; the fixture is l4_realsock_test.go's.

// efFirstReads wraps a listener: the first Read of every accepted conn
// reads once from the socket into a 256 KiB buffer, records those bytes —
// what the passive's first read of the socket returned — and serves them
// to the reader before the socket's later bytes.
type efFirstReads struct {
	net.Listener
	mu    sync.Mutex
	first [][]byte // per accepted conn, in accept order
}

func (l *efFirstReads) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	i := len(l.first)
	l.first = append(l.first, nil)
	l.mu.Unlock()
	return &efConn{Conn: c, l: l, i: i}, nil
}

// reads returns the recorded first reads (nil: not read yet).
func (l *efFirstReads) reads() [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([][]byte(nil), l.first...)
}

type efConn struct {
	net.Conn
	l    *efFirstReads
	i    int
	done bool   // the first read happened (the reader's goroutine only)
	rest []byte // its bytes not yet served
}

func (c *efConn) Read(p []byte) (int, error) {
	if !c.done {
		c.done = true
		buf := make([]byte, 256<<10)
		k, err := c.Conn.Read(buf)
		c.l.mu.Lock()
		c.l.first[c.i] = append([]byte{}, buf[:k]...)
		c.l.mu.Unlock()
		c.rest = buf[:k]
		if k == 0 {
			return 0, err
		}
	}
	if len(c.rest) > 0 {
		k := copy(p, c.rest)
		c.rest = c.rest[k:]
		return k, nil
	}
	return c.Conn.Read(p)
}

// efCheckFirstFlight checks that b is exactly PREFACE ‖ OPEN(EARLY) ‖
// DATA(offset 0, early) as a dialer's first flight on a fresh carrier:
// the PREFACE (stream kind; the MUX option iff mux), the OPEN at the
// PREFACE's first fseq on handle 1 with the EARLY flag and the L4
// metadata of addr, then the DATA at the next fseq carrying early.
func efCheckFirstFlight(b []byte, mux bool, addr string, early []byte) error {
	if len(b) < wire.PrefaceLen || !wire.IsPreface(b) {
		return fmt.Errorf("%d bytes that do not start with a PREFACE", len(b))
	}
	pf, err := wire.ParsePreface(b[:wire.PrefaceLen])
	if err != nil {
		return fmt.Errorf("PREFACE: %w", err)
	}
	if pf.Kind != wire.KindStream || (pf.Opt&wire.OptMux != 0) != mux {
		return fmt.Errorf("PREFACE kind %d opt %#x, want stream with MUX %v", pf.Kind, pf.Opt, mux)
	}
	fseq := wire.PrefaceFseq(b[:wire.PrefaceLen])
	rest := b[wire.PrefaceLen:]
	open, k, err := wire.DecodeFrame(rest)
	if err != nil {
		return fmt.Errorf("the frame after the PREFACE (%d bytes left): %w", len(rest), err)
	}
	if open.Type != wire.TypeOpen || open.Fseq != fseq || open.Handle != wire.SessionHandle {
		return fmt.Errorf("the frame after the PREFACE is %v fseq %d handle %d, want OPEN fseq %d handle %d", open.Type, open.Fseq, open.Handle, fseq, wire.SessionHandle)
	}
	o, err := wire.ParseOpen(open.Payload, wire.MaxMetadata)
	if err != nil {
		return fmt.Errorf("OPEN: %w", err)
	}
	if o.Flags != wire.OpenFlagEarly {
		return fmt.Errorf("OPEN flags %#x, want EARLY (%#x)", o.Flags, wire.OpenFlagEarly)
	}
	if r, err := l4.ParseMetadata(o.Metadata); err != nil || r.Addr != addr {
		return fmt.Errorf("OPEN metadata %+v, %v; want L4 metadata of %s", r, err, addr)
	}
	rest = rest[k:]
	data, k, err := wire.DecodeFrame(rest)
	if err != nil {
		return fmt.Errorf("the frame after the OPEN (%d bytes left): %w", len(rest), err)
	}
	if data.Type != wire.TypeData || data.Fseq != fseq+1 || data.Handle != wire.SessionHandle {
		return fmt.Errorf("the frame after the OPEN is %v fseq %d handle %d, want DATA fseq %d handle %d", data.Type, data.Fseq, data.Handle, fseq+1, wire.SessionHandle)
	}
	if off, err := wire.ParseDataOffset(data.Payload); err != nil || off != 0 || !bytes.Equal(data.Payload[wire.DataPrefixLen:], early) {
		return fmt.Errorf("DATA offset %d (%v) with %d bytes, want offset 0 with the %d early bytes", off, err, len(data.Payload)-wire.DataPrefixLen, len(early))
	}
	if extra := len(rest) - k; extra != 0 {
		return fmt.Errorf("%d bytes after the DATA frame", extra)
	}
	return nil
}

// TestL4RealEarlyFirstFlight (§A12.4; M4-D4, M4-D9, plan:663): an
// EarlyReturn L4 session over carrier/tcp (no DialEarly) on a fresh
// carrier — a dedicated one (Props.CheapSubflow) and handle 1 of a fresh
// MUX trunk — sends its first Write's bytes with the OPEN: the passive's
// first read of the socket holds exactly PREFACE ‖ OPEN(EARLY) ‖ DATA
// (the 1 KiB request at offset 0), one physical write with nothing after
// it. Twenty sessions per variant, one at a time, each on a carrier of its
// own (a MUX trunk closes at its last view before the next session
// dials). Stimulus: l4.Dial returned before any network I/O (no carrier
// accepted yet), and the dialer's BeforeFirstFlight hook saw 1,024 early
// bytes for every session. Integrity: the target echoes the request, the
// client reads it back (PRNG content) and io.EOF, the session ends clean,
// and its dialer reports EarlyBytes == 1,024.
func TestL4RealEarlyFirstFlight(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const (
		runs = 20
		size = 1 << 10
	)
	for _, mux := range []bool{false, true} {
		name := "dedicated"
		if mux {
			name = "mux"
		}
		t.Run(name, func(t *testing.T) {
			tg := newL4rTarget(t, func(i int, c *net.TCPConn) {
				defer c.Close()
				if _, err := io.Copy(struct{ io.Writer }{c}, c); err == nil {
					c.CloseWrite()
					io.Copy(io.Discard, c)
				}
			})
			var flights atomic.Int64
			var badK atomic.Int64
			hooks := &testhooks.Hooks{BeforeFirstFlight: func(k int) {
				flights.Add(1)
				if k != size {
					badK.Store(int64(k))
				}
			}}
			var fr *efFirstReads
			n := newL4rNet(t, l4rOpts{
				dov:   &testhooks.Overrides{Hooks: hooks},
				props: rendr.Props{CheapSubflow: !mux},
				wrap: func(l net.Listener) net.Listener {
					fr = &efFirstReads{Listener: l}
					return fr
				},
			})
			for i := range runs {
				seed := uint64(100 + i)
				before := len(fr.reads())
				c, err := n.dial(tg.addr(), rendr.DialOptions{EarlyReturn: true})
				if err != nil {
					t.Fatalf("run %d: l4.Dial: %v", i, err)
				}
				if got := len(fr.reads()); got != before {
					t.Fatalf("stimulus: run %d: the passive accepted a carrier before the first Write (EarlyReturn opened at Dial)", i)
				}
				req, _ := io.ReadAll(io.LimitReader(rendrtest.PRNG(seed), size))
				if _, err := c.Write(req); err != nil {
					t.Fatalf("run %d: Write: %v", i, err)
				}
				if err := c.CloseWrite(); err != nil {
					t.Fatalf("run %d: CloseWrite: %v", i, err)
				}
				if _, err := l4rRecv(c, size, seed, nil); err != nil {
					t.Fatalf("run %d: the echo: %v", i, err)
				}
				l4rDone(t, c, 10*time.Second, fmt.Sprintf("run %d", i))
				if err := c.Status().Err; err != io.EOF {
					t.Errorf("run %d: the session ended with %v, want io.EOF", i, err)
				}
				if eb := c.Status().EarlyBytes; eb != size {
					t.Errorf("run %d: EarlyBytes %d, want %d", i, eb, size)
				}
				c.Close()
				n.muxZero()
				reads := fr.reads()
				if len(reads) != before+1 {
					t.Fatalf("run %d: the passive accepted %d carriers, want 1 (a fresh carrier per session)", i, len(reads)-before)
				}
				if err := efCheckFirstFlight(reads[before], mux, tg.addr(), req); err != nil {
					t.Errorf("run %d: the passive's first read: %v", i, err)
				}
			}
			if got := flights.Load(); got != runs {
				t.Errorf("stimulus: BeforeFirstFlight ran %d times for %d sessions", got, runs)
			}
			if k := badK.Load(); k != 0 {
				t.Errorf("stimulus: a first flight carried %d early bytes, want %d", k, size)
			}
			msUntil(t, 10*time.Second, "the Server's forwards ended", func() bool { return n.srv.Status().Live == 0 })
			if ss := n.srv.Status(); ss.Confirmed != runs || ss.Rejected != 0 {
				t.Errorf("Server: %+v, want %d confirmed, none rejected", ss, runs)
			}
			n.close()
			tg.close()
		})
	}
}
