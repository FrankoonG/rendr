package lessons3

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Data flows of the scenario kit: one direction of a session carrying the
// deterministic PRNG stream of a seed, written by one goroutine and checked
// byte for byte by another (the integrity part of every scenario's
// three-part assertion, plan §10.1). A flow ends with the writer's
// CloseWrite and the reader's io.EOF, which is accepted only after exactly
// the bytes written (L64).

// flowOpts shape a flow.
type flowOpts struct {
	n     int64         // bytes to write; 0 = until stop
	chunk int           // bytes per Write (default 64 KiB)
	gap   time.Duration // pause after every Write (0 = back to back)
	// readGate, if set, holds the reader until it is closed: the receiving
	// application does not read meanwhile (ACK = delivered, design §4.6).
	readGate <-chan struct{}
	// keepOpen (with n > 0): the writer does not half-close and the reader
	// stops after n bytes, so a later flow can use the same direction.
	keepOpen bool
}

// flow is one direction of a session carrying PRNG(seed).
type flow struct {
	name         string
	stopCh       chan struct{}
	stopOnce     sync.Once
	sent, recvd  atomic.Int64
	writes       atomic.Int64
	wdone, rdone chan struct{}
	werr, rerr   error
}

// startFlow starts a flow from the application of `from` to the
// application of `to`.
func (w *world) startFlow(name string, from, to *rendr.Conn, seed uint64, o flowOpts) *flow {
	if o.chunk <= 0 {
		o.chunk = 64 * kib
	}
	f := &flow{name: name, stopCh: make(chan struct{}), wdone: make(chan struct{}), rdone: make(chan struct{})}
	if o.keepOpen && o.n <= 0 {
		panic("lessons3: a keep-open flow needs n > 0")
	}
	w.goBG(func() {
		defer close(f.wdone)
		f.werr = f.write(from, seed, o)
	})
	w.goBG(func() {
		defer close(f.rdone)
		if o.readGate != nil {
			select {
			case <-o.readGate:
			case <-w.done: // the world closed first (a failed test)
				f.rerr = fmt.Errorf("flow %s: the world closed before the reader started", f.name)
				return
			}
		}
		f.rerr = f.read(to, seed, o)
	})
	return f
}

// write writes the stream, then half-closes.
func (f *flow) write(c *rendr.Conn, seed uint64, o flowOpts) error {
	src := rendrtest.PRNG(seed)
	buf := make([]byte, o.chunk)
	var pause *time.Timer
	if o.gap > 0 {
		pause = time.NewTimer(time.Hour)
		pause.Stop()
		defer pause.Stop()
	}
	for o.n <= 0 || f.sent.Load() < o.n {
		select {
		case <-f.stopCh:
			return closeWrite(c)
		default:
		}
		k := o.chunk
		if o.n > 0 {
			k = int(min(int64(k), o.n-f.sent.Load()))
		}
		src.Read(buf[:k])
		m, err := c.Write(buf[:k])
		f.sent.Add(int64(m))
		f.writes.Add(1)
		if err != nil {
			return fmt.Errorf("flow %s: write after %d bytes: %w", f.name, f.sent.Load(), err)
		}
		if pause != nil {
			pause.Reset(o.gap)
			select {
			case <-pause.C:
			case <-f.stopCh:
				return closeWrite(c)
			}
		}
	}
	if o.keepOpen {
		return nil
	}
	return closeWrite(c)
}

func closeWrite(c *rendr.Conn) error {
	if err := c.CloseWrite(); err != nil {
		return fmt.Errorf("CloseWrite: %w", err)
	}
	return nil
}

// read checks every received byte against the stream until io.EOF (a
// keep-open flow: until its n bytes arrived).
func (f *flow) read(c *rendr.Conn, seed uint64, o flowOpts) error {
	want := rendrtest.PRNG(seed)
	got := make([]byte, 64*kib)
	exp := make([]byte, 64*kib)
	for {
		buf := got
		if o.keepOpen {
			left := o.n - f.recvd.Load()
			if left == 0 {
				return nil
			}
			buf = got[:min(int64(len(got)), left)]
		}
		n, err := c.Read(buf)
		if n < 0 || n > len(buf) {
			return fmt.Errorf("flow %s: invalid read count %d", f.name, n)
		}
		if n > 0 {
			want.Read(exp[:n])
			if !bytes.Equal(got[:n], exp[:n]) {
				i := 0
				for got[i] == exp[i] {
					i++
				}
				return fmt.Errorf("flow %s: byte mismatch at offset %d", f.name, f.recvd.Load()+int64(i))
			}
			f.recvd.Add(int64(n))
		}
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return fmt.Errorf("flow %s: read after %d bytes: %w", f.name, f.recvd.Load(), err)
		}
	}
}

// stop makes the writer half-close after its current Write.
func (f *flow) stop() { f.stopOnce.Do(func() { close(f.stopCh) }) }

// wait waits until both ends of the flow finished and requires that every
// byte written arrived intact, followed by io.EOF.
func (f *flow) wait(t testing.TB, within time.Duration) {
	t.Helper()
	timer := time.NewTimer(within)
	defer timer.Stop()
	for _, ch := range []chan struct{}{f.wdone, f.rdone} {
		select {
		case <-ch:
		case <-timer.C:
			t.Fatalf("flow %s not finished within %v: sent %d, received %d", f.name, within, f.sent.Load(), f.recvd.Load())
		}
	}
	if f.werr != nil {
		t.Fatal(f.werr)
	}
	if f.rerr != nil {
		t.Fatal(f.rerr)
	}
	if s, r := f.sent.Load(), f.recvd.Load(); s != r {
		t.Fatalf("flow %s: %d bytes written, %d received before EOF", f.name, s, r)
	}
}

// finishSession ends a session cleanly (design §4.7, Z5): both ends
// half-close, read io.EOF (nothing else may be left unread), close, and the
// session must end on both ends with io.EOF.
func finishSession(t testing.TB, dc, pc *rendr.Conn) {
	t.Helper()
	ends := []*rendr.Conn{dc, pc}
	for _, c := range ends {
		if err := c.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	}
	for _, c := range ends {
		if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var b [64]byte
		if n, err := c.Read(b[:]); n != 0 || err != io.EOF {
			t.Fatalf("%v: Read after the peer's FIN: (%d, %v), want (0, EOF)", c.Status().Role, n, err)
		}
	}
	for _, c := range ends {
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	for _, c := range ends {
		waitFor(t, 30*time.Second, "the session end", func() bool { return c.Status().State == rendr.StateEnded })
		if st := c.Status(); !errors.Is(st.Err, io.EOF) {
			t.Fatalf("%v ended with %v, want io.EOF", st.Role, st.Err)
		}
	}
}
