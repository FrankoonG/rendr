package rendrtest

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// Behaviour is a far-end application handler run on the passive end of a
// session (any net.Conn). It returns its own verdict: nil when it behaved
// as specified. Behaviours use CloseWrite through the optional interface
// { CloseWrite() error } of the conn they are given. Every goroutine a
// behaviour starts has ended when it returns.
type Behaviour func(c net.Conn) error

// Echo copies everything it reads back until EOF, then CloseWrite, drains
// until the read side ends, and closes.
func Echo() Behaviour {
	return func(c net.Conn) error {
		defer c.Close()
		if _, err := copyPlain(c, c); err != nil {
			return fmt.Errorf("rendrtest: Echo: %w", err)
		}
		if err := closeWrite(c); err != nil {
			return fmt.Errorf("rendrtest: Echo: %w", err)
		}
		if _, err := copyPlain(io.Discard, c); err != nil {
			return fmt.Errorf("rendrtest: Echo: drain: %w", err)
		}
		return nil
	}
}

// Gen writes n bytes of PRNG(seed) while discarding anything it reads, then
// closes; it returns when a Write fails or the n bytes were written.
func Gen(n int64, seed uint64) Behaviour {
	return func(c net.Conn) error {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			copyPlain(io.Discard, c)
		}()
		_, err := copyPlain(c, io.LimitReader(PRNG(seed), n))
		c.Close()
		wg.Wait()
		if err != nil {
			return fmt.Errorf("rendrtest: Gen: %w", err)
		}
		return nil
	}
}

// Sink reads and counts into count until EOF, then closes. count may be nil.
func Sink(count *atomic.Int64) Behaviour {
	return func(c net.Conn) error {
		defer c.Close()
		if count == nil {
			count = new(atomic.Int64)
		}
		buf := make([]byte, 32<<10)
		for {
			n, err := c.Read(buf)
			if n < 0 || n > len(buf) {
				return fmt.Errorf("rendrtest: Sink: invalid read count %d", n)
			}
			count.Add(int64(n))
			switch {
			case err == io.EOF:
				return nil
			case err != nil:
				return fmt.Errorf("rendrtest: Sink: %w", err)
			}
		}
	}
}

// Stall reads until EOF, then holds the conn open without answering until
// release is closed, then closes.
func Stall(release <-chan struct{}) Behaviour {
	return func(c net.Conn) error {
		defer c.Close()
		_, err := copyPlain(io.Discard, c)
		<-release
		if err != nil {
			return fmt.Errorf("rendrtest: Stall: %w", err)
		}
		return nil
	}
}

// HalfCloseCheck (L04) reads exactly want bytes of PRNG(seed) followed by
// io.EOF, then writes reply bytes of PRNG(seed+1) and CloseWrite, then
// closes. Any deviation is its error.
func HalfCloseCheck(want int64, seed uint64, reply int64) Behaviour {
	return func(c net.Conn) error {
		defer c.Close()
		if err := NewVerifier(seed, want).ReadAll(c); err != nil {
			return fmt.Errorf("rendrtest: HalfCloseCheck: %w", err)
		}
		if _, err := copyPlain(c, io.LimitReader(PRNG(seed+1), reply)); err != nil {
			return fmt.Errorf("rendrtest: HalfCloseCheck: reply: %w", err)
		}
		if err := closeWrite(c); err != nil {
			return fmt.Errorf("rendrtest: HalfCloseCheck: %w", err)
		}
		return nil
	}
}

// closeWrite half-closes c through the optional CloseWrite method.
func closeWrite(c net.Conn) error {
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		return fmt.Errorf("%T has no CloseWrite", c)
	}
	if err := cw.CloseWrite(); err != nil {
		return fmt.Errorf("CloseWrite: %w", err)
	}
	return nil
}

// copyPlain copies with plain Read and Write calls (no ReaderFrom/WriterTo
// shortcut, which could bypass the conn under test).
func copyPlain(dst io.Writer, src io.Reader) (int64, error) {
	return io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, make([]byte, 32<<10))
}
