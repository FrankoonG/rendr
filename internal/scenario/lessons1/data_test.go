package lessons1

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Data helpers: deterministic PRNG streams (rendrtest.PRNG), the strict
// verifier (L64: EOF only after exactly the expected bytes), SHA-256
// digests, and a byte gauge with threshold gates so that a test can strike
// in the middle of a transfer.

// writeStream writes n bytes of PRNG(seed) to c in Writes of at most chunk
// bytes and returns the bytes accepted and the first error.
func writeStream(c net.Conn, n int64, seed uint64, chunk int) (int64, error) {
	src := rendrtest.PRNG(seed)
	buf := make([]byte, chunk)
	var done int64
	for done < n {
		k := int(min(int64(chunk), n-done))
		src.Read(buf[:k])
		m, err := c.Write(buf[:k])
		done += int64(m)
		if err != nil {
			return done, err
		}
		if m != k {
			return done, fmt.Errorf("short Write: %d of %d with a nil error", m, k)
		}
	}
	return done, nil
}

// gauge counts received bytes and opens gates at thresholds.
type gauge struct {
	mu    sync.Mutex
	n     int64
	gates []gate
}

type gate struct {
	at int64
	ch chan struct{}
}

func (g *gauge) add(k int64) {
	g.mu.Lock()
	g.n += k
	kept := g.gates[:0]
	for _, gt := range g.gates {
		if g.n >= gt.at {
			close(gt.ch)
		} else {
			kept = append(kept, gt)
		}
	}
	g.gates = kept
	g.mu.Unlock()
}

// at returns a channel closed once the gauge reached k bytes.
func (g *gauge) at(k int64) <-chan struct{} {
	ch := make(chan struct{})
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n >= k {
		close(ch)
	} else {
		g.gates = append(g.gates, gate{k, ch})
	}
	return ch
}

func (g *gauge) get() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n
}

// readStream reads exactly n bytes of PRNG(seed) followed by io.EOF from c
// (rendrtest.Verifier: any other error or byte fails), counting into g
// (may be nil).
func readStream(c net.Conn, n int64, seed uint64, g *gauge) error {
	v := rendrtest.NewVerifier(seed, n)
	buf := make([]byte, 64<<10)
	for idle := 0; ; {
		k, err := c.Read(buf)
		if k < 0 || k > len(buf) {
			return v.Done(fmt.Errorf("invalid read count %d", k))
		}
		if k > 0 {
			idle = 0
			if _, werr := v.Write(buf[:k]); werr != nil {
				return v.Done(err)
			}
			if g != nil {
				g.add(int64(k))
			}
		} else if err == nil {
			if idle++; idle > 100 {
				return v.Done(io.ErrNoProgress)
			}
		}
		if err != nil {
			return v.Done(err)
		}
	}
}

// digest returns the SHA-256 of n bytes of PRNG(seed).
func digest(n int64, seed uint64) [32]byte {
	d, err := rendrtest.Digest(rendrtest.PRNG(seed), n)
	if err != nil {
		panic(err) // PRNG never ends
	}
	return d
}

// shaReader reads c to its end, hashing everything, and returns the digest,
// the byte count and the terminating error (io.EOF on a clean end).
func shaReader(c net.Conn, g *gauge) ([32]byte, int64, error) {
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var n int64
	for {
		k, err := c.Read(buf)
		if k > 0 {
			h.Write(buf[:k])
			n += int64(k)
			if g != nil {
				g.add(int64(k))
			}
		}
		if err != nil {
			var d [32]byte
			h.Sum(d[:0])
			return d, n, err
		}
	}
}

// exchange streams n bytes of PRNG(seed) from a to b and n bytes of
// PRNG(seed+1) from b to a at the same time, then half-closes both
// directions and verifies both streams end in io.EOF after exactly n bytes.
// It returns the first failure.
func exchange(a, b net.Conn, n int64, seed uint64, chunk int) error {
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	pump := func(w, r net.Conn, seed uint64) {
		wg.Go(func() {
			_, err := writeStream(w, n, seed, chunk)
			if err == nil {
				err = closeWrite(w)
			}
			errs <- err
		})
		wg.Go(func() { errs <- readStream(r, n, seed, nil) })
	}
	pump(a, b, seed)
	pump(b, a, seed+1)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// closeWrite half-closes c through its CloseWrite method.
func closeWrite(c net.Conn) error {
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		return fmt.Errorf("%T has no CloseWrite", c)
	}
	return cw.CloseWrite()
}
