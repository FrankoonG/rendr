package lessons2

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestConcurrentCallsInBubble_L41 (design §0.14 B12; L41: concurrent
// writers never interleave). net.Conn allows concurrent Writes and
// concurrent Reads, and a Conn serializes each direction; inside a
// synctest bubble the call queued behind another must block durably, or
// the bubble can never advance its clock while the call ahead waits for
// the network: with sync.Mutex the queued call waited in Mutex.Lock and
// the bubble hung until the test binary's timeout. One path, 10 ms one way.
//
// writes: two goroutines each Write 16 MiB on the dialer's Conn at the same
// instant; one reader drains the passive's Conn. The first Write commits
// the 8 MiB window and waits for room while the second waits for it (the
// stimulus: both calls blocked, 8 MiB committed); they return (16 MiB,
// nil) one after the other, and the stream is the first-returned Write's
// bytes followed by the other's, each intact (SHA-256 per 16 MiB half).
//
// reads: two goroutines read the passive's Conn concurrently until io.EOF;
// both wait inside Read before a byte is written (the stimulus). Then the
// dialer writes 16 MiB and half-closes: both readers receive data and end
// with io.EOF, and their pieces, merged in each reader's order, form the
// written stream exactly (every byte once, in order).
func TestConcurrentCallsInBubble_L41(t *testing.T) {
	t.Run("writes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const half = 16 << 20
			e := newEnv(t, rendr.Config{}, rendr.Config{}, nil)
			a := e.path("a", 10*time.Millisecond)
			dc, pc := e.open(e.peer(a), rendr.DialOptions{})
			srcs := [2][]byte{prngBytes(410, half), prngBytes(411, half)}
			sums := [2][32]byte{sha256.Sum256(srcs[0]), sha256.Sum256(srcs[1])}

			type halves struct {
				sum [2][32]byte
				err error
			}
			read := make(chan halves, 1)
			go func() {
				var r halves
				buf := make([]byte, 64<<10)
				for i := range r.sum {
					h := sha256.New()
					n, err := io.CopyBuffer(h, io.LimitReader(pc, half), buf)
					if err == nil && n != half {
						err = fmt.Errorf("half %d ended after %d of %d bytes", i, n, half)
					}
					if r.err = err; err != nil {
						break
					}
					copy(r.sum[i][:], h.Sum(nil))
				}
				read <- r
			}()
			start := time.Now()
			var ws [2]<-chan opResult
			for i := range ws {
				ws[i] = goOp(func() (int, error) { return dc.Write(srcs[i]) })
			}
			synctest.Wait()
			if !running(ws[0]) || !running(ws[1]) || dc.Status().TxBytes != 8<<20 {
				t.Fatalf("stimulus: Writes running %v %v with %d bytes committed, want both blocked and the 8 MiB window committed",
					running(ws[0]), running(ws[1]), dc.Status().TxBytes)
			}

			var rs [2]opResult
			for i := range ws {
				if rs[i] = await(t, ws[i], time.Minute, "a 16 MiB Write"); rs[i].n != half || rs[i].err != nil {
					t.Fatalf("Write %d = (%d, %v), want (%d, nil)", i, rs[i].n, rs[i].err, half)
				}
			}
			first := 0
			if rs[1].at.Before(rs[0].at) {
				first = 1
			}
			if rs[0].at.Equal(rs[1].at) {
				t.Fatalf("both Writes returned at %v: the second did not wait for the first", rs[0].at)
			}
			var h halves
			select {
			case h = <-read:
			case <-time.After(time.Minute):
				t.Fatal("the reader did not receive 32 MiB within a minute")
			}
			if h.err != nil {
				t.Fatalf("reader: %v", h.err)
			}
			if h.sum != [2][32]byte{sums[first], sums[1-first]} {
				t.Fatalf("stream halves do not match Write %d then Write %d (SHA-256): the Writes interleaved or bytes were corrupted", first, 1-first)
			}
			t.Logf("Write %d returned after %v, Write %d after %v", first, rs[first].at.Sub(start), 1-first, rs[1-first].at.Sub(start))
			endClean(t, dc, pc)
			e.close()
		})
	})

	t.Run("reads", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const total = 16 << 20
			e := newEnv(t, rendr.Config{}, rendr.Config{}, nil)
			a := e.path("a", 10*time.Millisecond)
			dc, pc := e.open(e.peer(a), rendr.DialOptions{})
			src := prngBytes(412, total)

			type pieces struct {
				b   [][]byte
				err error
			}
			var readers [2]chan pieces
			for i := range readers {
				readers[i] = make(chan pieces, 1)
				go func() {
					var p pieces
					buf := make([]byte, 64<<10)
					for {
						n, err := pc.Read(buf)
						if n > 0 {
							p.b = append(p.b, bytes.Clone(buf[:n]))
						}
						if err != nil {
							p.err = err
							readers[i] <- p
							return
						}
					}
				}()
			}
			synctest.Wait()
			if len(readers[0]) != 0 || len(readers[1]) != 0 {
				t.Fatal("stimulus: a reader returned before any byte was written, want both blocked in Read")
			}

			w := goOp(func() (int, error) { return dc.Write(src) })
			if r := await(t, w, time.Minute, "the 16 MiB Write"); r.n != total || r.err != nil {
				t.Fatalf("Write = (%d, %v), want (%d, nil)", r.n, r.err, total)
			}
			if err := dc.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			var got [2]pieces
			for i := range readers {
				select {
				case got[i] = <-readers[i]:
				case <-time.After(time.Minute):
					t.Fatalf("reader %d did not reach io.EOF within a minute", i)
				}
				n := 0
				for _, b := range got[i].b {
					n += len(b)
				}
				if got[i].err != io.EOF || n == 0 {
					t.Fatalf("reader %d: %d pieces, %d bytes, ended with %v; want data, then io.EOF", i, len(got[i].b), n, got[i].err)
				}
			}
			if !g7Merged(src, got[0].b, got[1].b) {
				t.Fatalf("the readers' pieces (%d and %d) do not merge into the written stream", len(got[0].b), len(got[1].b))
			}
			t.Logf("16 MiB read in %d and %d pieces", len(got[0].b), len(got[1].b))
			endClean(t, dc, pc)
			e.close()
		})
	})
}

// g7Merged reports whether src is exactly an interleaving of a and b, each
// taken in order: the pieces two concurrent readers received. A piece that
// fits at the current position in both lists is tried in both orders.
func g7Merged(src []byte, a, b [][]byte) bool {
	var merge func(pos, i, j int) bool
	merge = func(pos, i, j int) bool {
		for {
			if i == len(a) && j == len(b) {
				return pos == len(src)
			}
			ma := i < len(a) && bytes.HasPrefix(src[pos:], a[i])
			mb := j < len(b) && bytes.HasPrefix(src[pos:], b[j])
			switch {
			case ma && mb:
				if merge(pos+len(a[i]), i+1, j) {
					return true
				}
				pos, j = pos+len(b[j]), j+1
			case ma:
				pos, i = pos+len(a[i]), i+1
			case mb:
				pos, j = pos+len(b[j]), j+1
			default:
				return false
			}
		}
	}
	return merge(0, 0, 0)
}
