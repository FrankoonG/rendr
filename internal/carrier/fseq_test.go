package carrier

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// fqRec records every byte its conn wrote and read.
type fqRec struct {
	net.Conn
	mu      sync.Mutex
	wr, rdb bytes.Buffer
}

func (c *fqRec) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.wr.Write(p[:max(n, 0)])
	c.mu.Unlock()
	return n, err
}

func (c *fqRec) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.rdb.Write(p[:max(n, 0)])
	c.mu.Unlock()
	return n, err
}

// streams returns copies of the bytes written and read so far.
func (c *fqRec) streams() (written, read []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.wr.Bytes()), bytes.Clone(c.rdb.Bytes())
}

// fqFseqs decodes the frames after the 40-byte preface of a recorded
// direction and returns the preface and every frame's fseq.
func fqFseqs(t *testing.T, b []byte) (preface []byte, fseqs []uint32) {
	t.Helper()
	if len(b) < wire.PrefaceLen {
		t.Fatalf("%d bytes recorded, want a preface", len(b))
	}
	preface, b = b[:wire.PrefaceLen], b[wire.PrefaceLen:]
	for len(b) >= wire.HeaderLen {
		f, n, err := wire.DecodeFrame(b)
		if err == wire.ErrShort {
			break // a frame still being written
		}
		if err != nil {
			t.Fatalf("frame %d: %v", len(fseqs), err)
		}
		fseqs = append(fseqs, f.Fseq)
		b = b[n:]
	}
	return preface, fseqs
}

// TestPrefaceDerivedFseq_L43 (design §0.13 A6): with no preset, each
// direction of a carrier numbers its frames from its own preface's CRC
// field — the dialer's from its PREFACE, the passive's from its
// PREFACE_ACK — and continues by +1 through the handshake into the running
// carrier, so two carriers (two sessions, or two carriers of one Runtime)
// start their directions at different fseqs and a frame spliced from one
// into the other at the same frame index fails the fseq check (the
// end-to-end splice is TestSplicedSessionsKilled_L43).
func TestPrefaceDerivedFseq_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		envD, envP := phEnvs()
		envD.Presets, envP.Presets = Presets{}, Presets{} // production: derived first fseqs
		type pair struct {
			dc, pc *Conn
			rec    *fqRec
			sink   *ltSink
		}
		const n = 512 << 10
		var pairs []pair
		for range 2 {
			sink := newLtSink(n)
			pass := make(chan *Conn, 1)
			link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "f", Accept: func(nc net.Conn) error {
				h, err := ReadHello(envP, nc, time.Now().Add(10*time.Second), 4096, nil)
				if err != nil {
					pass <- nil
					return nil
				}
				h.Conn.Start(sink, &hBell{}, StartOptions{Hold: true})
				pass <- h.Conn
				return nil
			}})
			link.SetDelay(time.Millisecond, 0)
			defer link.Close()
			var rec *fqRec
			dial := func(ctx context.Context) (net.Conn, error) {
				c, err := link.Dial(ctx)
				if err != nil {
					return nil, err
				}
				rec = &fqRec{Conn: c}
				return rec, nil
			}
			est, err := Establish(context.Background(), envD, Factory{Name: "f", Dial: dial}, envD.IDs.Next(), wire.TypeOpen, openPayload(0), nil)
			if err != nil {
				t.Fatalf("Establish: %v", err)
			}
			pc := <-pass
			if pc == nil {
				t.Fatal("the passive handshake failed")
			}
			src := newSource(envD, ChunkSize, true)
			defer src.chunk.Release()
			src.offer(n)
			est.Conn.Start(src, &hBell{}, StartOptions{})
			pairs = append(pairs, pair{est.Conn, pc, rec, sink})
		}
		for _, p := range pairs {
			select {
			case <-p.sink.done:
			case <-time.After(10 * time.Second):
				next, bad, _ := p.sink.result()
				t.Fatalf("transfer: %d of %d bytes (%s)", next, n, bad)
			}
		}
		synctest.Wait()

		var starts [2][2]uint32 // per pair: dialer's and passive's first fseq
		for i, p := range pairs {
			w, r := p.rec.streams()
			pre, out := fqFseqs(t, w)
			ack, in := fqFseqs(t, r)
			if _, err := wire.ParsePreface(pre); err != nil {
				t.Fatalf("pair %d: the dialer's preface: %v", i, err)
			}
			if _, err := wire.ParsePrefaceAck(ack); err != nil {
				t.Fatalf("pair %d: the passive's preface: %v", i, err)
			}
			for _, d := range []struct {
				who    string
				hello  []byte
				fseqs  []uint32
				starts *uint32
			}{{"dialer", pre, out, &starts[i][0]}, {"passive", ack, in, &starts[i][1]}} {
				want := wire.PrefaceFseq(d.hello)
				if len(d.fseqs) < 2 || d.fseqs[0] != want {
					t.Fatalf("pair %d, %s direction: fseqs %v, want them to start at its preface's CRC field %#x", i, d.who, d.fseqs[:min(len(d.fseqs), 4)], want)
				}
				for k, f := range d.fseqs {
					if f != want+uint32(k) {
						t.Fatalf("pair %d, %s direction: frame %d has fseq %#x, want %#x", i, d.who, k, f, want+uint32(k))
					}
				}
				*d.starts = want
			}
			if next, bad, _ := p.sink.result(); next != n || bad != "" {
				t.Fatalf("pair %d: %d bytes in order, violation %q", i, next, bad)
			}
		}
		// Every direction starts elsewhere, so no frame of one carrier passes
		// another's fseq check at the same index.
		all := map[uint32]bool{}
		for _, s := range starts {
			for _, f := range s {
				all[f] = true
			}
		}
		if len(all) != 4 {
			t.Fatalf("first fseqs %#x: want four distinct starts", starts)
		}
		for _, p := range pairs {
			for _, c := range []*Conn{p.dc, p.pc} {
				if dead, cause, detail, _ := c.Death(); dead {
					t.Fatalf("carrier %d died: %v %s", c.ID(), cause, detail)
				}
			}
		}
		for _, p := range pairs {
			for _, c := range []*Conn{p.dc, p.pc} {
				c.Kill(CauseLocalClose, "test end")
				hWait(t, c)
			}
		}
	})
}
