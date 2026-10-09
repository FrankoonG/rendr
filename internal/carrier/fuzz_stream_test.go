package carrier

import (
	"bytes"
	"encoding/binary"
	"flag"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// FuzzCarrierStream_L43 (M3 design §A9.4; L43): a recorded dialer →
// passive carrier byte stream — the frames a real dialer trunk wrote after
// its handshake, dedicated or with three views on a MUX trunk — damaged by
// up to eight operations (flip a bit, drop, duplicate or insert bytes,
// truncate, splice in the other recording from some point) is fed into a
// real passive trunk reader whose views have recording endpoints. The
// properties: no panic; each view's endpoint sees exactly a prefix of the
// calls (type, offset or seq, payload) the undamaged recording gives it,
// and the trunk admits a prefix of its views; then the trunk dies once,
// of protocol_violation or transport_error (the input ends); the reader,
// the writer and every view goroutine exit (the bubble ends); and one
// input allocates less than 2 MiB (no allocation proportional to a forged
// length or to the input).
//
// The recordings are testdata/rec_*.bin, written by
// `go test -run TestRecord -update` with a fixed PRNG seed: each holds the
// frames only (the handshake is the reader's caller's), numbered from the
// first frame's fseq, a different start per recording (a splice of the
// two then fails the fseq check as two real carriers would).

var recUpdate = flag.Bool("update", false, "rewrite testdata/rec_*.bin (TestRecord) from a fixed PRNG seed")

// recording is one recorded carrier byte stream.
type recording struct {
	name string
	mux  bool
	b    []byte // the frames, as the dialer wrote them
}

// first is the recording's first fseq: its first frame's.
func (r *recording) first() uint32 { return binary.BigEndian.Uint32(r.b[5:9]) }

// recFiles are the recordings, in selector order.
var recFiles = []struct {
	name string
	mux  bool
}{{"rec_dedicated.bin", false}, {"rec_mux3.bin", true}}

var (
	recOnce sync.Once
	recs    []*recording
	recErr  error
	origs   [2]fzResult // the undamaged recordings' results, by selector
	origOne [2]sync.Once
)

// loadRecs reads the recordings once.
func loadRecs() ([]*recording, error) {
	recOnce.Do(func() {
		for _, f := range recFiles {
			b, err := os.ReadFile(filepath.Join("testdata", f.name))
			if err != nil {
				recErr = err
				return
			}
			recs = append(recs, &recording{name: f.name, mux: f.mux, b: b})
		}
	})
	return recs, recErr
}

// fzCall is one endpoint call as the fuzz target compares it.
type fzCall struct {
	typ wire.Type
	off uint64 // DATA offset, DGRAM seq
	n   int
	sum uint32 // CRC-32C of the payload
}

// fzEP records every call of every view's endpoint, by handle.
type fzEP struct {
	mu     sync.Mutex
	calls  map[uint32][]fzCall
	admits []uint32
}

func (e *fzEP) add(c *Conn, k fzCall) {
	e.mu.Lock()
	e.calls[c.Handle()] = append(e.calls[c.Handle()], k)
	e.mu.Unlock()
}
func (e *fzEP) Handle() uint32         { return 0 }
func (e *fzEP) Fill(c *Conn, b *Batch) {}
func (e *fzEP) WriteBlocked(c *Conn)   {}
func (e *fzEP) Control(c *Conn, h wire.Header, p []byte) error {
	e.add(c, fzCall{typ: h.Type, n: len(p), sum: wire.CRC(p)})
	return nil
}
func (e *fzEP) Data(c *Conn, off uint64, p []byte, buf *Buf) error {
	e.add(c, fzCall{typ: wire.TypeData, off: off, n: len(p), sum: wire.CRC(p)})
	buf.Release()
	return nil
}
func (e *fzEP) Datagram(c *Conn, seq uint64, p []byte, buf *Buf) error {
	e.add(c, fzCall{typ: wire.TypeDgram, off: seq, n: len(p), sum: wire.CRC(p)})
	buf.Release()
	return nil
}

// fzResult is what one fed stream did to the trunk.
type fzResult struct {
	calls  map[uint32][]fzCall
	admits []uint32
	cause  Cause
	detail string
	dead   bool
}

// feedTrunk feeds stream into a started passive trunk (MUX or dedicated,
// numbered from first) inside a synctest bubble: the reader reads it to its
// end, the views an OPEN admits start with the recording endpoint, and the
// bubble returns once every goroutine of the trunk exited.
func feedTrunk(t *testing.T, mux bool, first uint32, stream []byte) fzResult {
	var res fzResult
	synctest.Test(t, func(t *testing.T) {
		env := dgEnv()
		env.Presets.FirstFseq = first
		ep := &fzEP{calls: make(map[uint32][]fzCall)}
		c := newConn(env, &fuzzConn{r: bytes.NewReader(stream)}, 7, hPeerInst, -1, "", false)
		c.mux = mux
		if mux {
			env.Admit = func(v *Conn, h wire.Header, p []byte) {
				ep.mu.Lock()
				ep.admits = append(ep.admits, v.Handle())
				ep.mu.Unlock()
				v.Start(ep, &hBell{}, StartOptions{})
			}
		}
		c.Start(ep, &hBell{}, StartOptions{})
		select {
		case <-c.trunk.tdone:
		case <-time.After(time.Minute):
			t.Fatal("the trunk did not end after its input ended")
		}
		res.dead, res.cause, res.detail, _ = c.Death()
		ep.mu.Lock()
		res.calls, res.admits = ep.calls, ep.admits
		ep.mu.Unlock()
	})
	return res
}

// original returns the undamaged recording i's result.
func original(t *testing.T, i int, r *recording) fzResult {
	origOne[i].Do(func() { origs[i] = feedTrunk(t, r.mux, r.first(), r.b) })
	return origs[i]
}

// fzOps applies script's operations (7 bytes each: kind, position u24,
// argument u24; at most eight) to a copy of s; other is the splice source.
func fzOps(s, other, script []byte) []byte {
	s = slices.Clone(s)
	for k := 0; k < 8 && len(script) >= 7; k++ {
		op, pos, arg := script[0]%6, int(script[1])<<16|int(script[2])<<8|int(script[3]), int(script[4])<<16|int(script[5])<<8|int(script[6])
		script = script[7:]
		switch op {
		case 0: // flip one bit
			if len(s) > 0 {
				s[pos%len(s)] ^= 1 << (arg % 8)
			}
		case 1: // drop up to 4 KiB
			if len(s) > 0 {
				at := pos % len(s)
				s = slices.Delete(s, at, min(at+1+arg%4096, len(s)))
			}
		case 2: // duplicate up to 4 KiB in place
			if len(s) > 0 {
				at := pos % len(s)
				end := min(at+1+arg%4096, len(s))
				s = slices.Insert(s, end, slices.Clone(s[at:end])...)
			}
		case 3: // insert 1–32 pseudo-random bytes
			at := pos % (len(s) + 1)
			ins := make([]byte, 1+arg%32)
			r := rand.New(rand.NewPCG(uint64(arg), 0x5eed))
			for i := range ins {
				ins[i] = byte(r.Uint32())
			}
			s = slices.Insert(s, at, ins...)
		case 4: // truncate
			s = s[:pos%(len(s)+1)]
		case 5: // splice: the other recording from some point on
			if len(other) > 0 {
				s = append(s[:pos%(len(s)+1)], other[arg%len(other):]...)
			}
		}
	}
	return s
}

// fzOp encodes one operation for the seeds.
func fzOp(kind byte, pos, arg int) []byte {
	return []byte{kind, byte(pos >> 16), byte(pos >> 8), byte(pos), byte(arg >> 16), byte(arg >> 8), byte(arg)}
}

func FuzzCarrierStream_L43(f *testing.F) {
	rs, err := loadRecs()
	if err != nil {
		f.Fatalf("recordings: %v (go test -run TestRecord -update writes them)", err)
	}
	for i, r := range rs {
		sel := []byte{byte(i), byte(1 - i)}
		n := len(r.b)
		f.Add(sel)                                                      // the recording itself
		f.Add(append(slices.Clone(sel), fzOp(4, n-1, 0)...))            // truncated by one byte
		f.Add(append(slices.Clone(sel), fzOp(3, n, 0)...))              // extended by one byte
		f.Add(append(slices.Clone(sel), fzOp(0, n/2, 3)...))            // one flip mid-stream
		f.Add(append(slices.Clone(sel), fzOp(5, n/3, n/3)...))          // the other recording spliced in
		f.Add(append(slices.Clone(sel), fzOp(2, n/4, 100)...))          // 101 bytes duplicated
		f.Add(append(slices.Clone(sel), fzOp(1, n/5, 4095)...))         // 4 KiB dropped
		f.Add(append(slices.Clone(sel), fzOp(4, wire.HeaderLen, 0)...)) // cut inside the first header
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) < 2 {
			return
		}
		if len(in) > 64 {
			in = in[:64]
		}
		i, j := int(in[0])%len(rs), int(in[1])%len(rs)
		r := rs[i]
		want := original(t, i, r)
		stream := fzOps(r.b, rs[j].b, in[2:])
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		got := feedTrunk(t, r.mux, r.first(), stream)
		runtime.ReadMemStats(&m1)
		if a := m1.TotalAlloc - m0.TotalAlloc; a >= 2<<20 {
			t.Fatalf("one input allocated %d bytes (≥ 2 MiB)", a)
		}
		if !got.dead || got.cause != CauseProtocolViolation && got.cause != CauseTransportError {
			t.Fatalf("the trunk ended %v %v %q, want one death of protocol_violation or transport_error", got.dead, got.cause, got.detail)
		}
		for h, calls := range got.calls {
			o := want.calls[h]
			if len(calls) > len(o) || !slices.Equal(calls, o[:len(calls)]) {
				t.Fatalf("handle %d saw %d calls that are not a prefix of its %d original ones (death %v %q)", h, len(calls), len(o), got.cause, got.detail)
			}
		}
		if len(got.admits) > len(want.admits) || !slices.Equal(got.admits, want.admits[:len(got.admits)]) {
			t.Fatalf("admitted %v, not a prefix of %v", got.admits, want.admits)
		}
	})
}

// TestRecord checks the recordings: every frame decodes, the fseqs run on
// from the first frame's, the dedicated one carries handle 1 only and the
// MUX one three views with an OPEN for 2 and 3, each view has DATA and a
// FIN, and the undamaged stream fed to a passive trunk reaches every view
// with every session frame, admits views 2 and 3 and ends at the input's
// end (transport_error). The recordings start at different fseqs, far
// apart. With -update it first writes them from a real dialer trunk.
func TestRecord(t *testing.T) {
	if *recUpdate {
		for i, f := range recFiles {
			b := recordTrunk(t, uint64(i), f.mux)
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join("testdata", f.name), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	rs, err := loadRecs()
	if err != nil {
		t.Fatalf("recordings: %v (go test -run TestRecord -update writes them)", err)
	}
	if d := rs[0].first() - rs[1].first(); d < 1<<24 || -d < 1<<24 {
		t.Fatalf("the recordings start %d fseqs apart: a splice could continue the sequence", d)
	}
	for i, r := range rs {
		session := map[uint32]int{}
		opens, fins := 0, map[uint32]bool{}
		fseq := r.first()
		for b := r.b; len(b) > 0; fseq++ {
			fr, n, err := wire.DecodeFrame(b)
			if err != nil {
				t.Fatalf("%s: frame at %d: %v", r.name, len(r.b)-len(b), err)
			}
			if fr.Fseq != fseq {
				t.Fatalf("%s: fseq %d, want %d", r.name, fr.Fseq, fseq)
			}
			switch {
			case fr.Type == wire.TypeOpen:
				opens++
			case !fr.Type.CarrierLevel() && !fr.Type.Extension():
				session[fr.Handle]++
				fins[fr.Handle] = fins[fr.Handle] || fr.Type == wire.TypeFin
			}
			b = b[n:]
		}
		views := 1
		if r.mux {
			views = 3
		}
		if len(session) != views || r.mux && opens != 2 || !r.mux && opens != 0 {
			t.Fatalf("%s: session frames by handle %v, %d OPENs", r.name, session, opens)
		}
		res := original(t, i, r)
		if !res.dead || res.cause != CauseTransportError {
			t.Fatalf("%s: the undamaged stream ended the trunk %v %v %q, want transport_error at its end", r.name, res.dead, res.cause, res.detail)
		}
		for h, k := range session {
			if !fins[h] || len(res.calls[h]) != k {
				t.Fatalf("%s: handle %d: %d calls of its %d session frames reached the endpoint (FIN %v)", r.name, h, len(res.calls[h]), k, fins[h])
			}
		}
		if r.mux && !slices.Equal(res.admits, []uint32{2, 3}) {
			t.Fatalf("%s: admitted %v, want [2 3]", r.name, res.admits)
		}
	}
}

// recConn records every byte written through it.
type recConn struct {
	net.Conn
	mu sync.Mutex
	b  []byte
}

func (c *recConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.b = append(c.b, p...)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.b)
}

// recordTrunk runs a dialer trunk against a passive one over net.Pipe in
// a bubble and returns what the dialer wrote: dedicated, view 1; MUX,
// views 1–3 (2 and 3 opened with OPEN on the live trunk); each view sends
// eight rounds of DATA and then a FIN. The fseq start, the round sizes and
// the DATA segment sizes come from a PRNG seeded with seed.
func recordTrunk(t *testing.T, seed uint64, mux bool) []byte {
	var out []byte
	synctest.Test(t, func(t *testing.T) {
		rng := rand.New(rand.NewPCG(0x4c3a9f, seed))
		first := rng.Uint32()
		mod := func(env *Env) { env.Presets.FirstFseq = first }
		a, b := net.Pipe()
		rc := &recConn{Conn: a}
		d := newMuxSide(t, muxEnv(mod), rc, true)
		p := newMuxSide(t, muxEnv(mod), b, false)
		d.c.mux, p.c.mux = mux, mux
		d.start()
		p.start()
		views := []*mView{d.v1}
		if mux {
			for sid := byte(2); sid <= 3; sid++ {
				mv, _ := d.open(t, wire.TypeOpen, sid)
				views = append(views, mv)
			}
		}
		// Eight rounds: each view offers 1–13 KiB more in DATA segments of
		// a size drawn per round, then all wait for the passive; a FIN
		// closes each view's stream.
		totals := make([]uint64, len(views))
		for range 8 {
			for k, v := range views {
				n := uint64(1000 + rng.IntN(12<<10))
				v.src.mu.Lock()
				v.src.seg = []int{300, 1000, 1500, 4000, 16 << 10, 20 << 10}[rng.IntN(6)]
				v.src.mu.Unlock()
				v.src.offer(n)
				v.c.Wake()
				totals[k] += n
			}
			synctest.Wait()
		}
		var total int64
		for k, v := range views {
			v.src.addCtl(hFrame{t: wire.TypeFin, payload: finInner(totals[k])})
			v.c.Wake()
			total += int64(totals[k])
		}
		synctest.Wait()
		var got int64
		p.mu.Lock()
		for _, v := range p.views {
			got += v.ep.rxBytes.Load()
		}
		p.mu.Unlock()
		if got != total {
			t.Fatalf("the passive received %d of %d DATA bytes", got, total)
		}
		out = rc.bytes()
		d.c.KillTrunk(CauseLocalClose, "recorded")
		p.c.KillTrunk(CauseLocalClose, "recorded")
	})
	return out
}
