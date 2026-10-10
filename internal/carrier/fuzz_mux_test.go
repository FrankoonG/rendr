package carrier

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// FuzzMuxDispatch_L43_L14 (M3-D47, R1-26; L43, L14): a sequence of
// harness-sealed frames (valid CRC and fseq) with fuzz-chosen types,
// handles and order is fed into a trunk in the passive or the dialer role,
// MUX or dedicated, stream or datagram, with a fake Env.Admit. Every
// frame's classification — dispatched, admitted, dropped, ignored,
// violation — must equal the reference model of §A3.3 and §A5.4 below;
// the trunk dies iff the model says so; the largest handle seen never
// decreases; no endpoint call reaches a handle the model does not hold.
// The passive harness defers the attach of every OPEN for a handle that is
// a multiple of 3 (deferStart: a second OPEN of a pending session, whose
// actor attaches it later, WP16 W1): until then only one RST — a dialer's
// withdrawal (R1-5) — and the DETACH are legal for it.

// fuzzTypes is the frame alphabet.
var fuzzTypes = []wire.Type{wire.TypeOpen, wire.TypeJoin, wire.TypeOpenAck, wire.TypeJoinAck, wire.TypeFin, wire.TypeRst, wire.TypeDetach, wire.TypeData}

// fuzzOut is one frame's outcome.
type fuzzOut uint8

const (
	fzDispatch fuzzOut = iota
	fzAdmit
	fzDrop      // a §A3.3 row on a datagram trunk: dropped and counted
	fzIgnore    // legal, not delivered, not counted
	fzViolation // the trunk dies
	fzResponse  // a dialer view's response
)

// muxModel is the reference model of the reader's side of §A3.3/§A5.4 for
// the harness trunk's fixed starting states.
type muxModel struct {
	dialer, mux, dg bool
	maxHandle       uint32
	// per handle: "live", "pending", "awaiting", "attached", "retiring-ours",
	// "retiring-awaiting" (abandoned before its response, our DETACH
	// placed), "retiring-answered" (its response crossed our DETACH),
	// "retiring-peer", "gone", "unattached" (passive: an OPEN no session
	// attached yet), "unattached-rst" (its withdrawal RST arrived)
	st       map[uint32]string
	tolerate map[uint32]bool // refused handles: a crossing RST, response or DETACH is dropped
	tolAll   map[uint32]bool // retired at the DETACH bound: every session frame and the DETACH are dropped
	joins    int             // JOINs the harness refused at admission (its Admit saw them)
}

func newMuxModel(dialer, mux, dg bool) *muxModel {
	m := &muxModel{dialer: dialer, mux: mux, dg: dg, maxHandle: 1, st: map[uint32]string{1: "live"}, tolerate: map[uint32]bool{}, tolAll: map[uint32]bool{}}
	if dialer && mux {
		m.st[2], m.st[3], m.st[4], m.st[5], m.st[6] = "awaiting", "attached", "live", "retiring-ours", "retiring-awaiting"
		m.tolAll[7] = true
	}
	return m
}

// illegal is the §A3.3 outcome of a rule broken on a MUX trunk.
func (m *muxModel) illegal() fuzzOut {
	if m.dg {
		return fzDrop
	}
	return fzViolation
}

// step returns the outcome of frame (t, h) and applies it.
func (m *muxModel) step(t wire.Type, h uint32) fuzzOut {
	if !m.mux {
		// A dedicated carrier: handle 1 session frames only (M1/M2). On a
		// datagram carrier a bare frame of another handle is M2's framing
		// error: the rest of its datagram is dropped and counted and the
		// carrier lives (dedicatedOK, PA-1); inside REL it is a violation.
		if m.dg && t == wire.TypeDgram && h != wire.SessionHandle {
			return fzDrop
		}
		if t == wire.TypeDetach || isFirstType(t) || h != wire.SessionHandle {
			return fzViolation
		}
		return fzDispatch
	}
	if t == wire.TypeDetach {
		s, ok := m.st[h]
		switch {
		case !ok && (m.tolerate[h] || m.tolAll[h]):
			delete(m.tolerate, h)
			delete(m.tolAll, h)
			return fzIgnore
		case !ok, s == "gone", s == "awaiting", s == "retiring-peer":
			return m.illegal()
		case s == "retiring-ours", s == "retiring-awaiting", s == "retiring-answered":
			m.st[h] = "gone" // the exchange completes
			delete(m.st, h)
			return fzIgnore
		}
		m.st[h] = "retiring-peer"
		return fzIgnore
	}
	s, ok := m.st[h]
	if !ok {
		if t != wire.TypeOpen && t != wire.TypeJoin && m.tolAll[h] {
			return fzIgnore // a frame the peer placed before our DETACH reached it
		}
		if (t == wire.TypeRst || t == wire.TypeOpenAck || t == wire.TypeJoinAck) && m.tolerate[h] {
			return fzIgnore
		}
		if !m.dialer && (t == wire.TypeOpen || t == wire.TypeJoin) && h > m.maxHandle {
			m.maxHandle = h
			if t == wire.TypeOpen {
				m.st[h] = "pending"
				if deferStart(h) {
					m.st[h] = "unattached"
				}
				return fzAdmit
			}
			m.tolerate[h] = true // the harness refuses JOINs at admission
			m.joins++
			return fzIgnore
		}
		return m.illegal()
	}
	if t == wire.TypeOpen || t == wire.TypeJoin {
		return m.illegal()
	}
	switch s {
	case "awaiting":
		if t == wire.TypeOpenAck { // view 2 opened with OPEN
			m.st[h] = "attached"
			return fzResponse
		}
		return m.illegal()
	case "retiring-awaiting":
		if t == wire.TypeOpenAck { // the response crossed our DETACH (E6)
			m.st[h] = "retiring-answered"
			return fzResponse
		}
		return m.illegal() // no session frame before its response and the go frame
	case "attached", "retiring-peer", "retiring-answered":
		return m.illegal()
	case "pending":
		if isFirstType(t) {
			return m.illegal()
		}
		return fzDispatch
	case "unattached":
		if t == wire.TypeRst {
			m.st[h] = "unattached-rst" // the withdrawal: legal, recorded
			return fzIgnore
		}
		return m.illegal()
	case "live", "retiring-ours":
		if isFirstType(t) {
			return m.illegal()
		}
		return fzDispatch
	}
	return m.illegal()
}

// deferStart reports an OPEN handle whose attach the passive harness defers
// (the model's "unattached" state).
func deferStart(h uint32) bool { return h%3 == 0 }

// fuzzConn serves a byte stream to the reader and discards writes.
type fuzzConn struct {
	nopConn
	r *bytes.Reader
}

func (f *fuzzConn) Read(p []byte) (int, error) { return f.r.Read(p) }

// recEP records endpoint calls per view.
type recEP struct {
	mu    sync.Mutex
	calls map[uint32]int
}

func (e *recEP) add(c *Conn) {
	e.mu.Lock()
	e.calls[c.Handle()]++
	e.mu.Unlock()
}
func (e *recEP) Handle() uint32         { return 0 }
func (e *recEP) Fill(c *Conn, b *Batch) {}
func (e *recEP) WriteBlocked(c *Conn)   {}
func (e *recEP) Control(c *Conn, h wire.Header, p []byte) error {
	e.add(c)
	return nil
}
func (e *recEP) Data(c *Conn, off uint64, p []byte, buf *Buf) error {
	e.add(c)
	buf.Release()
	return nil
}
func (e *recEP) Datagram(c *Conn, seq uint64, p []byte, buf *Buf) error {
	e.add(c)
	buf.Release()
	return nil
}

// fuzzTrunk builds a started-ready trunk (no goroutines) in the role and
// kind given, with the model's starting views.
func fuzzTrunk(dialer, mux, dg bool, ep *recEP, admits *[]uint32) (*Conn, *fuzzConn, *fakeIO) {
	env := dgEnv()
	var c *Conn
	var fc *fuzzConn
	var io *fakeIO
	if dg {
		io, _ = newFakeIOPair(1200)
		c = dgConn(env, io, 1200, dialer)
	} else {
		fc = &fuzzConn{r: bytes.NewReader(nil)}
		factory := -1
		if dialer {
			factory = 0
		}
		c = newConn(env, fc, 7, hPeerInst, factory, "", dialer)
	}
	c.mux = mux
	c.ep, c.pep = ep, ep
	c.join.started = true
	if mux {
		c.startMux()
	}
	if !dialer {
		env.Admit = func(v *Conn, h wire.Header, p []byte) {
			*admits = append(*admits, v.Handle())
			if h.Type == wire.TypeJoin {
				v.Refuse(v.Handle(), Answer{Type: wire.TypeJoinAck, Status: wire.StatusUnknownSession})
				return
			}
			if deferStart(v.Handle()) {
				return // its session's actor attaches it later (never, here)
			}
			v.Start(ep, nil, StartOptions{})
		}
	}
	if dialer && mux {
		c.mx.Lock()
		mk := func(h uint32, st viewState) *Conn {
			v := c.newViewLocked(h, st)
			v.vx.dialer, v.vx.first, v.vx.resp = true, wire.TypeOpen, make(chan struct{})
			if st == viewRetiring {
				v.vx.detSent.Store(true)
				v.vx.detCseq = c.env.Presets.firstCseq() - 1 // already acknowledged on a datagram trunk
				if dg {
					c.ms.awaitAck.Add(1)
				}
			}
			return v
		}
		mk(2, viewAwaiting)
		v3 := mk(3, viewAttachedPending)
		v3.vx.respGot = true
		v4 := mk(4, viewLive)
		v4.ep, v4.pep, v4.vx.attached, v4.vx.respGot = ep, ep, true, true
		v5 := mk(5, viewRetiring)
		v5.ep, v5.pep, v5.vx.attached, v5.vx.respGot = ep, ep, true, true
		mk(6, viewRetiring) // abandoned while awaiting its response: our DETACH placed
		var pl postList
		c.expireLocked(mk(7, viewRetiring), &pl) // retired at the DETACH bound without the peer's DETACH
		c.next = 8
		c.mx.Unlock()
		c.runPost(&pl)
	}
	return c, fc, io
}

// fuzzPayload returns a valid payload of type t for handle h.
func fuzzPayload(t wire.Type, h uint32, dg bool) []byte {
	switch t {
	case wire.TypeOpen:
		return mOpenPayload(byte(h), dg)
	case wire.TypeJoin:
		return mJoinPayload(byte(h))
	case wire.TypeOpenAck, wire.TypeJoinAck:
		return okAck(t)
	case wire.TypeFin:
		return finInner(0)
	case wire.TypeRst:
		return rstPayload(wire.RstWithdrawn)
	case wire.TypeDetach:
		return detachPayload(h, wire.DetachEnded)
	case wire.TypeData:
		return dataPayload(0, 16)
	case wire.TypeDgram:
		b := make([]byte, wire.DgramPrefixLen+16)
		return b
	}
	return nil
}

func FuzzMuxDispatch_L43_L14(f *testing.F) {
	f.Add([]byte{0x2, 0, 1, 4, 1, 7, 1, 6, 1, 4, 1})                   // passive mux: OPEN 2, DATA 2, DETACH 2, DATA 2
	f.Add([]byte{0x3, 2, 1, 4, 1, 6, 2, 4, 3, 6, 4})                   // dialer mux: OPEN_ACK 2, DATA 2, DETACH 3, DATA 4, DETACH 5
	f.Add([]byte{0x6, 0, 2, 1, 3, 0, 1, 5, 2, 6, 3, 7, 2})             // passive datagram mux
	f.Add([]byte{0x7, 2, 1, 2, 1, 6, 1, 6, 4, 4, 4, 0, 5})             // dialer datagram mux
	f.Add([]byte{0x0, 7, 0, 7, 1, 6, 0})                               // passive dedicated stream
	f.Add([]byte{0x0, 4, 0, 0, 0})                                     // passive dedicated stream: an OPEN after establishment
	f.Add([]byte{0x1, 4, 0, 2, 0})                                     // dialer dedicated stream: an OPEN_ACK after establishment
	f.Add([]byte{0x4, 4, 0, 6, 0, 0, 1})                               // passive dedicated datagram
	f.Add([]byte{0x2, 0, 3, 0, 2, 1, 4, 5, 4, 6, 4, 6, 4, 0, 7, 0, 6}) // passive: a handle not above, a tolerated DETACH
	f.Add([]byte{0x2, 1, 1, 5, 1, 7, 1})                               // passive: JOIN 2 refused, RST 2 (crossing), DATA 2 (a violation)
	f.Add([]byte{0x3, 2, 5, 6, 5, 4, 5})                               // dialer: OPEN_ACK 6 crossing our DETACH, DETACH 6, FIN 6 (a violation)
	f.Add([]byte{0x3, 7, 6, 4, 6, 5, 6, 3, 6, 6, 6, 7, 6})             // dialer: retired at the bound: DATA, FIN, RST, JOIN_ACK 7, DETACH 7, DATA 7 (a violation)
	f.Add([]byte{0x7, 2, 5, 4, 5, 6, 5, 7, 6, 5, 6, 6, 6, 6, 6, 4, 6}) // dialer datagram: the same rows, drops counted
	f.Add([]byte{0x2, 0, 2, 5, 2, 6, 2, 7, 2})                         // passive: OPEN 3 unattached, RST 3 (withdrawal), DETACH 3, DATA 3 (a violation)
	f.Add([]byte{0x2, 0, 2, 7, 2})                                     // passive: OPEN 3 unattached, DATA 3 (a violation)
	f.Add([]byte{0x6, 0, 2, 5, 2, 5, 2, 6, 2, 4, 2})                   // passive datagram: OPEN 3, RST 3, a second RST (dropped), DETACH 3, FIN 3 (dropped)
	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) < 1 {
			return
		}
		dialer, mux, dg := in[0]&1 != 0, in[0]&2 != 0, in[0]&4 != 0
		in = in[1:]
		if len(in) > 256 {
			in = in[:256]
		}
		ep := &recEP{calls: map[uint32]int{}}
		var admits []uint32
		c, fc, io := fuzzTrunk(dialer, mux, dg, ep, &admits)
		defer func() {
			c.KillTrunk(CauseLocalClose, "fuzz end")
			select {
			case <-c.trunk.tdone:
			case <-time.After(10 * time.Second):
				t.Fatal("trunk not done")
			}
		}()
		_ = io
		m := newMuxModel(dialer, mux, dg)
		want := map[uint32]int{}
		var wantAdmits []uint32
		drops := 0
		fseq := c.env.Presets.firstFseq()
		cseq := c.env.Presets.firstCseq()
		rd := &c.rd
		if !dg {
			rd.stage = c.env.Bufs.Get(BigData, nil)
		}
		maxSeen := uint32(0)
		for i := 0; i+1 < len(in); i += 2 {
			typ := fuzzTypes[int(in[i])%len(fuzzTypes)]
			if typ == wire.TypeData && dg {
				typ = wire.TypeDgram
			}
			h := uint32(1 + in[i+1]%8)
			if in[i+1]%8 == 7 {
				h = 0xFFFFFFF0 + uint32(in[i+1]>>3)%16
			}
			out := m.step(typ, h)
			switch out {
			case fzDispatch:
				want[h]++
			case fzAdmit:
				wantAdmits = append(wantAdmits, h)
			case fzDrop:
				drops++
			}
			// Encode and feed the frame.
			if !dg {
				var hdr wire.Header
				if typ == wire.TypeDetach {
					hdr = wire.Header{Type: typ, Fseq: fseq, Handle: 0}
				} else {
					hdr = wire.Header{Type: typ, Fseq: fseq, Handle: h}
				}
				fseq++
				fc.r.Reset(wire.AppendFrame(nil, hdr, fuzzPayload(typ, h, dg)))
				rd.r, rd.w, rd.pending = 0, 0, nil
				ok := c.readFrame(rd)
				dead := c.death.Load() != nil
				if (out == fzViolation) != dead || ok == dead {
					t.Fatalf("frame %d %v(%d): model %d, trunk dead %v (readFrame %v)", i/2, typ, h, out, dead, ok)
				}
			} else {
				var d []byte
				if typ == wire.TypeDgram {
					d = wire.AppendFrame(nil, wire.Header{Type: typ, Fseq: fseq, Handle: h}, fuzzPayload(typ, h, dg))
				} else {
					ih := h
					if typ == wire.TypeDetach {
						ih = 0
					}
					d = wire.AppendFrame(nil, wire.Header{Type: wire.TypeRel, Fseq: fseq}, relPayloadOf(cseq, typ, 0, ih, fuzzPayload(typ, h, dg)))
					cseq++
				}
				fseq++
				ok := c.dgFrames(d, PeerKey{}, ReadOK, time.Now())
				dead := c.death.Load() != nil
				if (out == fzViolation) != dead || ok == dead {
					t.Fatalf("frame %d %v(%d): model %d, trunk dead %v (dgFrames %v)", i/2, typ, h, out, dead, ok)
				}
			}
			if c.mux && !c.dialer {
				c.mx.Lock()
				mh := c.maxHandle
				c.mx.Unlock()
				if mh < maxSeen {
					t.Fatalf("maxHandle fell from %d to %d", maxSeen, mh)
				}
				maxSeen = mh
			}
			if out == fzViolation {
				break
			}
		}
		ep.mu.Lock()
		got := ep.calls
		ep.mu.Unlock()
		for h, n := range got {
			if want[h] != n {
				t.Fatalf("handle %d: %d endpoint calls, model %d (all: got %v, want %v)", h, n, want[h], got, want)
			}
		}
		for h, n := range want {
			if got[h] != n {
				t.Fatalf("handle %d: %d endpoint calls, model %d", h, got[h], n)
			}
		}
		if len(admits) != len(wantAdmits)+m.joins {
			t.Fatalf("admitted %v, model %v", admits, wantAdmits)
		}
		if dg {
			if n := int(c.Stats().Dropped); n != drops {
				t.Fatalf("dropped %d, model %d", n, drops)
			}
		}
	})
}
