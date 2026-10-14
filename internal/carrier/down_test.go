package carrier

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// PA-86 (F-7): the trunk death notice DOWN (down.go). The rows build MUX
// trunks of one Env — one Runtime, whose TrunkSet indexes them by pair —
// against scripted peers (stream: a wirePeer over net.Pipe; datagram: a
// rawPeer over the in-memory link) and judge what each trunk writes and
// how it ends. Everything runs inside synctest bubbles.

// downOtherInst is the InstanceID of a third Runtime (another pair).
var downOtherInst = [16]byte{0xdd, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 0xdd}

// downPayload encodes the DOWN payload naming id.
func downPayload(id uint32) []byte {
	b := make([]byte, wire.DownLen)
	wire.PutDown(b, id)
	return b
}

// downEnv is the mux harness Env with the Runtime's trunk index.
func downEnv() *Env {
	env := muxEnv(nil)
	env.Trunks = NewTrunkSet()
	return env
}

// downStream returns a started stream MUX trunk of env with CarrierID id,
// role dialer or passive and peer instance inst, against a raw wire peer.
func downStream(t testing.TB, env *Env, id uint32, dialer bool, inst [16]byte) (*muxSide, *wirePeer) {
	t.Helper()
	a, b := net.Pipe()
	tap := newFrameTap(a)
	s := newMuxSide(t, env, tap, dialer)
	s.tap = tap
	s.c.trunk.id, s.c.trunk.peer = id, inst
	t.Cleanup(tap.release)
	p := startPeer(b, env.Presets.firstFseq())
	t.Cleanup(p.close)
	s.start()
	return s, p
}

// downDg returns a started datagram MUX trunk of env with CarrierID id,
// role dialer or passive and peer instance inst, against a raw peer.
func downDg(t testing.TB, env *Env, id uint32, dialer bool, inst [16]byte) (*muxSide, *rawPeer) {
	t.Helper()
	ia, ib := newFakeIOPair(t, 1200)
	s := newDgMuxSide(t, env, ia, 1200, dialer)
	s.c.trunk.id, s.c.trunk.peer = id, inst
	p := &rawPeer{io: ib, fseq: env.Presets.firstFseq()}
	s.start()
	return s, p
}

// streamDowns returns the CarrierIDs of the DOWNs a stream peer received,
// in wire order.
func streamDowns(p *wirePeer) []uint32 {
	var out []uint32
	for _, f := range p.received() {
		if f.Type == wire.TypeDown {
			id, err := wire.ParseDown(f.Payload)
			if err != nil {
				id = 0
			}
			out = append(out, id)
		}
	}
	return out
}

// dgRel is one REL a datagram trunk wrote.
type dgRel struct {
	cseq   uint32
	t      wire.Type
	flags  uint8
	handle uint32
	p      []byte
}

// relsWritten decodes every REL of the datagrams ds, in wire order; bare
// counts the bare (unwrapped) DOWNs among them.
func relsWritten(ds [][]byte) (rels []dgRel, bare int) {
	for _, d := range ds {
		fs, _ := dgDecode(d)
		for _, f := range fs {
			switch f.Type {
			case wire.TypeDown:
				bare++
			case wire.TypeRel:
				if h, inner, err := wire.ParseRel(f.Payload); err == nil {
					rels = append(rels, dgRel{cseq: h.Cseq, t: h.Type, flags: h.Flags, handle: h.Handle, p: append([]byte(nil), inner...)})
				}
			}
		}
	}
	return rels, bare
}

// dgDowns returns the CarrierIDs of the REL{DOWN}s in rels, in wire order.
func dgDowns(rels []dgRel) []uint32 {
	var out []uint32
	for _, r := range rels {
		if r.t == wire.TypeDown {
			id, err := wire.ParseDown(r.p)
			if err != nil {
				id = 0
			}
			out = append(out, id)
		}
	}
	return out
}

// pending returns the trunk's pending DOWNs, oldest first.
func (q *downQueue) pending() []uint32 {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]uint32, 0, q.n)
	for i := range q.n {
		out = append(out, q.ids[(q.head+i)%downCap])
	}
	return out
}

func sameIDs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// bellFunc is a Doorbell that runs a function (on the ringing goroutine).
type bellFunc func()

func (f bellFunc) Ring() { f() }

// downCauses is the sender's cause table (Cause.sendsDown): every death
// whose cause the peer does not know is reported; goaway and peer_down
// (the peer knows them) and retired (no death) are not.
var downCauses = []struct {
	c    Cause
	down bool
}{
	{CauseTransportError, true},
	{CausePingTimeout, true},
	{CauseWriteStall, true},
	{CauseProtocolViolation, true},
	{CauseInstanceMismatch, true},
	{CauseLocalClose, true},
	{CauseGoAway, false},
	{CausePeerDown, false},
	{CauseRetired, false},
}

// TestDownSentForTrunkDeath_PA86 (sender): a MUX trunk's death queues
// DOWN(its CarrierID) on every other live MUX trunk of its pair — same
// peer instance, same direction — and the survivor's writer places it at
// once, bare on a stream trunk and REL-wrapped (inner handle 0) on a
// datagram trunk; never on a trunk of another pair (another peer instance,
// or the other direction toward the same instance), and only for the
// causes of downCauses. A dedicated carrier's death sends none.
func TestDownSentForTrunkDeath_PA86(t *testing.T) {
	for _, kind := range []string{"stream", "datagram"} {
		for _, tc := range downCauses {
			t.Run(kind+"/"+tc.c.String(), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) { downSentRow(t, kind == "datagram", tc.c, tc.down) })
			})
		}
	}
	t.Run("dedicated", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := downEnv()
			_, mate := downStream(t, env, 12, true, mPassiveInst)
			c, _ := hPair(t, env, nil)
			c.trunk.dialer, c.trunk.peer, c.trunk.id = true, mPassiveInst, 11
			c.Start(&hEP{}, &hBell{}, StartOptions{})
			synctest.Wait()
			if env.Trunks.lookup(c.trunk, 11) != nil {
				t.Fatal("a dedicated carrier entered the Runtime's trunk set")
			}
			c.KillTrunk(CauseTransportError, "test: a dedicated carrier dies")
			synctest.Wait()
			if got := streamDowns(mate); len(got) != 0 {
				t.Fatalf("a dedicated carrier's death sent DOWN %v", got)
			}
		})
	})
}

func downSentRow(t *testing.T, dg bool, cause Cause, want bool) {
	env := downEnv()
	type end struct {
		s      *muxSide
		stream *wirePeer
		raw    *rawPeer
	}
	mk := func(id uint32, dialer bool, inst [16]byte) end {
		if dg {
			s, p := downDg(t, env, id, dialer, inst)
			return end{s: s, raw: p}
		}
		s, p := downStream(t, env, id, dialer, inst)
		return end{s: s, stream: p}
	}
	downs := func(e end) []uint32 {
		if e.stream != nil {
			return streamDowns(e.stream)
		}
		rels, bare := relsWritten(e.raw.read())
		if bare != 0 {
			t.Fatalf("a datagram trunk wrote %d bare DOWNs", bare)
		}
		for _, r := range rels {
			if r.t == wire.TypeDown && (r.handle != 0 || r.flags != 0) {
				t.Fatalf("REL{DOWN} with handle %d flags %#x", r.handle, r.flags)
			}
		}
		return dgDowns(rels)
	}
	dying := mk(11, true, mPassiveInst)
	mates := []end{mk(12, true, mPassiveInst), mk(13, true, mPassiveInst)}
	others := []end{mk(14, true, downOtherInst), mk(15, false, mPassiveInst)} // another instance; the other direction
	synctest.Wait()
	for _, e := range append(append([]end{dying}, mates...), others...) {
		if dg {
			e.raw.read() // what the starts wrote
		}
	}
	// The sessions on the dying trunk learn of its death when its doorbell
	// rings: by then every mate has queued the DOWN (its writer may have
	// placed it already).
	var atRing []uint64
	var rang atomic.Int32
	dying.s.c.bell.Store(&ringer{bellFunc(func() {
		if rang.Add(1) == 1 {
			for _, m := range mates {
				q := &m.s.c.downs
				q.mu.Lock()
				atRing = append(atRing, q.queued)
				q.mu.Unlock()
			}
		}
	})})
	dying.s.c.KillTrunk(cause, "test: the trunk dies")
	synctest.Wait()
	if _, got, _, _ := dying.s.c.Death(); got != cause || rang.Load() == 0 {
		t.Fatalf("premise: the trunk died with %v (want %v), its doorbell rang %d times", got, cause, rang.Load())
	}
	for i, n := range atRing {
		if want && n != 1 || !want && n != 0 {
			t.Errorf("%v: mate %d had queued %d DOWNs when the dying trunk's doorbell rang, want %v", cause, mates[i].s.c.ID(), n, want)
		}
	}
	var wantIDs []uint32
	if want {
		wantIDs = []uint32{11}
	}
	for _, m := range mates {
		if got := downs(m); !sameIDs(got, wantIDs) {
			t.Errorf("%v: mate %d wrote DOWNs %v, want %v", cause, m.s.c.ID(), got, wantIDs)
		}
		if q := m.s.c.downs.pending(); len(q) != 0 {
			t.Errorf("mate %d still holds pending DOWNs %v", m.s.c.ID(), q)
		}
	}
	for _, o := range others {
		if got := downs(o); len(got) != 0 {
			t.Errorf("%v: trunk %d of another pair wrote DOWNs %v", cause, o.s.c.ID(), got)
		}
	}
}

// TestDownReceiver_PA86 (receiver): a DOWN naming a live trunk of the
// receiving trunk's pair kills that trunk with peer_down (as a local
// transport death; the receiving trunk lives), and its death sends no DOWN
// of its own; an unknown, dead, retiring or other-pair ID (another peer
// instance, or the other direction toward the same instance) is ignored —
// no violation, nothing killed; a DOWN naming the trunk it arrives on is a
// protocol violation of that trunk. Stream trunks (bare DOWN) and datagram
// trunks (REL{DOWN}).
func TestDownReceiver_PA86(t *testing.T) {
	for _, kind := range []string{"stream", "datagram"} {
		dg := kind == "datagram"
		t.Run(kind+"/live", func(t *testing.T) { synctest.Test(t, func(t *testing.T) { downReceiveLive(t, dg) }) })
		t.Run(kind+"/ignored", func(t *testing.T) { synctest.Test(t, func(t *testing.T) { downReceiveIgnored(t, dg) }) })
		t.Run(kind+"/self", func(t *testing.T) { synctest.Test(t, func(t *testing.T) { downReceiveSelf(t, dg) }) })
	}
}

// downRx is one trunk of a receiver row with its scripted peer.
type downRx struct {
	s      *muxSide
	stream *wirePeer
	raw    *rawPeer
	rs     relSeq
}

func newDownRx(t *testing.T, env *Env, dg bool, id uint32, dialer bool, inst [16]byte) *downRx {
	if dg {
		s, p := downDg(t, env, id, dialer, inst)
		return &downRx{s: s, raw: p}
	}
	s, p := downStream(t, env, id, dialer, inst)
	return &downRx{s: s, stream: p}
}

// sendDown makes the peer send DOWN(id) on the trunk.
func (r *downRx) sendDown(id uint32) {
	if r.stream != nil {
		_ = r.stream.send(wire.TypeDown, 0, 0, downPayload(id))
		return
	}
	r.raw.send(r.rs.rel(wire.TypeDown, 0, 0, downPayload(id)))
}

// downs returns the DOWNs the trunk wrote so far.
func (r *downRx) downs() []uint32 {
	if r.stream != nil {
		return streamDowns(r.stream)
	}
	rels, _ := relsWritten(r.raw.read())
	return dgDowns(rels)
}

func downReceiveLive(t *testing.T, dg bool) {
	env := downEnv()
	rx := newDownRx(t, env, dg, 21, true, mPassiveInst)
	victim := newDownRx(t, env, dg, 22, true, mPassiveInst)
	third := newDownRx(t, env, dg, 23, true, mPassiveInst)
	synctest.Wait()
	rx.downs()
	third.downs()
	rx.sendDown(22)
	synctest.Wait()
	dead, cause, detail, _ := victim.s.c.Death()
	if !dead || cause != CausePeerDown || cause.String() != "peer_down" || !strings.Contains(detail, "carrier 21") {
		t.Fatalf("the named trunk: dead %v, cause %v %q; want peer_down by the DOWN on carrier 21", dead, cause, detail)
	}
	if dead, cause, detail, _ := rx.s.c.Death(); dead {
		t.Fatalf("the receiving trunk died: %v %q", cause, detail)
	}
	if env.Trunks.lookup(rx.s.c.trunk, 22) != nil {
		t.Fatal("the killed trunk is still in the Runtime's trunk set")
	}
	// A trunk killed by a DOWN sends none (the peer knows): neither the
	// receiving trunk nor the third trunk of the pair writes DOWN(22).
	if got := append(rx.downs(), third.downs()...); len(got) != 0 {
		t.Fatalf("a peer_down death sent DOWNs %v", got)
	}
	if q := append(rx.s.c.downs.pending(), third.s.c.downs.pending()...); len(q) != 0 {
		t.Fatalf("a peer_down death queued DOWNs %v", q)
	}
}

func downReceiveIgnored(t *testing.T, dg bool) {
	env := downEnv()
	rx := newDownRx(t, env, dg, 31, true, mPassiveInst)
	dead := newDownRx(t, env, dg, 32, true, mPassiveInst)
	retiring := newDownRx(t, env, dg, 33, true, mPassiveInst)
	otherInst := newDownRx(t, env, dg, 34, true, downOtherInst)
	otherDir := newDownRx(t, env, dg, 35, false, mPassiveInst)
	synctest.Wait()
	dead.s.c.KillTrunk(CauseTransportError, "test: died before the DOWN")
	retiring.s.c.RetireTrunk(wire.CloseRetire) // its peer never answers the CLOSE: it stays retiring
	synctest.Wait()
	if !retiring.s.c.TrunkCloseSent() || retiring.s.c.TrunkDying() {
		t.Fatalf("premise: the retiring trunk wrote its CLOSE %v, dying %v", retiring.s.c.TrunkCloseSent(), retiring.s.c.TrunkDying())
	}
	for _, id := range []uint32{999, 32, 33, 34, 35} {
		rx.sendDown(id)
	}
	synctest.Wait()
	if d, cause, detail, _ := rx.s.c.Death(); d {
		t.Fatalf("the receiving trunk died: %v %q", cause, detail)
	}
	if _, cause, _, _ := dead.s.c.Death(); cause != CauseTransportError {
		t.Errorf("the dead trunk's cause became %v", cause)
	}
	for _, r := range []*downRx{retiring, otherInst, otherDir} {
		if d, cause, detail, _ := r.s.c.Death(); d {
			t.Errorf("trunk %d died: %v %q (a DOWN naming it was to be ignored)", r.s.c.ID(), cause, detail)
		}
	}
}

func downReceiveSelf(t *testing.T, dg bool) {
	env := downEnv()
	rx := newDownRx(t, env, dg, 41, true, mPassiveInst)
	mate := newDownRx(t, env, dg, 42, true, mPassiveInst)
	synctest.Wait()
	rx.sendDown(41)
	synctest.Wait()
	dead, cause, detail, _ := rx.s.c.Death()
	if !dead || cause != CauseProtocolViolation || !strings.Contains(detail, "DOWN naming the trunk it arrives on") {
		t.Fatalf("a DOWN naming its own trunk: dead %v, cause %v %q; want protocol_violation", dead, cause, detail)
	}
	if d, cause, detail, _ := mate.s.c.Death(); d {
		t.Fatalf("the other trunk of the pair died: %v %q", cause, detail)
	}
}

// TestDownIllegalCarrier_PA86 (legality): DOWN belongs to established MUX
// trunks only. On a dedicated stream carrier — a session's, a dialer's
// probe carrier, a passive sessionless carrier — a DOWN is a protocol
// violation, and so is a REL{DOWN} on a dedicated datagram carrier
// (session or sessionless), a bare DOWN on a datagram MUX trunk (DOWN is a
// reliable frame there) and a DOWN naming CarrierID 0, even when a live
// trunk of the pair could have been named.
func TestDownIllegalCarrier_PA86(t *testing.T) {
	for _, st := range []struct {
		name   string
		ep     bool
		dialer bool
		opts   StartOptions
	}{
		{"stream session", true, true, StartOptions{}},
		{"stream probe", false, true, StartOptions{Probe: true}},
		{"stream sessionless", false, false, StartOptions{Sessionless: true}},
	} {
		t.Run(st.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := downEnv()
				mate, _ := downStream(t, env, 52, st.dialer, hPeerInst)
				c, p := hPair(t, env, nil)
				c.trunk.dialer, c.trunk.id = st.dialer, 51
				if st.ep {
					c.Start(&hEP{}, &hBell{}, st.opts)
				} else {
					c.Start(nil, &hBell{}, st.opts)
				}
				synctest.Wait()
				go p.send(wire.TypeDown, 0, 0, downPayload(52))
				hWait(t, c)
				if _, cause, detail, _ := c.Death(); cause != CauseProtocolViolation || !strings.Contains(detail, "DOWN on a dedicated carrier") {
					t.Fatalf("cause %v %q, want protocol_violation for a DOWN on a dedicated carrier", cause, detail)
				}
				if d, cause, _, _ := mate.c.Death(); d {
					t.Fatalf("the trunk it named died: %v", cause)
				}
			})
		})
	}
	for _, st := range []struct {
		name    string
		session bool
	}{{"datagram session", true}, {"datagram sessionless", false}} {
		t.Run(st.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := downEnv()
				mate, _ := downDg(t, env, 62, true, hPeerInst)
				s, p := rawPairWith(t, 1200, true, func(e *Env) { *e = *env })
				s.c.trunk.id = 61
				if st.session {
					s.start(StartOptions{})
				} else {
					s.c.Start(nil, s.bell, StartOptions{Sessionless: true})
				}
				synctest.Wait()
				p.send(relFrame(1, wire.TypeDown, 0, 0, downPayload(62)))
				hWait(t, s.c)
				if _, cause, detail, _ := s.c.Death(); cause != CauseProtocolViolation || !strings.Contains(detail, "DOWN on a dedicated carrier") {
					t.Fatalf("cause %v %q, want protocol_violation for a REL{DOWN} on a dedicated carrier", cause, detail)
				}
				if d, cause, _, _ := mate.c.Death(); d {
					t.Fatalf("the trunk it named died: %v", cause)
				}
			})
		})
	}
	t.Run("bare DOWN on a datagram trunk", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := downEnv()
			s, p := downDg(t, env, 71, true, mPassiveInst)
			mate, _ := downDg(t, env, 72, true, mPassiveInst)
			synctest.Wait()
			p.send(rawFrame{t: wire.TypeDown, payload: downPayload(72)})
			hWait(t, s.c)
			if _, cause, detail, _ := s.c.Death(); cause != CauseProtocolViolation || !strings.Contains(detail, "bare DOWN") {
				t.Fatalf("cause %v %q, want protocol_violation for a bare DOWN", cause, detail)
			}
			if d, cause, _, _ := mate.c.Death(); d {
				t.Fatalf("the trunk it named died: %v", cause)
			}
		})
	})
	for _, kind := range []string{"stream", "datagram"} {
		t.Run("CarrierID 0/"+kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := downEnv()
				rx := newDownRx(t, env, kind == "datagram", 81, true, mPassiveInst)
				synctest.Wait()
				rx.sendDown(0)
				hWait(t, rx.s.c)
				if _, cause, detail, _ := rx.s.c.Death(); cause != CauseProtocolViolation || !strings.Contains(detail, "DOWN:") {
					t.Fatalf("cause %v %q, want protocol_violation for DOWN(0)", cause, detail)
				}
			})
		})
	}
}

// TestDownHeldTrunkWaitsForResponse_PA86: a passive trunk held for its
// first response (StartOptions.Hold, M3-D8: the response is the first
// frame on the wire) writes nothing while a DOWN is queued on it — not even
// the DOWN — and places the DOWN right behind the response once it left:
// the response is the first frame (stream) or the first REL (datagram),
// the DOWN follows it.
func TestDownHeldTrunkWaitsForResponse_PA86(t *testing.T) {
	for _, kind := range []string{"stream", "datagram"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { downHeldRow(t, kind == "datagram") })
		})
	}
}

func downHeldRow(t *testing.T, dg bool) {
	env := downEnv()
	dying := newDownRx(t, env, dg, 91, false, hPeerInst)
	var s *muxSide
	var sp *wirePeer
	var rp *rawPeer
	if dg {
		ia, ib := newFakeIOPair(t, 1200)
		s = newDgMuxSide(t, env, ia, 1200, false)
		rp = &rawPeer{io: ib, fseq: env.Presets.firstFseq()}
	} else {
		a, b := net.Pipe()
		s = newMuxSide(t, env, a, false)
		sp = startPeer(b, env.Presets.firstFseq())
		t.Cleanup(sp.close)
	}
	s.c.trunk.id, s.c.trunk.peer = 92, hPeerInst
	var answer atomic.Bool
	s.v1.ep.fill = func(c *Conn, b *Batch) {
		if answer.CompareAndSwap(true, false) && !b.AddOpenAck(wire.SessionHandle, &wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20}) {
			answer.Store(true)
		}
	}
	s.c.Start(s.v1.ep, s.v1.bell, StartOptions{Hold: true})
	synctest.Wait()
	dying.s.c.KillTrunk(CauseTransportError, "test: another trunk of the pair dies")
	synctest.Wait()
	if q := s.c.downs.pending(); !sameIDs(q, []uint32{91}) {
		t.Fatalf("the held trunk's pending DOWNs %v, want [91]", q)
	}
	if dg {
		if ds := rp.read(); len(ds) != 0 {
			t.Fatalf("the held trunk wrote %d datagrams before its response", len(ds))
		}
	} else if fs := sp.received(); len(fs) != 0 {
		t.Fatalf("the held trunk wrote %d frames before its response (first %v)", len(fs), fs[0].Type)
	}
	answer.Store(true)
	s.c.Wake()
	synctest.Wait()
	if q := s.c.downs.pending(); len(q) != 0 {
		t.Fatalf("pending DOWNs %v after the response", q)
	}
	if dg {
		rels, bare := relsWritten(rp.read())
		if bare != 0 || len(rels) < 2 || rels[0].t != wire.TypeOpenAck || rels[1].t != wire.TypeDown || rels[1].cseq != rels[0].cseq+1 {
			t.Fatalf("RELs after the response: %+v (%d bare DOWNs); want REL{OPEN_ACK} first, REL{DOWN(91)} next", rels, bare)
		}
		if got := dgDowns(rels); !sameIDs(got, []uint32{91}) {
			t.Fatalf("DOWNs %v, want [91]", got)
		}
		return
	}
	fs := sp.received()
	if len(fs) == 0 || fs[0].Type != wire.TypeOpenAck || fs[0].Handle != wire.SessionHandle {
		t.Fatalf("first frame %+v, want the OPEN_ACK of handle 1", fs)
	}
	if got := streamDowns(sp); !sameIDs(got, []uint32{91}) {
		t.Fatalf("DOWNs %v, want [91]", got)
	}
}

// deathSched encodes a death SCHED of epoch naming the carriers ids.
func deathSched(epoch uint32, ids ...uint32) []byte {
	s := wire.Sched{Epoch: epoch, Death: 1, N: len(ids)}
	copy(s.IDs[:], ids)
	b := make([]byte, wire.SchedFixedLen+4*len(ids))
	return b[:wire.PutSched(b, &s)]
}

// TestDownPrecedesDeathScheds_PA86 (ordering): on a datagram trunk the
// DOWN of a dead trunk of the pair takes a REL cseq below that of every
// death SCHED its sessions place after the death, so the peer applies the
// trunk's death before any session's new route and needs no SCHED to move
// off the dead trunk (the REL window paces SCHEDs eight at a time). Both
// writer states: between rounds (its carrier control places the DOWN
// first), and inside a round whose later calls place the SCHEDs (a reliable
// session frame goes behind every DOWN queued before it). Premise: the
// window has room for the DOWN and all six SCHEDs.
func TestDownPrecedesDeathScheds_PA86(t *testing.T) {
	t.Run("between rounds", func(t *testing.T) { synctest.Test(t, func(t *testing.T) { downOrderRow(t, false) }) })
	t.Run("inside a round", func(t *testing.T) { synctest.Test(t, func(t *testing.T) { downOrderRow(t, true) }) })
}

func downOrderRow(t *testing.T, inside bool) {
	env := downEnv()
	dying, _ := downDg(t, env, 101, true, mPassiveInst)
	s, p := downDg(t, env, 102, true, mPassiveInst)
	const k = 6 // sessions with a lane on both trunks; one more view holds the round
	var rs relSeq
	var views []*Conn
	var waits []func() (*Established, error)
	for i := range k + 1 {
		v, w := s.openRaw(t, wire.TypeOpen, byte(2+i))
		views, waits = append(views, v), append(waits, w)
	}
	synctest.Wait()
	for _, v := range views {
		p.send(rs.rel(wire.TypeOpenAck, 0, v.Handle(), okAck(wire.TypeOpenAck)))
	}
	for _, w := range waits {
		if _, err := w(); err != nil {
			t.Fatalf("attempt: %v", err)
		}
	}
	mvs := make([]*mView, len(views))
	for i, v := range views {
		mvs[i] = s.attach(v)
	}
	synctest.Wait()
	s.c.mu.Lock()
	last := s.c.dg.rel.next - 1
	s.c.mu.Unlock()
	p.send(rackFrame(last, 0)) // the OPENs are acknowledged: the REL window is free
	synctest.Wait()
	p.read()
	if room := s.c.RelRoom(); room < k+1 {
		t.Fatalf("premise: REL room %d, want ≥ %d", room, k+1)
	}

	release := func() {}
	if inside {
		// Round R−1 is held inside its write while every view is readied, so
		// round R calls them all; the first (handle 2, the lowest: no view
		// was served payload yet) holds round R inside its Fill.
		fio := s.c.dg.io.(*fakeIO)
		hold, inWrite := make(chan struct{}), make(chan struct{})
		var once atomic.Bool
		fio.setOut(func([]byte) error {
			if once.CompareAndSwap(false, true) {
				close(inWrite)
				<-hold
			}
			return nil
		})
		block, entered := make(chan struct{}), make(chan struct{})
		var armed atomic.Bool
		hb := mvs[0].src
		hb.mu.Lock()
		hb.hook = func(*Conn, *Batch) {
			if armed.CompareAndSwap(true, false) {
				close(entered)
				<-block
			}
		}
		hb.mu.Unlock()
		pk := make([]byte, wire.PackLen)
		wire.PutPack(pk, &wire.Pack{})
		hb.addCtl(hFrame{t: wire.TypePack, payload: pk})
		mvs[0].c.Wake()
		<-inWrite
		for _, mv := range mvs {
			mv.c.Wake()
		}
		armed.Store(true)
		close(hold)
		<-entered
		release = func() { close(block) }
	}
	dying.c.KillTrunk(CauseTransportError, "test: the other trunk of the pair dies")
	// The sessions on the dead trunk learn of the death (after its record:
	// the DOWN is already queued) and place their death SCHEDs on their
	// lanes of the surviving trunk.
	for i, mv := range mvs[1:] {
		mv.src.addCtl(hFrame{t: wire.TypeSched, flags: uint8(wire.SchedDeath), payload: deathSched(uint32(2+i), 102)})
		mv.c.Wake()
	}
	release()
	synctest.Wait()
	rels, bare := relsWritten(p.read())
	found, scheds := false, 0
	var down uint32
	for _, r := range rels {
		switch r.t {
		case wire.TypeDown:
			if id, err := wire.ParseDown(r.p); err == nil && id == 101 {
				found, down = true, r.cseq
			}
		case wire.TypeSched:
			scheds++
			if !found || !wire.SeqLess(down, r.cseq) {
				t.Errorf("death SCHED of handle %d at cseq %d: the DOWN (found %v, cseq %d) does not precede it", r.handle, r.cseq, found, down)
			}
		}
	}
	if !found || bare != 0 || scheds != k {
		t.Fatalf("RELs %+v: DOWN(101) found %v, %d bare DOWNs, %d death SCHEDs (want %d)", rels, found, bare, scheds, k)
	}
}

// TestDownQueueBound_PA86 (bound): a trunk's pending DOWNs are
// deduplicated by CarrierID and bounded by downCap = 2 × wire.MaxSchedIDs
// (one trunk per factory and session kind of a Peer's pool); an overflow
// drops the oldest and counts it, the rest keeps its order; the writer
// places them oldest first and only while they fit (a datagram batch's REL
// room), keeping the rest pending in order; a trunk that ended or wrote
// its CLOSE takes none.
func TestDownQueueBound_PA86(t *testing.T) {
	if downCap != 2*wire.MaxSchedIDs {
		t.Fatalf("downCap %d, want 2 × wire.MaxSchedIDs", downCap)
	}
	env := downEnv()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := newConn(env, a, 7, mPassiveInst, 0, "f0", true)
	c.mux = true
	const extra = 5
	for id := uint32(1); id <= downCap+extra; id++ {
		c.queueDown(id)
		c.queueDown(id) // a duplicate: no change
	}
	c.queueDown(downCap + extra) // still pending: no change
	q := &c.downs
	var want []uint32
	for id := uint32(extra + 1); id <= downCap+extra; id++ {
		want = append(want, id)
	}
	if got := q.pending(); !sameIDs(got, want) || q.dropped != extra || q.pend.Load() != downCap {
		t.Fatalf("pending %v (pend %d), dropped %d; want %v and %d dropped", got, q.pend.Load(), q.dropped, want, extra)
	}
	// A datagram batch with REL room 3 takes the oldest three.
	bt := NewBatch(0)
	bt.Reset(time.Now())
	bt.SetDatagram(1200, 3)
	q.place(bt)
	if bt.Len() != 3 || bt.RelRoom() != 0 {
		t.Fatalf("a batch with REL room 3 took %d frames (REL room left %d)", bt.Len(), bt.RelRoom())
	}
	for i := range 3 {
		f := bt.Frame(i)
		id, err := wire.ParseDown(f.Payload)
		if !f.Rel || f.Header.Type != wire.TypeDown || f.Header.Handle != 0 || err != nil || id != want[i] {
			t.Fatalf("frame %d: %+v (REL %v, DOWN %d, %v), want REL{DOWN(%d)}", i, f.Header, f.Rel, id, err, want[i])
		}
	}
	if got := q.pending(); !sameIDs(got, want[3:]) {
		t.Fatalf("pending after the datagram batch %v, want %v", got, want[3:])
	}
	// A stream batch takes the rest, in order.
	bt.Reset(time.Now())
	q.place(bt)
	if bt.Len() != len(want)-3 || q.pend.Load() != 0 || len(q.pending()) != 0 {
		t.Fatalf("a stream batch took %d of %d; %d still pending", bt.Len(), len(want)-3, len(q.pending()))
	}
	for i := range bt.Len() {
		if id, err := wire.ParseDown(bt.Frame(i).Payload); err != nil || id != want[3+i] {
			t.Fatalf("stream frame %d names %d (%v), want %d", i, id, err, want[3+i])
		}
	}
	// Nothing follows our CLOSE, and a dead trunk writes nothing.
	c.closeSent.Store(true)
	c.queueDown(77)
	c.closeSent.Store(false)
	c.KillTrunk(CauseLocalClose, "test: dead")
	c.queueDown(78)
	if got := q.pending(); len(got) != 0 {
		t.Fatalf("a trunk that wrote its CLOSE or ended took DOWNs %v", got)
	}
	<-c.Done()
}

// TestTrunkSetMembership_PA86: a MUX trunk enters its Runtime's trunk set
// when view 1 starts (not before: an unestablished trunk sends no DOWN and
// no DOWN may name it) and leaves at its death; a registration that races
// the death leaves nothing behind; a pair is the peer instance and the
// direction. (A dedicated carrier never enters: TestDownSentForTrunkDeath_PA86.)
func TestTrunkSetMembership_PA86(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := downEnv()
		a, b := net.Pipe()
		s := newMuxSide(t, env, a, true)
		p := startPeer(b, env.Presets.firstFseq())
		t.Cleanup(p.close)
		s.c.trunk.id = 111
		if env.Trunks.lookup(s.c.trunk, 111) != nil {
			t.Fatal("an unstarted trunk is in the set")
		}
		s.start()
		if env.Trunks.lookup(s.c.trunk, 111) != s.c.trunk {
			t.Fatal("a started MUX trunk is not in the set")
		}
		other := &trunk{peer: s.c.trunk.peer, dialer: false} // the same peer, the other direction
		if env.Trunks.lookup(other, 111) != nil {
			t.Fatal("the other direction's lookup found the trunk")
		}
		s.c.KillTrunk(CauseTransportError, "test")
		if env.Trunks.lookup(s.c.trunk, 111) != nil {
			t.Fatal("a dead trunk is still in the set")
		}
		env.Trunks.add(s.c.trunk) // a registration that raced the death
		env.Trunks.mu.Lock()
		n := len(env.Trunks.pairs)
		env.Trunks.mu.Unlock()
		if env.Trunks.lookup(s.c.trunk, 111) != nil || n != 0 {
			t.Fatalf("a registration after the death stayed (%d pairs)", n)
		}
		synctest.Wait()
	})
}
