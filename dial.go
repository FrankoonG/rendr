package rendr

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Dial opens a stream session over the Peer's stream factories (a Peer's
// datagram factories serve DialPacket only): with two or more factories it
// first waits for the first probe samples — only while probing is
// cold-starting and never longer than Probe.DialWait — then races OPEN over
// the ranked factories with JoinStagger and returns on the first
// OPEN_ACK(OK).
// Errors: *RejectError (ErrRejected), ErrCapacity, ErrVersion,
// ErrProtocol, ErrMetadataTooLarge, ErrSessionLost, ErrNoPath (no OPEN within
// NoPathGrace, wrapping the last carrier error; at once when the Peer has
// no stream factory), ctx.Err() wrapping the last carrier error (returned
// within 100 ms of cancellation; the session then withdraws in the
// background), net.ErrClosed after Peer.Close or Runtime.Close.
//
// ctx bounds only the Dial: cancelling it after Dial returned does not
// affect the session.
func (p *Peer) Dial(ctx context.Context, o DialOptions) (*Conn, error) {
	s, err := p.dial(ctx, o, false)
	if err != nil {
		return nil, err
	}
	c := newConn(p.rt, s)
	c.props = &p.props // CarrierStatus.FateGroup
	return c, nil
}

// dial is Peer.Dial (packet false) and Peer.DialPacket (packet true): the
// entry checks, the MaxSessions placeholder, the Runtime's in-flight Dial
// group and the opening phase (design §6.6; M2 design §A5.14).
func (p *Peer) dial(ctx context.Context, o DialOptions, packet bool) (*session.Session, error) {
	rt := p.rt
	name := "Dial"
	if packet {
		name = "DialPacket"
	}
	switch m := rt.eff.cfg.Handshake.MaxMetadata; {
	case p.isClosed() || rt.closing.Load():
		return nil, net.ErrClosed
	case !packet && p.streams == 0:
		// M2-D46: a stream session never dials a datagram factory.
		return nil, fmt.Errorf("rendr: Dial: no stream carrier factory: %w", ErrNoPath)
	case o.Mode > ModeRace:
		return nil, fmt.Errorf("rendr: %s: unknown %v: %w", name, o.Mode, ErrProtocol)
	case len(o.Metadata) > m:
		return nil, fmt.Errorf("rendr: %s: %d bytes of metadata, limit %d: %w", name, len(o.Metadata), m, ErrMetadataTooLarge)
	case packet && !openCapable(p.factories, len(o.Metadata)):
		// M2-D52: no factory can carry the OPEN with this metadata.
		return nil, fmt.Errorf("rendr: DialPacket: %d bytes of metadata, more than any carrier factory's OPEN can carry: %w", len(o.Metadata), ErrMetadataTooLarge)
	case rt.abandon.Full():
		return nil, fmt.Errorf("%w: %w", ErrCapacity, carrier.ErrAbandonFull)
	}
	sid, err := newSessionID(rand.Reader)
	if err != nil {
		return nil, err
	}
	if !rt.table.placeDialer(sid) {
		return nil, fmt.Errorf("rendr: %s: local MaxSessions %d reached: %w", name, rt.eff.cfg.MaxSessions, ErrCapacity)
	}
	if h := rt.eff.hooks; h != nil && h.DialBegin != nil {
		h.DialBegin()
	}
	if !rt.beginDial() {
		rt.table.ended(dialerKey(sid), nil, session.Verdict{}, time.Now())
		return nil, net.ErrClosed
	}
	reg := &dialReg{rt: rt, sid: sid}
	if packet && p.streams == 0 {
		reg.fit = newOpenFit(len(p.factories))
	}
	s, created, err := p.open(ctx, sid, o, packet, reg)
	if err != nil {
		// The placeholder's MaxSessions unit is free at once; the session's
		// own Ended, if it comes later, finds nothing to release.
		rt.table.ended(dialerKey(sid), nil, session.Verdict{}, time.Now())
		if !created || !reg.handOver() {
			rt.dial.done(nil)
		}
		if rt.closing.Load() && ctx.Err() == nil {
			return nil, net.ErrClosed // the Runtime closed during the Dial
		}
		if reg.fit.tooSmall(len(o.Metadata)) && errors.Is(err, ErrNoPath) {
			// W4 L3-1: every factory's carriers carried less than its MTU
			// promised, too little for this OPEN.
			return nil, fmt.Errorf("rendr: DialPacket: %d bytes of metadata, more than the carriers' OPEN can carry: %w (%v)", len(o.Metadata), ErrMetadataTooLarge, err)
		}
		return nil, err
	}
	// The attach and the closing check run before rt.dial.done: Runtime.Close
	// either finds the session live in the table after setting closing, or
	// this check sees closing and shuts the session down itself.
	rt.table.attach(sid, s) // false: the session already ended; its Conn reports the end error
	if rt.closing.Load() {
		s.Shutdown()
		rt.dial.done(nil)
		return nil, net.ErrClosed
	}
	rt.dial.done(nil)
	return s, nil
}

// open runs the opening phase of session sid (design §6.6): the cold-start
// wait for probe evidence (Health.Use, WaitFirst) and session.Dial, under a
// context that also ends when the Runtime closes. session.Dial holds the
// Peer's health layer itself for the session's lifetime. created reports
// whether session.Dial created a session — then that session calls reg's
// Ended exactly once, also when Dial failed (it withdraws in the
// background). A packet session's datagram factories are wrapped for the
// Dial (wrapDatagram).
func (p *Peer) open(ctx context.Context, sid SessionID, o DialOptions, packet bool, reg *dialReg) (s *session.Session, created bool, err error) {
	rt := p.rt
	dctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stop := context.AfterFunc(rt.ctx, func() { cancel(net.ErrClosed) })
	defer stop()
	if p.health != nil {
		p.health.Use()
		p.health.WaitFirst(dctx)
	}
	env := p.env
	env.Registry = reg
	ec := &entryCtx{Context: dctx}
	spec := p.spec(sid, o, packet)
	if packet {
		spec.Factories = wrapDatagram(spec.Factories, reg.fit, offerFromBudgets(spec.Factories, everyMemberCarries(spec.Params.Mode)))
	}
	s, err = session.Dial(ec, &env, spec)
	// session.Dial's documented contract: it creates no session (and makes
	// no Registry call) when ctx is done at its entry check — its first Err
	// call — or when spec has no eligible factory (never here: NewPeer
	// requires a factory, and dial refuses a stream session without a
	// stream factory). TestSessionDialEntryContract pins both, so that a
	// change on the session side fails visibly instead of leaving a Dial
	// membership that no Registry.Ended ever releases.
	return s, ec.live.Load() && anyEligible(len(spec.Factories), spec.Eligible), err
}

// spec is the frozen DialSpec of session sid (L20): the Peer's factory
// snapshot and the per-Dial Params (design §10.4 step 4). A stream session
// may dial the stream factories only (M2-D46); a packet session every
// factory, with its MaxPayload offer (M2-D49).
func (p *Peer) spec(sid SessionID, o DialOptions, packet bool) session.DialSpec {
	params := p.rt.eff.dialerParams(o.Mode, o.NoPathGrace)
	eligible := p.streams
	if packet {
		params = p.rt.eff.packetParams(params, packetOffer(p.factories, everyMemberCarries(params.Mode), p.rt.eff.cfg.Packet.MaxPayload))
		eligible = 0 // every factory
	} else if eligible == allFactories(len(p.factories)) {
		eligible = 0 // every factory, as for every M1 session
	}
	spec := session.DialSpec{
		SID:        sid,
		Params:     params,
		Factories:  p.factories,
		Health:     p.health,
		Metadata:   o.Metadata,
		GoneAway:   p.goneAway,
		NoteGoAway: p.noteGoAway,
		Eligible:   eligible,
	}
	p.props.dialProps(&spec) // fate groups and HoLCoupled (M3-D36)
	return spec
}

// allFactories is the DialSpec.Eligible mask of n factories.
func allFactories(n int) uint16 { return uint16(uint32(1)<<n - 1) }

// anyEligible reports whether a DialSpec with n factories and the Eligible
// mask e may dial any of them (0: all).
func anyEligible(n int, e uint16) bool { return n > 0 && (e == 0 || e&allFactories(n) != 0) }

// openOverhead is the part of a datagram carrier's first datagram that is
// not OPEN metadata: the PREFACE, the REL frame and its inner header, and
// the fixed OPEN payload — 99 bytes (M2-D52, plan:358).
const openOverhead = wire.PrefaceLen + wire.FrameOverhead + wire.RelHeadLen + wire.OpenFixedLen

// openCapable reports whether some factory can carry a packet session's
// OPEN with meta bytes of metadata (M2-D52): any stream factory, or a
// datagram factory whose frame budget holds the whole first datagram.
func openCapable(fs []carrier.Factory, meta int) bool {
	for i := range fs {
		if fs[i].Kind != wire.KindDatagram || openOverhead+meta <= fs[i].MTU {
			return true
		}
	}
	return false
}

// openFit records, for one packet Dial on a Peer without a stream
// factory, the frame budget of the latest carrier each datagram factory
// returned (W4 L3-1): a carrier/udp socket clamped at Dial to its interface
// MTU carries less than its factory MTU — the budget openCapable checked —,
// and an OPEN that does not fit it fails its attempt. When every datagram
// factory returned such a carrier too small for the OPEN, a Dial that ends
// with ErrNoPath ends with ErrMetadataTooLarge instead. A factory that
// never returned a carrier proves nothing: the Dial then keeps ErrNoPath.
type openFit struct {
	budget []atomic.Int32 // per factory: 0 unknown, else min(MTU, transport limit)
}

func newOpenFit(n int) *openFit { return &openFit{budget: make([]atomic.Int32, n)} }

// wrapDatagram returns, for one packet Dial, a copy of fs whose datagram
// factories' DialPacket first marks the attempt's MaxPayload offer as the
// datagram budgets' when fromBudgets (carrier.MarkBudgetOffer: the OPEN's
// pmtu then follows a lower carrier budget, W4 L3-1), and records in fit,
// when not nil, the budget of every rendr-owned UDP carrier it returns (an
// embedder conn's budget is its factory MTU, which openCapable already
// checked). It returns fs itself when there is nothing to do; the Peer's
// snapshot is never changed.
func wrapDatagram(fs []carrier.Factory, fit *openFit, fromBudgets bool) []carrier.Factory {
	if fit == nil && !fromBudgets {
		return fs
	}
	out := make([]carrier.Factory, len(fs))
	copy(out, fs)
	for i := range out {
		dial, mtu := out[i].DialPacket, out[i].MTU
		if out[i].Kind != wire.KindDatagram || dial == nil {
			continue
		}
		var b *atomic.Int32
		if fit != nil {
			b = &fit.budget[i]
		}
		out[i].DialPacket = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			if fromBudgets {
				carrier.MarkBudgetOffer(ctx)
			}
			pc, a, err := dial(ctx)
			if o, ok := pc.(*carrier.OwnedUDP); ok && o != nil && err == nil && b != nil {
				b.Store(int32(min(o.Limit(), mtu)))
			}
			return pc, a, err
		}
	}
	return out
}

// tooSmall reports whether every factory recorded a carrier budget too
// small for an OPEN with meta bytes of metadata (false for a nil f).
func (f *openFit) tooSmall(meta int) bool {
	if f == nil {
		return false
	}
	for i := range f.budget {
		if b := int(f.budget[i].Load()); b == 0 || openOverhead+meta <= b {
			return false
		}
	}
	return len(f.budget) > 0
}

// everyMemberCarries reports whether every member of a session in mode m
// carries data — bond and race (M3-D32) — so that its packet MaxPayload
// offer follows the bond rule of offerFromBudgets. Peer.spec (the offer)
// and Peer.open (whether a datagram attempt lowers the OPEN's pmtu to its
// carrier's budget) both take it from here, so the two cannot disagree.
func everyMemberCarries(m session.Mode) bool { return m != session.ModeSelector }

// packetOffer is a packet session's MaxPayload offer (M2-D49, M2 design
// §A5.4): the smallest datagram payload budget (MTU − 25) over the Peer's
// datagram factories when the offer comes from them (offerFromBudgets);
// else Packet.MaxPayload; never more than Packet.MaxPayload (maxPayload).
func packetOffer(fs []carrier.Factory, bond bool, maxPayload int) int {
	if !offerFromBudgets(fs, bond) {
		return maxPayload
	}
	dg := maxPayload
	for i := range fs {
		if fs[i].Kind == wire.KindDatagram {
			dg = min(dg, fs[i].MTU-wire.DgramOverhead)
		}
	}
	return dg
}

// offerFromBudgets reports whether a packet session's MaxPayload offer
// comes from the datagram factories' budgets (M2-D49): a selector session
// on a Peer with a datagram factory, or a bond or race session (bond true:
// every member carries data) without a stream factory to carry larger
// datagrams.
func offerFromBudgets(fs []carrier.Factory, bond bool) bool {
	hasDgram, hasStream := false, false
	for i := range fs {
		if fs[i].Kind == wire.KindDatagram {
			hasDgram = true
		} else {
			hasStream = true
		}
	}
	return hasDgram && (!bond || !hasStream)
}

// beginDial counts one more Dial inside session.Dial unless the Runtime is
// closing (then Close no longer waits for new members).
func (rt *Runtime) beginDial() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closing.Load() {
		return false
	}
	rt.dial.add()
	return true
}

// entryCtx is the context Peer.Dial hands to session.Dial. session.Dial
// creates a session — which then calls Registry.Ended exactly once, also
// when Dial fails — unless ctx was already done at its entry check, its
// first call of Err (its contract: no session and no Registry call then).
// entryCtx records that first result, so that a failed Dial knows whether
// a session withdraws in the background that Runtime.Close must join.
type entryCtx struct {
	context.Context
	once sync.Once
	live atomic.Bool // the first Err call returned nil
}

func (c *entryCtx) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { c.live.Store(err == nil) })
	return err
}

// dialReg is the session.Registry of one dialer session (design §6.6): it
// keeps the session's table entry (the MaxSessions unit, the Lingering
// count) and records the session for Runtime.Close until its Done closes.
// When the Dial failed after session.Dial had created the session, that
// session withdraws in the background and reports Ended later: the Dial
// then stays a member of the Runtime's in-flight Dial group until that
// Ended (handOver), so Runtime.Close joins the withdrawing session too.
type dialReg struct {
	rt  *Runtime
	sid SessionID
	fit *openFit // a packet Dial without stream factories: the carriers' budgets (W4 L3-1)

	mu    sync.Mutex
	ended bool // Ended ran
	owed  bool // the failed Dial left its group membership to Ended
}

var _ session.Registry = (*dialReg)(nil)

// Opened is a passive-side transition: Peer.Dial attaches a dialer session
// to its table placeholder when Dial returns.
func (*dialReg) Opened(*session.Session) {}

// Orphaned counts only passive sessions (SessionCounts.Orphaned).
func (*dialReg) Orphaned(*session.Session, bool) {}

// Lingering moves the session into (or out of) the Lingering count.
func (r *dialReg) Lingering(s *session.Session, on bool) {
	r.rt.table.setLingering(dialerKey(r.sid), s, on)
}

// Ended records the session for Runtime.Close, then removes its table entry
// (releasing its MaxSessions unit unless Peer.Dial's failure path already
// did) and, for a failed Dial that handed its membership over, ends it.
func (r *dialReg) Ended(s *session.Session, _ session.Verdict) {
	rt := r.rt
	rt.noteEnded(s)
	rt.table.ended(dialerKey(r.sid), s, session.Verdict{}, time.Now())
	r.mu.Lock()
	r.ended = true
	owed := r.owed
	r.mu.Unlock()
	if owed {
		rt.dial.done(nil)
	}
}

// handOver leaves the failed Dial's membership of rt.dial to Ended. It
// returns false when Ended already ran: the caller ends the membership.
func (r *dialReg) handOver() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return false
	}
	r.owed = true
	return true
}
