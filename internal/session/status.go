package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// statusSnap is the control part of Status (design §4.0, §10.1): an
// immutable value the actor builds and publishes through Session.snap under
// mu in the same critical section as every routing change, so the reported
// active carrier always equals the routed one (L27, L53). Session.Status
// adds the data counters (read under mu) and each lane's carrier.Stats: read
// from its Conn at call time, or, once a dead lane's carrier was joined and
// pruned (laneSnap.conn), its final Stats. A published snapshot is never
// modified.
type statusSnap struct {
	state State
	err   error // the end error once state == StateEnded

	epoch  uint32 // SchedEpoch: dialer: last published; passive: last applied
	echoed uint32 // SchedEchoed: dialer: highest epoch the passive echoed

	migDeath, migQuality, migExplicit uint64 // Migrations (§7.6)
	rejoins, episodes                 uint64 // Rejoins (dialer only), NoPathEpisodes
	inNoPath                          bool   // inside a no-path episode

	// verdict is what the session answers once ended (passive tombstone,
	// AttachOpen and Confirm after the actor exited).
	verdict Verdict

	// refusedGone (packet sessions): the DGRAMs refused by dead carriers no
	// longer in lanes (R1-31; the actor's refusedGone).
	refusedGone uint64

	lanes []laneSnap // live lanes in attach order (and in-flight dial attempts as joining), then the last 8 dead ones
}

// laneSnap is one carrier of a statusSnap (rendered as a CarrierStatus).
type laneSnap struct {
	id    uint32
	name  string // factory name; "" on the passive side
	gen   uint32 // dialer: incarnation number of the factory slot; passive: attach order
	state LaneState
	// conn is the carrier whose Stats Status reads at call time: a live
	// lane's, and a dead lane's until the actor prunes its carrier from the
	// join list after its join (its reader may still account frames it read
	// before the death). nil for a dial attempt in flight and for a dead
	// lane whose carrier was pruned: stats then holds the carrier's final
	// Stats, read after its join, so the dead-lane history keeps a carrier
	// — its Batch, timers and embedder conn — no longer than the join list
	// does (design §0.14 B7).
	conn  *carrier.Conn
	stats carrier.Stats // the final Stats of a joined dead carrier (conn == nil)

	deathCause  carrier.Cause
	deathDetail string
	deathAt     time.Time
}

// publishLocked builds and publishes the control snapshot (§10.1). It runs
// under mu at the end of every critical section that changed control state.
func (a *actor) publishLocked(now time.Time) {
	s := a.s
	ctl := &s.ctl
	sn := &statusSnap{
		state:       ctl.state,
		epoch:       ctl.epoch,
		echoed:      ctl.echoed,
		migDeath:    ctl.migDeath,
		migQuality:  ctl.migQuality,
		migExplicit: ctl.migExplicit,
		rejoins:     ctl.rejoins,
		episodes:    ctl.episodes,
		inNoPath:    ctl.inNoPath,
		refusedGone: a.refusedGone,
	}
	if a.ending {
		sn.err, sn.verdict = a.endErr, a.verdict
	}
	n := len(s.lanes) + len(a.dead)
	if d := a.d; d != nil {
		n += d.running
	}
	sn.lanes = make([]laneSnap, 0, n)
	for _, l := range s.lanes {
		sn.lanes = append(sn.lanes, laneSnap{id: l.id, name: l.c.Name(), gen: l.gen, state: l.state, conn: l.c})
	}
	if d := a.d; d != nil {
		for i := range d.slots {
			sl := &d.slots[i]
			if at := sl.att; at != nil {
				// A dial attempt in flight is a joining carrier (L22): it
				// carries nothing until its JOIN_ACK or OPEN_ACK is handled.
				sn.lanes = append(sn.lanes, laneSnap{id: at.cid, name: sl.f.Name, gen: sl.gen + 1, state: LaneJoining})
			}
		}
	}
	sn.lanes = append(sn.lanes, a.dead...)
	s.snap.Store(sn)
}

// initialSnapLocked publishes the snapshot of a session that is not yet
// visible to any other goroutine (Dial, NewPending).
func (s *Session) initialSnapLocked() {
	sn := &statusSnap{state: s.ctl.state, epoch: s.ctl.epoch}
	for _, l := range s.lanes {
		sn.lanes = append(sn.lanes, laneSnap{id: l.id, name: l.c.Name(), gen: l.gen, state: l.state, conn: l.c})
	}
	s.snap.Store(sn)
}

// status renders the snapshot with the data counters and live carrier
// statistics. A packet session adds its kind, MaxPayload and packet
// counters (M2 design §A7.2): the carriers' refused DGRAMs — placed, then
// refused by the transport as too large — count in DropTooLarge and not in
// Sent, so the send-side identity holds over public fields (R1-31). Its
// byte counters count datagram payload bytes; AckedBytes, Window and
// PeerWindow are 0.
func (s *Session) status() Status {
	sn := s.snap.Load()
	out := Status{ID: s.id, Mode: s.p.Mode, Role: s.p.Role, PeerInstance: s.peer, Kind: s.Kind()}
	var ctr PacketCounters
	if sn != nil {
		out.State, out.Err = sn.state, sn.err
		out.SchedEpoch, out.SchedEchoed = sn.epoch, sn.echoed
		if s.p.Role == RolePassive {
			// The passive echoes exactly the epoch it applied
			// (rendr.SessionStatus: "passive: equals SchedEpoch").
			out.SchedEchoed = sn.epoch
		}
		out.MigDeath, out.MigQuality, out.MigExplicit = sn.migDeath, sn.migQuality, sn.migExplicit
		out.Rejoins, out.NoPathEpisodes, out.InNoPath = sn.rejoins, sn.episodes, sn.inNoPath
	}
	s.mu.Lock()
	st := &s.st
	out.TxBytes = st.txBytes
	out.AckedBytes = st.sBase - s.p.FirstOffset
	out.RxBytes = st.rxBytes
	out.DeliveredBytes = st.delivered
	out.RetransmittedBytes = st.retxBytes
	out.Window = st.lastWin
	out.PeerWindow = int64(st.peerLimit - st.sBase)
	if s.pk != nil {
		ctr = s.pk.ctr
		out.MaxPayload = s.pk.maxPayload
	}
	s.mu.Unlock()
	if sn == nil {
		if s.pk != nil {
			out.Packet = &ctr
		}
		return out
	}
	out.Carriers = make([]CarrierStatus, len(sn.lanes))
	for i, ls := range sn.lanes {
		cs := CarrierStatus{
			ID: ls.id, Name: ls.name, Gen: ls.gen, State: ls.state, Stats: ls.stats,
			DeathCause: ls.deathCause, DeathDetail: ls.deathDetail, DeathAt: ls.deathAt,
		}
		if ls.conn != nil {
			cs.Stats = ls.conn.Stats()
		}
		out.Carriers[i] = cs
	}
	if s.pk != nil {
		refused := sn.refusedGone
		for i := range out.Carriers {
			refused += out.Carriers[i].Stats.Refused
		}
		out.Packet = pktReport(ctr, refused)
	}
	return out
}

// pktReport is the reported PacketCounters (R1-31): Sent = placed −
// refused, DropTooLarge = own + refused, where refused is the DGRAMs the
// session's carriers placed and their transports refused as too large.
// Sent never goes below 0 (a carrier's count may be read after the
// session's).
func pktReport(c PacketCounters, refused uint64) *PacketCounters {
	refused = min(refused, c.Sent)
	c.Sent -= refused
	c.DropTooLarge += refused
	return &c
}
