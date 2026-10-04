package rendr

import (
	"math"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/session"
)

// The internal packages mirror the public enums numerically (design §2.4,
// §2.5), so conversions are plain type conversions. These declarations fail
// to compile if a value ever diverges: an array length must be a
// non-negative constant, and [0]struct{} only accepts a zero difference.
var (
	_ [0]struct{} = [int(ModeSelector) - int(session.ModeSelector)]struct{}{}
	_ [0]struct{} = [int(ModeBond) - int(session.ModeBond)]struct{}{}
	_ [0]struct{} = [int(RoleDialer) - int(session.RoleDialer)]struct{}{}
	_ [0]struct{} = [int(RolePassive) - int(session.RolePassive)]struct{}{}
	_ [0]struct{} = [int(StatePending) - int(session.StatePending)]struct{}{}
	_ [0]struct{} = [int(StateOpen) - int(session.StateOpen)]struct{}{}
	_ [0]struct{} = [int(StateClosing) - int(session.StateClosing)]struct{}{}
	_ [0]struct{} = [int(StateEnded) - int(session.StateEnded)]struct{}{}
	_ [0]struct{} = [int(CarrierJoining) - int(session.LaneJoining)]struct{}{}
	_ [0]struct{} = [int(CarrierActive) - int(session.LaneActive)]struct{}{}
	_ [0]struct{} = [int(CarrierMember) - int(session.LaneMember)]struct{}{}
	_ [0]struct{} = [int(CarrierRetiring) - int(session.LaneRetiring)]struct{}{}
	_ [0]struct{} = [int(CarrierDead) - int(session.LaneDead)]struct{}{}
	_ [0]struct{} = [int(EventCarrierUp) - int(session.EventCarrierUp)]struct{}{}
	_ [0]struct{} = [int(EventCarrierDown) - int(session.EventCarrierDown)]struct{}{}
	_ [0]struct{} = [int(EventMigration) - int(session.EventMigration)]struct{}{}
	_ [0]struct{} = [int(EventNoPathStart) - int(session.EventNoPathStart)]struct{}{}
	_ [0]struct{} = [int(EventNoPathEnd) - int(session.EventNoPathEnd)]struct{}{}
	_ [0]struct{} = [int(EventSessionEnd) - int(session.EventSessionEnd)]struct{}{}
	_ [0]struct{} = [int(CauseNone) - int(carrier.CauseNone)]struct{}{}
	_ [0]struct{} = [int(CausePingTimeout) - int(carrier.CausePingTimeout)]struct{}{}
	_ [0]struct{} = [int(CauseWriteStall) - int(carrier.CauseWriteStall)]struct{}{}
	_ [0]struct{} = [int(CauseTransportError) - int(carrier.CauseTransportError)]struct{}{}
	_ [0]struct{} = [int(CauseProtocolViolation) - int(carrier.CauseProtocolViolation)]struct{}{}
	_ [0]struct{} = [int(CauseInstanceMismatch) - int(carrier.CauseInstanceMismatch)]struct{}{}
	_ [0]struct{} = [int(CauseGoAway) - int(carrier.CauseGoAway)]struct{}{}
	_ [0]struct{} = [int(CauseLocalClose) - int(carrier.CauseLocalClose)]struct{}{}
	_ [0]struct{} = [int(CauseRetired) - int(carrier.CauseRetired)]struct{}{}
	_ [0]struct{} = [int(CauseQuality) - int(carrier.CauseQuality)]struct{}{}
	_ [0]struct{} = [int(EvidenceUnknown) - int(sched.EvUnknown)]struct{}{}
	_ [0]struct{} = [int(EvidenceFresh) - int(sched.EvFresh)]struct{}{}
	_ [0]struct{} = [int(EvidenceHeld) - int(sched.EvHeld)]struct{}{}
	_ [0]struct{} = [int(EvidenceStale) - int(sched.EvStale)]struct{}{}
)

// eventFrom converts a session event; Seq is assigned by the event queue.
func eventFrom(ev session.Event) Event {
	return Event{
		Time:    ev.Time,
		Kind:    EventKind(ev.Kind),
		Session: SessionID(ev.Session),
		Carrier: CarrierID(ev.Carrier),
		From:    CarrierID(ev.From),
		To:      CarrierID(ev.To),
		Cause:   Cause(ev.Cause),
		Err:     ev.Err,
	}
}

// sessionStatusFrom converts a session snapshot. M1 sessions are all
// stream sessions.
func sessionStatusFrom(st session.Status) SessionStatus {
	out := SessionStatus{
		ID:           SessionID(st.ID),
		Kind:         KindStream,
		Mode:         Mode(st.Mode),
		Role:         Role(st.Role),
		PeerInstance: InstanceID(st.PeerInstance),
		State:        State(st.State),
		Err:          st.Err,
		SchedEpoch:   st.SchedEpoch,
		SchedEchoed:  st.SchedEchoed,
		Migrations: MigrationCounts{
			Death:    st.MigDeath,
			Quality:  st.MigQuality,
			Explicit: st.MigExplicit,
		},
		Rejoins:            st.Rejoins,
		NoPathEpisodes:     st.NoPathEpisodes,
		InNoPath:           st.InNoPath,
		TxBytes:            st.TxBytes,
		AckedBytes:         st.AckedBytes,
		RxBytes:            st.RxBytes,
		DeliveredBytes:     st.DeliveredBytes,
		RetransmittedBytes: st.RetransmittedBytes,
		Window:             st.Window,
		PeerWindow:         st.PeerWindow,
	}
	if len(st.Carriers) > 0 {
		out.Carriers = make([]CarrierStatus, len(st.Carriers))
		for i := range st.Carriers {
			out.Carriers[i] = carrierStatusFrom(&st.Carriers[i])
		}
	}
	return out
}

// carrierStatusFrom converts one lane of a session snapshot. M1 carriers
// are all stream carriers.
func carrierStatusFrom(cs *session.CarrierStatus) CarrierStatus {
	return CarrierStatus{
		ID:          CarrierID(cs.ID),
		Name:        cs.Name,
		Kind:        KindStream,
		Gen:         cs.Gen,
		State:       CarrierState(cs.State),
		SRTT:        cs.Stats.SRTT,
		MinRTT:      cs.Stats.MinRTT,
		Rate:        cs.Stats.Rate,
		Inflight:    clampInt(cs.Stats.Inflight),
		Cap:         clampInt(cs.Stats.Cap),
		TxBytes:     cs.Stats.TxBytes,
		RxBytes:     cs.Stats.RxBytes,
		RetxBytes:   cs.Stats.RetxBytes,
		Frames:      cs.Stats.Frames,
		DeathCause:  Cause(cs.DeathCause),
		DeathDetail: cs.DeathDetail,
	}
}

// peerStatusFrom converts a health snapshot classified at now (Peer.Status,
// design §10.1). names are the Peer's factory names in configuration order.
// A nil snapshot (single-factory Peer, nothing published yet) reports every
// factory Unknown without probing.
func peerStatusFrom(snap *carrier.Snapshot, names []string, now time.Time) PeerStatus {
	out := PeerStatus{Factories: make([]FactoryStatus, len(names))}
	if snap == nil {
		for i, n := range names {
			out.Factories[i] = FactoryStatus{Name: n}
		}
		return out
	}
	out.Probing = snap.Probing
	for i, n := range names {
		var (
			ev     sched.Evidence
			failed bool
			info   carrier.FactoryInfo
		)
		if i < len(snap.Sum) {
			ev = snap.Evidence(i, now)
		}
		if i < len(snap.Failed) {
			failed = snap.Failed[i]
		}
		if i < len(snap.Info) {
			info = snap.Info[i]
		}
		out.Factories[i] = factoryStatusFrom(n, ev, failed, info)
	}
	return out
}

// factoryStatusFrom builds one FactoryStatus from classified evidence. RTT
// is the aggregated value of Fresh and Held evidence (0 for a Held path
// without a value, and for Unknown and Stale).
func factoryStatusFrom(name string, ev sched.Evidence, failed bool, info carrier.FactoryInfo) FactoryStatus {
	fs := FactoryStatus{
		Name:          name,
		Evidence:      Evidence(ev.State),
		Samples:       info.Samples,
		LoadedSamples: info.LoadedSamples,
		Failed:        failed,
		FailReason:    info.FailReason,
		ProbeCarrier:  CarrierID(info.ProbeCarrier),
		Attempts:      info.Attempts,
	}
	if ev.State == sched.EvFresh || ev.State == sched.EvHeld {
		fs.RTT = ev.RTT
	}
	return fs
}

// clampInt converts an int64 counter to int, saturating on 32-bit platforms.
func clampInt(v int64) int {
	if v > math.MaxInt {
		return math.MaxInt
	}
	if v < math.MinInt {
		return math.MinInt
	}
	return int(v)
}
