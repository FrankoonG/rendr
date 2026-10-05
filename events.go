package rendr

import "time"

// Event describes a state change of a session (Config.OnEvent). Events are
// emitted only after the change took effect, in Seq order.
//
// EventMigration reports a migration counted in SessionStatus.Migrations.
// On the dialer of a selector session, From is the carrier that was active
// and To the one that became active; Cause is CauseQuality for a quality
// switch, else the death cause of the lost carrier, or CauseRetired when it
// ended by a CLOSE instead. The passive of a selector session takes its
// counts from the dialer's scheduling updates and emits their events when
// it applies the update that carries them, at most 4 per update (the counts
// are the record): From is the carrier the previously applied update named
// (initially the passive's first sending carrier), To the one this update
// names, and Cause is CauseQuality, CauseRetired, or CauseNone for a death,
// whose cause the passive does not learn. In a bond session each side
// reports every member that died with unacknowledged data of that side:
// From is the dead member and Cause its death cause; To is 0, or, when no
// other member was carrying data, the member that took the data over.
type Event struct {
	Seq     uint64    // Runtime-wide, assigned at enqueue; gaps are dropped events
	Time    time.Time // when the change was published
	Kind    EventKind
	Session SessionID
	Carrier CarrierID // EventCarrierUp/Down: the carrier
	From    CarrierID // EventMigration: the carrier the data left (see above)
	To      CarrierID // EventMigration: the carrier the data moved to, or 0 (see above)
	Cause   Cause     // EventCarrierDown: the carrier's end cause; EventMigration: the migration cause (see above)
	Err     error     // EventSessionEnd: the end error
}
