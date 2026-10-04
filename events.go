package rendr

import "time"

// Event describes a state change of a session (Config.OnEvent). Events are
// emitted only after the change took effect, in Seq order.
type Event struct {
	Seq     uint64    // Runtime-wide, assigned at enqueue; gaps are dropped events
	Time    time.Time // when the change was published (L09)
	Kind    EventKind
	Session SessionID
	Carrier CarrierID // EventCarrierUp/Down: the carrier
	From    CarrierID // EventMigration: the previous carrier (0 for a bond member death with no single successor)
	To      CarrierID // EventMigration: the new carrier
	Cause   Cause     // EventCarrierDown: death cause; EventMigration: migration cause
	Err     error     // EventSessionEnd: the end error
}
