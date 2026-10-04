package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// statusSnap is the control part of Status (design §4.0, §10.1): an
// immutable value the actor builds and publishes through Session.snap under
// mu in the same critical section as every routing change, so the reported
// active carrier always equals the routed one (L27, L53). Session.Status
// adds the data counters (read under mu) and each lane's live carrier.Stats
// (read from its Conn at call time). A published snapshot is never modified.
type statusSnap struct {
	state State
	err   error // the end error once state == StateEnded

	epoch  uint32 // SchedEpoch: dialer: last published; passive: last applied
	echoed uint32 // SchedEchoed: dialer: highest epoch the passive echoed

	migDeath, migQuality, migExplicit uint64 // Migrations (§7.6)
	rejoins, episodes                 uint64 // Rejoins (dialer only), NoPathEpisodes
	inNoPath                          bool   // inside a no-path episode

	lanes []laneSnap // live lanes in attach order, then the last 8 dead ones
}

// laneSnap is one carrier of a statusSnap (rendered as a CarrierStatus).
type laneSnap struct {
	id    uint32
	name  string // factory name; "" on the passive side
	gen   uint32 // dialer: incarnation number of the factory slot; passive: attach order
	state LaneState
	conn  *carrier.Conn // live Stats are read from it at Status time

	deathCause  carrier.Cause
	deathDetail string
	deathAt     time.Time
}
