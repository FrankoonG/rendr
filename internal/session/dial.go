package session

import (
	"context"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// DialSpec is everything a dialer session needs, snapshotted at Dial (L20).
type DialSpec struct {
	SID        [16]byte
	Params     Params
	Factories  []carrier.Factory        // the Peer's factory snapshot
	Health     *carrier.Health          // the Peer's health layer; nil = inert (no evidence, no marks, no waiting)
	Metadata   []byte                   // copied by Dial
	GoneAway   func(inst [16]byte) bool // instances that sent GOAWAY to this Peer: never OPEN to them
	NoteGoAway func(inst [16]byte)      // record an instance that answered GOING_AWAY or sent GOAWAY
}

// Dial creates a dialer session and runs its opening phase (design §6.6):
// an OPEN race over the ranked factories with JoinStagger and the per-factory
// redial cadence (at most Params.MaxCarriers attempts outstanding), bounded
// by Params.Grace from the call. It returns on the first OPEN_ACK(OK) — the
// session is then open, bound to that carrier's peer instance, with that
// carrier active (selector) or a member (bond); a later OPEN_ACK(OK) is kept
// only if it comes from the bound instance — or on a terminal outcome:
// *RejectError, ErrCapacity, ErrVersion, ErrProtocol, ErrMetadataTooLarge,
// ErrSessionLost, ErrNoPath (wrapping the last carrier error). OPEN_ACK
// CAPACITY with wire.CodeCarriers refuses one carrier of a pending session,
// not the session: that attempt backs off and the race continues. When ctx ends
// first it returns ctx.Err() wrapping the last carrier error within 100 ms.
// After any terminal outcome or cancellation the session withdraws in the
// background (outstanding attempts cancelled with carrier.ErrWithdrawn, so
// Establish sends RST(withdrawn) where an OPEN was written; a late
// OPEN_ACK(OK) gets RST(AbortWithdrawn); every carrier closed once; L49).
// An OPEN_ACK(OK) from an instance other than the bound one also gets
// RST(AbortWithdrawn) (that instance opened a session of its own); a
// selector race loser on the bound instance is retired with CLOSE instead.
// A success that raced the cancellation wins (one CAS decides).
// spec.Health may be nil (inert).
func Dial(ctx context.Context, env *Env, spec DialSpec) (*Session, error) {
	panic("unimplemented: M1b")
}
