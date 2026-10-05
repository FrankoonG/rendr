package carrier

import (
	"context"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// DialInfo describes the carrier a factory call is for (M2-D55; regress
// R-1). Establish attaches it to the context of every factory call it makes
// (Dial, DialEarly, DialPacket) from its own arguments, so no signature
// changes: the CarrierID it was given, the factory's kind, whether the first
// frame is a PING (a probe carrier of the Peer health layer) and, for an
// OPEN or JOIN, the session ID (payload bytes 0–15).
type DialInfo struct {
	Carrier uint32
	Kind    wire.CarrierKind
	Probe   bool
	Session [16]byte
}

// dialInfoKey is the context key of a DialInfo.
type dialInfoKey struct{}

// withDialInfo returns ctx carrying d.
func withDialInfo(ctx context.Context, d DialInfo) context.Context {
	return context.WithValue(ctx, dialInfoKey{}, d)
}

// DialInfoFrom returns the DialInfo of a factory call's context and true, or
// false for any other context. rendr.CarrierDialInfo exposes it.
func DialInfoFrom(ctx context.Context) (DialInfo, bool) {
	d, ok := ctx.Value(dialInfoKey{}).(DialInfo)
	return d, ok
}
