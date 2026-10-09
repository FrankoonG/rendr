package rendr

import "github.com/FrankoonG/rendr/v2/internal/session"

// The Props half of a Peer (M3 design §A7.1): what NewPeer derives from its
// factories' Props and every dialer session snapshots at Dial.

// peerProps is a Peer's interned Props, immutable after NewPeer.
type peerProps struct {
	groups  [maxFactories]uint8 // fate-group index per factory (internGroups; 0: a group of its own)
	coupled uint16              // bit i: factory i's group is HoLCoupled
	names   []string            // Props.FateGroup per factory (CarrierStatus.FateGroup on the dialer)
	cheap   uint16              // bit i: factory i is CheapSubflow (carrier.Factory.Mux is its complement)
}

// propsOf returns the Props of a PeerConfig carrier: a StreamCarrier or a
// DatagramCarrier, as a value or a non-nil pointer.
func propsOf(c Carrier) Props {
	panic("unimplemented: M3")
}

// dialProps fills the fate-group fields of a dialer session's spec from
// the Peer's interned Props (M3-D36, M3-D37, M3-D39): DialSpec.Groups and
// DialSpec.Coupled.
func (pp *peerProps) dialProps(spec *session.DialSpec) {
	panic("unimplemented: M3")
}

// fateGroup returns the Props.FateGroup of factory i ("" when it has none).
func (pp *peerProps) fateGroup(i int) string {
	panic("unimplemented: M3")
}
