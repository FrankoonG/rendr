package rendr

import (
	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
)

// The Props half of a Peer (M3 design §A7.1): what NewPeer derives from its
// factories' Props and every dialer session snapshots at Dial.

// peerProps is a Peer's interned Props, immutable after NewPeer.
type peerProps struct {
	groups  [maxFactories]uint8 // fate-group index per factory (internGroups; 0: a group of its own)
	coupled uint16              // bit i: factory i's group is HoLCoupled
	names   []string            // Props.FateGroup per factory (CarrierStatus.FateGroup on the dialer)
	cheap   uint16              // bit i: factory i is CheapSubflow (carrier.Factory.Mux is its complement)
	factory []string            // factory names in configuration order (the session snapshot's lane names)
}

// newPeerProps validates the Props of a PeerConfig's carriers, whose
// factory names (validated and unique) are names in the same order, and
// interns them (M3-D36). The error names the first offending factory.
func newPeerProps(carriers []Carrier, names []string) (peerProps, error) {
	props := make([]Props, len(carriers))
	for i, c := range carriers {
		props[i] = propsOf(c)
	}
	if err := validateProps(names, props); err != nil {
		return peerProps{}, err
	}
	pp := peerProps{names: make([]string, len(props)), factory: names}
	pp.groups, pp.coupled = internGroups(props)
	for i, pr := range props {
		pp.names[i] = pr.FateGroup
		if pr.CheapSubflow {
			pp.cheap |= 1 << i
		}
	}
	return pp, nil
}

// propsOf returns the Props of a PeerConfig carrier: a StreamCarrier or a
// DatagramCarrier, as a value or a non-nil pointer.
func propsOf(c Carrier) Props {
	switch v := c.(type) {
	case StreamCarrier:
		return v.Props
	case *StreamCarrier:
		if v != nil {
			return v.Props
		}
	case DatagramCarrier:
		return v.Props
	case *DatagramCarrier:
		if v != nil {
			return v.Props
		}
	}
	return Props{}
}

// dialProps fills the fate-group fields of a dialer session's spec from
// the Peer's interned Props (M3-D36, M3-D37, M3-D39): DialSpec.Groups and
// DialSpec.Coupled.
func (pp *peerProps) dialProps(spec *session.DialSpec) {
	spec.Groups = pp.groups
	spec.Coupled = pp.coupled
}

// fateGroup returns the Props.FateGroup of factory i ("" when it has none).
func (pp *peerProps) fateGroup(i int) string {
	if i < 0 || i >= len(pp.names) {
		return ""
	}
	return pp.names[i]
}

// muxFactories sets carrier.Factory.Mux on every factory of fs (the Peer's
// snapshot, in configuration order) that is not CheapSubflow (M3-D2): its
// session carriers negotiate rendr mux and go through the Peer's pool.
// Called by NewPeer once the pool exists (WP10).
func (pp *peerProps) muxFactories(fs []carrier.Factory) {
	for i := range fs {
		fs[i].Mux = pp.cheap&(1<<i) == 0
	}
}

// status converts a session snapshot (sessionStatusFrom) and, for a
// dialer session of this Peer (pp non-nil), reports each carrier's
// Props.FateGroup by its factory name (CarrierStatus.FateGroup, M3-D49).
// A nil pp (the passive side) leaves FateGroup empty.
func (pp *peerProps) status(st session.Status) SessionStatus {
	out := sessionStatusFrom(st)
	if pp == nil {
		return out
	}
	for i := range out.Carriers {
		c := &out.Carriers[i]
		for j, n := range pp.factory {
			if n == c.Name {
				c.FateGroup = pp.fateGroup(j)
				break
			}
		}
	}
	return out
}
