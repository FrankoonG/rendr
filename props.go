package rendr

// Props describe a carrier factory to the scheduler (plan §3.2). The zero
// value is a factory of its own fate group whose carriers the Peer's
// sessions share (rendr mux).
//
// NewPeer validates the Props of every factory: a FateGroup of at most 64
// bytes; HoLCoupled only with a FateGroup; the factories of one FateGroup
// agree on HoLCoupled. The error names the factory.
type Props struct {
	// FateGroup names factories whose carriers fail together (a shared first
	// hop, relay or transport connection). Bond and race keep at most one
	// member per group; selector failover tries other groups first. "" puts
	// the factory in a group of its own. At most 64 bytes; compared within
	// one Peer only.
	FateGroup string
	// CheapSubflow: opening a carrier of this factory is cheap (a native
	// subflow such as a new stream of an existing connection), so every
	// session dials its own carriers of it. When false (the default) the
	// sessions of one Peer share the live carriers of this factory: a new
	// session or a failover JOIN uses a live carrier instead of dialling,
	// sessions on one carrier share its head-of-line blocking and its fate,
	// and the carrier closes when its last session ends.
	CheapSubflow bool
	// HoLCoupled: the carriers of this factory's FateGroup share one
	// in-order pipe (for example streams of one TCP or TLS connection), so a
	// stall of one stalls all. A scheduling hint: rendr never moves a
	// write-blocked carrier's acknowledgement or scheduling duty onto a
	// coupled carrier while another exists. Requires FateGroup.
	HoLCoupled bool
}

// maxFateGroup bounds Props.FateGroup in bytes (M3-D36).
const maxFateGroup = 64

// validateProps checks the Props of a PeerConfig's factories, named by
// names in the same order (M3-D36): FateGroup at most maxFateGroup bytes,
// HoLCoupled only with a FateGroup, and the factories of one FateGroup
// agreeing on HoLCoupled. The error names the first offending factory.
func validateProps(names []string, props []Props) error {
	panic("unimplemented: M3")
}

// internGroups gives every factory a fate-group index (M3-D36, §A7.1):
// factories with equal non-empty FateGroups share one index from 1 up, a
// factory with an empty FateGroup gets index 0, which the scheduler reads
// as a group of its own (session.DialSpec.Groups), and coupled has bit i
// set when factory i's group is HoLCoupled.
func internGroups(props []Props) (groups [maxFactories]uint8, coupled uint16) {
	panic("unimplemented: M3")
}
