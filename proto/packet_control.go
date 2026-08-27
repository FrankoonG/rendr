package proto

// PacketControlClass states whether a control frame participates in the
// admitted packet-path runtime bound. Handshake-only frames are checked on the
// candidate that carries them; stream-only frames are forbidden in packet
// sessions; graph-dependent frames are sized from the negotiated selector set.
type PacketControlClass uint8

const (
	PacketControlInvalid PacketControlClass = iota
	PacketControlHandshakeOnly
	PacketControlRuntime
	PacketControlGraphDependent
	PacketControlStreamOnly
)

// PacketControlFrameBound is the maximum legal complete rendr frame for one
// control code under a graph with SelectorCount selector nodes.
type PacketControlFrameBound struct {
	Class        PacketControlClass
	MaxFrameSize int
}

type packetControlPayloadBound struct {
	class      PacketControlClass
	maxPayload int
}

var packetControlPayloadBounds = [CtrlCodeLimit]packetControlPayloadBound{
	CtrlHello:                {PacketControlHandshakeOnly, HelloPayloadSize + GraphManifestMaxWireBytes},
	CtrlMigrateNotify:        {PacketControlRuntime, MigrateNotifyPayloadSize},
	CtrlPathQuality:          {PacketControlRuntime, PathQualityPayloadSize},
	CtrlHeartbeat:            {PacketControlRuntime, HeartbeatPayloadSize},
	CtrlBye:                  {PacketControlRuntime, ByePayloadSize},
	CtrlPathProbe:            {PacketControlRuntime, ProbePayloadSize},
	CtrlPathProbeReply:       {PacketControlRuntime, AckPayloadSize},
	CtrlPolicyPrepare:        {PacketControlRuntime, PolicyPrepareHeaderSize + PolicyMaxCauseBytes},
	CtrlHelloAck:             {PacketControlHandshakeOnly, HelloAckPayloadSize + GraphManifestMaxWireBytes},
	CtrlPolicyAck:            {PacketControlRuntime, PolicyAckHeaderSize + PolicyMaxReasonBytes},
	CtrlPolicyCommit:         {PacketControlRuntime, PolicyCommitSize},
	CtrlPathAdmissionCommit:  {PacketControlRuntime, PathAdmissionCommitSize},
	CtrlPathAdmissionAck:     {PacketControlRuntime, PathAdmissionAckMaxSize},
	CtrlPathAdmissionConfirm: {PacketControlRuntime, PathAdmissionConfirmSize},
	CtrlPathRetire:           {PacketControlRuntime, PathRetirementPayloadSize},
	CtrlBridgeTag:            {PacketControlHandshakeOnly, BridgeTagPayloadSize},
	CtrlBridgeAck:            {PacketControlHandshakeOnly, BridgeAckMaxSize},
	CtrlLeafMobilityPrepare:  {PacketControlRuntime, LeafMobilityPeerPlanPrepareSize},
	CtrlLeafMobilityAck:      {PacketControlRuntime, LeafMobilityPeerPlanAckMaxSize},
	CtrlLeafMobilityCommit:   {PacketControlRuntime, LeafMobilityPeerPlanCommitSize},
	CtrlStreamFin:            {PacketControlStreamOnly, 0},
	CtrlSelectorState:        {PacketControlGraphDependent, SelectorStateHeaderSize},
}

// PacketControlFrameBoundFor returns the exact maximum legal complete frame
// for code. false means code is unknown, unclassified, or selectorCount is
// outside the protocol graph bound.
func PacketControlFrameBoundFor(code CtrlCode, selectorCount int) (PacketControlFrameBound, bool) {
	if code <= 0 || code >= CtrlCodeLimit || selectorCount < 0 || selectorCount > GraphManifestMaxNodes {
		return PacketControlFrameBound{}, false
	}
	bound := packetControlPayloadBounds[code]
	if bound.class == PacketControlInvalid {
		return PacketControlFrameBound{}, false
	}
	payload := bound.maxPayload
	if bound.class == PacketControlGraphDependent {
		payload += selectorCount * SelectorStateEntrySize
	}
	return PacketControlFrameBound{Class: bound.class, MaxFrameSize: HeaderSize + payload}, true
}
