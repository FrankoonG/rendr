package rendr

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	uflow "github.com/FrankoonG/rendr/transport/udpflow"
)

// ListenUDPFlow starts an opaque-UDP rendr listener bound to addr.
// It mirrors ListenTCP / ListenQUIC: inbound flows are demuxed by
// their first ctrl frame (HELLO -> new engine / BRIDGE_TAG ->
// attach path to existing engine), and the engine sees a
// transport.PathConn that hides the UDP demux machinery entirely.
//
// Migration over opaque UDP is implicit at the transport layer: a
// datagram arriving from a fresh 4-tuple but carrying a known
// flow_id updates the corresponding ServerPathConn's RemoteAddr
// without firing any engine-level migration. Engine-driven
// migration (Engine.Migrate / selector / race) layers on top of that
// and remains transport-agnostic.
func ListenUDPFlow(addr string) (Listener, error) {
	ln, err := uflow.Listen(addr)
	if err != nil {
		return nil, err
	}
	l := &udpFlowListener{
		ln:           ln,
		instanceID:   engine.NewInstanceID(),
		bridges:      engine.NewBridgeTable(),
		accept:       make(chan *engineBackedConn, 16),
		acceptPacket: make(chan *enginePacketConn, 16),
		closed:       make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

// ListenUDPFlowPacket is a convenience constructor returning the same
// listener cast to PacketListener. Stream and packet acceptors share
// the same socket; HELLO caps decide which channel each connection
// lands on.
func ListenUDPFlowPacket(addr string) (PacketListener, error) {
	ln, err := ListenUDPFlow(addr)
	if err != nil {
		return nil, err
	}
	return ln.(PacketListener), nil
}

type udpFlowListener struct {
	ln         *uflow.Listener
	instanceID proto.InstanceID

	bridges *engine.BridgeTable

	accept       chan *engineBackedConn
	acceptPacket chan *enginePacketConn
	acceptMu     sync.Mutex
	acceptErr    error

	closeOnce sync.Once
	closed    chan struct{}
}

func (l *udpFlowListener) Accept(ctx context.Context) (Conn, error) {
	select {
	case <-l.closed:
		return nil, listenerAcceptErr(&l.acceptMu, &l.acceptErr)
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case c, ok := <-l.accept:
		if !ok {
			return nil, listenerAcceptErr(&l.acceptMu, &l.acceptErr)
		}
		return c, nil
	case <-l.closed:
		return nil, listenerAcceptErr(&l.acceptMu, &l.acceptErr)
	}
}

// AcceptPacket blocks until a packet-mode HELLO arrives. A peer that
// did not set proto.CapsPacketMode is routed to the stream-mode
// Accept channel instead, not to AcceptPacket.
func (l *udpFlowListener) AcceptPacket(ctx context.Context) (PacketConn, error) {
	select {
	case <-l.closed:
		return nil, listenerAcceptErr(&l.acceptMu, &l.acceptErr)
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case c, ok := <-l.acceptPacket:
		if !ok {
			return nil, listenerAcceptErr(&l.acceptMu, &l.acceptErr)
		}
		return c, nil
	case <-l.closed:
		return nil, listenerAcceptErr(&l.acceptMu, &l.acceptErr)
	}
}

func (l *udpFlowListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		err = l.ln.Close()
		close(l.closed)
	})
	return err
}

func (l *udpFlowListener) Addr() net.Addr      { return l.ln.Addr() }
func (l *udpFlowListener) FlowIDs() [][16]byte { return l.bridges.Snapshot() }

func (l *udpFlowListener) acceptLoop() {
	for {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-l.closed
			cancel()
		}()
		pc, err := l.ln.Accept(ctx)
		cancel()
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
			}
			l.fail(err)
			return
		}
		go l.serveIncoming(pc)
	}
}

func (l *udpFlowListener) fail(err error) {
	l.acceptMu.Lock()
	if l.acceptErr == nil {
		l.acceptErr = err
	}
	l.acceptMu.Unlock()
	_ = l.Close()
}

func (l *udpFlowListener) serveIncoming(pc *uflow.ServerPathConn) {
	hdr, payload, err := engine.ReadFirstFrame(pc)
	if err != nil {
		_ = pc.Close()
		return
	}
	if hdr.Type != proto.FrameCtrl {
		_ = pc.Close()
		return
	}
	switch proto.CtrlCodeFromFlags(hdr.Flags) {
	case proto.CtrlHello:
		l.handleHello(pc, payload)
	case proto.CtrlBridgeTag:
		l.handleBridgeTag(pc, payload)
	default:
		_ = pc.Close()
	}
}

func (l *udpFlowListener) handleHello(pc *uflow.ServerPathConn, payload []byte) {
	p, err := proto.DecodeHello(payload)
	if err != nil {
		_ = pc.Close()
		return
	}

	e := engine.New(engine.SideServer, p.FlowID, engine.Limits{})
	if err := e.AcceptPeerNegotiation(p.Negotiation, p.LocalTXManifest); err != nil {
		_ = pc.Close()
		_ = e.Close()
		return
	}
	if err := e.MirrorPeerGraphForLocal(); err != nil {
		_ = pc.Close()
		_ = e.Close()
		return
	}
	e.SetLocalInstanceID(l.instanceID)
	e.SetPeerKind(engine.PeerRendr)
	e.SetPeerInstanceID(p.InstanceID)
	e.SetPeerCaps(p.Caps)
	packetMode := p.Caps&proto.CapsPacketMode != 0
	if packetMode {
		e.SetPacketMode()
	}
	if !l.bridges.Put(p.FlowID, e) {
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	spec := specWithTargetName(PathSpec{Transport: "udpflow", Address: pc.RemoteAddr()}, helloPathName(p))
	if _, err := e.AttachPath(pc, spec); err != nil {
		l.bridges.Remove(p.FlowID)
		_ = pc.Close()
		_ = e.Close()
		return
	}
	if err := engine.PerformHelloAck(pc, e, l.instanceID, eLocalCaps(e), p.InitialTargetID); err != nil {
		l.bridges.Remove(p.FlowID)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	lAddr := addrFromString(pc.LocalAddr())
	rAddr := addrFromString(pc.RemoteAddr())

	if packetMode {
		bp := newEnginePacketConn(e, ModeSelector, lAddr, rAddr)
		go func(flowID [16]byte) {
			<-bp.e.Closed()
			l.bridges.Remove(flowID)
		}(p.FlowID)
		select {
		case l.acceptPacket <- bp:
		case <-l.closed:
			_ = bp.Close()
		}
		return
	}

	c := &engine.Conn{
		E:     e,
		LAddr: lAddr,
		RAddr: rAddr,
	}
	bc := newEngineBackedConn(e, c, ModeSelector)

	go func(flowID [16]byte) {
		<-bc.e.Closed()
		l.bridges.Remove(flowID)
	}(p.FlowID)

	select {
	case l.accept <- bc:
	case <-l.closed:
		_ = bc.Close()
	}
}

func (l *udpFlowListener) handleBridgeTag(pc *uflow.ServerPathConn, payload []byte) {
	p, err := proto.DecodeBridgeTag(payload)
	if err != nil {
		_ = pc.Close()
		return
	}
	e, ok := l.bridges.Get(p.BridgeID)
	if !ok {
		e, ok = waitBridgeArrival(l.bridges, p.BridgeID, 500*time.Millisecond)
	}
	if !ok {
		_ = engine.PerformBridgeAck(pc, p, l.instanceID, proto.AckRejectUnknown, "unknown flow")
		_ = pc.Close()
		return
	}
	if p.ExpectedPeerInstanceID != (proto.InstanceID{}) && p.ExpectedPeerInstanceID != l.instanceID {
		_ = engine.PerformBridgeAck(pc, p, l.instanceID, proto.AckRejectInstance, "peer instance mismatch")
		_ = pc.Close()
		return
	}
	if err := e.ValidateBridgeBinding(p); err != nil {
		_ = engine.PerformBridgeAck(pc, p, l.instanceID, bridgeValidationAckCode(err), err.Error())
		_ = pc.Close()
		return
	}
	spec := specWithTargetName(PathSpec{Transport: "udpflow", Address: pc.RemoteAddr()}, bridgePathName(e, p))
	if _, err := e.AttachPath(pc, spec); err != nil {
		_ = engine.PerformBridgeAck(pc, p, l.instanceID, proto.AckRejectAttach, err.Error())
		_ = pc.Close()
		return
	}
	_ = engine.PerformBridgeAck(pc, p, l.instanceID, proto.AckOK, "")
}
