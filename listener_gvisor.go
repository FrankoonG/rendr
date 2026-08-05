package rendr

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	gadapter "github.com/FrankoonG/rendr/transport/gvisor"
)

// ListenGVisor starts a gVisor-netstack-only rendr listener. The
// returned address is a process-local registry key, not an OS socket.
func ListenGVisor(addr string) (Listener, error) {
	ln, err := gadapter.Listen(addr)
	if err != nil {
		return nil, err
	}
	l := &gvisorListener{
		ln:         ln,
		instanceID: engine.NewInstanceID(),
		bridges:    engine.NewBridgeTable(),
		accept:     make(chan *engineBackedConn, 16),
		closed:     make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

// ListenGVisorPacket starts a gVisor-netstack rendr listener whose
// virtual link is carried over outer UDP datagrams. The returned
// address is a real OS UDP address and can be used by a remote
// Dialer path with Transport "gvisor".
func ListenGVisorPacket(addr string) (Listener, error) {
	ln, err := gadapter.ListenPacket(addr)
	if err != nil {
		return nil, err
	}
	l := &gvisorListener{
		ln:         ln,
		instanceID: engine.NewInstanceID(),
		bridges:    engine.NewBridgeTable(),
		accept:     make(chan *engineBackedConn, 16),
		closed:     make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

type gvisorListener struct {
	ln         *gadapter.Listener
	instanceID proto.InstanceID

	bridges *engine.BridgeTable

	accept    chan *engineBackedConn
	acceptMu  sync.Mutex
	acceptErr error

	closeOnce sync.Once
	closed    chan struct{}
}

func (l *gvisorListener) Accept(ctx context.Context) (Conn, error) {
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

func (l *gvisorListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		err = l.ln.Close()
		close(l.closed)
	})
	return err
}

func (l *gvisorListener) Addr() net.Addr { return l.ln.Addr() }

func (l *gvisorListener) FlowIDs() [][16]byte { return l.bridges.Snapshot() }

func (l *gvisorListener) acceptLoop() {
	for {
		pc, err := l.ln.Accept(context.Background())
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

func (l *gvisorListener) fail(err error) {
	l.acceptMu.Lock()
	if l.acceptErr == nil {
		l.acceptErr = err
	}
	l.acceptMu.Unlock()
	_ = l.Close()
}

func (l *gvisorListener) serveIncoming(pc transport.PathConn) {
	hdr, payload, err := engine.ReadFirstFrame(pc)
	if err != nil {
		_ = pc.Close()
		return
	}
	code, ok := canonicalFirstControlCode(hdr)
	if !ok {
		_ = pc.Close()
		return
	}
	switch code {
	case proto.CtrlHello:
		l.handleHello(pc, payload)
	case proto.CtrlBridgeTag:
		l.handleBridgeTag(pc, payload)
	default:
		_ = pc.Close()
	}
}

func (l *gvisorListener) handleHello(pc transport.PathConn, payload []byte) {
	p, err := decodeHelloForAdmission(pc, payload)
	if err != nil {
		_ = pc.Close()
		return
	}
	reservation, ok := reserveInitialBridge(l.bridges, p.FlowID, pc)
	if !ok {
		return
	}
	activated := false
	defer func() {
		if !activated {
			l.bridges.Abort(reservation)
		}
	}()

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
	spec := specWithTargetName(PathSpec{Transport: "gvisor", Address: pc.RemoteAddr()}, helloPathName(p))
	pathID, localTargetID, err := attachServerPath(e, pc, spec, p.InitialTargetID)
	if err != nil {
		_ = pc.Close()
		_ = e.Close()
		return
	}
	if err := acknowledgeInitialServerPath(context.Background(), e, pathID, pc, l.instanceID, eLocalCaps(e), localTargetID, p, payload); err != nil {
		_ = pc.Close()
		_ = e.Close()
		return
	}
	if err := l.bridges.Activate(reservation, e); err != nil {
		_ = e.Close()
		return
	}
	activated = true

	c := &engine.Conn{
		E:     e,
		LAddr: addrFromString(pc.LocalAddr()),
		RAddr: addrFromString(pc.RemoteAddr()),
	}
	bc := newEngineBackedConn(e, c, ModeSelector)

	go func() {
		<-bc.e.Closed()
		l.bridges.RemoveActive(reservation, e)
	}()

	select {
	case l.accept <- bc:
	case <-l.closed:
		_ = bc.Close()
	}
}

func (l *gvisorListener) handleBridgeTag(pc transport.PathConn, payload []byte) {
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
		_ = engine.PerformBridgeAck(pc, p, l.instanceID, proto.AckRejectInstance, "instance mismatch")
		_ = pc.Close()
		return
	}
	if err := e.ValidateBridgeBinding(p); err != nil {
		_ = engine.PerformBridgeAck(pc, p, l.instanceID, bridgeValidationAckCode(err), err.Error())
		_ = pc.Close()
		return
	}
	spec := specWithTargetName(PathSpec{Transport: "gvisor", Address: pc.RemoteAddr()}, bridgePathName(e, p))
	pathID, localTargetID, err := attachServerPath(e, pc, spec, p.TargetID)
	if err != nil {
		_ = engine.PerformBridgeAck(pc, p, l.instanceID, proto.AckRejectAttach, err.Error())
		_ = pc.Close()
		return
	}
	_ = acknowledgeServerPath(context.Background(), e, pathID, pc, p, payload, l.instanceID, localTargetID)
}
