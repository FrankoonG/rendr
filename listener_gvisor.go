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

func (l *gvisorListener) handleHello(pc transport.PathConn, payload []byte) {
	p, err := proto.DecodeHello(payload)
	if err != nil {
		_ = pc.Close()
		return
	}

	e := engine.New(engine.SideServer, p.FlowID, engine.Limits{})
	e.SetLocalInstanceID(l.instanceID)
	e.SetPeerKind(engine.PeerRendr)
	e.SetPeerInstanceID(p.InstanceID)
	e.SetPeerCaps(p.Caps)
	if !l.bridges.Put(p.FlowID, e) {
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	spec := specWithTargetName(PathSpec{Transport: "gvisor", Address: pc.RemoteAddr()}, p.PathName)
	if _, err := e.AttachPath(pc, spec); err != nil {
		l.bridges.Remove(p.FlowID)
		_ = pc.Close()
		_ = e.Close()
		return
	}
	if err := engine.PerformHelloAck(pc, p.FlowID, l.instanceID, eLocalCaps(e)); err != nil {
		l.bridges.Remove(p.FlowID)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	c := &engine.Conn{
		E:     e,
		LAddr: addrFromString(pc.LocalAddr()),
		RAddr: addrFromString(pc.RemoteAddr()),
	}
	bc := newEngineBackedConn(e, c, ModePrime)

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
		_ = engine.PerformBridgeAck(pc, p.BridgeID, l.instanceID, proto.AckRejectUnknown, "unknown flow")
		_ = pc.Close()
		return
	}
	if p.ExpectedPeerInstanceID != (proto.InstanceID{}) && p.ExpectedPeerInstanceID != l.instanceID {
		_ = engine.PerformBridgeAck(pc, p.BridgeID, l.instanceID, proto.AckRejectInstance, "instance mismatch")
		_ = pc.Close()
		return
	}
	spec := specWithTargetName(PathSpec{Transport: "gvisor", Address: pc.RemoteAddr()}, p.PathName)
	if _, err := e.AttachPath(pc, spec); err != nil {
		_ = engine.PerformBridgeAck(pc, p.BridgeID, l.instanceID, proto.AckRejectAttach, err.Error())
		_ = pc.Close()
		return
	}
	_ = engine.PerformBridgeAck(pc, p.BridgeID, l.instanceID, proto.AckOK, "")
}
