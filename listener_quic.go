package rendr

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	qadapter "github.com/FrankoonG/rendr/transport/quic"
)

// ListenQUIC starts a QUIC-only rendr listener bound to addr.
//
// tlsCfg may be nil during local development; production embedders
// MUST supply a real *tls.Config. Inbound QUIC connections are
// demultiplexed by their first frame (HELLO -> new flow_id /
// engine; BRIDGE_TAG -> attach to existing engine), exactly as
// ListenTCP does.
func ListenQUIC(addr string, tlsCfg *tls.Config) (Listener, error) {
	ln, err := qadapter.Listen(addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	l := &quicListener{
		ln:         ln,
		instanceID: engine.NewInstanceID(),
		bridges:    engine.NewBridgeTable(),
		accept:     make(chan *engineBackedConn, 16),
		closed:     make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

type quicListener struct {
	ln         *qadapter.Listener
	instanceID proto.InstanceID

	bridges *engine.BridgeTable

	accept    chan *engineBackedConn
	acceptMu  sync.Mutex
	acceptErr error

	closeOnce sync.Once
	closed    chan struct{}
}

func (l *quicListener) Accept(ctx context.Context) (Conn, error) {
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

func (l *quicListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		err = l.ln.Close()
		close(l.closed)
	})
	return err
}

func (l *quicListener) Addr() net.Addr { return l.ln.Addr() }

func (l *quicListener) FlowIDs() [][16]byte { return l.bridges.Snapshot() }

func (l *quicListener) acceptLoop() {
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

func (l *quicListener) fail(err error) {
	l.acceptMu.Lock()
	if l.acceptErr == nil {
		l.acceptErr = err
	}
	l.acceptMu.Unlock()
	_ = l.Close()
}

func (l *quicListener) serveIncoming(pc *qadapter.PathConn) {
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

func (l *quicListener) handleHello(pc *qadapter.PathConn, payload []byte) {
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
	if !l.bridges.Put(p.FlowID, e) {
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	spec := specWithTargetName(PathSpec{Transport: "quic", Address: pc.RemoteAddr()}, helloPathName(p))
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

	c := &engine.Conn{
		E:     e,
		LAddr: addrFromString(pc.LocalAddr()),
		RAddr: addrFromString(pc.RemoteAddr()),
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

func (l *quicListener) handleBridgeTag(pc *qadapter.PathConn, payload []byte) {
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
	spec := specWithTargetName(PathSpec{Transport: "quic", Address: pc.RemoteAddr()}, bridgePathName(e, p))
	if _, err := e.AttachPath(pc, spec); err != nil {
		_ = engine.PerformBridgeAck(pc, p, l.instanceID, proto.AckRejectAttach, err.Error())
		_ = pc.Close()
		return
	}
	_ = engine.PerformBridgeAck(pc, p, l.instanceID, proto.AckOK, "")
}
