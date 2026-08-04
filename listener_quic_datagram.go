package rendr

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	qadapter "github.com/FrankoonG/rendr/transport/quic"
)

// ListenQUICDatagram starts a QUIC listener that accepts incoming
// connections in DATAGRAM mode (RFC 9221). One DATAGRAM == one rendr
// frame; no bidi stream is opened. Pair with Dialer.DialPacket and
// PathSpec.Opts["mode"]="datagram" on the client side.
//
// The server's engine is forced into packet mode regardless of the
// CapsPacketMode bit on HELLO - a DATAGRAM-mode peer cannot honour
// stream-style byte concatenation, so accepting one here implies
// packet-boundary semantics on both ends.
//
// tlsCfg may be nil during local development; production embedders
// MUST supply a real *tls.Config.
func ListenQUICDatagram(addr string, tlsCfg *tls.Config) (PacketListener, error) {
	ln, err := qadapter.Listen(addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	l := &quicDatagramListener{
		ln:           ln,
		instanceID:   engine.NewInstanceID(),
		bridges:      engine.NewBridgeTable(),
		acceptPacket: make(chan *enginePacketConn, 16),
		closed:       make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

type quicDatagramListener struct {
	ln         *qadapter.Listener
	instanceID proto.InstanceID

	bridges *engine.BridgeTable

	acceptPacket chan *enginePacketConn
	acceptMu     sync.Mutex
	acceptErr    error

	closeOnce sync.Once
	closed    chan struct{}
}

func (l *quicDatagramListener) AcceptPacket(ctx context.Context) (PacketConn, error) {
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

func (l *quicDatagramListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		err = l.ln.Close()
		close(l.closed)
	})
	return err
}

func (l *quicDatagramListener) Addr() net.Addr      { return l.ln.Addr() }
func (l *quicDatagramListener) FlowIDs() [][16]byte { return l.bridges.Snapshot() }

func (l *quicDatagramListener) acceptLoop() {
	for {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-l.closed
			cancel()
		}()
		pc, err := l.ln.AcceptDatagram(ctx)
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

func (l *quicDatagramListener) fail(err error) {
	l.acceptMu.Lock()
	if l.acceptErr == nil {
		l.acceptErr = err
	}
	l.acceptMu.Unlock()
	_ = l.Close()
}

func (l *quicDatagramListener) serveIncoming(pc transport.PathConn) {
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

func (l *quicDatagramListener) handleHello(pc transport.PathConn, payload []byte) {
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
	// DATAGRAM-mode peer implies packet boundaries regardless of
	// whether CapsPacketMode was set; force it.
	e.SetPacketMode()
	if !l.bridges.Put(p.FlowID, e) {
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	spec := PathSpec{
		Transport: "quic",
		Address:   pc.RemoteAddr(),
		Opts:      map[string]string{"mode": "datagram"},
	}
	spec = specWithTargetName(spec, helloPathName(p))
	pathID, localTargetID, err := attachServerPath(e, pc, spec, p.InitialTargetID)
	if err != nil {
		l.bridges.Remove(p.FlowID)
		_ = pc.Close()
		_ = e.Close()
		return
	}
	if err := acknowledgeInitialServerPath(e, pathID, pc, l.instanceID, eLocalCaps(e), localTargetID, p.InitialTargetID); err != nil {
		l.bridges.Remove(p.FlowID)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	lAddr := addrFromString(pc.LocalAddr())
	rAddr := addrFromString(pc.RemoteAddr())
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
}

func (l *quicDatagramListener) handleBridgeTag(pc transport.PathConn, payload []byte) {
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
	spec := PathSpec{
		Transport: "quic",
		Address:   pc.RemoteAddr(),
		Opts:      map[string]string{"mode": "datagram"},
	}
	spec = specWithTargetName(spec, bridgePathName(e, p))
	pathID, localTargetID, err := attachServerPath(e, pc, spec, p.TargetID)
	if err != nil {
		_ = engine.PerformBridgeAck(pc, p, l.instanceID, proto.AckRejectAttach, err.Error())
		_ = pc.Close()
		return
	}
	_ = acknowledgeServerPath(e, pathID, pc, p, l.instanceID, localTargetID)
}
