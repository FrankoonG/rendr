package rendr

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport/tcp"
)

// ListenTCP starts a TCP-only rendr listener bound to addr. The
// returned Listener accepts inbound paths, demultiplexes them by
// flow_id, and yields one rendr.Conn per new flow.
//
// M1: TCP is the only transport. M2 expands this to a generic
// Listener with a TransportSet.
func ListenTCP(addr string) (Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &tcpListener{
		ln:         ln,
		instanceID: engine.NewInstanceID(),
		bridges:    engine.NewBridgeTable(),
		accept:     make(chan *engineBackedConn, 16),
		closed:     make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

type tcpListener struct {
	ln         net.Listener
	instanceID proto.InstanceID

	bridges *engine.BridgeTable

	accept    chan *engineBackedConn
	acceptMu  sync.Mutex
	acceptErr error

	closeOnce sync.Once
	closed    chan struct{}
}

func (l *tcpListener) Accept(ctx context.Context) (Conn, error) {
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

func listenerAcceptErr(mu *sync.Mutex, errp *error) error {
	mu.Lock()
	defer mu.Unlock()
	if *errp != nil {
		return *errp
	}
	return net.ErrClosed
}

func (l *tcpListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		err = l.ln.Close()
		close(l.closed)
	})
	return err
}

func (l *tcpListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *tcpListener) FlowIDs() [][16]byte {
	return l.bridges.Snapshot()
}

func (l *tcpListener) acceptLoop() {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
			}
			l.fail(err)
			return
		}
		go l.serveIncoming(c)
	}
}

func (l *tcpListener) fail(err error) {
	l.acceptMu.Lock()
	if l.acceptErr == nil {
		l.acceptErr = err
	}
	l.acceptMu.Unlock()
	_ = l.Close()
}

// serveIncoming handles a single inbound TCP socket: reads the first
// frame, decides whether to create a new engine (HELLO) or attach to
// an existing one (BRIDGE_TAG), and either pushes the new
// rendr.Conn on the accept channel or attaches the path to the
// existing engine.
func (l *tcpListener) serveIncoming(rawC net.Conn) {
	pc := tcp.Wrap(rawC)
	hdr, payload, err := engine.ReadFirstFrame(pc)
	if err != nil {
		_ = pc.Close()
		return
	}
	if hdr.Type != proto.FrameCtrl {
		_ = pc.Close()
		return
	}
	code := proto.CtrlCodeFromFlags(hdr.Flags)
	switch code {
	case proto.CtrlHello:
		l.handleHello(pc, payload)
	case proto.CtrlBridgeTag:
		l.handleBridgeTag(pc, payload)
	default:
		// Anything else as the first frame is malformed.
		_ = pc.Close()
	}
}

func (l *tcpListener) handleHello(pc *tcp.PathConn, payload []byte) {
	p, err := proto.DecodeHello(payload)
	if err != nil {
		_ = pc.Close()
		return
	}

	e := engine.New(engine.SideServer, p.FlowID, engine.Limits{})
	if err := e.AcceptPeerNegotiation(p.Negotiation); err != nil {
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
		// Collision: BYE and drop.
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	spec := specFromAddrName(pc.RemoteAddr(), p.PathName)
	if _, err := e.AttachPath(pc, spec); err != nil {
		l.bridges.Remove(p.FlowID)
		_ = pc.Close()
		_ = e.Close()
		return
	}
	if err := engine.PerformHelloAck(pc, e, l.instanceID, eLocalCaps(e)); err != nil {
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

	// GC bridge entry when the engine dies.
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

func (l *tcpListener) handleBridgeTag(pc *tcp.PathConn, payload []byte) {
	p, err := proto.DecodeBridgeTag(payload)
	if err != nil {
		_ = pc.Close()
		return
	}
	// Brief retry: under high concurrent dial pressure the BRIDGE_TAG
	// goroutine can run before the corresponding HELLO has finished
	// Put-ing the engine into the bridge table. Wait briefly for the
	// flow_id to land before declaring it unknown.
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
		_ = engine.PerformBridgeAck(pc, p, l.instanceID, proto.AckRejectProtoState, err.Error())
		_ = pc.Close()
		return
	}
	spec := specFromAddrName(pc.RemoteAddr(), p.PathName)
	if _, err := e.AttachPath(pc, spec); err != nil {
		_ = engine.PerformBridgeAck(pc, p, l.instanceID, proto.AckRejectAttach, err.Error())
		_ = pc.Close()
		return
	}
	_ = engine.PerformBridgeAck(pc, p, l.instanceID, proto.AckOK, "")
}

// waitBridgeArrival polls the bridge table for flow_id up to total,
// returning the engine once present. Caller handles the not-found
// branch (BYE + close) when total elapses.
func waitBridgeArrival(bridges *engine.BridgeTable, flowID [16]byte, total time.Duration) (*engine.Engine, bool) {
	deadline := time.Now().Add(total)
	for time.Now().Before(deadline) {
		if e, ok := bridges.Get(flowID); ok {
			return e, true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, false
}

func specFromAddr(addr string) PathSpec {
	return PathSpec{Transport: "tcp", Address: addr}
}

func specFromAddrName(addr, name string) PathSpec {
	spec := specFromAddr(addr)
	if name != "" {
		spec.Opts = map[string]string{"name": name}
	}
	return spec
}

func eLocalCaps(e *engine.Engine) uint32 {
	var caps uint32
	if e.Packetized() {
		caps |= proto.CapsPacketMode
	}
	if e.PeerCaps()&proto.CapsL3Identity != 0 {
		caps |= proto.CapsL3Identity
	}
	return caps
}
