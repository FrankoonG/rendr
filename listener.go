package rendr

import (
	"context"
	"net"
	"sync"

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
		ln:      ln,
		bridges: engine.NewBridgeTable(),
		accept:  make(chan *engineBackedConn, 16),
		closed:  make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

type tcpListener struct {
	ln net.Listener

	bridges *engine.BridgeTable

	accept    chan *engineBackedConn
	acceptMu  sync.Mutex
	acceptErr error

	closeOnce sync.Once
	closed    chan struct{}
}

func (l *tcpListener) Accept(ctx context.Context) (Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case c, ok := <-l.accept:
		if !ok {
			l.acceptMu.Lock()
			err := l.acceptErr
			l.acceptMu.Unlock()
			if err == nil {
				err = net.ErrClosed
			}
			return nil, err
		}
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
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
			l.acceptMu.Lock()
			l.acceptErr = err
			l.acceptMu.Unlock()
			close(l.accept)
			return
		}
		go l.serveIncoming(c)
	}
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
	if !l.bridges.Put(p.FlowID, e) {
		// Collision: BYE and drop.
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	spec := specFromAddr(pc.RemoteAddr())
	if _, err := e.AttachPath(pc, spec); err != nil {
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
	e, ok := l.bridges.Get(p.BridgeID)
	if !ok {
		// Unknown bridge_id: BYE.
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		return
	}
	spec := specFromAddr(pc.RemoteAddr())
	if _, err := e.AttachPath(pc, spec); err != nil {
		_ = pc.Close()
	}
}

func specFromAddr(addr string) PathSpec {
	return PathSpec{Transport: "tcp", Address: addr}
}

