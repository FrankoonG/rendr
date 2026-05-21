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
		ln:      ln,
		bridges: engine.NewBridgeTable(),
		accept:  make(chan *engineBackedConn, 16),
		closed:  make(chan struct{}),
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
		ln:      ln,
		bridges: engine.NewBridgeTable(),
		accept:  make(chan *engineBackedConn, 16),
		closed:  make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

type gvisorListener struct {
	ln *gadapter.Listener

	bridges *engine.BridgeTable

	accept    chan *engineBackedConn
	acceptMu  sync.Mutex
	acceptErr error

	closeOnce sync.Once
	closed    chan struct{}
}

func (l *gvisorListener) Accept(ctx context.Context) (Conn, error) {
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
			l.acceptMu.Lock()
			l.acceptErr = err
			l.acceptMu.Unlock()
			close(l.accept)
			return
		}
		go l.serveIncoming(pc)
	}
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
	if !l.bridges.Put(p.FlowID, e) {
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	spec := PathSpec{Transport: "gvisor", Address: pc.RemoteAddr()}
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
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		return
	}
	spec := PathSpec{Transport: "gvisor", Address: pc.RemoteAddr()}
	if _, err := e.AttachPath(pc, spec); err != nil {
		_ = pc.Close()
	}
}
