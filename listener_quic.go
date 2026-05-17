package rendr

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

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
		ln:      ln,
		bridges: engine.NewBridgeTable(),
		accept:  make(chan *engineBackedConn, 16),
		closed:  make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

type quicListener struct {
	ln *qadapter.Listener

	bridges *engine.BridgeTable

	accept    chan *engineBackedConn
	acceptMu  sync.Mutex
	acceptErr error

	closeOnce sync.Once
	closed    chan struct{}
}

func (l *quicListener) Accept(ctx context.Context) (Conn, error) {
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
			l.acceptMu.Lock()
			l.acceptErr = err
			l.acceptMu.Unlock()
			close(l.accept)
			return
		}
		go l.serveIncoming(pc)
	}
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
	if !l.bridges.Put(p.FlowID, e) {
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	spec := PathSpec{Transport: "quic", Address: pc.RemoteAddr()}
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

func (l *quicListener) handleBridgeTag(pc *qadapter.PathConn, payload []byte) {
	p, err := proto.DecodeBridgeTag(payload)
	if err != nil {
		_ = pc.Close()
		return
	}
	e, ok := l.bridges.Get(p.BridgeID)
	if !ok {
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		return
	}
	spec := PathSpec{Transport: "quic", Address: pc.RemoteAddr()}
	if _, err := e.AttachPath(pc, spec); err != nil {
		_ = pc.Close()
	}
}
