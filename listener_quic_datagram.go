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
		bridges:      engine.NewBridgeTable(),
		acceptPacket: make(chan *enginePacketConn, 16),
		closed:       make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

type quicDatagramListener struct {
	ln *qadapter.Listener

	bridges *engine.BridgeTable

	acceptPacket chan *enginePacketConn
	acceptMu     sync.Mutex
	acceptErr    error

	closeOnce sync.Once
	closed    chan struct{}
}

func (l *quicDatagramListener) AcceptPacket(ctx context.Context) (PacketConn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case c, ok := <-l.acceptPacket:
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
			l.acceptMu.Lock()
			l.acceptErr = err
			l.acceptMu.Unlock()
			close(l.acceptPacket)
			return
		}
		go l.serveIncoming(pc)
	}
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
	spec = specWithTargetName(spec, p.PathName)
	if _, err := e.AttachPath(pc, spec); err != nil {
		l.bridges.Remove(p.FlowID)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	lAddr := addrFromString(pc.LocalAddr())
	rAddr := addrFromString(pc.RemoteAddr())
	bp := newEnginePacketConn(e, ModePrime, lAddr, rAddr)

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
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		return
	}
	spec := PathSpec{
		Transport: "quic",
		Address:   pc.RemoteAddr(),
		Opts:      map[string]string{"mode": "datagram"},
	}
	spec = specWithTargetName(spec, p.PathName)
	if _, err := e.AttachPath(pc, spec); err != nil {
		_ = pc.Close()
	}
}
