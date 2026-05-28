package rendr

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	qadapter "github.com/FrankoonG/rendr/transport/quic"
	"github.com/FrankoonG/rendr/transport/tcp"
)

// ListenSpec describes one stream transport socket accepted by Listen.
//
// Supported transports are currently "tcp" and "quic". All specs in
// one Listen call share a single server-side bridge table, so a flow
// that starts on one transport can attach additional paths over the
// other transports.
type ListenSpec struct {
	Transport string
	Address   string
	TLSConfig *tls.Config
}

// MultiListener is a stream Listener backed by multiple transport
// sockets that share one bridge table.
type MultiListener struct {
	bridges *engine.BridgeTable

	accept    chan *engineBackedConn
	acceptMu  sync.Mutex
	acceptErr error

	addrs   []net.Addr
	closers []func() error

	closeOnce sync.Once
	failOnce  sync.Once
	closed    chan struct{}
}

// Listen starts a multi-transport stream listener. It is the generic
// counterpart to ListenTCP and ListenQUIC for embedders that want a
// single rendr server endpoint with TCP and QUIC paths attached to
// the same flow_id bridge table.
func Listen(specs ...ListenSpec) (*MultiListener, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("rendr: Listen requires at least one ListenSpec")
	}
	l := &MultiListener{
		bridges: engine.NewBridgeTable(),
		accept:  make(chan *engineBackedConn, 16),
		closed:  make(chan struct{}),
	}
	for _, spec := range specs {
		if err := l.start(spec); err != nil {
			_ = l.Close()
			return nil, err
		}
	}
	return l, nil
}

func (l *MultiListener) start(spec ListenSpec) error {
	switch spec.Transport {
	case "tcp":
		ln, err := net.Listen("tcp", spec.Address)
		if err != nil {
			return fmt.Errorf("rendr: listen tcp %s: %w", spec.Address, err)
		}
		l.addrs = append(l.addrs, ln.Addr())
		l.closers = append(l.closers, ln.Close)
		go l.acceptTCP(ln)
		return nil
	case "quic":
		ln, err := qadapter.Listen(spec.Address, spec.TLSConfig)
		if err != nil {
			return fmt.Errorf("rendr: listen quic %s: %w", spec.Address, err)
		}
		l.addrs = append(l.addrs, ln.Addr())
		l.closers = append(l.closers, ln.Close)
		go l.acceptQUIC(ln)
		return nil
	default:
		return fmt.Errorf("rendr: unsupported Listen transport %q", spec.Transport)
	}
}

func (l *MultiListener) Accept(ctx context.Context) (Conn, error) {
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

func (l *MultiListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)
		for _, closeFn := range l.closers {
			if e := closeFn(); err == nil && e != nil {
				err = e
			}
		}
	})
	return err
}

// Addr returns the first bound address for compatibility with
// Listener. Use Addrs when a caller needs every bound transport.
func (l *MultiListener) Addr() net.Addr {
	if len(l.addrs) == 0 {
		return nil
	}
	return l.addrs[0]
}

// Addrs returns the bound addresses in the same order as the
// ListenSpecs supplied to Listen.
func (l *MultiListener) Addrs() []net.Addr {
	return append([]net.Addr(nil), l.addrs...)
}

func (l *MultiListener) FlowIDs() [][16]byte { return l.bridges.Snapshot() }

func (l *MultiListener) acceptTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
			}
			l.fail(err)
			return
		}
		go l.serveIncoming(tcp.Wrap(c), "tcp")
	}
}

func (l *MultiListener) acceptQUIC(ln *qadapter.Listener) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-l.closed
		cancel()
	}()
	for {
		pc, err := ln.Accept(ctx)
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
			}
			l.fail(err)
			return
		}
		go l.serveIncoming(pc, "quic")
	}
}

func (l *MultiListener) fail(err error) {
	l.failOnce.Do(func() {
		l.acceptMu.Lock()
		l.acceptErr = err
		l.acceptMu.Unlock()
		_ = l.Close()
	})
}

func (l *MultiListener) serveIncoming(pc transport.PathConn, transportName string) {
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
		l.handleHello(pc, transportName, payload)
	case proto.CtrlBridgeTag:
		l.handleBridgeTag(pc, transportName, payload)
	default:
		_ = pc.Close()
	}
}

func (l *MultiListener) handleHello(pc transport.PathConn, transportName string, payload []byte) {
	p, err := proto.DecodeHello(payload)
	if err != nil {
		_ = pc.Close()
		return
	}

	e := engine.New(engine.SideServer, p.FlowID, engine.Limits{})
	e.SetPeerCaps(p.Caps)
	if !l.bridges.Put(p.FlowID, e) {
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
		_ = pc.Close()
		_ = e.Close()
		return
	}

	spec := specWithTargetName(PathSpec{Transport: transportName, Address: pc.RemoteAddr()}, p.PathName)
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

func (l *MultiListener) handleBridgeTag(pc transport.PathConn, transportName string, payload []byte) {
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
	spec := specWithTargetName(PathSpec{Transport: transportName, Address: pc.RemoteAddr()}, p.PathName)
	if _, err := e.AttachPath(pc, spec); err != nil {
		_ = pc.Close()
	}
}
