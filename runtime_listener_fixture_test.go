package rendr

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
	gadapter "github.com/FrankoonG/rendr/transport/gvisor"
	qadapter "github.com/FrankoonG/rendr/transport/quic"
	tadapter "github.com/FrankoonG/rendr/transport/tcp"
)

type runtimeFixtureSourceKind uint8

const (
	runtimeFixtureRawTCP runtimeFixtureSourceKind = iota
	runtimeFixtureRawUDP
	runtimeFixtureQUICStream
	runtimeFixtureQUICDatagram
	runtimeFixtureGVisor
	runtimeFixtureGVisorPacket
)

type runtimeFixtureSource struct {
	name      string
	kind      runtimeFixtureSourceKind
	address   string
	tlsConfig *tls.Config
}

func runtimeTCPSource(name, address string) runtimeFixtureSource {
	return runtimeFixtureSource{name: name, kind: runtimeFixtureRawTCP, address: address}
}

func runtimeUDPSource(name, address string) runtimeFixtureSource {
	return runtimeFixtureSource{name: name, kind: runtimeFixtureRawUDP, address: address}
}

func runtimeQUICSource(name, address string, tlsConfig *tls.Config) runtimeFixtureSource {
	return runtimeFixtureSource{name: name, kind: runtimeFixtureQUICStream, address: address, tlsConfig: tlsConfig}
}

func runtimeQUICDatagramSource(name, address string, tlsConfig *tls.Config) runtimeFixtureSource {
	return runtimeFixtureSource{name: name, kind: runtimeFixtureQUICDatagram, address: address, tlsConfig: tlsConfig}
}

func runtimeGVisorSource(name, address string) runtimeFixtureSource {
	return runtimeFixtureSource{name: name, kind: runtimeFixtureGVisor, address: address}
}

func runtimeGVisorPacketSource(name, address string) runtimeFixtureSource {
	return runtimeFixtureSource{name: name, kind: runtimeFixtureGVisorPacket, address: address}
}

func bindOptionalFramedFactory(tb testing.TB, dialer *sessionDialer, name string) {
	tb.Helper()
	var (
		carrier CarrierFamily
		factory transport.PathFactory
	)
	switch name {
	case "quic":
		carrier, factory = CarrierUDP, qadapter.New()
	case "gvisor":
		carrier, factory = CarrierUnknown, gadapter.New()
	default:
		tb.Fatalf("unknown optional framed factory %q", name)
	}
	if err := dialer.AddFramedPathFactory(name, carrier, factory); err != nil {
		tb.Fatalf("bind optional framed factory %q: %v", name, err)
	}
}

type runtimeListenerFixture struct {
	listener    *SessionListener
	sourceAddrs map[string]net.Addr
	streams     map[string]*runtimeTrackedStreamListener
	framed      map[string]*runtimeTrackedPathListener
}

func listenRuntimeTCP(address string) (*runtimeListenerFixture, error) {
	return listenRuntimeSources(runtimeTCPSource("tcp", address))
}

func listenRuntimeUDP(address string) (*runtimeListenerFixture, error) {
	return listenRuntimeSources(runtimeUDPSource("udpflow", address))
}

func listenRuntimeQUIC(address string, tlsConfig *tls.Config) (*runtimeListenerFixture, error) {
	return listenRuntimeSources(runtimeQUICSource("quic", address, tlsConfig))
}

func listenRuntimeQUICDatagram(address string, tlsConfig *tls.Config) (*runtimeListenerFixture, error) {
	return listenRuntimeSources(runtimeQUICDatagramSource("quic", address, tlsConfig))
}

func listenRuntimeGVisor(address string) (*runtimeListenerFixture, error) {
	return listenRuntimeSources(runtimeGVisorSource("gvisor", address))
}

func listenRuntimeGVisorPacket(address string) (*runtimeListenerFixture, error) {
	return listenRuntimeSources(runtimeGVisorPacketSource("gvisor", address))
}

func listenRuntimeSources(sources ...runtimeFixtureSource) (*runtimeListenerFixture, error) {
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		return nil, err
	}

	config := ListenConfig{}
	sourceAddrs := make(map[string]net.Addr, len(sources))
	streams := make(map[string]*runtimeTrackedStreamListener)
	framedPaths := make(map[string]*runtimeTrackedPathListener)
	closers := make([]func() error, 0, len(sources))
	closeSources := func() {
		for _, closeSource := range closers {
			_ = closeSource()
		}
	}

	for _, source := range sources {
		var sourceAddr net.Addr
		switch source.kind {
		case runtimeFixtureRawTCP:
			raw, listenErr := net.Listen("tcp", source.address)
			if listenErr != nil {
				closeSources()
				return nil, fmt.Errorf("test runtime source %q: %w", source.name, listenErr)
			}
			tracked := &runtimeTrackedStreamListener{Listener: raw}
			config.Streams = append(config.Streams, StreamSource{
				Name: source.name, Carrier: CarrierTCP, Listener: tracked,
			})
			sourceAddr = raw.Addr()
			streams[source.name] = tracked
			closers = append(closers, raw.Close)
		case runtimeFixtureRawUDP:
			raw, listenErr := net.ListenPacket("udp", source.address)
			if listenErr != nil {
				closeSources()
				return nil, fmt.Errorf("test runtime source %q: %w", source.name, listenErr)
			}
			config.Packets = append(config.Packets, PacketSource{
				Name: source.name, Carrier: CarrierUDP, Conn: raw,
			})
			sourceAddr = raw.LocalAddr()
			closers = append(closers, raw.Close)
		case runtimeFixtureQUICStream:
			framed, listenErr := qadapter.Listen(source.address, source.tlsConfig)
			if listenErr != nil {
				closeSources()
				return nil, fmt.Errorf("test runtime source %q: %w", source.name, listenErr)
			}
			tracked := &runtimeTrackedPathListener{PathListener: framed}
			config.Framed = append(config.Framed, FramedSource{
				Name: source.name, Carrier: CarrierUDP, Listener: tracked,
			})
			sourceAddr = framed.Addr()
			framedPaths[source.name] = tracked
			closers = append(closers, framed.Close)
		case runtimeFixtureQUICDatagram:
			framed, listenErr := qadapter.ListenDatagram(source.address, source.tlsConfig)
			if listenErr != nil {
				closeSources()
				return nil, fmt.Errorf("test runtime source %q: %w", source.name, listenErr)
			}
			tracked := &runtimeTrackedPathListener{PathListener: framed}
			config.Framed = append(config.Framed, FramedSource{
				Name: source.name, Carrier: CarrierUDP, Listener: tracked,
			})
			sourceAddr = framed.Addr()
			framedPaths[source.name] = tracked
			closers = append(closers, framed.Close)
		case runtimeFixtureGVisor:
			framed, listenErr := gadapter.NewDomain().Listen(source.address)
			if listenErr != nil {
				closeSources()
				return nil, fmt.Errorf("test runtime source %q: %w", source.name, listenErr)
			}
			tracked := &runtimeTrackedPathListener{PathListener: framed}
			config.Framed = append(config.Framed, FramedSource{
				Name: source.name, Carrier: CarrierUnknown, Listener: tracked,
			})
			sourceAddr = framed.Addr()
			framedPaths[source.name] = tracked
			closers = append(closers, framed.Close)
		case runtimeFixtureGVisorPacket:
			framed, listenErr := gadapter.ListenPacket(source.address)
			if listenErr != nil {
				closeSources()
				return nil, fmt.Errorf("test runtime source %q: %w", source.name, listenErr)
			}
			tracked := &runtimeTrackedPathListener{PathListener: framed}
			config.Framed = append(config.Framed, FramedSource{
				Name: source.name, Carrier: CarrierUDP, Listener: tracked,
			})
			sourceAddr = framed.Addr()
			framedPaths[source.name] = tracked
			closers = append(closers, framed.Close)
		default:
			closeSources()
			return nil, fmt.Errorf("test runtime source %q has unknown kind %d", source.name, source.kind)
		}
		sourceAddrs[source.name] = sourceAddr
	}

	listener, err := runtime.Listen(config)
	if err != nil {
		closeSources()
		return nil, err
	}
	return &runtimeListenerFixture{
		listener:    listener,
		sourceAddrs: sourceAddrs,
		streams:     streams,
		framed:      framedPaths,
	}, nil
}

func (l *runtimeListenerFixture) Accept(ctx context.Context) (Conn, error) {
	if l == nil || l.listener == nil {
		return nil, net.ErrClosed
	}
	return l.listener.AcceptStream(ctx)
}

func (l *runtimeListenerFixture) AcceptPacket(ctx context.Context) (PacketConn, error) {
	if l == nil || l.listener == nil {
		return nil, net.ErrClosed
	}
	return l.listener.AcceptPacket(ctx)
}

func (l *runtimeListenerFixture) Close() error {
	if l == nil || l.listener == nil {
		return nil
	}
	return l.listener.Close()
}

func (l *runtimeListenerFixture) Addr() net.Addr {
	if l == nil || l.listener == nil {
		return nil
	}
	return l.listener.Addr()
}

func (l *runtimeListenerFixture) Addrs() []net.Addr {
	if l == nil || l.listener == nil {
		return nil
	}
	return l.listener.Addrs()
}

func (l *runtimeListenerFixture) SourceAddr(name string) net.Addr {
	if l == nil {
		return nil
	}
	return l.sourceAddrs[name]
}

func (l *runtimeListenerFixture) FlowIDs() [][16]byte {
	if l == nil || l.listener == nil {
		return nil
	}
	return l.listener.FlowIDs()
}

func (l *runtimeListenerFixture) CloseAcceptedPath(source string, ordinal int) error {
	if l == nil {
		return net.ErrClosed
	}
	if tracked := l.streams[source]; tracked != nil {
		return tracked.closeAccepted(ordinal)
	}
	if tracked := l.framed[source]; tracked != nil {
		return tracked.closeAccepted(ordinal)
	}
	return fmt.Errorf("test runtime source %q does not expose accepted paths", source)
}

// CloseAcceptedPeerPath closes the one accepted carrier whose peer endpoint
// matches a dial-side path. This binds a fault to the intended path without
// relying on accept order.
func (l *runtimeListenerFixture) CloseAcceptedPeerPath(source, peerLocal string) (int, error) {
	if l == nil {
		return -1, net.ErrClosed
	}
	if tracked := l.streams[source]; tracked != nil {
		return tracked.closePeer(peerLocal)
	}
	if tracked := l.framed[source]; tracked != nil {
		return tracked.closePeer(peerLocal)
	}
	return -1, fmt.Errorf("test runtime source %q does not expose accepted paths", source)
}

func runtimeSameEndpoint(left, right string) bool {
	if left == right {
		return true
	}
	leftHost, leftPort, leftErr := net.SplitHostPort(left)
	rightHost, rightPort, rightErr := net.SplitHostPort(right)
	if leftErr != nil || rightErr != nil || leftPort != rightPort {
		return false
	}
	leftIP := net.ParseIP(leftHost)
	rightIP := net.ParseIP(rightHost)
	if leftIP == nil || rightIP == nil {
		return leftHost == rightHost
	}
	return leftIP.IsUnspecified() || rightIP.IsUnspecified() || leftIP.Equal(rightIP)
}

type runtimeTrackedStreamListener struct {
	net.Listener
	mu       sync.Mutex
	accepted []net.Conn
}

func (l *runtimeTrackedStreamListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.accepted = append(l.accepted, conn)
	l.mu.Unlock()
	return conn, nil
}

func (l *runtimeTrackedStreamListener) closeAccepted(ordinal int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ordinal < 0 || ordinal >= len(l.accepted) {
		return fmt.Errorf("accepted stream ordinal %d out of range [0,%d)", ordinal, len(l.accepted))
	}
	return l.accepted[ordinal].Close()
}

func (l *runtimeTrackedStreamListener) closePeer(peerLocal string) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	match := -1
	for ordinal, conn := range l.accepted {
		if runtimeSameEndpoint(conn.RemoteAddr().String(), peerLocal) {
			if match >= 0 {
				return -1, fmt.Errorf("accepted stream peer %q matches multiple carriers", peerLocal)
			}
			match = ordinal
		}
	}
	if match < 0 {
		return -1, fmt.Errorf("accepted stream peer %q not found", peerLocal)
	}
	return match, l.accepted[match].Close()
}

type runtimeTrackedPathListener struct {
	transport.PathListener
	mu       sync.Mutex
	accepted []transport.PathConn
}

func (l *runtimeTrackedPathListener) closePeer(peerLocal string) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	match := -1
	for ordinal, path := range l.accepted {
		if runtimeSameEndpoint(path.RemoteAddr(), peerLocal) {
			if match >= 0 {
				return -1, fmt.Errorf("accepted framed peer %q matches multiple carriers", peerLocal)
			}
			match = ordinal
		}
	}
	if match < 0 {
		return -1, fmt.Errorf("accepted framed peer %q not found", peerLocal)
	}
	return match, l.accepted[match].Close()
}

const runtimeControlledTCPTransportName = "rendr-test-controlled-tcp"

var (
	runtimeControlledTCPSequence atomic.Uint64
	runtimeControlledTCPMux      = &runtimeControlledTCPMuxTransport{controllers: make(map[string]*runtimeControlledTCPTransport)}
)

type runtimeControlledTCPMuxTransport struct {
	mu          sync.RWMutex
	controllers map[string]*runtimeControlledTCPTransport
}

func (*runtimeControlledTCPMuxTransport) Name() string { return runtimeControlledTCPTransportName }

func (m *runtimeControlledTCPMuxTransport) controller(spec transport.PathSpec) (*runtimeControlledTCPTransport, error) {
	id := spec.Opts["test_control_id"]
	m.mu.RLock()
	controller := m.controllers[id]
	m.mu.RUnlock()
	if id == "" || controller == nil {
		return nil, fmt.Errorf("controlled TCP test controller %q is unavailable", id)
	}
	return controller, nil
}

func (m *runtimeControlledTCPMuxTransport) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	controller, err := m.controller(spec)
	if err != nil {
		return nil, err
	}
	return controller.dialPath(ctx, spec)
}

func (m *runtimeControlledTCPMuxTransport) Probe(ctx context.Context, spec transport.PathSpec) (transport.PathQuality, error) {
	controller, err := m.controller(spec)
	if err != nil {
		return transport.PathQuality{}, err
	}
	return controller.probe(ctx, spec)
}

// runtimeControlledTCPTransport is a test-owned path adapter. It retains
// carrier handles so tests can bind faults and observations to named leaves
// without an engine backdoor.
type runtimeControlledTCPTransport struct {
	id            string
	baseTransport string

	mu        sync.Mutex
	dialCond  *sync.Cond
	paths     []*runtimeControlledTCPPath
	blocked   map[string]bool
	closing   bool
	dialing   int
	closeOnce sync.Once
	dialHook  func(context.Context, transport.PathSpec) (transport.PathConn, net.Conn, error)
}

func newRuntimeControlledTCPTransport(t testing.TB) *runtimeControlledTCPTransport {
	return newRuntimeControlledPathTransport(t, "tcp")
}

func newRuntimeControlledQUICTransport(t testing.TB) *runtimeControlledTCPTransport {
	return newRuntimeControlledPathTransport(t, "quic")
}

func newRuntimeControlledPathTransport(t testing.TB, baseTransport string) *runtimeControlledTCPTransport {
	t.Helper()
	tr := &runtimeControlledTCPTransport{
		id:            fmt.Sprintf("control-%d", runtimeControlledTCPSequence.Add(1)),
		baseTransport: baseTransport,
		blocked:       make(map[string]bool),
	}
	tr.dialCond = sync.NewCond(&tr.mu)
	runtimeControlledTCPMux.mu.Lock()
	runtimeControlledTCPMux.controllers[tr.id] = tr
	runtimeControlledTCPMux.mu.Unlock()
	t.Cleanup(tr.close)
	return tr
}

func (*runtimeControlledTCPTransport) Name() string { return runtimeControlledTCPTransportName }

func (t *runtimeControlledTCPTransport) Bind(tb testing.TB, dialer *sessionDialer) {
	tb.Helper()
	carrier := CarrierTCP
	if t.baseTransport == "quic" {
		carrier = CarrierUDP
	}
	if err := dialer.AddFramedPathFactory(runtimeControlledTCPTransportName, carrier, runtimeControlledTCPMux); err != nil {
		tb.Fatalf("bind controlled path factory: %v", err)
	}
}

func (t *runtimeControlledTCPTransport) Spec(address, pathName string) PathSpec {
	return PathSpec{
		Transport: runtimeControlledTCPTransportName,
		Address:   address,
		Opts:      map[string]string{"name": pathName, "test_control_id": t.id},
	}
}

func (t *runtimeControlledTCPTransport) dialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	pathName := spec.Opts["name"]
	t.mu.Lock()
	blocked := t.blocked[pathName]
	if t.closing {
		t.mu.Unlock()
		return nil, net.ErrClosed
	}
	if !blocked {
		t.dialing++
	}
	hook := t.dialHook
	t.mu.Unlock()
	if blocked {
		return nil, fmt.Errorf("controlled TCP path %q is blocked", pathName)
	}

	var (
		base transport.PathConn
		raw  net.Conn
		err  error
	)
	if hook != nil {
		base, raw, err = hook(ctx, spec.Clone())
	} else if t.baseTransport == "tcp" {
		raw, err = (&net.Dialer{}).DialContext(ctx, "tcp", spec.Address)
		if err == nil {
			base = tadapter.Wrap(raw)
		}
	} else {
		baseSpec := spec.Clone()
		baseSpec.Transport = t.baseTransport
		base, err = qadapter.New().DialPath(ctx, baseSpec)
	}

	t.mu.Lock()
	t.dialing--
	if t.dialing == 0 {
		t.dialCond.Broadcast()
	}
	if err == nil && base == nil {
		err = errors.New("controlled transport dial returned a nil path")
	}
	if err != nil {
		t.mu.Unlock()
		return nil, err
	}
	path := &runtimeControlledTCPPath{
		raw:  raw,
		base: base,
		spec: spec.Clone(),
	}
	if t.closing {
		t.mu.Unlock()
		_ = path.Close()
		return nil, net.ErrClosed
	}
	t.paths = append(t.paths, path)
	t.mu.Unlock()
	return path, nil
}

func (t *runtimeControlledTCPTransport) probe(ctx context.Context, spec transport.PathSpec) (transport.PathQuality, error) {
	t.mu.Lock()
	if t.closing {
		t.mu.Unlock()
		return transport.PathQuality{}, net.ErrClosed
	}
	t.dialing++
	t.mu.Unlock()

	var backend transport.PathFactory = tadapter.New()
	if t.baseTransport == "quic" {
		backend = qadapter.New()
	}
	var err error
	var quality transport.PathQuality
	baseSpec := spec.Clone()
	baseSpec.Transport = t.baseTransport
	quality, err = backend.Probe(ctx, baseSpec)

	t.mu.Lock()
	t.dialing--
	closing := t.closing
	if t.dialing == 0 {
		t.dialCond.Broadcast()
	}
	t.mu.Unlock()
	if closing && err == nil {
		return transport.PathQuality{}, net.ErrClosed
	}
	return quality, err
}

func (t *runtimeControlledTCPTransport) path(pathName string) (*runtimeControlledTCPPath, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.paths) - 1; i >= 0; i-- {
		path := t.paths[i]
		if path.spec.Opts["name"] == pathName && !path.closed.Load() {
			return path, nil
		}
	}
	return nil, fmt.Errorf("controlled TCP path %q not found", pathName)
}

func (t *runtimeControlledTCPTransport) Fail(pathName string) error {
	t.mu.Lock()
	t.blocked[pathName] = true
	var selected *runtimeControlledTCPPath
	for i := len(t.paths) - 1; i >= 0; i-- {
		path := t.paths[i]
		if path.spec.Opts["name"] == pathName && !path.closed.Load() {
			selected = path
			break
		}
	}
	t.mu.Unlock()
	if selected == nil {
		return fmt.Errorf("controlled TCP path %q not found", pathName)
	}
	return selected.Fail()
}

func (t *runtimeControlledTCPTransport) Block(pathName string) {
	t.mu.Lock()
	t.blocked[pathName] = true
	t.mu.Unlock()
}

func (t *runtimeControlledTCPTransport) LocalAddr(pathName string) (string, error) {
	path, err := t.path(pathName)
	if err != nil {
		return "", err
	}
	return path.LocalAddr(), nil
}

func (t *runtimeControlledTCPTransport) SetQuality(pathName string, quality PathQuality) error {
	path, err := t.path(pathName)
	if err != nil {
		return err
	}
	path.SetTestQuality(quality)
	return nil
}

func (t *runtimeControlledTCPTransport) close() {
	t.closeOnce.Do(func() {
		runtimeControlledTCPMux.mu.Lock()
		delete(runtimeControlledTCPMux.controllers, t.id)
		runtimeControlledTCPMux.mu.Unlock()
		t.mu.Lock()
		t.closing = true
		for t.dialing != 0 {
			t.dialCond.Wait()
		}
		paths := append([]*runtimeControlledTCPPath(nil), t.paths...)
		t.paths = nil
		t.mu.Unlock()
		for _, path := range paths {
			_ = path.Close()
		}
	})
}

type runtimeControlledTCPPath struct {
	raw    net.Conn
	base   transport.PathConn
	spec   transport.PathSpec
	closed atomic.Bool

	qualityMu     sync.RWMutex
	forcedQuality *transport.PathQuality
}

func (p *runtimeControlledTCPPath) Read(buf []byte) (int, error) { return p.base.Read(buf) }

func (p *runtimeControlledTCPPath) Write(frame []byte) (int, error) {
	return p.base.Write(frame)
}

func (p *runtimeControlledTCPPath) Close() error {
	p.closed.Store(true)
	return p.base.Close()
}

func (p *runtimeControlledTCPPath) Quality() transport.PathQuality {
	p.qualityMu.RLock()
	forced := p.forcedQuality
	if forced != nil {
		quality := *forced
		p.qualityMu.RUnlock()
		return quality
	}
	p.qualityMu.RUnlock()
	return p.base.Quality()
}

func (p *runtimeControlledTCPPath) SetQuality(quality transport.PathQuality) {
	if setter, ok := p.base.(interface{ SetQuality(transport.PathQuality) }); ok {
		setter.SetQuality(quality)
	}
}

func (p *runtimeControlledTCPPath) SetTestQuality(quality transport.PathQuality) {
	p.qualityMu.Lock()
	p.forcedQuality = &quality
	p.qualityMu.Unlock()
}

func (p *runtimeControlledTCPPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.base.OnDeath(fn)
}

func (p *runtimeControlledTCPPath) LocalAddr() string  { return p.base.LocalAddr() }
func (p *runtimeControlledTCPPath) RemoteAddr() string { return p.base.RemoteAddr() }
func (p *runtimeControlledTCPPath) Reads() uint64 {
	if observer, ok := p.base.(interface{ Reads() uint64 }); ok {
		return observer.Reads()
	}
	return 0
}
func (p *runtimeControlledTCPPath) Writes() uint64 {
	if observer, ok := p.base.(interface{ Writes() uint64 }); ok {
		return observer.Writes()
	}
	return 0
}
func (p *runtimeControlledTCPPath) MarkByeSeen() {
	if marker, ok := p.base.(interface{ MarkByeSeen() }); ok {
		marker.MarkByeSeen()
	}
}
func (p *runtimeControlledTCPPath) MarkQuiesced() {
	if marker, ok := p.base.(interface{ MarkQuiesced() }); ok {
		marker.MarkQuiesced()
	}
}
func (p *runtimeControlledTCPPath) CloseWrite() error {
	if closer, ok := p.base.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

func (p *runtimeControlledTCPPath) Fail() error {
	if p.raw == nil {
		return errors.New("controlled path has no raw carrier fault handle")
	}
	p.closed.Store(true)
	return p.raw.Close()
}

type runtimeTrackedPacketFactory struct {
	mu      sync.Mutex
	conns   []net.PacketConn
	blocked bool
}

func (f *runtimeTrackedPacketFactory) Dial(context.Context, string) (net.PacketConn, error) {
	f.mu.Lock()
	blocked := f.blocked
	f.mu.Unlock()
	if blocked {
		return nil, errors.New("tracked packet factory is blocked")
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.conns = append(f.conns, conn)
	f.mu.Unlock()
	return conn, nil
}

func (f *runtimeTrackedPacketFactory) Fail(ordinal int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ordinal < 0 || ordinal >= len(f.conns) {
		return fmt.Errorf("tracked packet ordinal %d out of range [0,%d)", ordinal, len(f.conns))
	}
	f.blocked = true
	return f.conns[ordinal].Close()
}

func (l *runtimeTrackedPathListener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	path, err := l.PathListener.AcceptPath(ctx)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.accepted = append(l.accepted, path)
	l.mu.Unlock()
	return path, nil
}

func (l *runtimeTrackedPathListener) closeAccepted(ordinal int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ordinal < 0 || ordinal >= len(l.accepted) {
		return fmt.Errorf("accepted framed path ordinal %d out of range [0,%d)", ordinal, len(l.accepted))
	}
	return l.accepted[ordinal].Close()
}

func TestRuntimeSessionListenerStandardHTTPServer(t *testing.T) {
	fixture, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var standard net.Listener = fixture.listener
	serveErr := make(chan error, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "rendr-http")
	})}
	go func() { serveErr <- server.Serve(standard) }()

	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientRuntime.Dial(context.Background(), SessionConfig{Root: Path("tcp", PathSpec{
		Transport: "tcp",
		Address:   fixture.Addr().String(),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: rendr.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got != "rendr-http" {
		t.Fatalf("HTTP response body=%q", got)
	}

	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveErr:
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("http.Server.Serve close error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("http.Server.Serve did not unblock after SessionListener.Close")
	}
}

func TestRuntimeConnectionsExcludeTestBackdoors(t *testing.T) {
	// This contract covers removed engine, fault-injection, and manual mobility
	// surfaces. Mobility planning is internal and read-only through Status.
	t.Run("stream", func(t *testing.T) {
		fixture, err := listenRuntimeTCP("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer fixture.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		accepted := make(chan Conn, 1)
		errc := make(chan error, 1)
		go func() {
			conn, err := fixture.Accept(ctx)
			if err != nil {
				errc <- err
				return
			}
			accepted <- conn
		}()

		runtime, err := NewRuntime(RuntimeConfig{})
		if err != nil {
			t.Fatal(err)
		}
		client, err := runtime.Dial(ctx, SessionConfig{Root: Path("tcp", PathSpec{
			Transport: "tcp", Address: fixture.Addr().String(),
		})})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		var server Conn
		select {
		case server = <-accepted:
		case err := <-errc:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		defer server.Close()

		assertNoRuntimeTestBackdoors(t, "dialed stream", client)
		assertNoRuntimeTestBackdoors(t, "accepted stream", server)
	})

	t.Run("packet", func(t *testing.T) {
		fixture, err := listenRuntimeUDP("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer fixture.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		accepted := make(chan PacketConn, 1)
		errc := make(chan error, 1)
		go func() {
			conn, err := fixture.AcceptPacket(ctx)
			if err != nil {
				errc <- err
				return
			}
			accepted <- conn
		}()

		runtime, err := NewRuntime(RuntimeConfig{})
		if err != nil {
			t.Fatal(err)
		}
		client, err := runtime.DialPacket(ctx, SessionConfig{Root: Path("udp", PathSpec{
			Transport: "udpflow", Address: fixture.Addr().String(),
		})})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		var server PacketConn
		select {
		case server = <-accepted:
		case err := <-errc:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		defer server.Close()

		assertNoRuntimeTestBackdoors(t, "dialed packet", client)
		assertNoRuntimeTestBackdoors(t, "accepted packet", server)
	})
}

func TestRuntimeControlledTransportCloseJoinsInFlightDial(t *testing.T) {
	controlled := newRuntimeControlledTCPTransport(t)
	client, peer := net.Pipe()
	defer peer.Close()
	started := make(chan struct{})
	release := make(chan struct{})
	controlled.dialHook = func(context.Context, transport.PathSpec) (transport.PathConn, net.Conn, error) {
		close(started)
		<-release
		return tadapter.Wrap(client), client, nil
	}

	dialDone := make(chan error, 1)
	go func() {
		_, err := controlled.dialPath(context.Background(), controlled.Spec("unused", "A"))
		dialDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("controlled dial did not enter hook")
	}

	closeDone := make(chan struct{})
	go func() {
		controlled.close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		t.Fatal("controlled transport close returned before in-flight dial joined")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-dialDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("in-flight dial error=%v, want %v", err, net.ErrClosed)
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("controlled transport close did not finish after dial joined")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("late dial carrier remained open after controlled transport close")
	}
}

func assertNoRuntimeTestBackdoors(t *testing.T, label string, value any) {
	t.Helper()
	type forceKillPathBackdoor interface {
		ForceKillPathForTest(uint32) error
	}
	if _, exposed := value.(forceKillPathBackdoor); exposed {
		t.Fatalf("%s exposes ForceKillPathForTest through interface assertion", label)
	}
	valueType := reflect.TypeOf(value)
	for _, method := range []string{"Engine", "ForceKillPathForTest", "MigratePathLocalAddr"} {
		if _, exposed := valueType.MethodByName(method); exposed {
			t.Fatalf("%s exposes production method %s", label, method)
		}
	}
}

func TestTCPListenerFailKeepsAcceptChannelOpen(t *testing.T) {
	boom := errors.New("accept failed")
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen(ListenConfig{Streams: []StreamSource{{
		Name: "terminal-tcp", Carrier: CarrierTCP, Listener: &runtimeFailingStreamListener{err: boom},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	waitRuntimeFixtureShutdown(t, listener)

	select {
	case _, ok := <-listener.streamAccept:
		if !ok {
			t.Fatal("failure closed stream accept channel")
		}
	default:
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := listener.AcceptStream(ctx); !errors.Is(err, boom) {
		t.Fatalf("AcceptStream error = %v, want %v", err, boom)
	}
}

func TestUDPFlowListenerFailKeepsPacketAcceptChannelOpen(t *testing.T) {
	boom := errors.New("udpflow accept failed")
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen(ListenConfig{Packets: []PacketSource{{
		Name: "terminal-udp", Carrier: CarrierUDP, Conn: &runtimeFailingPacketConn{err: boom},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	waitRuntimeFixtureShutdown(t, listener)

	select {
	case _, ok := <-listener.packetAccept:
		if !ok {
			t.Fatal("failure closed packet accept channel")
		}
	default:
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := listener.AcceptPacket(ctx); !errors.Is(err, boom) {
		t.Fatalf("AcceptPacket error = %v, want %v", err, boom)
	}
}

func waitRuntimeFixtureShutdown(t *testing.T, listener *SessionListener) {
	t.Helper()
	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("terminal source did not shut down Runtime listener")
	}
}

type runtimeFailingStreamListener struct{ err error }

func (l *runtimeFailingStreamListener) Accept() (net.Conn, error) { return nil, l.err }
func (*runtimeFailingStreamListener) Close() error                { return nil }
func (*runtimeFailingStreamListener) Addr() net.Addr              { return stringAddr("terminal-tcp") }

type runtimeFailingPacketConn struct{ err error }

func (c *runtimeFailingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, c.err
}
func (c *runtimeFailingPacketConn) WriteTo([]byte, net.Addr) (int, error) { return 0, c.err }
func (*runtimeFailingPacketConn) Close() error                            { return nil }
func (*runtimeFailingPacketConn) LocalAddr() net.Addr                     { return stringAddr("terminal-udp") }
func (*runtimeFailingPacketConn) SetDeadline(time.Time) error             { return nil }
func (*runtimeFailingPacketConn) SetReadDeadline(time.Time) error         { return nil }
func (*runtimeFailingPacketConn) SetWriteDeadline(time.Time) error        { return nil }
