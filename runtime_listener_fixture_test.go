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

	"github.com/FrankoonG/rendr/proto"
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
		carrier, factory = CarrierUnknown, gadapter.New(gadapter.WithTrustedCarrier())
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
	return listenRuntimeSourcesWithConfig(ListenConfig{}, sources...)
}

func listenRuntimeSourcesWithConfig(config ListenConfig, sources ...runtimeFixtureSource) (*runtimeListenerFixture, error) {
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		return nil, err
	}

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
				Name: source.name, Carrier: CarrierUDP, Conn: raw, MaxDatagramSize: 1400,
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
			framed, listenErr := gadapter.ListenPacket(source.address, gadapter.WithTrustedCarrier())
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

// CloseSource stops future admissions for one named fixture source without
// closing paths that it already accepted. This lets fault tests distinguish a
// permanent carrier outage from a reconnectable physical incarnation.
func (l *runtimeListenerFixture) CloseSource(source string) error {
	if l == nil {
		return net.ErrClosed
	}
	if tracked := l.streams[source]; tracked != nil {
		return tracked.Listener.Close()
	}
	if tracked := l.framed[source]; tracked != nil {
		return tracked.PathListener.Close()
	}
	return fmt.Errorf("test runtime source %q is unavailable", source)
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

// runtimeControlledTCPTransport is a test-owned dialing path adapter. It
// retains only dial-side carrier generations; listener-owned peer endpoints
// are outside this controller. Tests can bind faults and observations to
// named leaves without an engine backdoor.
type runtimeControlledTCPTransport struct {
	id            string
	baseTransport string

	mu              sync.Mutex
	dialCond        *sync.Cond
	dialGenerations []*runtimeControlledTCPPath
	blocked         map[string]bool
	probeDelay      map[string]time.Duration
	dataPaths       map[string]*runtimeControlledTCPDataPath
	qualities       map[string]PathQuality
	closing         bool
	dialing         int
	closeOnce       sync.Once
	dialHook        func(context.Context, transport.PathSpec) (transport.PathConn, net.Conn, error)
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
		probeDelay:    make(map[string]time.Duration),
		dataPaths:     make(map[string]*runtimeControlledTCPDataPath),
		qualities:     make(map[string]PathQuality),
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
	dataPath := t.dataPaths[pathName]
	if dataPath == nil {
		dataPath = newRuntimeControlledTCPDataPath()
		t.dataPaths[pathName] = dataPath
	}
	path := &runtimeControlledTCPPath{
		raw:              raw,
		base:             base,
		spec:             spec.Clone(),
		dataPath:         dataPath,
		probeDelayClosed: make(chan struct{}),
	}
	if quality, ok := t.qualities[pathName]; ok {
		path.SetTestQuality(quality)
	}
	path.probeDelayNanos.Store(int64(t.probeDelay[pathName]))
	if t.closing {
		t.mu.Unlock()
		_ = path.Close()
		return nil, net.ErrClosed
	}
	t.dialGenerations = append(t.dialGenerations, path)
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

func (t *runtimeControlledTCPTransport) latestDialGeneration(pathName string) (*runtimeControlledTCPPath, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.dialGenerations) - 1; i >= 0; i-- {
		path := t.dialGenerations[i]
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
	for i := len(t.dialGenerations) - 1; i >= 0; i-- {
		path := t.dialGenerations[i]
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
	path, err := t.latestDialGeneration(pathName)
	if err != nil {
		return "", err
	}
	return path.LocalAddr(), nil
}

func (t *runtimeControlledTCPTransport) SetQuality(pathName string, quality PathQuality) error {
	t.mu.Lock()
	if t.qualities == nil {
		t.qualities = make(map[string]PathQuality)
	}
	t.qualities[pathName] = quality
	paths := make([]*runtimeControlledTCPPath, 0, 2)
	for _, path := range t.dialGenerations {
		if path.spec.Opts["name"] == pathName && !path.closed.Load() {
			paths = append(paths, path)
		}
	}
	t.mu.Unlock()
	for _, path := range paths {
		path.SetTestQuality(quality)
	}
	return nil
}

func (t *runtimeControlledTCPTransport) SetProbeDelay(pathName string, delay time.Duration) error {
	if delay < 0 {
		return fmt.Errorf("controlled TCP path %q probe delay is negative: %s", pathName, delay)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closing {
		return net.ErrClosed
	}
	t.probeDelay[pathName] = delay
	for _, path := range t.dialGenerations {
		if path.spec.Opts["name"] == pathName && !path.closed.Load() {
			path.probeDelayNanos.Store(int64(delay))
		}
	}
	return nil
}

// SetDataWriteRate shapes only complete DATA frames written on pathName. A
// zero rate disables shaping. The setting applies to current and future dials.
func (t *runtimeControlledTCPTransport) SetDataWriteRate(pathName string, bytesPerSecond uint64) error {
	dataPath, err := t.dataPath(pathName, true)
	if err != nil {
		return err
	}
	dataPath.mu.Lock()
	dataPath.writeBytesPerSecond = bytesPerSecond
	dataPath.mu.Unlock()
	return nil
}

// SetDataReadRate shapes only complete DATA frames read on pathName. A zero
// rate disables shaping. The setting applies to current and future dials.
func (t *runtimeControlledTCPTransport) SetDataReadRate(pathName string, bytesPerSecond uint64) error {
	dataPath, err := t.dataPath(pathName, true)
	if err != nil {
		return err
	}
	dataPath.mu.Lock()
	dataPath.readBytesPerSecond = bytesPerSecond
	dataPath.mu.Unlock()
	return nil
}

// PathStats returns one coherent snapshot for the logical named path. Its
// counters span every physical dial made for that path name.
func (t *runtimeControlledTCPTransport) PathStats(pathName string) (runtimeControlledTCPPathStats, error) {
	dataPath, err := t.dataPath(pathName, false)
	if err != nil {
		return runtimeControlledTCPPathStats{}, err
	}
	return dataPath.snapshot(), nil
}

func (t *runtimeControlledTCPTransport) dataPath(pathName string, create bool) (*runtimeControlledTCPDataPath, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if create && t.closing {
		return nil, net.ErrClosed
	}
	dataPath := t.dataPaths[pathName]
	if dataPath == nil && create {
		dataPath = newRuntimeControlledTCPDataPath()
		t.dataPaths[pathName] = dataPath
	}
	if dataPath == nil {
		return nil, fmt.Errorf("controlled TCP path %q has no DATA statistics", pathName)
	}
	return dataPath, nil
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
		paths := append([]*runtimeControlledTCPPath(nil), t.dialGenerations...)
		t.dialGenerations = nil
		t.mu.Unlock()
		for _, path := range paths {
			_ = path.Close()
		}
	})
}

type runtimeControlledTCPPath struct {
	raw              net.Conn
	base             transport.PathConn
	spec             transport.PathSpec
	dataPath         *runtimeControlledTCPDataPath
	closed           atomic.Bool
	probeDelayNanos  atomic.Int64
	probeDelayClosed chan struct{}
	probeDelayOnce   sync.Once
	readMu           sync.Mutex
	probePumpMu      sync.Mutex
	probeDelayFIFO   *runtimeControlledTCPProbeDelayFIFO
	probeClock       runtimeControlledTCPProbeClock

	qualityMu     sync.RWMutex
	forcedQuality *transport.PathQuality

	writeGateMu sync.Mutex
	writeGate   *runtimePathWriteGate
}

func (p *runtimeControlledTCPPath) Read(buf []byte) (int, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()

	fifo := p.loadProbeDelayFIFO()
	var (
		n   int
		err error
	)
	if fifo != nil {
		n, err = fifo.Read(buf)
	} else {
		n, err = p.base.Read(buf)
		arrivedAt := p.probeDelayClock().Now()
		if n > 0 && time.Duration(p.probeDelayNanos.Load()) > 0 {
			fifo, startErr := p.startProbeDelayFIFO(buf[:n], arrivedAt, err)
			if startErr != nil {
				return 0, startErr
			}
			n, err = fifo.Read(buf)
		}
	}
	if n > 0 && isDataFrame(buf[:n]) {
		p.dataPath.recordReadBytes(uint64(n))
		if delayErr := p.delayData(n, false); delayErr != nil {
			return 0, delayErr
		}
	}
	return n, err
}

func (p *runtimeControlledTCPPath) Write(frame []byte) (int, error) {
	p.writeGateMu.Lock()
	gate := p.writeGate
	if gate != nil && gate.matches(frame) {
		p.writeGate = nil
	} else {
		gate = nil
	}
	p.writeGateMu.Unlock()
	if gate != nil {
		close(gate.entered)
		<-gate.release
	}
	if isDataFrame(frame) {
		if err := p.delayData(len(frame), true); err != nil {
			if gate != nil {
				gate.result <- runtimePathWriteResult{err: err}
			}
			return 0, err
		}
	}
	n, err := p.base.Write(frame)
	if n > 0 && isDataFrame(frame) {
		p.dataPath.recordWriteBytes(uint64(n))
	}
	if gate != nil {
		gate.result <- runtimePathWriteResult{n: n, err: err}
	}
	return n, err
}

func (p *runtimeControlledTCPPath) Close() error {
	p.signalClosed()
	err := p.base.Close()
	p.waitProbeDelayPump()
	return err
}

func (p *runtimeControlledTCPPath) signalClosed() {
	p.closed.Store(true)
	p.probeDelayOnce.Do(func() { close(p.probeDelayClosed) })
}

func (p *runtimeControlledTCPPath) loadProbeDelayFIFO() *runtimeControlledTCPProbeDelayFIFO {
	p.probePumpMu.Lock()
	defer p.probePumpMu.Unlock()
	return p.probeDelayFIFO
}

func (p *runtimeControlledTCPPath) startProbeDelayFIFO(first []byte, arrivedAt time.Time, sourceErr error) (*runtimeControlledTCPProbeDelayFIFO, error) {
	p.probePumpMu.Lock()
	defer p.probePumpMu.Unlock()
	if p.probeDelayFIFO != nil {
		return p.probeDelayFIFO, nil
	}
	if p.closed.Load() {
		return nil, net.ErrClosed
	}
	fifo := newRuntimeControlledTCPProbeDelayFIFO(
		p.base,
		&p.probeDelayNanos,
		p.probeDelayClock(),
		runtimeControlledTCPProbeQueueLimits{
			frames: runtimeControlledTCPProbeQueueMaxFrames,
			bytes:  runtimeControlledTCPProbeQueueMaxBytes,
		},
		p.probeDelayClosed,
	)
	if err := fifo.enqueue(first, arrivedAt); err != nil {
		return nil, err
	}
	if sourceErr != nil {
		fifo.finishSource(sourceErr)
	}
	p.probeDelayFIFO = fifo
	fifo.start()
	return fifo, nil
}

func (p *runtimeControlledTCPPath) probeDelayClock() runtimeControlledTCPProbeClock {
	if p.probeClock != nil {
		return p.probeClock
	}
	return runtimeControlledTCPRealProbeClock{}
}

func (p *runtimeControlledTCPPath) waitProbeDelayPump() {
	p.probePumpMu.Lock()
	fifo := p.probeDelayFIFO
	p.probePumpMu.Unlock()
	if fifo != nil {
		fifo.wait()
	}
}

func isDataFrame(frame []byte) bool {
	if len(frame) < proto.HeaderSize {
		return false
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	return err == nil && header.Type == proto.FrameData
}

func isPathProbeControl(frame []byte, code proto.CtrlCode) bool {
	if len(frame) < proto.HeaderSize {
		return false
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	return err == nil && header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == code
}

const (
	runtimeControlledTCPProbeQueueMaxFrames = 128
	runtimeControlledTCPProbeQueueMaxBytes  = 2 << 20
)

var errRuntimeControlledTCPProbeQueueOverflow = errors.New("controlled TCP probe-delay queue overflow")

type runtimeControlledTCPProbeClock interface {
	Now() time.Time
	NewTimerAt(time.Time) runtimeControlledTCPProbeTimer
}

type runtimeControlledTCPProbeTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type runtimeControlledTCPRealProbeClock struct{}

func (runtimeControlledTCPRealProbeClock) Now() time.Time { return time.Now() }

func (runtimeControlledTCPRealProbeClock) NewTimerAt(deadline time.Time) runtimeControlledTCPProbeTimer {
	delay := time.Until(deadline)
	if delay < 0 {
		delay = 0
	}
	return runtimeControlledTCPRealProbeTimer{Timer: time.NewTimer(delay)}
}

type runtimeControlledTCPRealProbeTimer struct {
	*time.Timer
}

func (t runtimeControlledTCPRealProbeTimer) C() <-chan time.Time { return t.Timer.C }

type runtimeControlledTCPProbeQueueLimits struct {
	frames int
	bytes  int
}

type runtimeControlledTCPProbeFrame struct {
	frame     []byte
	releaseAt time.Time
}

// runtimeControlledTCPProbeDelayFIFO keeps physical arrival independent from
// delayed delivery. Only an exact probe-reply payload receives artificial
// latency; later frames remain FIFO-ordered behind it without each adding the
// same delay again.
type runtimeControlledTCPProbeDelayFIFO struct {
	base   transport.PathConn
	delay  *atomic.Int64
	clock  runtimeControlledTCPProbeClock
	limits runtimeControlledTCPProbeQueueLimits
	closed <-chan struct{}

	readMu sync.Mutex
	mu     sync.Mutex
	frames []runtimeControlledTCPProbeFrame
	head   int
	bytes  int

	fatalErr      error
	sourceErr     error
	sourceStopped bool
	wake          chan struct{}
	space         chan struct{}
	done          chan struct{}
	startOnce     sync.Once
	started       atomic.Bool
}

func newRuntimeControlledTCPProbeDelayFIFO(
	base transport.PathConn,
	delay *atomic.Int64,
	clock runtimeControlledTCPProbeClock,
	limits runtimeControlledTCPProbeQueueLimits,
	closed <-chan struct{},
) *runtimeControlledTCPProbeDelayFIFO {
	return &runtimeControlledTCPProbeDelayFIFO{
		base:   base,
		delay:  delay,
		clock:  clock,
		limits: limits,
		closed: closed,
		wake:   make(chan struct{}, 1),
		space:  make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
}

func (q *runtimeControlledTCPProbeDelayFIFO) start() {
	q.startOnce.Do(func() {
		q.started.Store(true)
		go q.pump()
	})
}

func (q *runtimeControlledTCPProbeDelayFIFO) wait() {
	if q != nil && q.started.Load() {
		<-q.done
	}
}

func (q *runtimeControlledTCPProbeDelayFIFO) pump() {
	defer close(q.done)
	q.mu.Lock()
	stopped := q.sourceStopped
	q.mu.Unlock()
	if stopped {
		return
	}

	buf := make([]byte, tadapter.MaxFrameSize)
	for {
		if !q.waitForPumpCapacity(len(buf)) {
			return
		}
		n, err := q.base.Read(buf)
		arrivedAt := q.clock.Now()
		if n > 0 {
			if enqueueErr := q.enqueue(buf[:n], arrivedAt); enqueueErr != nil {
				_ = q.base.Close()
				return
			}
		}
		if err != nil {
			q.finishSource(err)
			return
		}
		if n == 0 {
			q.finishSource(errors.New("controlled TCP probe-delay pump read made no progress"))
			_ = q.base.Close()
			return
		}
	}
}

func (q *runtimeControlledTCPProbeDelayFIFO) waitForPumpCapacity(maxFrameBytes int) bool {
	for {
		q.mu.Lock()
		queuedFrames := len(q.frames) - q.head
		capacity := q.fatalErr == nil && !q.sourceStopped &&
			queuedFrames < q.limits.frames && maxFrameBytes <= q.limits.bytes-q.bytes
		q.mu.Unlock()
		if capacity {
			return true
		}
		select {
		case <-q.space:
		case <-q.closed:
			return false
		}
	}
}

func (q *runtimeControlledTCPProbeDelayFIFO) enqueue(frame []byte, arrivedAt time.Time) error {
	delay := time.Duration(q.delay.Load())
	releaseAt := arrivedAt
	if delay > 0 && isExactPathProbeReply(frame) {
		releaseAt = arrivedAt.Add(delay)
	}
	owned := append([]byte(nil), frame...)

	q.mu.Lock()
	defer q.mu.Unlock()
	if q.fatalErr != nil {
		return q.fatalErr
	}
	queuedFrames := len(q.frames) - q.head
	if queuedFrames >= q.limits.frames || len(owned) > q.limits.bytes-q.bytes {
		q.fatalErr = fmt.Errorf(
			"%w: queued_frames=%d frame_bytes=%d queued_bytes=%d limits=(%d,%d)",
			errRuntimeControlledTCPProbeQueueOverflow,
			queuedFrames,
			len(owned),
			q.bytes,
			q.limits.frames,
			q.limits.bytes,
		)
		q.signalLocked()
		return q.fatalErr
	}
	if q.head > 0 && len(q.frames) == cap(q.frames) {
		copy(q.frames, q.frames[q.head:])
		q.frames = q.frames[:queuedFrames]
		q.head = 0
	}
	q.frames = append(q.frames, runtimeControlledTCPProbeFrame{frame: owned, releaseAt: releaseAt})
	q.bytes += len(owned)
	if queuedFrames == 0 {
		q.signalLocked()
	}
	return nil
}

func (q *runtimeControlledTCPProbeDelayFIFO) finishSource(err error) {
	if err == nil {
		err = io.EOF
	}
	q.mu.Lock()
	if !q.sourceStopped {
		q.sourceStopped = true
		q.sourceErr = err
		q.signalLocked()
	}
	q.mu.Unlock()
}

func (q *runtimeControlledTCPProbeDelayFIFO) signalLocked() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *runtimeControlledTCPProbeDelayFIFO) Read(buf []byte) (int, error) {
	q.readMu.Lock()
	defer q.readMu.Unlock()

	for {
		q.mu.Lock()
		if q.fatalErr != nil {
			err := q.fatalErr
			q.mu.Unlock()
			return 0, err
		}
		select {
		case <-q.closed:
			q.mu.Unlock()
			return 0, net.ErrClosed
		default:
		}

		if q.head < len(q.frames) {
			head := q.frames[q.head]
			wait := head.releaseAt.Sub(q.clock.Now())
			if wait <= 0 {
				q.frames[q.head] = runtimeControlledTCPProbeFrame{}
				q.head++
				q.bytes -= len(head.frame)
				if q.head == len(q.frames) {
					q.frames = q.frames[:0]
					q.head = 0
				}
				q.signalSpaceLocked()
				q.mu.Unlock()
				if len(buf) < len(head.frame) {
					copy(buf, head.frame)
					return len(buf), io.ErrShortBuffer
				}
				return copy(buf, head.frame), nil
			}
			q.mu.Unlock()
			timer := q.clock.NewTimerAt(head.releaseAt)
			select {
			case <-timer.C():
			case <-q.wake:
			case <-q.closed:
			}
			timer.Stop()
			continue
		}

		if q.sourceStopped {
			err := q.sourceErr
			q.mu.Unlock()
			return 0, err
		}
		q.mu.Unlock()
		select {
		case <-q.wake:
		case <-q.closed:
		}
	}
}

func (q *runtimeControlledTCPProbeDelayFIFO) signalSpaceLocked() {
	select {
	case q.space <- struct{}{}:
	default:
	}
}

func isExactPathProbeReply(frame []byte) bool {
	if !isPathProbeControl(frame, proto.CtrlPathProbeReply) {
		return false
	}
	_, err := proto.DecodeProbe(frame[proto.HeaderSize:])
	return err == nil
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

func (p *runtimeControlledTCPPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	select {
	case <-ctx.Done():
		return transport.PathQuality{}, ctx.Err()
	default:
		return p.Quality(), nil
	}
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
	p.signalClosed()
	err := p.raw.Close()
	p.waitProbeDelayPump()
	return err
}

type runtimeControlledTCPPathStats struct {
	DataWriteBytesPerSecond uint64
	DataReadBytesPerSecond  uint64
	PhysicalDataBytes       uint64
	PhysicalDataWriteBytes  uint64
	PhysicalDataReadBytes   uint64
	DelayedDataWrites       uint64
	DelayedDataReads        uint64
	DataWriteBlocked        time.Duration
	DataReadBlocked         time.Duration
	CumulativeDataBlocked   time.Duration
}

type runtimeControlledTCPDataPath struct {
	mu sync.Mutex

	writeTurn chan struct{}
	readTurn  chan struct{}

	writeBytesPerSecond uint64
	readBytesPerSecond  uint64
	physicalWriteBytes  uint64
	physicalReadBytes   uint64
	delayedWrites       uint64
	delayedReads        uint64
	writeBlocked        time.Duration
	readBlocked         time.Duration
}

func newRuntimeControlledTCPDataPath() *runtimeControlledTCPDataPath {
	p := &runtimeControlledTCPDataPath{
		writeTurn: make(chan struct{}, 1),
		readTurn:  make(chan struct{}, 1),
	}
	p.writeTurn <- struct{}{}
	p.readTurn <- struct{}{}
	return p
}

func (p *runtimeControlledTCPDataPath) snapshot() runtimeControlledTCPPathStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return runtimeControlledTCPPathStats{
		DataWriteBytesPerSecond: p.writeBytesPerSecond,
		DataReadBytesPerSecond:  p.readBytesPerSecond,
		PhysicalDataBytes:       p.physicalWriteBytes + p.physicalReadBytes,
		PhysicalDataWriteBytes:  p.physicalWriteBytes,
		PhysicalDataReadBytes:   p.physicalReadBytes,
		DelayedDataWrites:       p.delayedWrites,
		DelayedDataReads:        p.delayedReads,
		DataWriteBlocked:        p.writeBlocked,
		DataReadBlocked:         p.readBlocked,
		CumulativeDataBlocked:   p.writeBlocked + p.readBlocked,
	}
}

func (p *runtimeControlledTCPDataPath) rate(write bool) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if write {
		return p.writeBytesPerSecond
	}
	return p.readBytesPerSecond
}

func (p *runtimeControlledTCPDataPath) recordWriteBytes(n uint64) {
	p.mu.Lock()
	p.physicalWriteBytes += n
	p.mu.Unlock()
}

func (p *runtimeControlledTCPDataPath) recordReadBytes(n uint64) {
	p.mu.Lock()
	p.physicalReadBytes += n
	p.mu.Unlock()
}

func (p *runtimeControlledTCPDataPath) beginDelay(write bool) {
	p.mu.Lock()
	if write {
		p.delayedWrites++
	} else {
		p.delayedReads++
	}
	p.mu.Unlock()
}

func (p *runtimeControlledTCPDataPath) addBlocked(write bool, blocked time.Duration) {
	p.mu.Lock()
	if write {
		p.writeBlocked += blocked
	} else {
		p.readBlocked += blocked
	}
	p.mu.Unlock()
}

func runtimeControlledTCPDataDelay(frameBytes int, bytesPerSecond uint64) time.Duration {
	if frameBytes <= 0 || bytesPerSecond == 0 {
		return 0
	}
	// Every supported fixture carrier bounds a complete frame far below the
	// point where this nanosecond conversion can overflow uint64.
	nanoseconds := uint64(frameBytes) * uint64(time.Second)
	return time.Duration((nanoseconds-1)/bytesPerSecond + 1)
}

func (p *runtimeControlledTCPPath) delayData(frameBytes int, write bool) error {
	if p == nil || p.dataPath == nil {
		return nil
	}
	if runtimeControlledTCPDataDelay(frameBytes, p.dataPath.rate(write)) <= 0 {
		return nil
	}
	p.dataPath.beginDelay(write)
	started := time.Now()
	turn := p.dataPath.readTurn
	if write {
		turn = p.dataPath.writeTurn
	}
	select {
	case <-turn:
		defer func() { turn <- struct{}{} }()
	case <-p.probeDelayClosed:
		p.dataPath.addBlocked(write, time.Since(started))
		return net.ErrClosed
	}
	delay := runtimeControlledTCPDataDelay(frameBytes, p.dataPath.rate(write))
	if delay <= 0 {
		p.dataPath.addBlocked(write, time.Since(started))
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	var err error
	select {
	case <-timer.C:
	case <-p.probeDelayClosed:
		err = net.ErrClosed
	}
	p.dataPath.addBlocked(write, time.Since(started))
	return err
}

type runtimePathWriteResult struct {
	n   int
	err error
}

type runtimePathWriteGate struct {
	entered     chan struct{}
	release     chan struct{}
	result      chan runtimePathWriteResult
	releaseOnce sync.Once
	frameType   proto.FrameType
}

func newRuntimePathWriteGate(frameType proto.FrameType) *runtimePathWriteGate {
	return &runtimePathWriteGate{
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
		result:    make(chan runtimePathWriteResult, 1),
		frameType: frameType,
	}
}

func (g *runtimePathWriteGate) matches(frame []byte) bool {
	if g == nil || len(frame) < proto.HeaderSize {
		return false
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	return err == nil && header.Type == g.frameType
}

func (g *runtimePathWriteGate) Release() {
	if g != nil {
		g.releaseOnce.Do(func() { close(g.release) })
	}
}

func (t *runtimeControlledTCPTransport) ArmNextDataWrite(pathName string) (*runtimePathWriteGate, error) {
	path, err := t.latestDialGeneration(pathName)
	if err != nil {
		return nil, err
	}
	gate := newRuntimePathWriteGate(proto.FrameData)
	path.writeGateMu.Lock()
	defer path.writeGateMu.Unlock()
	if path.writeGate != nil {
		return nil, fmt.Errorf("controlled path %q already has an armed write gate", pathName)
	}
	path.writeGate = gate
	return gate, nil
}

type runtimeTrackedPacketFactory struct {
	mu      sync.Mutex
	conns   []net.PacketConn
	blocked bool
}

func (f *runtimeTrackedPacketFactory) Dial(_ context.Context, address string) (PacketEndpoint, error) {
	f.mu.Lock()
	blocked := f.blocked
	f.mu.Unlock()
	if blocked {
		return PacketEndpoint{}, errors.New("tracked packet factory is blocked")
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return PacketEndpoint{}, err
	}
	f.mu.Lock()
	f.conns = append(f.conns, conn)
	f.mu.Unlock()
	return testPacketEndpointForAddress(conn, address)
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

func TestRuntimeControlledTCPDataShapingAndStats(t *testing.T) {
	controlled := newRuntimeControlledTCPTransport(t)
	client, server := net.Pipe()
	peer := tadapter.Wrap(server)
	defer peer.Close()
	controlled.dialHook = func(context.Context, transport.PathSpec) (transport.PathConn, net.Conn, error) {
		return tadapter.Wrap(client), client, nil
	}

	dataFrame := runtimeControlledTCPTestFrame(t, proto.FrameData, 0, 32)
	rate := uint64(len(dataFrame)) * 50 // One frame takes 20ms.
	if err := controlled.SetDataWriteRate("A", rate); err != nil {
		t.Fatal(err)
	}
	dialed, err := controlled.dialPath(context.Background(), controlled.Spec("unused", "A"))
	if err != nil {
		t.Fatal(err)
	}
	path := dialed.(*runtimeControlledTCPPath)
	if err := controlled.SetDataReadRate("A", rate); err != nil {
		t.Fatal(err)
	}

	for _, code := range []proto.CtrlCode{
		proto.CtrlHello, proto.CtrlHelloAck, proto.CtrlPathProbe, proto.CtrlPathProbeReply,
	} {
		control := runtimeControlledTCPTestFrame(t, proto.FrameCtrl, proto.FlagsForCtrl(code), 8)
		runtimeControlledTCPWriteAndReceive(t, path, peer, control)
		runtimeControlledTCPWriteAndReceive(t, peer, path, control)
	}
	stats, err := controlled.PathStats("A")
	if err != nil {
		t.Fatal(err)
	}
	if stats.PhysicalDataBytes != 0 || stats.DelayedDataWrites != 0 || stats.DelayedDataReads != 0 {
		t.Fatalf("control frames changed DATA stats: %+v", stats)
	}

	writeStarted := time.Now()
	runtimeControlledTCPWriteAndReceive(t, path, peer, dataFrame)
	writeElapsed := time.Since(writeStarted)
	readStarted := time.Now()
	runtimeControlledTCPWriteAndReceive(t, peer, path, dataFrame)
	readElapsed := time.Since(readStarted)
	if writeElapsed < 15*time.Millisecond || readElapsed < 15*time.Millisecond {
		t.Fatalf("DATA delay write=%s read=%s, want each near 20ms", writeElapsed, readElapsed)
	}

	stats, err = controlled.PathStats("A")
	if err != nil {
		t.Fatal(err)
	}
	if stats.DataWriteBytesPerSecond != rate || stats.DataReadBytesPerSecond != rate {
		t.Fatalf("configured DATA rates = (%d,%d), want (%d,%d)", stats.DataWriteBytesPerSecond, stats.DataReadBytesPerSecond, rate, rate)
	}
	if stats.PhysicalDataWriteBytes != uint64(len(dataFrame)) || stats.PhysicalDataReadBytes != uint64(len(dataFrame)) {
		t.Fatalf("physical DATA bytes write=%d read=%d, want %d each", stats.PhysicalDataWriteBytes, stats.PhysicalDataReadBytes, len(dataFrame))
	}
	if stats.PhysicalDataBytes != 2*uint64(len(dataFrame)) {
		t.Fatalf("total physical DATA bytes=%d, want %d", stats.PhysicalDataBytes, 2*len(dataFrame))
	}
	if stats.DelayedDataWrites != 1 || stats.DelayedDataReads != 1 {
		t.Fatalf("delayed DATA calls write=%d read=%d, want 1 each", stats.DelayedDataWrites, stats.DelayedDataReads)
	}
	if stats.DataWriteBlocked < 15*time.Millisecond || stats.DataReadBlocked < 15*time.Millisecond {
		t.Fatalf("blocked DATA duration write=%s read=%s, want each near 20ms", stats.DataWriteBlocked, stats.DataReadBlocked)
	}
	if stats.CumulativeDataBlocked != stats.DataWriteBlocked+stats.DataReadBlocked {
		t.Fatalf("cumulative blocked=%s, want %s", stats.CumulativeDataBlocked, stats.DataWriteBlocked+stats.DataReadBlocked)
	}
}

func TestRuntimeControlledTCPDataDelayIsCloseCancellable(t *testing.T) {
	t.Run("write", func(t *testing.T) {
		controlled := newRuntimeControlledTCPTransport(t)
		client, server := net.Pipe()
		defer server.Close()
		controlled.dialHook = func(context.Context, transport.PathSpec) (transport.PathConn, net.Conn, error) {
			return tadapter.Wrap(client), client, nil
		}
		if err := controlled.SetDataWriteRate("A", 1); err != nil {
			t.Fatal(err)
		}
		dialed, err := controlled.dialPath(context.Background(), controlled.Spec("unused", "A"))
		if err != nil {
			t.Fatal(err)
		}
		dataFrame := runtimeControlledTCPTestFrame(t, proto.FrameData, 0, 8)
		gate, err := controlled.ArmNextDataWrite("A")
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			_, err := dialed.Write(dataFrame)
			result <- err
		}()
		select {
		case <-gate.entered:
		case <-time.After(time.Second):
			t.Fatal("DATA write did not enter gate")
		}
		gate.Release()
		deadline := time.Now().Add(time.Second)
		for {
			stats, statsErr := controlled.PathStats("A")
			if statsErr != nil {
				t.Fatal(statsErr)
			}
			if stats.DelayedDataWrites == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("DATA write did not enter shaping delay")
			}
			time.Sleep(time.Millisecond)
		}
		controlled.close()
		select {
		case err := <-result:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("cancelled DATA write error=%v, want %v", err, net.ErrClosed)
			}
		case <-time.After(time.Second):
			t.Fatal("close did not cancel DATA write delay")
		}
		stats, err := controlled.PathStats("A")
		if err != nil {
			t.Fatal(err)
		}
		if stats.DelayedDataWrites != 1 || stats.PhysicalDataWriteBytes != 0 {
			t.Fatalf("cancelled DATA write stats: %+v", stats)
		}
	})

	t.Run("read", func(t *testing.T) {
		controlled := newRuntimeControlledTCPTransport(t)
		client, server := net.Pipe()
		peer := tadapter.Wrap(server)
		defer peer.Close()
		controlled.dialHook = func(context.Context, transport.PathSpec) (transport.PathConn, net.Conn, error) {
			return tadapter.Wrap(client), client, nil
		}
		if err := controlled.SetDataReadRate("A", 1); err != nil {
			t.Fatal(err)
		}
		dialed, err := controlled.dialPath(context.Background(), controlled.Spec("unused", "A"))
		if err != nil {
			t.Fatal(err)
		}
		dataFrame := runtimeControlledTCPTestFrame(t, proto.FrameData, 0, 8)
		readResult := make(chan error, 1)
		go func() {
			buf := make([]byte, len(dataFrame))
			_, err := dialed.Read(buf)
			readResult <- err
		}()
		if _, err := peer.Write(dataFrame); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(time.Second)
		for {
			stats, statsErr := controlled.PathStats("A")
			if statsErr != nil {
				t.Fatal(statsErr)
			}
			if stats.PhysicalDataReadBytes == uint64(len(dataFrame)) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("DATA read did not enter shaping delay")
			}
			time.Sleep(time.Millisecond)
		}
		controlled.close()
		select {
		case err := <-readResult:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("cancelled DATA read error=%v, want %v", err, net.ErrClosed)
			}
		case <-time.After(time.Second):
			t.Fatal("close did not cancel DATA read delay")
		}
		stats, err := controlled.PathStats("A")
		if err != nil {
			t.Fatal(err)
		}
		if stats.DelayedDataReads != 1 || stats.PhysicalDataReadBytes != uint64(len(dataFrame)) {
			t.Fatalf("cancelled DATA read stats: %+v", stats)
		}
	})
}

func runtimeControlledTCPTestFrame(t testing.TB, frameType proto.FrameType, flags uint16, payloadBytes int) []byte {
	t.Helper()
	frame := make([]byte, proto.HeaderSize+payloadBytes)
	if err := (proto.Header{Version: proto.Version, Type: frameType, Last: true, Flags: flags, Seq: 1}).Encode(frame); err != nil {
		t.Fatal(err)
	}
	for i := proto.HeaderSize; i < len(frame); i++ {
		frame[i] = byte(i)
	}
	return frame
}

func runtimeControlledTCPWriteAndReceive(t testing.TB, writer, reader transport.PathConn, frame []byte) {
	t.Helper()
	readResult := make(chan error, 1)
	go func() {
		buf := make([]byte, len(frame))
		n, err := reader.Read(buf)
		if err == nil && (n != len(frame) || !reflect.DeepEqual(buf[:n], frame)) {
			err = fmt.Errorf("received frame length/content mismatch: got %d bytes", n)
		}
		readResult <- err
	}()
	if n, err := writer.Write(frame); err != nil || n != len(frame) {
		t.Fatalf("write frame = (%d,%v), want (%d,nil)", n, err, len(frame))
	}
	select {
	case err := <-readResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("frame receive timed out")
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
		Name: "terminal-udp", Carrier: CarrierUDP, Conn: &runtimeFailingPacketConn{err: boom}, MaxDatagramSize: 1400,
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
