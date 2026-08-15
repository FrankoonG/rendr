package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
	transporttcp "github.com/FrankoonG/rendr/transport/tcp"
)

func TestMobilityCapabilityCollectorUnionsProviderEvidenceRegardlessOfPathOrder(t *testing.T) {
	runtime := newMobilityCapabilityRuntime()
	var genericDials atomic.Int32
	if err := runtime.RegisterStreamFactory("generic-first", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(context.Context, string) (net.Conn, error) {
			genericDials.Add(1)
			return nil, errors.New("unexpected generic dial")
		},
	}); err != nil {
		t.Fatal(err)
	}
	provider := newMobilityCapabilityFactory(
		leafmobility.OperationTCPRepair,
		leafmobility.OperationQUICCIDRebind,
	)
	if err := runtime.RegisterFramedFactory("provider", FramedFactory{
		Carrier: CarrierTCP,
		Factory: provider,
	}); err != nil {
		t.Fatal(err)
	}

	resolver := frozenMobilityCapabilityResolver(t, runtime)
	orders := [][]PathSpec{
		{
			{Transport: "generic-first"},
			{Transport: "provider"},
		},
		{
			{Transport: "provider"},
			{Transport: "generic-first"},
		},
	}
	for _, paths := range orders {
		capabilities, err := resolver.mobilityCapabilities(paths, leafmobility.SessionStream)
		if err != nil {
			t.Fatal(err)
		}
		assertMobilityCapabilityOperations(t, capabilities,
			leafmobility.OperationTCPRepair,
			leafmobility.OperationQUICCIDRebind,
		)
	}
	if got := genericDials.Load(); got != 0 {
		t.Fatalf("generic factory dial calls = %d, want 0", got)
	}
}

func TestMobilityCapabilityCollectorIgnoresGenericFactoryMetadata(t *testing.T) {
	runtime := newMobilityCapabilityRuntime()
	var streamDials, packetDials atomic.Int32
	if err := runtime.RegisterStreamFactory("tcp-repair-owned", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(context.Context, string) (net.Conn, error) {
			streamDials.Add(1)
			return nil, errors.New("unexpected stream dial")
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.RegisterPacketFactory("quic-cid-rebind", PacketFactory{
		Carrier: CarrierTCP,
		Dial: func(context.Context, string) (net.PacketConn, error) {
			packetDials.Add(1)
			return nil, errors.New("unexpected packet dial")
		},
	}); err != nil {
		t.Fatal(err)
	}

	paths := []PathSpec{
		{Transport: "tcp-repair-owned"},
		{Transport: "quic-cid-rebind"},
	}
	resolver := frozenMobilityCapabilityResolver(t, runtime)
	for _, session := range []leafmobility.Session{
		leafmobility.SessionStream,
		leafmobility.SessionPacket,
	} {
		capabilities, err := resolver.mobilityCapabilities(paths, session)
		if err != nil {
			t.Fatal(err)
		}
		assertMobilityCapabilityOperations(t, capabilities)
	}
	if streamDials.Load() != 0 || packetDials.Load() != 0 {
		t.Fatalf("collector dialed generic factories: stream=%d packet=%d", streamDials.Load(), packetDials.Load())
	}
}

func TestMobilityCapabilityCollectorDeduplicatesProviderPaths(t *testing.T) {
	provider := newMobilityCapabilityFactory(leafmobility.OperationUDPFlowRebind)
	resolver := &pathFactoryResolver{
		framed: map[string]transport.PathFactory{"provider": provider},
	}
	capabilities, err := resolver.mobilityCapabilities([]PathSpec{
		{Transport: "provider", Address: "first"},
		{Transport: "provider", Address: "second"},
		{Transport: "provider", Address: "third"},
	}, leafmobility.SessionPacket)
	if err != nil {
		t.Fatal(err)
	}
	assertMobilityCapabilityOperations(t, capabilities, leafmobility.OperationUDPFlowRebind)
	if got := provider.evidenceCalls.Load(); got != 1 {
		t.Fatalf("provider evidence calls = %d, want 1", got)
	}
}

func TestMobilityCapabilityCollectorFiltersOperationsBySession(t *testing.T) {
	provider := newMobilityCapabilityFactory(
		leafmobility.OperationTCPRepair,
		leafmobility.OperationQUICCIDRebind,
		leafmobility.OperationUDPFlowRebind,
		leafmobility.OperationGVisorLinkRebind,
	)
	resolver := &pathFactoryResolver{
		framed: map[string]transport.PathFactory{"provider": provider},
	}
	paths := []PathSpec{{Transport: "provider"}}

	stream, err := resolver.mobilityCapabilities(paths, leafmobility.SessionStream)
	if err != nil {
		t.Fatal(err)
	}
	assertMobilityCapabilityOperations(t, stream,
		leafmobility.OperationTCPRepair,
		leafmobility.OperationQUICCIDRebind,
		leafmobility.OperationGVisorLinkRebind,
	)

	packet, err := resolver.mobilityCapabilities(paths, leafmobility.SessionPacket)
	if err != nil {
		t.Fatal(err)
	}
	assertMobilityCapabilityOperations(t, packet,
		leafmobility.OperationQUICCIDRebind,
		leafmobility.OperationUDPFlowRebind,
	)
}

func TestMobilityCapabilityPromotedFactoryEvidenceFailsBeforeDial(t *testing.T) {
	runtime := newMobilityCapabilityRuntime()
	base := newMobilityCapabilityFactory(leafmobility.OperationTCPRepair)
	wrapper := &promotedMobilityCapabilityFactory{mobilityCapabilityFactory: base}
	if _, ok := any(wrapper).(leafmobility.ImplementationProvider); !ok {
		t.Fatal("embedded provider method was not promoted")
	}
	if err := runtime.RegisterFramedFactory("wrapped", FramedFactory{
		Carrier: CarrierTCP,
		Factory: wrapper,
	}); err != nil {
		t.Fatal(err)
	}

	conn, err := runtime.Dial(context.Background(), SessionConfig{
		Root: Path("wrapped", PathSpec{Transport: "wrapped", Address: "unused"}),
	})
	if conn != nil {
		_ = conn.Close()
		t.Fatal("Dial returned a connection for promoted implementation evidence")
	}
	if !errors.Is(err, leafmobility.ErrImplementationOwnerMismatch) {
		t.Fatalf("Dial error = %v, want %v", err, leafmobility.ErrImplementationOwnerMismatch)
	}
	if base.dialCalls.Load() != 0 || base.probeCalls.Load() != 0 {
		t.Fatalf("factory used before rejection: dials=%d probes=%d", base.dialCalls.Load(), base.probeCalls.Load())
	}
}

func TestMobilityCapabilityListenerFiltersSessionKinds(t *testing.T) {
	runtime := newMobilityCapabilityRuntime()
	stream := newMobilityCapabilityListener(transport.PathSessionStream, leafmobility.OperationTCPRepair)
	packet := newMobilityCapabilityListener(transport.PathSessionPacket, leafmobility.OperationUDPFlowRebind)
	anySession := newMobilityCapabilityListener(transport.PathSessionAny, leafmobility.OperationQUICCIDRebind)

	listener, err := runtime.Listen(ListenConfig{Framed: []FramedSource{
		{Name: "stream", Carrier: CarrierTCP, Listener: stream},
		{Name: "packet", Carrier: CarrierUDP, Listener: packet},
		{Name: "any", Carrier: CarrierTCP, Listener: anySession},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	assertMobilityCapabilityOperations(t, listener.streamMobility,
		leafmobility.OperationTCPRepair,
		leafmobility.OperationQUICCIDRebind,
	)
	assertMobilityCapabilityOperations(t, listener.packetMobility,
		leafmobility.OperationQUICCIDRebind,
		leafmobility.OperationUDPFlowRebind,
	)
}

func TestMobilityCapabilityListenerIgnoresGenericSources(t *testing.T) {
	runtime := newMobilityCapabilityRuntime()
	stream := newMobilityCapabilityStreamSource(leafmobility.OperationTCPRepair)
	packet := newMobilityCapabilityPacketSource(leafmobility.OperationQUICCIDRebind)

	listener, err := runtime.Listen(ListenConfig{
		Streams: []StreamSource{{Name: "tcp-repair", Carrier: CarrierTCP, Listener: stream}},
		Packets: []PacketSource{{Name: "quic-cid", Carrier: CarrierUDP, Conn: packet}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	assertMobilityCapabilityOperations(t, listener.streamMobility)
	assertMobilityCapabilityOperations(t, listener.packetMobility)
	if stream.evidenceCalls.Load() != 0 || packet.evidenceCalls.Load() != 0 {
		t.Fatalf("generic source evidence was inspected: stream=%d packet=%d",
			stream.evidenceCalls.Load(), packet.evidenceCalls.Load())
	}
}

func TestMobilityCapabilityInvalidListenerProviderFailsBeforeAccept(t *testing.T) {
	runtime := newMobilityCapabilityRuntime()
	listener := newMobilityCapabilityListener(transport.PathSessionAny)
	listener.invalidEvidence = true

	got, err := runtime.Listen(ListenConfig{Framed: []FramedSource{{
		Name: "invalid", Carrier: CarrierTCP, Listener: listener,
	}}})
	if got != nil {
		_ = got.Close()
		t.Fatal("Listen returned a listener for invalid implementation evidence")
	}
	if !errors.Is(err, leafmobility.ErrImplementationOwnerMismatch) {
		t.Fatalf("Listen error = %v, want %v", err, leafmobility.ErrImplementationOwnerMismatch)
	}
	if listener.acceptCalls.Load() != 0 || listener.addrCalls.Load() != 0 || listener.closeCalls.Load() != 0 {
		t.Fatalf("invalid listener was used: accepts=%d addrs=%d closes=%d",
			listener.acceptCalls.Load(), listener.addrCalls.Load(), listener.closeCalls.Load())
	}
	if runtime.listener != nil {
		t.Fatal("invalid provider claimed the Runtime listener slot")
	}
}

func TestMobilityCapabilityRuntimeNegotiatesProviderUnionAndRoundTripsStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	firstListener := newMobilityCapabilityListener(
		transport.PathSessionStream,
		leafmobility.OperationTCPRepair,
	)
	secondListener := newMobilityCapabilityListener(
		transport.PathSessionStream,
		leafmobility.OperationQUICCIDRebind,
	)
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{
		{Name: "first-provider", Carrier: CarrierTCP, Listener: firstListener},
		{Name: "second-provider", Carrier: CarrierTCP, Listener: secondListener},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	firstFactory := newPairedMobilityCapabilityFactory(
		firstListener,
		leafmobility.OperationTCPRepair,
	)
	secondFactory := newPairedMobilityCapabilityFactory(
		secondListener,
		leafmobility.OperationQUICCIDRebind,
	)
	if err := clientRuntime.RegisterFramedFactory("first-provider", FramedFactory{
		Carrier: CarrierTCP,
		Factory: firstFactory,
	}); err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterFramedFactory("second-provider", FramedFactory{
		Carrier: CarrierTCP,
		Factory: secondFactory,
	}); err != nil {
		t.Fatal(err)
	}

	client, err := clientRuntime.Dial(ctx, SessionConfig{Root: Selector("root", []Target{
		Path("first", PathSpec{Transport: "first-provider", Address: "memory"}),
		Path("second", PathSpec{Transport: "second-provider", Address: "memory"}),
	})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	clientConn, ok := client.(*engineBackedConn)
	if !ok {
		t.Fatalf("client connection type = %T, want *engineBackedConn", client)
	}
	serverConn, ok := server.(*acceptedStreamConn)
	if !ok {
		t.Fatalf("server connection type = %T, want *acceptedStreamConn", server)
	}
	wantSupport, err := (leafmobility.OperationTCPRepair | leafmobility.OperationQUICCIDRebind).ProtocolSet()
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []struct {
		name        string
		negotiation func() (supported, required uint16)
	}{
		{name: "client", negotiation: func() (uint16, uint16) {
			n := clientConn.e.LocalNegotiation()
			return uint16(n.MobilitySupported), uint16(n.MobilityRequired)
		}},
		{name: "server", negotiation: func() (uint16, uint16) {
			n := serverConn.engine.LocalNegotiation()
			return uint16(n.MobilitySupported), uint16(n.MobilityRequired)
		}},
	} {
		supported, required := side.negotiation()
		if supported != uint16(wantSupport) || required != 0 {
			t.Fatalf("%s local mobility negotiation = (0x%x,0x%x), want (0x%x,0)",
				side.name, supported, required, uint16(wantSupport))
		}
	}
	if err := clientConn.e.ValidatePeerNegotiation(
		serverConn.engine.LocalNegotiation(),
		serverConn.engine.LocalGraphManifest(),
	); err != nil {
		t.Fatalf("client frozen peer negotiation does not carry provider union: %v", err)
	}
	if err := serverConn.engine.ValidatePeerNegotiation(
		clientConn.e.LocalNegotiation(),
		clientConn.e.LocalGraphManifest(),
	); err != nil {
		t.Fatalf("server frozen peer negotiation does not carry provider union: %v", err)
	}
	if !waitForRuntimePathCount(client, server, 2, 3*time.Second) {
		t.Fatalf("provider paths did not converge after background attachment: client_status=%+v server_status=%+v",
			client.Status(), server.Status())
	}
	assertMobilityCapabilityStreamRoundTrip(t, client, server, []byte("provider-union"))
}

type mobilityCapabilityDriver struct {
	operation leafmobility.Operation
}

func (d *mobilityCapabilityDriver) Operation() leafmobility.Operation { return d.operation }

func (*mobilityCapabilityDriver) Preflight(
	context.Context,
	leafmobility.PreflightRequest,
) (leafmobility.DriverAttempt, leafmobility.PreflightResult, error) {
	return nil, leafmobility.PreflightResult{}, nil
}

type mobilityCapabilityFactory struct {
	drivers       []leafmobility.Driver
	listener      *mobilityCapabilityListener
	evidenceCalls atomic.Int32
	dialCalls     atomic.Int32
	probeCalls    atomic.Int32
}

func newMobilityCapabilityFactory(operations ...leafmobility.Operation) *mobilityCapabilityFactory {
	return &mobilityCapabilityFactory{drivers: mobilityCapabilityDrivers(operations...)}
}

func newPairedMobilityCapabilityFactory(
	listener *mobilityCapabilityListener,
	operations ...leafmobility.Operation,
) *mobilityCapabilityFactory {
	return &mobilityCapabilityFactory{
		drivers:  mobilityCapabilityDrivers(operations...),
		listener: listener,
	}
}

func (f *mobilityCapabilityFactory) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	f.evidenceCalls.Add(1)
	return leafmobility.MustNewImplementationEvidence(f, f.drivers...)
}

func (f *mobilityCapabilityFactory) DialPath(ctx context.Context, _ transport.PathSpec) (transport.PathConn, error) {
	f.dialCalls.Add(1)
	if f.listener == nil {
		return nil, errors.New("unexpected framed dial")
	}
	client, server := net.Pipe()
	serverPath := transporttcp.Wrap(server)
	if err := f.listener.publish(ctx, serverPath); err != nil {
		_ = client.Close()
		_ = serverPath.Close()
		return nil, err
	}
	return transporttcp.Wrap(client), nil
}

func (f *mobilityCapabilityFactory) Probe(context.Context, transport.PathSpec) (transport.PathQuality, error) {
	f.probeCalls.Add(1)
	return transport.PathQuality{}, errors.New("unexpected framed probe")
}

type promotedMobilityCapabilityFactory struct {
	*mobilityCapabilityFactory
}

type mobilityCapabilityListener struct {
	drivers         []leafmobility.Driver
	kind            transport.PathSessionKind
	invalidEvidence bool
	paths           chan transport.PathConn
	closed          chan struct{}
	closeOnce       sync.Once
	acceptCalls     atomic.Int32
	addrCalls       atomic.Int32
	closeCalls      atomic.Int32
}

func newMobilityCapabilityListener(kind transport.PathSessionKind, operations ...leafmobility.Operation) *mobilityCapabilityListener {
	return &mobilityCapabilityListener{
		drivers: mobilityCapabilityDrivers(operations...),
		kind:    kind,
		paths:   make(chan transport.PathConn),
		closed:  make(chan struct{}),
	}
}

func (l *mobilityCapabilityListener) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	if l.invalidEvidence {
		return leafmobility.ImplementationEvidence{}
	}
	return leafmobility.MustNewImplementationEvidence(l, l.drivers...)
}

func (l *mobilityCapabilityListener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	l.acceptCalls.Add(1)
	select {
	case path := <-l.paths:
		return path, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *mobilityCapabilityListener) publish(ctx context.Context, path transport.PathConn) error {
	select {
	case l.paths <- path:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-l.closed:
		return net.ErrClosed
	}
}

func (l *mobilityCapabilityListener) SessionKind() transport.PathSessionKind { return l.kind }

func (l *mobilityCapabilityListener) Close() error {
	l.closeCalls.Add(1)
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *mobilityCapabilityListener) Addr() net.Addr {
	l.addrCalls.Add(1)
	return stringAddr("mobility-capability-framed")
}

type mobilityCapabilityStreamSource struct {
	drivers       []leafmobility.Driver
	evidenceCalls atomic.Int32
	closed        chan struct{}
	closeOnce     sync.Once
}

func newMobilityCapabilityStreamSource(operations ...leafmobility.Operation) *mobilityCapabilityStreamSource {
	return &mobilityCapabilityStreamSource{
		drivers: mobilityCapabilityDrivers(operations...),
		closed:  make(chan struct{}),
	}
}

func (s *mobilityCapabilityStreamSource) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	s.evidenceCalls.Add(1)
	return leafmobility.MustNewImplementationEvidence(s, s.drivers...)
}

func (s *mobilityCapabilityStreamSource) Accept() (net.Conn, error) {
	<-s.closed
	return nil, net.ErrClosed
}

func (s *mobilityCapabilityStreamSource) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (*mobilityCapabilityStreamSource) Addr() net.Addr {
	return stringAddr("mobility-capability-stream")
}

type mobilityCapabilityPacketSource struct {
	drivers       []leafmobility.Driver
	evidenceCalls atomic.Int32
	closed        chan struct{}
	closeOnce     sync.Once
}

func newMobilityCapabilityPacketSource(operations ...leafmobility.Operation) *mobilityCapabilityPacketSource {
	return &mobilityCapabilityPacketSource{
		drivers: mobilityCapabilityDrivers(operations...),
		closed:  make(chan struct{}),
	}
}

func (s *mobilityCapabilityPacketSource) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	s.evidenceCalls.Add(1)
	return leafmobility.MustNewImplementationEvidence(s, s.drivers...)
}

func (s *mobilityCapabilityPacketSource) ReadFrom([]byte) (int, net.Addr, error) {
	<-s.closed
	return 0, nil, net.ErrClosed
}

func (*mobilityCapabilityPacketSource) WriteTo([]byte, net.Addr) (int, error) {
	return 0, net.ErrClosed
}

func (s *mobilityCapabilityPacketSource) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (*mobilityCapabilityPacketSource) LocalAddr() net.Addr {
	return stringAddr("mobility-capability-packet")
}

func (*mobilityCapabilityPacketSource) SetDeadline(time.Time) error      { return nil }
func (*mobilityCapabilityPacketSource) SetReadDeadline(time.Time) error  { return nil }
func (*mobilityCapabilityPacketSource) SetWriteDeadline(time.Time) error { return nil }

func mobilityCapabilityDrivers(operations ...leafmobility.Operation) []leafmobility.Driver {
	drivers := make([]leafmobility.Driver, len(operations))
	for index, operation := range operations {
		drivers[index] = &mobilityCapabilityDriver{operation: operation}
	}
	return drivers
}

func newMobilityCapabilityRuntime() *Runtime {
	return &Runtime{
		streamFactories: make(map[string]StreamFactory),
		packetFactories: make(map[string]PacketFactory),
		framedFactories: make(map[string]FramedFactory),
	}
}

func frozenMobilityCapabilityResolver(t *testing.T, runtime *Runtime) *pathFactoryResolver {
	t.Helper()
	dialer, err := runtime.sessionDialer(SessionConfig{
		Root: Path("freeze", PathSpec{Transport: "tcp", Address: "unused"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return dialer.snapshotFactoryResolver()
}

func assertMobilityCapabilityOperations(
	t *testing.T,
	capabilities []leafmobility.Capability,
	want ...leafmobility.Operation,
) {
	t.Helper()
	if len(capabilities) != len(want) {
		t.Fatalf("capability count = %d, want %d", len(capabilities), len(want))
	}
	for index, capability := range capabilities {
		if got := capability.Operation(); got != want[index] {
			t.Fatalf("capability[%d] = %#x, want %#x", index, got, want[index])
		}
	}
}

func assertMobilityCapabilityStreamRoundTrip(t *testing.T, client, server Conn, payload []byte) {
	t.Helper()
	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeErr <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("server payload = %q, want %q", got, payload)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}

	go func() {
		_, err := server.Write(payload)
		writeErr <- err
	}()
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("client payload = %q, want %q", got, payload)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}

var (
	_ leafmobility.Driver                 = (*mobilityCapabilityDriver)(nil)
	_ leafmobility.ImplementationProvider = (*mobilityCapabilityFactory)(nil)
	_ transport.PathFactory               = (*mobilityCapabilityFactory)(nil)
	_ leafmobility.ImplementationProvider = (*mobilityCapabilityListener)(nil)
	_ transport.PathListener              = (*mobilityCapabilityListener)(nil)
	_ leafmobility.ImplementationProvider = (*mobilityCapabilityStreamSource)(nil)
	_ net.Listener                        = (*mobilityCapabilityStreamSource)(nil)
	_ leafmobility.ImplementationProvider = (*mobilityCapabilityPacketSource)(nil)
	_ net.PacketConn                      = (*mobilityCapabilityPacketSource)(nil)
)
