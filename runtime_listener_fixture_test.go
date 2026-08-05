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
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
	gadapter "github.com/FrankoonG/rendr/transport/gvisor"
	qadapter "github.com/FrankoonG/rendr/transport/quic"
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
			framed, listenErr := gadapter.Listen(source.address)
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

type runtimeTrackedPathListener struct {
	transport.PathListener
	mu       sync.Mutex
	accepted []transport.PathConn
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
