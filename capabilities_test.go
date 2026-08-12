package rendr

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/virtualif"
)

const l3CapabilityRejectAttempts = 128

func TestDialerAdvertisesL3IdentityCapability(t *testing.T) {
	ln, err := listenRuntimeSourcesWithConfig(
		ListenConfig{AcceptL3Identity: true},
		runtimeTCPSource("tcp", "127.0.0.1:0"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- c
	}()

	client, err := (&sessionDialer{
		Root:               Path("tcp", PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
		PreserveL3Identity: true,
	}).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()
	stats := server.(ConnectionObserver).Stats()
	if stats.PeerCaps&proto.CapsL3Identity == 0 {
		t.Fatalf("server PeerCaps=0x%08x missing CapsL3Identity", stats.PeerCaps)
	}
	if stats.PeerCaps&proto.CapsPacketMode != 0 {
		t.Fatalf("stream PeerCaps=0x%08x unexpectedly has CapsPacketMode", stats.PeerCaps)
	}
}

func TestDialPacketAdvertisesL3IdentityAndPacketMode(t *testing.T) {
	ln, err := listenRuntimeSourcesWithConfig(
		ListenConfig{AcceptL3Identity: true},
		runtimeUDPSource("udpflow", "127.0.0.1:0"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptPacket(ctx)
		if err != nil {
			t.Errorf("accept packet: %v", err)
			return
		}
		accepted <- c
	}()

	client, err := (&sessionDialer{
		Root:               Path("udp", PathSpec{Transport: "udpflow", Address: ln.Addr().String()}),
		PreserveL3Identity: true,
	}).DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()
	stats := server.(ConnectionObserver).Stats()
	if stats.PeerCaps&proto.CapsL3Identity == 0 {
		t.Fatalf("packet PeerCaps=0x%08x missing CapsL3Identity", stats.PeerCaps)
	}
	if stats.PeerCaps&proto.CapsPacketMode == 0 {
		t.Fatalf("packet PeerCaps=0x%08x missing CapsPacketMode", stats.PeerCaps)
	}
}

func TestRuntimeDialRejectsPeerWithoutL3IdentityCapabilityHighCount(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	runtime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	var closed atomic.Int64
	if err := runtime.RegisterStreamFactory("l3-close-tracked-tcp", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
			if err != nil {
				return nil, err
			}
			return &l3CloseTrackedConn{Conn: conn, closed: &closed}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	config := SessionConfig{
		Root: Path("tcp", PathSpec{
			Transport: "l3-close-tracked-tcp",
			Address:   ln.Addr().String(),
		}),
		PreserveL3Identity: true,
	}
	runCtx, cancelRun := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelRun()
	for i := 0; i < l3CapabilityRejectAttempts; i++ {
		attemptCtx, cancelAttempt := context.WithTimeout(runCtx, time.Second)
		conn, dialErr := runtime.Dial(attemptCtx, config)
		cancelAttempt()
		if conn != nil {
			_ = conn.Close()
			t.Fatalf("attempt %d returned a stream session without peer L3 capability", i)
		}
		assertPeerL3IdentityUnsupported(t, i, dialErr)
	}
	assertL3RejectedCarriersClosed(t, &closed)
	assertNoL3HandshakeSlots(t, ln)
	if flows := ln.FlowIDs(); len(flows) != 0 {
		t.Fatalf("incapable stream listener retained %d active flows", len(flows))
	}
	acceptCtx, cancelAccept := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelAccept()
	conn, acceptErr := ln.Accept(acceptCtx)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("incapable stream listener published an accepted session")
	}
	if !errors.Is(acceptErr, context.DeadlineExceeded) {
		t.Fatalf("Accept error = %v, want deadline exceeded", acceptErr)
	}
}

func TestRuntimeDialPacketRejectsPeerWithoutL3IdentityCapabilityHighCount(t *testing.T) {
	ln, err := listenRuntimeUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	runtime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	var closed atomic.Int64
	if err := runtime.RegisterPacketFactory("l3-close-tracked-udp", PacketFactory{
		Carrier: CarrierUDP,
		Dial: func(context.Context, string) (net.PacketConn, error) {
			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			return &l3CloseTrackedPacketConn{PacketConn: conn, closed: &closed}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	config := SessionConfig{
		Root: Path("udp", PathSpec{
			Transport: "l3-close-tracked-udp",
			Address:   ln.Addr().String(),
		}),
		PreserveL3Identity: true,
	}
	runCtx, cancelRun := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelRun()
	for i := 0; i < l3CapabilityRejectAttempts; i++ {
		attemptCtx, cancelAttempt := context.WithTimeout(runCtx, time.Second)
		conn, dialErr := runtime.DialPacket(attemptCtx, config)
		cancelAttempt()
		if conn != nil {
			_ = conn.Close()
			t.Fatalf("attempt %d returned a packet session without peer L3 capability", i)
		}
		assertPeerL3IdentityUnsupported(t, i, dialErr)
	}
	assertL3RejectedCarriersClosed(t, &closed)
	assertNoL3HandshakeSlots(t, ln)
	if flows := ln.FlowIDs(); len(flows) != 0 {
		t.Fatalf("incapable packet listener retained %d active flows", len(flows))
	}
	acceptCtx, cancelAccept := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelAccept()
	conn, acceptErr := ln.AcceptPacket(acceptCtx)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("incapable packet listener published an accepted session")
	}
	if !errors.Is(acceptErr, context.DeadlineExceeded) {
		t.Fatalf("AcceptPacket error = %v, want deadline exceeded", acceptErr)
	}
}

func assertPeerL3IdentityUnsupported(t *testing.T, attempt int, err error) {
	t.Helper()
	var capabilityErr *virtualif.Error
	if !errors.As(err, &capabilityErr) {
		t.Fatalf("attempt %d error = %v, want *virtualif.Error", attempt, err)
	}
	if capabilityErr.Reason != virtualif.ReasonPeerL3IdentityUnsupported {
		t.Fatalf("attempt %d reason = %q, want %q", attempt, capabilityErr.Reason, virtualif.ReasonPeerL3IdentityUnsupported)
	}
}

func assertL3RejectedCarriersClosed(t *testing.T, closed *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for closed.Load() != l3CapabilityRejectAttempts && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := closed.Load(); got != l3CapabilityRejectAttempts {
		t.Fatalf("temporary carrier closes = %d, want %d", got, l3CapabilityRejectAttempts)
	}
}

func assertNoL3HandshakeSlots(t *testing.T, fixture *runtimeListenerFixture) {
	t.Helper()
	listener := fixture.listener
	deadline := time.Now().Add(time.Second)
	for len(listener.handshakes) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if held := len(listener.handshakes); held != 0 {
		t.Fatalf("incapable listener retained %d handshake slots", held)
	}
}

type l3CloseTrackedConn struct {
	net.Conn
	closed *atomic.Int64
	once   sync.Once
}

func (c *l3CloseTrackedConn) Close() error {
	c.once.Do(func() { c.closed.Add(1) })
	return c.Conn.Close()
}

type l3CloseTrackedPacketConn struct {
	net.PacketConn
	closed *atomic.Int64
	once   sync.Once
}

func (c *l3CloseTrackedPacketConn) Close() error {
	c.once.Do(func() { c.closed.Add(1) })
	return c.PacketConn.Close()
}
