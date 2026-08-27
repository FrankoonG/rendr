package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport/udpflow"
)

const testPacketMaxDatagramSize = udpflow.MaxDatagram

func TestPacketFactoryEndpointPreservesOpaqueAddressAndCustomPeer(t *testing.T) {
	const (
		factoryID = "opaque-packet"
		address   = "caller://opaque token?not=host:port"
	)
	peer := packetContractAddr{
		network: "custom-datagram",
		value:   "peer/object/17",
		padding: []byte{1}, // Keep the dynamic net.Addr value non-comparable.
	}
	conn := &packetContractConn{}
	var receivedAddress string
	resolver := &pathFactoryResolver{packet: map[string]packetPathFactory{
		factoryID: func(_ context.Context, token string) (PacketEndpoint, error) {
			receivedAddress = token
			return PacketEndpoint{Conn: conn, Peer: peer, MaxDatagramSize: testPacketMaxDatagramSize}, nil
		},
	}}

	path, err := resolver.dialPath(context.Background(), PathSpec{
		Transport: factoryID,
		Address:   address,
		Opts:      map[string]string{"flow_id_hex": "01020304050607"},
	})
	if err != nil {
		t.Fatalf("dial opaque packet path: %v", err)
	}
	if receivedAddress != address {
		t.Fatalf("factory address=%q want exact opaque token %q", receivedAddress, address)
	}
	if n, err := path.Write([]byte{0x42}); err != nil || n != 1 {
		t.Fatalf("path Write=(%d,%v) want (1,nil)", n, err)
	}
	writtenPeer := conn.lastPeer()
	if writtenPeer == nil || writtenPeer.Network() != peer.Network() || writtenPeer.String() != peer.String() {
		t.Fatalf("WriteTo peer=(%v,%v) want (%q,%q)", addrNetwork(writtenPeer), addrString(writtenPeer), peer.Network(), peer.String())
	}
}

func TestPacketFactoryEndpointPropagatesFactualDatagramCapacity(t *testing.T) {
	const maxDatagramSize = 1200
	conn := &packetContractConn{}
	resolver := &pathFactoryResolver{packet: map[string]packetPathFactory{
		"capacity": func(context.Context, string) (PacketEndpoint, error) {
			return PacketEndpoint{
				Conn:            conn,
				Peer:            packetContractAddr{network: "custom", value: "peer"},
				MaxDatagramSize: maxDatagramSize,
			}, nil
		},
	}}
	path, err := resolver.dialPath(context.Background(), PathSpec{Transport: "capacity"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = path.Close() })
	reporter, ok := path.(interface{ MaxFrameSize() int })
	if !ok {
		t.Fatalf("generic packet path %T does not report frame capacity", path)
	}
	want := maxDatagramSize - proto.UDPFlowHeaderSize
	if got := reporter.MaxFrameSize(); got != want {
		t.Fatalf("MaxFrameSize=%d want factual %d", got, want)
	}
}

func TestPacketWriteDestinationRejectsTextSpoofWithoutCallbacks(t *testing.T) {
	peer := newPacketSessionAddr([16]byte{1, 2, 3})
	conn := &enginePacketConn{rAddr: peer}
	spoof := &hostilePacketDestinationAddr{}

	if n, err := conn.WriteTo([]byte("must-not-send"), spoof); n != 0 || !errors.Is(err, ErrPacketDestinationMismatch) {
		t.Fatalf("WriteTo hostile destination=(%d,%v), want mismatch", n, err)
	}
	if spoof.networkCalls.Load() != 0 || spoof.stringCalls.Load() != 0 {
		t.Fatalf("hostile destination callbacks invoked: Network=%d String=%d", spoof.networkCalls.Load(), spoof.stringCalls.Load())
	}
}

func TestPacketFactoryEndpointValidationReleasesCleanupAuthority(t *testing.T) {
	type endpointCase struct {
		name       string
		endpoint   func(*packetContractConn) PacketEndpoint
		wantReason FactoryErrorReason
		wantCloses int32
	}
	var typedNilConn *packetContractConn
	var typedNilPeer *packetContractAddr
	tests := []endpointCase{
		{
			name: "nil conn",
			endpoint: func(*packetContractConn) PacketEndpoint {
				return PacketEndpoint{Peer: packetContractAddr{network: "custom", value: "peer"}}
			},
			wantReason: FactoryReasonInvalidPacketConn,
		},
		{
			name: "typed nil conn",
			endpoint: func(*packetContractConn) PacketEndpoint {
				return PacketEndpoint{Conn: typedNilConn, Peer: packetContractAddr{network: "custom", value: "peer"}, MaxDatagramSize: testPacketMaxDatagramSize}
			},
			wantReason: FactoryReasonInvalidPacketConn,
		},
		{
			name: "missing datagram capacity",
			endpoint: func(conn *packetContractConn) PacketEndpoint {
				return PacketEndpoint{Conn: conn, Peer: packetContractAddr{network: "custom", value: "peer"}}
			},
			wantReason: FactoryReasonInvalidPacketCapacity,
			wantCloses: 1,
		},
		{
			name: "negative datagram capacity",
			endpoint: func(conn *packetContractConn) PacketEndpoint {
				return PacketEndpoint{Conn: conn, Peer: packetContractAddr{network: "custom", value: "peer"}, MaxDatagramSize: -1}
			},
			wantReason: FactoryReasonInvalidPacketCapacity,
			wantCloses: 1,
		},
		{
			name: "datagram cannot contain udpflow header",
			endpoint: func(conn *packetContractConn) PacketEndpoint {
				return PacketEndpoint{Conn: conn, Peer: packetContractAddr{network: "custom", value: "peer"}, MaxDatagramSize: 8}
			},
			wantReason: FactoryReasonInvalidPacketCapacity,
			wantCloses: 1,
		},
		{
			name: "nil peer",
			endpoint: func(conn *packetContractConn) PacketEndpoint {
				return PacketEndpoint{Conn: conn, MaxDatagramSize: testPacketMaxDatagramSize}
			},
			wantReason: FactoryReasonInvalidPacketPeer,
			wantCloses: 1,
		},
		{
			name: "typed nil peer",
			endpoint: func(conn *packetContractConn) PacketEndpoint {
				return PacketEndpoint{Conn: conn, Peer: typedNilPeer, MaxDatagramSize: testPacketMaxDatagramSize}
			},
			wantReason: FactoryReasonInvalidPacketPeer,
			wantCloses: 1,
		},
		{
			name: "peer Network panic",
			endpoint: func(conn *packetContractConn) PacketEndpoint {
				return PacketEndpoint{Conn: conn, Peer: panicPacketContractAddr{network: true}, MaxDatagramSize: testPacketMaxDatagramSize}
			},
			wantReason: FactoryReasonInvalidPacketPeer,
			wantCloses: 1,
		},
		{
			name: "peer String panic",
			endpoint: func(conn *packetContractConn) PacketEndpoint {
				return PacketEndpoint{Conn: conn, Peer: panicPacketContractAddr{}, MaxDatagramSize: testPacketMaxDatagramSize}
			},
			wantReason: FactoryReasonInvalidPacketPeer,
			wantCloses: 1,
		},
		{
			name: "empty peer network",
			endpoint: func(conn *packetContractConn) PacketEndpoint {
				return PacketEndpoint{Conn: conn, Peer: packetContractAddr{value: "peer"}, MaxDatagramSize: testPacketMaxDatagramSize}
			},
			wantReason: FactoryReasonInvalidPacketPeer,
			wantCloses: 1,
		},
		{
			name: "empty peer address",
			endpoint: func(conn *packetContractConn) PacketEndpoint {
				return PacketEndpoint{Conn: conn, Peer: packetContractAddr{network: "custom"}, MaxDatagramSize: testPacketMaxDatagramSize}
			},
			wantReason: FactoryReasonInvalidPacketPeer,
			wantCloses: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			budget := newFactoryCallbackBudget(1)
			conn := &packetContractConn{}
			resolver := &pathFactoryResolver{
				runtimeBudget: budget,
				packet: map[string]packetPathFactory{
					"invalid": func(context.Context, string) (PacketEndpoint, error) {
						return test.endpoint(conn), nil
					},
				},
			}
			lease, err := resolver.dialPathForAdoption(context.Background(), PathSpec{Transport: "invalid", Address: "opaque"})
			if lease != nil {
				t.Fatalf("invalid endpoint returned lease %v", lease)
			}
			assertFactoryReason(t, err, "invalid", FactoryKindPacket, test.wantReason)
			if got := conn.closeCalls.Load(); got != test.wantCloses {
				t.Fatalf("Conn.Close calls=%d want %d", got, test.wantCloses)
			}
			if got := len(budget.permits); got != 0 {
				t.Fatalf("retained callback permits=%d want 0", got)
			}
		})
	}
}

func TestPacketFactoryConnectedPeerMismatchFailsSynchronouslyAndCleansOwnership(t *testing.T) {
	actual, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer actual.Close()
	declared, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer declared.Close()
	client, err := net.DialUDP("udp", nil, actual.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}

	const factoryID = "connected-peer-mismatch"
	healthy := &packetContractConn{}
	var calls atomic.Int32
	runtimeUnderTest, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	runtimeUnderTest.factoryCallbackBudget = newFactoryCallbackBudget(1)
	if err := runtimeUnderTest.RegisterPacketFactory(factoryID, PacketFactory{
		Carrier: CarrierUDP,
		Dial: func(context.Context, string) (PacketEndpoint, error) {
			if calls.Add(1) == 1 {
				return PacketEndpoint{Conn: client, Peer: declared.LocalAddr(), MaxDatagramSize: testPacketMaxDatagramSize}, nil
			}
			return PacketEndpoint{Conn: healthy, Peer: declared.LocalAddr(), MaxDatagramSize: testPacketMaxDatagramSize}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	spec := PathSpec{
		Transport: factoryID,
		Address:   "opaque",
		Opts:      map[string]string{"flow_id_hex": "01020304050607"},
	}
	dialer, err := runtimeUnderTest.sessionDialer(SessionConfig{
		Root: Path("mismatched", spec),
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := dialer.snapshotFactoryResolver()
	budget := runtimeUnderTest.factoryCallbackBudget
	lease, err := resolver.dialPathForAdoption(context.Background(), spec)
	if lease != nil || !errors.Is(err, udpflow.ErrConnectedPacketPeerMismatch) {
		t.Fatalf("mismatched resolver lease=%v err=%v want nil, typed mismatch", lease, err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("packet factory calls=%d want=1", got)
	}
	if got := len(budget.permits); got != 0 {
		t.Fatalf("mismatch retained callback permits=%d want=0", got)
	}
	if _, err := client.Write([]byte("must-not-reach-network")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("mismatched connected socket remains caller-usable: %v", err)
	}
	if err := actual.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if n, _, err := actual.ReadFromUDP(buffer); n != 0 || err == nil {
		t.Fatalf("mismatch emitted network data: ReadFromUDP=%d, %v", n, err)
	}

	lease, err = resolver.dialPathForAdoption(context.Background(), spec)
	if err != nil || lease == nil {
		t.Fatalf("healthy retry after mismatch lease=%v err=%v", lease, err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if got := healthy.closeCalls.Load(); got != 1 {
		t.Fatalf("healthy retry Close calls=%d want exactly 1", got)
	}
	if got := len(budget.permits); got != 0 {
		t.Fatalf("healthy retry retained callback permits=%d want=0", got)
	}
}

func TestPacketFactorySnapshotsMutablePeerExactlyOnce(t *testing.T) {
	peer := &mutablePacketContractAddr{network: "custom", value: "peer-before"}
	conn := &packetContractConn{}
	resolver := &pathFactoryResolver{packet: map[string]packetPathFactory{
		"mutable": func(context.Context, string) (PacketEndpoint, error) {
			return PacketEndpoint{Conn: conn, Peer: peer, MaxDatagramSize: testPacketMaxDatagramSize}, nil
		},
	}}
	path, err := resolver.dialPath(context.Background(), PathSpec{
		Transport: "mutable",
		Address:   "opaque-token",
		Opts:      map[string]string{"flow_id_hex": "01020304050607"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer path.Close()
	if networkCalls, stringCalls := peer.calls(); networkCalls != 1 || stringCalls != 1 {
		t.Fatalf("peer snapshot calls=(%d,%d) want (1,1)", networkCalls, stringCalls)
	}
	peer.set("mutated", "peer-after")
	if got := path.RemoteAddr(); got != "peer-before" {
		t.Fatalf("PathConn.RemoteAddr=%q want immutable peer-before", got)
	}
	if n, err := path.Write([]byte{0x42}); err != nil || n != 1 {
		t.Fatalf("PathConn.Write=(%d,%v) want (1,nil)", n, err)
	}
	got := conn.lastPeer()
	if got == peer {
		t.Fatal("WriteTo retained the original mutable peer object")
	}
	if got == nil || got.Network() != "custom" || got.String() != "peer-before" {
		t.Fatalf("WriteTo peer=(%T,%q,%q) want immutable (custom,peer-before)", got, addrNetwork(got), addrString(got))
	}
	accepted := conn.acceptedSnapshot()
	if accepted == nil || accepted.Network() != got.Network() || accepted.String() != got.String() {
		t.Fatalf("accepted snapshot=(%T,%q,%q) diverged from WriteTo peer=(%T,%q,%q)",
			accepted, addrNetwork(accepted), addrString(accepted), got, addrNetwork(got), addrString(got))
	}
	if networkCalls, stringCalls := peer.calls(); networkCalls != 1 || stringCalls != 1 {
		t.Fatalf("mutable peer was consulted after adoption: calls=(%d,%d)", networkCalls, stringCalls)
	}
}

func TestPacketFactoryStandardPeerWritesUseFreshDeepSnapshots(t *testing.T) {
	original := &net.UDPAddr{IP: net.ParseIP("192.0.2.10").To4(), Port: 4242, Zone: "before"}
	conn := &packetContractConn{}
	resolver := &pathFactoryResolver{packet: map[string]packetPathFactory{
		"standard": func(context.Context, string) (PacketEndpoint, error) {
			return PacketEndpoint{Conn: conn, Peer: original, MaxDatagramSize: testPacketMaxDatagramSize}, nil
		},
	}}
	path, err := resolver.dialPath(context.Background(), PathSpec{
		Transport: "standard",
		Opts:      map[string]string{"flow_id_hex": "01020304050607"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer path.Close()
	original.IP[0] = 203
	original.Port = 9999
	original.Zone = "after"
	if _, err := path.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	first, ok := conn.lastPeer().(*net.UDPAddr)
	if !ok {
		t.Fatalf("first WriteTo peer type=%T want *net.UDPAddr", conn.lastPeer())
	}
	if got := first.String(); got != "192.0.2.10%before:4242" {
		t.Fatalf("first WriteTo peer=%q want frozen standard address", got)
	}
	first.IP[0] = 198
	first.Port = 1
	if _, err := path.Write([]byte{2}); err != nil {
		t.Fatal(err)
	}
	second, ok := conn.lastPeer().(*net.UDPAddr)
	if !ok {
		t.Fatalf("second WriteTo peer type=%T want *net.UDPAddr", conn.lastPeer())
	}
	if first == second || &first.IP[0] == &second.IP[0] {
		t.Fatal("WriteTo reused mutable standard address storage")
	}
	if got := second.String(); got != "192.0.2.10%before:4242" {
		t.Fatalf("second WriteTo peer=%q want independent frozen snapshot", got)
	}
	if conn.snapshotCalls.Load() != 0 {
		t.Fatalf("standard address unexpectedly required custom snapshot contract %d times", conn.snapshotCalls.Load())
	}
}

func TestPacketFactoryCustomPeerSnapshotContractFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		conn net.PacketConn
	}{
		{name: "missing", conn: &packetContractConnWithoutSnapshot{}},
		{name: "reject", conn: &packetContractConn{snapshotErr: errors.New("reject snapshot")}},
		{name: "panic", conn: &packetContractConn{snapshotPanic: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &pathFactoryResolver{packet: map[string]packetPathFactory{
				"custom": func(context.Context, string) (PacketEndpoint, error) {
					return PacketEndpoint{Conn: test.conn, Peer: packetContractAddr{network: "custom", value: "peer"}, MaxDatagramSize: testPacketMaxDatagramSize}, nil
				},
			}}
			path, err := resolver.dialPath(context.Background(), PathSpec{Transport: "custom"})
			if path != nil {
				t.Fatalf("invalid custom peer contract returned path %T", path)
			}
			assertFactoryReason(t, err, "custom", FactoryKindPacket, FactoryReasonInvalidPacketPeer)
			if !strings.Contains(err.Error(), "invalid packet peer identity") {
				t.Fatalf("FactoryError message=%q does not describe general invalid identity", err)
			}
		})
	}
}

func TestPacketFactoryBlockedPeerValidationRemainsBounded(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	peer := &blockingPacketContractAddr{started: started, release: release}
	conn := &packetContractConn{}
	budget := newFactoryCallbackBudget(1)
	resolver := &pathFactoryResolver{
		runtimeBudget: budget,
		packet: map[string]packetPathFactory{
			"blocking-peer": func(context.Context, string) (PacketEndpoint, error) {
				return PacketEndpoint{Conn: conn, Peer: peer, MaxDatagramSize: testPacketMaxDatagramSize}, nil
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		lease, err := resolver.dialPathForAdoption(ctx, PathSpec{Transport: "blocking-peer", Address: "opaque"})
		if lease != nil {
			_ = lease.Close()
		}
		result <- err
	}()
	awaitFactorySignal(t, started, "blocked packet peer validation")
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked peer validation error=%v want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked peer validation delayed cancellation")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for conn.closeCalls.Load() != 1 || len(budget.permits) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("late peer validation cleanup did not quiesce: closes=%d permits=%d", conn.closeCalls.Load(), len(budget.permits))
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPacketFactoryBlockedCustomPeerAcceptanceRemainsBounded(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	conn := &blockingSnapshotPacketContractConn{started: started, release: release}
	budget := newFactoryCallbackBudget(1)
	resolver := &pathFactoryResolver{
		runtimeBudget: budget,
		packet: map[string]packetPathFactory{
			"blocking-acceptance": func(context.Context, string) (PacketEndpoint, error) {
				return PacketEndpoint{Conn: conn, Peer: packetContractAddr{network: "custom", value: "peer"}, MaxDatagramSize: testPacketMaxDatagramSize}, nil
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		lease, err := resolver.dialPathForAdoption(ctx, PathSpec{Transport: "blocking-acceptance", Address: "opaque"})
		if lease != nil {
			_ = lease.Close()
		}
		result <- err
	}()
	awaitFactorySignal(t, started, "blocked packet peer snapshot acceptance")
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked snapshot acceptance error=%v want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked snapshot acceptance delayed cancellation")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for conn.closed.Load() != 1 || len(budget.permits) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("late snapshot acceptance cleanup did not quiesce: closes=%d permits=%d", conn.closed.Load(), len(budget.permits))
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPacketFactoryPeerValidationGoexitClosesAcquiredEndpointExactlyOnce(t *testing.T) {
	tests := []struct {
		name        string
		badEndpoint func() (PacketEndpoint, func() int32)
	}{
		{
			name: "peer identity",
			badEndpoint: func() (PacketEndpoint, func() int32) {
				conn := &packetContractConn{}
				return PacketEndpoint{Conn: conn, Peer: goexitPacketContractAddr{}, MaxDatagramSize: testPacketMaxDatagramSize}, conn.closeCalls.Load
			},
		},
		{
			name: "custom peer acceptance",
			badEndpoint: func() (PacketEndpoint, func() int32) {
				conn := &goexitSnapshotPacketContractConn{}
				return PacketEndpoint{Conn: conn, Peer: packetContractAddr{network: "custom", value: "peer"}, MaxDatagramSize: testPacketMaxDatagramSize}, conn.closed.Load
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bad, badCloses := test.badEndpoint()
			healthy := &packetContractConn{}
			budget := newFactoryCallbackBudget(1)
			var calls atomic.Int32
			resolver := &pathFactoryResolver{
				runtimeBudget: budget,
				packet: map[string]packetPathFactory{
					"goexit-validation": func(context.Context, string) (PacketEndpoint, error) {
						if calls.Add(1) == 1 {
							return bad, nil
						}
						return PacketEndpoint{Conn: healthy, Peer: packetContractAddr{network: "custom", value: "healthy"}, MaxDatagramSize: testPacketMaxDatagramSize}, nil
					},
				},
			}

			lease, err := resolver.dialPathForAdoption(context.Background(), PathSpec{Transport: "goexit-validation", Address: "opaque"})
			if lease != nil {
				t.Fatalf("Goexit validation returned lease %v", lease)
			}
			assertFactoryReason(t, err, "goexit-validation", FactoryKindPacket, FactoryReasonAbnormal)
			if got := badCloses(); got != 1 {
				t.Fatalf("acquired endpoint Close calls=%d want exactly 1", got)
			}
			if got := len(budget.permits); got != 0 {
				t.Fatalf("retained callback permits=%d want 0", got)
			}

			lease, err = resolver.dialPathForAdoption(context.Background(), PathSpec{Transport: "goexit-validation", Address: "opaque"})
			if err != nil || lease == nil {
				t.Fatalf("healthy retry after Goexit lease=%v err=%v", lease, err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			if got := healthy.closeCalls.Load(); got != 1 {
				t.Fatalf("healthy endpoint Close calls=%d want 1", got)
			}
			if got := badCloses(); got != 1 {
				t.Fatalf("bad endpoint final Close calls=%d want exactly 1", got)
			}
		})
	}
}

func TestPacketLogicalPeerStableAcrossOpaqueFallback(t *testing.T) {
	serverSocket, listener := packetContractRuntimeListener(t)

	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var failedToken, healthyToken atomic.Value
	if err := clientRuntime.RegisterPacketFactory("packet-fail", PacketFactory{
		Carrier: CarrierUDP,
		Dial: func(_ context.Context, token string) (PacketEndpoint, error) {
			failedToken.Store(token)
			return PacketEndpoint{}, errors.New("injected initial path failure")
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterPacketFactory("packet-good", PacketFactory{
		Carrier: CarrierUDP,
		Dial: func(_ context.Context, token string) (PacketEndpoint, error) {
			healthyToken.Store(token)
			return packetContractUDPEndpoint(serverSocket.LocalAddr())
		},
	}); err != nil {
		t.Fatal(err)
	}
	accepted := acceptPacketContractSession(t, listener)
	client, err := clientRuntime.DialPacket(context.Background(), SessionConfig{Root: Selector("root", []Target{
		Path("failed", PathSpec{Transport: "packet-fail", Address: "opaque://first/path"}),
		Path("healthy", PathSpec{Transport: "packet-good", Address: "opaque://second/path"}),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := awaitPacketContractSession(t, accepted)
	defer server.Close()

	gotFailedToken, _ := failedToken.Load().(string)
	gotHealthyToken, _ := healthyToken.Load().(string)
	if gotFailedToken != "opaque://first/path" || gotHealthyToken != "opaque://second/path" {
		t.Fatalf("factory tokens=(%q,%q) want exact opaque tokens", gotFailedToken, gotHealthyToken)
	}
	assertPacketSessionIdentity(t, client)
	assertPacketSessionIdentity(t, server)
	clientPeer := packetContractRemoteAddr(t, client)
	serverPeer := packetContractRemoteAddr(t, server)
	if clientPeer.String() != serverPeer.String() {
		t.Fatalf("dial/accept logical peers differ: client=%q server=%q", clientPeer, serverPeer)
	}
	if clientPeer.String() == gotFailedToken || clientPeer.String() == gotHealthyToken {
		t.Fatalf("logical peer leaked opaque path token %q", clientPeer)
	}
	assertPacketContractAddressRoundTrip(t, client, server, clientPeer, serverPeer, "fallback")
}

func TestPacketLogicalPeerStableAcrossGenericMigration(t *testing.T) {
	serverSocket, listener := packetContractRuntimeListener(t)
	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var carriersMu sync.Mutex
	var carriers []*net.UDPConn
	if err := clientRuntime.RegisterPacketFactory("packet-migrate", PacketFactory{
		Carrier: CarrierUDP,
		Dial: func(_ context.Context, token string) (PacketEndpoint, error) {
			if token != "opaque://stable/session" {
				return PacketEndpoint{}, errors.New("opaque token changed")
			}
			endpoint, err := packetContractUDPEndpoint(serverSocket.LocalAddr())
			if err != nil {
				return PacketEndpoint{}, err
			}
			carriersMu.Lock()
			carriers = append(carriers, endpoint.Conn.(*net.UDPConn))
			carriersMu.Unlock()
			return endpoint, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	accepted := acceptPacketContractSession(t, listener)
	clientConn, err := clientRuntime.DialPacket(context.Background(), SessionConfig{Root: Selector("root", []Target{
		Path("migrate", PathSpec{Transport: "packet-migrate", Address: "opaque://stable/session"}),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	server := awaitPacketContractSession(t, accepted)
	defer server.Close()
	client := clientConn.(*enginePacketConn)

	clientPeerBefore := client.RemoteAddr()
	serverPeerBefore := packetContractRemoteAddr(t, server)
	assertPacketContractAddressRoundTrip(t, client, server, clientPeerBefore, serverPeerBefore, "before-migration")
	oldClientID, oldServerID := client.Paths()[0].ID, server.Paths()[0].ID
	carriersMu.Lock()
	firstCarrier := carriers[0]
	carriersMu.Unlock()
	if err := firstCarrier.Close(); err != nil {
		t.Fatal(err)
	}
	waitForPacketReplacement(t, client, server, oldClientID, oldServerID, 5*time.Second)

	assertPacketSessionIdentity(t, client)
	assertPacketSessionIdentity(t, server)
	if client.RemoteAddr().Network() != clientPeerBefore.Network() || client.RemoteAddr().String() != clientPeerBefore.String() {
		t.Fatalf("client logical peer changed: before=%q after=%q", clientPeerBefore, client.RemoteAddr())
	}
	serverPeerAfter := packetContractRemoteAddr(t, server)
	if serverPeerAfter.Network() != serverPeerBefore.Network() || serverPeerAfter.String() != serverPeerBefore.String() {
		t.Fatalf("server logical peer changed: before=%q after=%q", serverPeerBefore, serverPeerAfter)
	}
	assertPacketContractAddressRoundTrip(t, client, server, clientPeerBefore, serverPeerBefore, "after-migration")
}

func TestPacketFactoryCancellationClosesLateEndpointExactlyOnce(t *testing.T) {
	const factoryID = "late-packet-endpoint"
	started := make(chan struct{})
	release := make(chan struct{})
	late := &packetContractConn{}
	healthy := &packetContractConn{}
	var calls atomic.Int32
	budget := newFactoryCallbackBudget(1)
	resolver := &pathFactoryResolver{
		runtimeBudget: budget,
		packet: map[string]packetPathFactory{
			factoryID: func(context.Context, string) (PacketEndpoint, error) {
				if calls.Add(1) == 1 {
					close(started)
					<-release
					return PacketEndpoint{Conn: late, Peer: packetContractAddr{network: "custom", value: "late"}, MaxDatagramSize: testPacketMaxDatagramSize}, nil
				}
				return PacketEndpoint{Conn: healthy, Peer: packetContractAddr{network: "custom", value: "healthy"}, MaxDatagramSize: testPacketMaxDatagramSize}, nil
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		lease, err := resolver.dialPathForAdoption(ctx, PathSpec{Transport: factoryID, Address: "opaque"})
		if lease != nil {
			_ = lease.Close()
		}
		result <- err
	}()
	awaitFactorySignal(t, started, "late packet endpoint factory")
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled dial error=%v want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled packet endpoint dial did not return")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for late.closeCalls.Load() != 1 || len(budget.permits) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("late cleanup did not quiesce: closes=%d permits=%d", late.closeCalls.Load(), len(budget.permits))
		}
		time.Sleep(time.Millisecond)
	}

	lease, err := resolver.dialPathForAdoption(context.Background(), PathSpec{Transport: factoryID, Address: "opaque"})
	if err != nil {
		t.Fatalf("factory gate did not recover after late cleanup: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("close healthy endpoint lease: %v", err)
	}
	if got := healthy.closeCalls.Load(); got != 1 {
		t.Fatalf("healthy endpoint Close calls=%d want 1", got)
	}
	if got := late.closeCalls.Load(); got != 1 {
		t.Fatalf("late endpoint final Close calls=%d want exactly 1", got)
	}
}

type packetContractAddr struct {
	network string
	value   string
	padding []byte
}

type hostilePacketDestinationAddr struct {
	networkCalls atomic.Int32
	stringCalls  atomic.Int32
}

func (addr *hostilePacketDestinationAddr) Network() string {
	addr.networkCalls.Add(1)
	panic("hostile destination Network callback")
}

func (addr *hostilePacketDestinationAddr) String() string {
	addr.stringCalls.Add(1)
	panic("hostile destination String callback")
}

func (a packetContractAddr) Network() string { return a.network }
func (a packetContractAddr) String() string  { return a.value }

type panicPacketContractAddr struct {
	network bool
}

func (addr panicPacketContractAddr) Network() string {
	if addr.network {
		panic("hostile packet peer Network")
	}
	return "custom"
}
func (panicPacketContractAddr) String() string { panic("hostile packet peer String") }

type mutablePacketContractAddr struct {
	mu           sync.Mutex
	network      string
	value        string
	networkCalls int
	stringCalls  int
}

func (addr *mutablePacketContractAddr) Network() string {
	addr.mu.Lock()
	defer addr.mu.Unlock()
	addr.networkCalls++
	return addr.network
}
func (addr *mutablePacketContractAddr) String() string {
	addr.mu.Lock()
	defer addr.mu.Unlock()
	addr.stringCalls++
	return addr.value
}
func (addr *mutablePacketContractAddr) set(network, value string) {
	addr.mu.Lock()
	addr.network = network
	addr.value = value
	addr.mu.Unlock()
}
func (addr *mutablePacketContractAddr) calls() (int, int) {
	addr.mu.Lock()
	defer addr.mu.Unlock()
	return addr.networkCalls, addr.stringCalls
}

type blockingPacketContractAddr struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (addr *blockingPacketContractAddr) Network() string {
	addr.once.Do(func() { close(addr.started) })
	<-addr.release
	return "custom"
}
func (*blockingPacketContractAddr) String() string { return "peer" }

type goexitPacketContractAddr struct{}

func (goexitPacketContractAddr) Network() string {
	runtime.Goexit()
	return ""
}
func (goexitPacketContractAddr) String() string { return "peer" }

type packetContractConn struct {
	mu            sync.Mutex
	written       net.Addr
	snapshot      net.Addr
	snapshotErr   error
	snapshotPanic bool
	closeCalls    atomic.Int32
	snapshotCalls atomic.Int32
}

func (*packetContractConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (conn *packetContractConn) WriteTo(payload []byte, peer net.Addr) (int, error) {
	conn.mu.Lock()
	conn.written = peer
	conn.mu.Unlock()
	return len(payload), nil
}
func (conn *packetContractConn) Close() error {
	conn.closeCalls.Add(1)
	return nil
}
func (conn *packetContractConn) AcceptPacketPeerSnapshot(peer net.Addr) error {
	conn.snapshotCalls.Add(1)
	if conn.snapshotPanic {
		panic("reject custom peer snapshot")
	}
	conn.mu.Lock()
	conn.snapshot = peer
	conn.mu.Unlock()
	return conn.snapshotErr
}
func (*packetContractConn) LocalAddr() net.Addr {
	return packetContractAddr{network: "custom", value: "local"}
}
func (*packetContractConn) SetDeadline(time.Time) error      { return nil }
func (*packetContractConn) SetReadDeadline(time.Time) error  { return nil }
func (*packetContractConn) SetWriteDeadline(time.Time) error { return nil }

func (conn *packetContractConn) lastPeer() net.Addr {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.written
}

func (conn *packetContractConn) acceptedSnapshot() net.Addr {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.snapshot
}

type packetContractConnWithoutSnapshot struct {
	packetContractConnBase
}

type blockingSnapshotPacketContractConn struct {
	packetContractConnBase
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (conn *blockingSnapshotPacketContractConn) AcceptPacketPeerSnapshot(net.Addr) error {
	conn.once.Do(func() { close(conn.started) })
	<-conn.release
	return nil
}

type goexitSnapshotPacketContractConn struct {
	packetContractConnBase
}

func (*goexitSnapshotPacketContractConn) AcceptPacketPeerSnapshot(net.Addr) error {
	runtime.Goexit()
	return nil
}

type packetContractConnBase struct {
	closed atomic.Int32
}

func (*packetContractConnBase) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (*packetContractConnBase) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}
func (conn *packetContractConnBase) Close() error {
	conn.closed.Add(1)
	return nil
}
func (*packetContractConnBase) LocalAddr() net.Addr {
	return packetContractAddr{network: "custom", value: "local"}
}
func (*packetContractConnBase) SetDeadline(time.Time) error      { return nil }
func (*packetContractConnBase) SetReadDeadline(time.Time) error  { return nil }
func (*packetContractConnBase) SetWriteDeadline(time.Time) error { return nil }

func addrNetwork(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.Network()
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

type packetContractAcceptResult struct {
	conn PacketConn
	err  error
}

func packetContractRuntimeListener(t *testing.T) (net.PacketConn, *SessionListener) {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		_ = socket.Close()
		t.Fatal(err)
	}
	listener, err := runtime.Listen(ListenConfig{Packets: []PacketSource{{
		Name:            "packet-contract-ingress",
		Carrier:         CarrierUDP,
		Conn:            socket,
		MaxDatagramSize: 1400,
	}}})
	if err != nil {
		_ = socket.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = socket.Close()
	})
	return socket, listener
}

func acceptPacketContractSession(t *testing.T, listener *SessionListener) <-chan packetContractAcceptResult {
	t.Helper()
	accepted := make(chan packetContractAcceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := listener.AcceptPacket(ctx)
		accepted <- packetContractAcceptResult{conn: conn, err: err}
	}()
	return accepted
}

func awaitPacketContractSession(t *testing.T, accepted <-chan packetContractAcceptResult) PacketConn {
	t.Helper()
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatal(result.err)
		}
		return result.conn
	case <-time.After(6 * time.Second):
		t.Fatal("packet contract accept timed out")
		return nil
	}
}

func packetContractUDPEndpoint(peer net.Addr) (PacketEndpoint, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return PacketEndpoint{}, err
	}
	return PacketEndpoint{Conn: conn, Peer: peer, MaxDatagramSize: testPacketMaxDatagramSize}, nil
}

func assertPacketSessionIdentity(t *testing.T, conn PacketConn) {
	t.Helper()
	remote := packetContractRemoteAddr(t, conn)
	peer, ok := remote.(packetSessionAddr)
	if !ok {
		t.Fatalf("RemoteAddr type=%T want packetSessionAddr", remote)
	}
	if peer.flowID != conn.FlowID() {
		t.Fatalf("logical peer flow=%x want session flow=%x", peer.flowID, conn.FlowID())
	}
	if peer.Network() != "rendr-packet" || peer.String() == "" {
		t.Fatalf("logical peer identity=(%q,%q)", peer.Network(), peer.String())
	}
}

func packetContractRemoteAddr(t *testing.T, conn PacketConn) net.Addr {
	t.Helper()
	remote, ok := conn.(interface{ RemoteAddr() net.Addr })
	if !ok {
		t.Fatalf("rendr packet connection %T does not expose RemoteAddr", conn)
	}
	addr := remote.RemoteAddr()
	if addr == nil {
		t.Fatalf("rendr packet connection %T returned nil RemoteAddr", conn)
	}
	return addr
}

func assertPacketContractAddressRoundTrip(
	t *testing.T,
	client, server PacketConn,
	clientDestination, serverDestination net.Addr,
	label string,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	defer client.SetDeadline(time.Time{})
	defer server.SetDeadline(time.Time{})

	request := []byte(label + "-request")
	if _, err := client.WriteTo(request, clientDestination); err != nil {
		t.Fatalf("client WriteTo with logical peer: %v", err)
	}
	buffer := make([]byte, 256)
	n, source, err := server.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != string(request) {
		t.Fatalf("server payload=%q want %q", buffer[:n], request)
	}
	serverPeer := packetContractRemoteAddr(t, server)
	if source.Network() != serverPeer.Network() || source.String() != serverPeer.String() {
		t.Fatalf("server ReadFrom source=%q want logical peer %q", source, serverPeer)
	}

	reply := []byte(label + "-reply")
	if _, err := server.WriteTo(reply, serverDestination); err != nil {
		t.Fatalf("server WriteTo with logical peer: %v", err)
	}
	n, source, err = client.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != string(reply) {
		t.Fatalf("client payload=%q want %q", buffer[:n], reply)
	}
	clientPeer := packetContractRemoteAddr(t, client)
	if source.Network() != clientPeer.Network() || source.String() != clientPeer.String() {
		t.Fatalf("client ReadFrom source=%q want logical peer %q", source, clientPeer)
	}
}
