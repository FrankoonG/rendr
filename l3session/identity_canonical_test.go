package l3session

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

func TestL3SessionWireRejectsNonCanonicalIdentityRecords(t *testing.T) {
	for _, proto := range []l3ingress.Protocol{l3ingress.ProtocolTCP, l3ingress.ProtocolUDP} {
		t.Run(proto.String(), func(t *testing.T) {
			id := canonicalWireTestIdentity(proto)
			valid := canonicalWireTestEnvelope(t, id)
			identityOffset := tcpEnvelopeHeaderSize
			if proto == l3ingress.ProtocolUDP {
				identityOffset = udpEnvelopeHeaderSize
			}

			mapped := id
			mapped.SrcIP = netip.MustParseAddr("::ffff:192.0.2.10")
			mapped.DstIP = netip.MustParseAddr("::ffff:198.51.100.20")
			mappedWire, err := id.EncodeBinary()
			if err != nil {
				t.Fatal(err)
			}
			mappedWire[2] = 6
			copy(mappedWire[8:24], mapped.SrcIP.AsSlice())
			copy(mappedWire[24:40], mapped.DstIP.AsSlice())

			cases := map[string]func([]byte){
				"reserved byte": func(wire []byte) {
					wire[identityOffset+3] = 1
				},
				"IPv4 source padding": func(wire []byte) {
					wire[identityOffset+12] = 1
				},
				"IPv4 destination padding": func(wire []byte) {
					wire[identityOffset+28] = 1
				},
				"IPv4-mapped IPv6 alias": func(wire []byte) {
					copy(wire[identityOffset:identityOffset+l3ingress.IdentityWireSize], mappedWire)
				},
			}
			for name, mutate := range cases {
				t.Run(name, func(t *testing.T) {
					wire := append([]byte(nil), valid...)
					mutate(wire)
					if err := decodeCanonicalWireTestEnvelope(proto, wire); err == nil {
						t.Fatal("accepted a non-canonical L3 identity record")
					}
				})
			}
		})
	}
}

func TestL3SessionWireEncoderRejectsIdentityAliases(t *testing.T) {
	for _, proto := range []l3ingress.Protocol{l3ingress.ProtocolTCP, l3ingress.ProtocolUDP} {
		t.Run(proto.String(), func(t *testing.T) {
			mapped := canonicalWireTestIdentity(proto)
			mapped.SrcIP = netip.MustParseAddr("::ffff:192.0.2.10")
			mapped.DstIP = netip.MustParseAddr("::ffff:198.51.100.20")
			if err := encodeCanonicalWireTestEnvelope(proto, mapped); err == nil {
				t.Fatal("encoded an IPv4-mapped IPv6 identity alias")
			}

			zoned := canonicalWireTestIdentity(proto)
			zoned.SrcIP = netip.MustParseAddr("fe80::10%ingress0")
			zoned.DstIP = netip.MustParseAddr("fe80::20%egress0")
			if err := encodeCanonicalWireTestEnvelope(proto, zoned); err == nil {
				t.Fatal("encoded an identity whose IPv6 zones cannot survive the wire format")
			}
		})
	}
}

func TestPacketSourceMatchesRejectsPortTruncationAliases(t *testing.T) {
	expected := netip.MustParseAddrPort("198.51.100.20:53")
	if !packetSourceMatches(&net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 53}, expected) {
		t.Fatal("canonical UDP source did not match its immutable route identity")
	}
	for _, port := range []int{1<<16 + 53, -1<<16 + 53} {
		source := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: port}
		if packetSourceMatches(source, expected) {
			t.Fatalf("accepted UDP port alias %d as %s", port, expected)
		}
	}
}

func TestManagerConcurrentlyRejectsIdentityAliasesBeforePublication(t *testing.T) {
	id := canonicalWireTestIdentity(l3ingress.ProtocolTCP)
	id.SrcIP = netip.MustParseAddr("::ffff:192.0.2.10")
	id.DstIP = netip.MustParseAddr("::ffff:198.51.100.20")
	event := l3ingress.PacketEvent{
		Meta:    l3ingress.PacketMeta{Identity: id},
		Flow:    l3ingress.FlowMeta{L3Identity: id},
		Decided: true,
		Decision: l3ingress.FlowDecision{
			Peer:   "peer",
			Root:   rendr.Path("unused", rendr.PathSpec{Transport: "unused", Address: "unused"}),
			Egress: "direct",
		},
	}
	manager := &Manager{}

	const attempts = 64
	errs := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- manager.HandlePacket(context.Background(), event)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, ErrNonCanonicalL3Identity) {
			t.Fatalf("HandlePacket error=%v want ErrNonCanonicalL3Identity", err)
		}
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.pending) != 0 || len(manager.sessions) != 0 {
		t.Fatalf("non-canonical identity reached routing maps: pending=%d sessions=%d", len(manager.pending), len(manager.sessions))
	}
}

func TestStarterRejectsIdentityAliasBeforeExternalConfiguration(t *testing.T) {
	id := canonicalWireTestIdentity(l3ingress.ProtocolTCP)
	id.SrcIP = netip.MustParseAddr("::ffff:192.0.2.10")
	id.DstIP = netip.MustParseAddr("::ffff:198.51.100.20")
	configured := false
	starter := &Starter{ConfigureSession: func(l3ingress.SessionRequest, *rendr.SessionConfig) error {
		configured = true
		return nil
	}}
	_, err := starter.Start(context.Background(), l3ingress.SessionRequest{
		Kind:               l3ingress.SessionKindStream,
		Identity:           id,
		Peer:               "peer",
		Root:               rendr.Path("unused", rendr.PathSpec{Transport: "unused", Address: "unused"}),
		Egress:             "direct",
		PreserveL3Identity: true,
	})
	if !errors.Is(err, ErrNonCanonicalL3Identity) {
		t.Fatalf("Start error=%v want ErrNonCanonicalL3Identity", err)
	}
	if configured {
		t.Fatal("non-canonical identity reached external ConfigureSession callback")
	}
}

func TestDataPlanePacketReadFromOwnsUDPAddressSnapshot(t *testing.T) {
	conn := newPeerTestPacketConn()
	packet := newDataPlanePacket(conn, "identity snapshot", conn.Close)
	defer packet.close()

	original := &net.UDPAddr{
		IP:   net.IP{198, 51, 100, 20},
		Port: 53,
	}
	conn.reads <- peerTestPacket{payload: []byte("reply"), addr: original}
	buf := make([]byte, 16)
	n, snapshot, err := packet.readFrom(context.Background(), buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len("reply") {
		t.Fatalf("read bytes=%d want=%d", n, len("reply"))
	}

	const workers = 32
	start := make(chan struct{})
	results := make(chan bool, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- packetSourceMatches(snapshot, netip.MustParseAddrPort("198.51.100.20:53"))
		}()
	}
	close(start)
	for i := range original.IP {
		original.IP[i] = byte(i + 1)
	}
	original.Port = 5353
	original.Zone = "mutated"
	wg.Wait()
	close(results)
	for matched := range results {
		if !matched {
			t.Fatal("caller mutation changed the published immutable route identity")
		}
	}

	got, ok := snapshot.(*net.UDPAddr)
	if !ok {
		t.Fatalf("snapshot type=%T want *net.UDPAddr", snapshot)
	}
	if got == original || bytes.Equal(got.IP, original.IP) || got.Port != 53 || got.Zone != "" {
		t.Fatalf("snapshot still aliases caller address: got=%v original=%v", got, original)
	}
}

func canonicalWireTestIdentity(proto l3ingress.Protocol) l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto:   proto,
		SrcIP:   netip.MustParseAddr("192.0.2.10"),
		SrcPort: 42000,
		DstIP:   netip.MustParseAddr("198.51.100.20"),
		DstPort: 443,
	}
}

func canonicalWireTestEnvelope(t *testing.T, id l3ingress.L3Identity) []byte {
	t.Helper()
	if id.Proto == l3ingress.ProtocolTCP {
		wire, err := encodeTCPEnvelope(id, "direct")
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	wire, err := appendUDPEnvelope(nil, id, "direct", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func encodeCanonicalWireTestEnvelope(proto l3ingress.Protocol, id l3ingress.L3Identity) error {
	if proto == l3ingress.ProtocolTCP {
		_, err := encodeTCPEnvelope(id, "direct")
		return err
	}
	_, err := appendUDPEnvelope(nil, id, "direct", nil)
	return err
}

func decodeCanonicalWireTestEnvelope(proto l3ingress.Protocol, wire []byte) error {
	if proto == l3ingress.ProtocolTCP {
		_, err := readTCPEnvelope(bytes.NewReader(wire))
		return err
	}
	_, err := decodeUDPEnvelope(wire)
	return err
}
