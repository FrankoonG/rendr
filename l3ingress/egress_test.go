package l3ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestEgressRegistryDispatchesIdentity(t *testing.T) {
	tcpID := L3Identity{
		Proto:   ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 12345,
		DstIP:   netip.MustParseAddr("198.51.100.20"),
		DstPort: 443,
	}
	udpID := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 5353,
		DstIP:   netip.MustParseAddr("198.51.100.30"),
		DstPort: 53,
	}
	hook := &recordingEgress{
		udpRemote: netip.MustParseAddrPort("198.51.100.30:53"),
	}
	reg := NewEgressRegistry()
	if err := reg.Register("vpn-egress", hook); err != nil {
		t.Fatal(err)
	}

	conn, err := reg.DialTCP(context.Background(), "vpn-egress", tcpID)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if hook.tcpID != tcpID {
		t.Fatalf("tcp identity=%+v want %+v", hook.tcpID, tcpID)
	}

	pc, remote, err := reg.DialUDP(context.Background(), "vpn-egress", udpID)
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.Close()
	if hook.udpID != udpID {
		t.Fatalf("udp identity=%+v want %+v", hook.udpID, udpID)
	}
	if remote != hook.udpRemote {
		t.Fatalf("remote=%v want %v", remote, hook.udpRemote)
	}
}

func TestEgressRegistryMachineReadableErrors(t *testing.T) {
	reg := NewEgressRegistry()
	if err := reg.Register("", &recordingEgress{}); err == nil {
		t.Fatal("empty name accepted")
	} else if reason, ok := EgressErrorReasonOf(err); !ok || reason != ReasonInvalidEgressName {
		t.Fatalf("register reason=%q ok=%v err=%v", reason, ok, err)
	}

	_, err := reg.DialTCP(context.Background(), "missing", L3Identity{Proto: ProtocolTCP})
	if reason, ok := EgressErrorReasonOf(err); !ok || reason != ReasonEgressNotFound {
		t.Fatalf("missing reason=%q ok=%v err=%v", reason, ok, err)
	}

	if err := reg.Register("direct", &recordingEgress{}); err != nil {
		t.Fatal(err)
	}
	_, err = reg.DialTCP(context.Background(), "direct", L3Identity{Proto: ProtocolUDP})
	if reason, ok := EgressErrorReasonOf(err); !ok || reason != ReasonProtocolMismatch {
		t.Fatalf("protocol reason=%q ok=%v err=%v", reason, ok, err)
	}

	if _, ok := EgressErrorReasonOf(errors.New("other")); ok {
		t.Fatal("unrelated error matched EgressError")
	}
}

func TestEgressRegistryRejectsTypedNilHooksAndConnections(t *testing.T) {
	reg := NewEgressRegistry()
	var nilHook *recordingEgress
	if err := reg.Register("typed-nil", nilHook); err == nil {
		t.Fatal("registered typed-nil egress hook")
	}
	if err := reg.Register("nil-connections", nilConnectionEgress{}); err != nil {
		t.Fatal(err)
	}
	_, err := reg.DialTCP(context.Background(), "nil-connections", L3Identity{Proto: ProtocolTCP})
	if reason, ok := EgressErrorReasonOf(err); !ok || reason != ReasonInvalidEgressConn {
		t.Fatalf("typed-nil TCP error=%v reason=%q, want invalid_egress_connection", err, reason)
	}
	_, _, err = reg.DialUDP(context.Background(), "nil-connections", L3Identity{Proto: ProtocolUDP})
	if reason, ok := EgressErrorReasonOf(err); !ok || reason != ReasonInvalidEgressConn {
		t.Fatalf("typed-nil UDP error=%v reason=%q, want invalid_egress_connection", err, reason)
	}
}

type nilConnectionEgress struct{}

func (nilConnectionEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
	var conn *net.TCPConn
	return conn, nil
}

func (nilConnectionEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	var conn *net.UDPConn
	return conn, netip.MustParseAddrPort("127.0.0.1:9"), nil
}

type recordingEgress struct {
	tcpID     L3Identity
	udpID     L3Identity
	udpRemote netip.AddrPort
}

func (e *recordingEgress) DialTCP(_ context.Context, id L3Identity) (TCPConn, error) {
	e.tcpID = id
	client, server, err := newTestTCPConnPair()
	if err != nil {
		return nil, err
	}
	_ = server.Close()
	return client, nil
}

func (e *recordingEgress) DialUDP(_ context.Context, id L3Identity) (net.PacketConn, netip.AddrPort, error) {
	e.udpID = id
	return &fakePacketConn{}, e.udpRemote, nil
}

type fakePacketConn struct {
	closed bool
}

func (c *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, fakeAddr("fake"), nil }
func (c *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *fakePacketConn) Close() error {
	c.closed = true
	return nil
}
func (c *fakePacketConn) LocalAddr() net.Addr              { return fakeAddr("local") }
func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }
func (a fakeAddr) Network() string                         { return "fake" }
func (a fakeAddr) String() string                          { return string(a) }

type fakeAddr string
