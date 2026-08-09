package l3session

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport/tcp"
	"github.com/FrankoonG/rendr/virtualif"
)

func TestStarterStreamSessionPreservesL3Capability(t *testing.T) {
	ln := newTestStreamSessionListener(t, "test-stream")
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptStream(ctx)
		if err != nil {
			t.Errorf("accept stream: %v", err)
			return
		}
		accepted <- c
	}()

	runtime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.RegisterStreamFactory("test-stream", rendr.StreamFactory{
		Carrier: rendr.CarrierTCP,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
	}); err != nil {
		t.Fatal(err)
	}

	req := l3ingress.SessionRequest{
		Kind:               l3ingress.SessionKindStream,
		Identity:           testIdentity(l3ingress.ProtocolTCP),
		Peer:               "peer-a",
		Root:               rendr.Path("tcp-a", rendr.PathSpec{Transport: "test-stream", Address: ln.Addr().String()}),
		Egress:             "direct",
		PreserveL3Identity: true,
	}
	starter := &Starter{
		Runtime: runtime,
		ConfigureSession: func(_ l3ingress.SessionRequest, config *rendr.SessionConfig) error {
			config.PreserveL3Identity = false
			return nil
		},
	}
	sess, err := starter.Start(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if sess.Conn == nil || sess.PacketConn != nil {
		t.Fatalf("session shape conn=%T packet=%T", sess.Conn, sess.PacketConn)
	}

	server := <-accepted
	defer server.Close()
	assertPeerL3Cap(t, server.(rendr.ConnectionObserver).Stats().PeerCaps, false)

	go func() {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(server, buf); err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if string(buf) != "hello" {
			t.Errorf("server read %q", buf)
			return
		}
		if _, err := server.Write([]byte("world")); err != nil {
			t.Errorf("server write: %v", err)
		}
	}()
	if _, err := sess.Conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(sess.Conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "world" {
		t.Fatalf("client read %q want world", got)
	}
}

func TestStarterPacketSessionPreservesL3Capability(t *testing.T) {
	ln := newTestPacketSessionListener(t, "udpflow")
	defer ln.Close()

	accepted := make(chan rendr.PacketConn, 1)
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

	req := l3ingress.SessionRequest{
		Kind:               l3ingress.SessionKindPacket,
		Identity:           testIdentity(l3ingress.ProtocolUDP),
		Peer:               "peer-a",
		Root:               rendr.Path("udp-a", rendr.PathSpec{Transport: "udpflow", Address: ln.Addr().String()}),
		Egress:             "direct",
		PreserveL3Identity: true,
	}
	starter := &Starter{}
	sess, err := starter.Start(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if sess.Conn != nil || sess.PacketConn == nil {
		t.Fatalf("session shape conn=%T packet=%T", sess.Conn, sess.PacketConn)
	}

	server := <-accepted
	defer server.Close()
	assertPeerL3Cap(t, server.(rendr.ConnectionObserver).Stats().PeerCaps, true)

	go func() {
		buf := make([]byte, 32)
		n, addr, err := server.ReadFrom(buf)
		if err != nil {
			t.Errorf("server readfrom: %v", err)
			return
		}
		if string(buf[:n]) != "ping" {
			t.Errorf("server read %q", buf[:n])
			return
		}
		if _, err := server.WriteTo([]byte("pong"), addr); err != nil {
			t.Errorf("server writeto: %v", err)
		}
	}()
	if _, err := sess.PacketConn.WriteTo([]byte("ping"), dummyAddr("peer")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, _, err := sess.PacketConn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("client read %q want pong", buf[:n])
	}
}

func TestStarterRejectsUnsupportedRequest(t *testing.T) {
	starter := &Starter{}
	_, err := starter.Start(context.Background(), l3ingress.SessionRequest{
		Kind:               l3ingress.SessionKindStream,
		Identity:           testIdentity(l3ingress.ProtocolTCP),
		Peer:               "peer-a",
		Root:               "not-a-target",
		Egress:             "direct",
		PreserveL3Identity: true,
	})
	assertReason(t, err, ReasonUnsupportedRoot)

	_, err = starter.Start(context.Background(), l3ingress.SessionRequest{
		Kind:               l3ingress.SessionKind("raw"),
		Identity:           testIdentity(l3ingress.ProtocolTCP),
		Peer:               "peer-a",
		Root:               rendr.Path("tcp-a", rendr.PathSpec{Transport: "tcp", Address: "127.0.0.1:1"}),
		Egress:             "direct",
		PreserveL3Identity: true,
	})
	assertReason(t, err, ReasonUnsupportedKind)
}

func TestStarterCreatesAndReusesDefaultRuntime(t *testing.T) {
	starter := &Starter{}
	first, err := starter.sessionRuntime()
	if err != nil {
		t.Fatal(err)
	}
	second, err := starter.sessionRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if first == nil || first != second {
		t.Fatalf("default Runtime was not reused: first=%p second=%p", first, second)
	}
}

func TestStarterFailsClosedWhenPeerLacksL3Identity(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	stop := make(chan struct{})
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- servePeerWithoutL3Identity(ln, stop)
	}()

	starter := &Starter{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, startErr := starter.Start(ctx, l3ingress.SessionRequest{
		Kind:               l3ingress.SessionKindStream,
		Identity:           testIdentity(l3ingress.ProtocolTCP),
		Peer:               "peer-a",
		Root:               rendr.Path("tcp-a", rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
		Egress:             "direct",
		PreserveL3Identity: true,
	})
	close(stop)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	var identityErr *virtualif.Error
	if !errors.As(startErr, &identityErr) {
		t.Fatalf("err=%v, want *virtualif.Error", startErr)
	}
	if identityErr.Reason != virtualif.ReasonPeerL3IdentityUnsupported {
		t.Fatalf("reason=%q want %q", identityErr.Reason, virtualif.ReasonPeerL3IdentityUnsupported)
	}
}

func servePeerWithoutL3Identity(ln net.Listener, stop <-chan struct{}) error {
	raw, err := ln.Accept()
	if err != nil {
		return err
	}
	defer raw.Close()
	path := tcp.Wrap(raw)
	buf := make([]byte, tcp.MaxFrameSize)
	n, err := path.Read(buf)
	if err != nil {
		return err
	}
	header, err := proto.DecodeHeader(buf[:proto.HeaderSize])
	if err != nil {
		return err
	}
	if header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlHello {
		return errors.New("test peer: expected HELLO")
	}
	hello, err := proto.DecodeHello(buf[proto.HeaderSize:n])
	if err != nil {
		return err
	}
	finalEpoch := hello.FlowID
	finalEpoch[0] ^= 0x80
	if finalEpoch == ([16]byte{}) {
		finalEpoch[1] = 1
	}
	ackNegotiation := hello.Negotiation
	ackNegotiation.SessionEpoch = proto.SessionEpoch(finalEpoch)
	ackPayload, err := (proto.HelloAckPayload{
		Negotiation:          ackNegotiation,
		FlowID:               finalEpoch,
		InstanceID:           proto.InstanceID{1},
		Caps:                 0,
		InitialTargetID:      hello.InitialTargetID,
		AcceptedPeerBinding:  proto.GraphBinding{Revision: hello.GraphRevision, Digest: hello.GraphDigest},
		AcceptedPeerTargetID: hello.InitialTargetID,
		LocalTXManifest:      hello.LocalTXManifest,
	}).Encode()
	if err != nil {
		return err
	}
	frame := make([]byte, proto.HeaderSize+len(ackPayload))
	if err := (proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlHelloAck),
	}).Encode(frame[:proto.HeaderSize]); err != nil {
		return err
	}
	copy(frame[proto.HeaderSize:], ackPayload)
	if _, err := path.Write(frame); err != nil {
		return err
	}
	proposalHash := sha256.Sum256(buf[proto.HeaderSize:n])
	responseHash := sha256.Sum256(ackPayload)
	binding := proto.PathAdmissionBinding{
		Kind:                   proto.PathAdmissionKindHello,
		Direction:              proto.SenderDirectionClientToServer,
		SessionEpoch:           proto.SessionEpoch(finalEpoch),
		AdmissionID:            proto.PathAdmissionID(hello.FlowID),
		InitiatorGraphRevision: hello.GraphRevision,
		InitiatorGraphDigest:   hello.GraphDigest,
		InitiatorTargetID:      hello.InitialTargetID,
		ResponderTargetID:      hello.InitialTargetID,
		BaseLeafGeneration:     0,
		ProposalDigest:         proto.PathAdmissionProposalDigest(proposalHash),
		ResponderPlanDigest:    proto.PathAdmissionPlanDigest(responseHash),
	}
	prepared, err := (proto.PathAdmissionAck{PathAdmissionBinding: binding, Phase: proto.PathAdmissionPhasePrepared, Code: proto.AckOK}).Encode()
	if err != nil {
		return err
	}
	if err := writeTestAdmissionControl(path, proto.CtrlPathAdmissionAck, prepared); err != nil {
		return err
	}
	commitWire, err := readTestAdmissionControl(path, proto.CtrlPathAdmissionCommit)
	if err != nil {
		return err
	}
	commit, err := proto.DecodePathAdmissionCommit(commitWire)
	if err != nil || commit.PathAdmissionBinding != binding {
		return errors.New("test peer: invalid path admission COMMIT")
	}
	committed, err := (proto.PathAdmissionAck{PathAdmissionBinding: binding, Phase: proto.PathAdmissionPhaseCommitted, Code: proto.AckOK}).Encode()
	if err != nil {
		return err
	}
	if err := writeTestAdmissionControl(path, proto.CtrlPathAdmissionAck, committed); err != nil {
		return err
	}
	confirmWire, err := readTestAdmissionControl(path, proto.CtrlPathAdmissionConfirm)
	if err != nil {
		return err
	}
	confirm, err := proto.DecodePathAdmissionConfirm(confirmWire)
	if err != nil || confirm.PathAdmissionBinding != binding {
		return errors.New("test peer: invalid path admission CONFIRM")
	}
	finalAck, err := (proto.PathAdmissionAck{PathAdmissionBinding: binding, Phase: proto.PathAdmissionPhaseFinal, Code: proto.AckOK}).Encode()
	if err != nil {
		return err
	}
	if err := writeTestAdmissionControl(path, proto.CtrlPathAdmissionAck, finalAck); err != nil {
		return err
	}
	receiptWire, err := readTestAdmissionControl(path, proto.CtrlPathAdmissionAck)
	if err != nil {
		return err
	}
	receipt, err := proto.DecodePathAdmissionAck(receiptWire)
	if err != nil || receipt.Phase != proto.PathAdmissionPhaseFinal || receipt.PathAdmissionBinding != binding {
		return errors.New("test peer: invalid path admission FINAL receipt")
	}
	activated, err := (proto.PathAdmissionAck{PathAdmissionBinding: binding, Phase: proto.PathAdmissionPhaseActivated, Code: proto.AckOK}).Encode()
	if err != nil {
		return err
	}
	if err := writeTestAdmissionControl(path, proto.CtrlPathAdmissionAck, activated); err != nil {
		return err
	}
	<-stop
	return nil
}

func writeTestAdmissionControl(path *tcp.PathConn, code proto.CtrlCode, payload []byte) error {
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameCtrl, Flags: proto.FlagsForCtrl(code)}).Encode(frame[:proto.HeaderSize]); err != nil {
		return err
	}
	copy(frame[proto.HeaderSize:], payload)
	_, err := path.Write(frame)
	return err
}

func readTestAdmissionControl(path *tcp.PathConn, want proto.CtrlCode) ([]byte, error) {
	buf := make([]byte, tcp.MaxFrameSize)
	n, err := path.Read(buf)
	if err != nil {
		return nil, err
	}
	hdr, err := proto.DecodeHeader(buf[:proto.HeaderSize])
	if err != nil {
		return nil, err
	}
	if hdr.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(hdr.Flags) != want || hdr.Seq != 0 {
		return nil, errors.New("test peer: unexpected admission control")
	}
	return append([]byte(nil), buf[proto.HeaderSize:n]...), nil
}

func testIdentity(protoNum l3ingress.Protocol) l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto:   protoNum,
		SrcIP:   netip.MustParseAddr("192.0.2.10"),
		SrcPort: 12345,
		DstIP:   netip.MustParseAddr("198.51.100.20"),
		DstPort: 443,
	}
}

func assertPeerL3Cap(t *testing.T, caps uint32, packet bool) {
	t.Helper()
	if caps&proto.CapsL3Identity == 0 {
		t.Fatalf("PeerCaps=0x%08x missing CapsL3Identity", caps)
	}
	if packet && caps&proto.CapsPacketMode == 0 {
		t.Fatalf("PeerCaps=0x%08x missing CapsPacketMode", caps)
	}
	if !packet && caps&proto.CapsPacketMode != 0 {
		t.Fatalf("PeerCaps=0x%08x unexpectedly has CapsPacketMode", caps)
	}
}

func assertReason(t *testing.T, err error, reason ErrorReason) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err=%v, want *Error", err)
	}
	if e.Reason != reason {
		t.Fatalf("reason=%q want %q", e.Reason, reason)
	}
}

type dummyAddr string

func (d dummyAddr) Network() string { return "dummy" }
func (d dummyAddr) String() string  { return string(d) }

var _ net.Addr = dummyAddr("")
