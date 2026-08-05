package rendr

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type handshakeAdversarialTransport struct {
	name string
	path transport.PathConn
}

var handshakeAdversarialTransportSequence atomic.Uint64

func nextHandshakeAdversarialTransportName(prefix string) string {
	return fmt.Sprintf("test-handshake-%s-%d", prefix, handshakeAdversarialTransportSequence.Add(1))
}

func (t *handshakeAdversarialTransport) Name() string { return t.name }

func (t *handshakeAdversarialTransport) DialPath(context.Context, transport.PathSpec) (transport.PathConn, error) {
	return t.path, nil
}

func (*handshakeAdversarialTransport) Probe(context.Context, transport.PathSpec) (transport.PathQuality, error) {
	return transport.PathQuality{}, nil
}

type handshakeAdversarialPath struct {
	respond func([]byte) ([]byte, error)

	responses chan []byte
	written   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	writeOnce sync.Once
	deathMu   sync.Mutex
	deathFn   func(transport.DeathCause, error)
}

func newHandshakeAdversarialPath(respond func([]byte) ([]byte, error)) *handshakeAdversarialPath {
	return &handshakeAdversarialPath{
		respond:   respond,
		responses: make(chan []byte, 1),
		written:   make(chan struct{}),
		closed:    make(chan struct{}),
	}
}

func (p *handshakeAdversarialPath) Read(buf []byte) (int, error) {
	select {
	case frame := <-p.responses:
		return copy(buf, frame), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *handshakeAdversarialPath) Write(frame []byte) (int, error) {
	var responseErr error
	p.writeOnce.Do(func() {
		close(p.written)
		if p.respond == nil {
			return
		}
		var response []byte
		response, responseErr = p.respond(append([]byte(nil), frame...))
		if responseErr == nil {
			p.responses <- response
		}
	})
	if responseErr != nil {
		return 0, responseErr
	}
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
		return len(frame), nil
	}
}

func (p *handshakeAdversarialPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (*handshakeAdversarialPath) Quality() transport.PathQuality {
	return transport.PathQuality{}
}

func (p *handshakeAdversarialPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.deathFn = fn
	p.deathMu.Unlock()
}

func (*handshakeAdversarialPath) LocalAddr() string  { return "handshake-adversarial-local" }
func (*handshakeAdversarialPath) RemoteAddr() string { return "handshake-adversarial-remote" }

func handshakeAdversarialSessionDialer(t *testing.T, transportName string, path transport.PathConn) *sessionDialer {
	t.Helper()
	dialer := &sessionDialer{Root: Path("handshake-path", PathSpec{
		Transport: transportName,
		Address:   "handshake-peer",
	})}
	if err := dialer.AddFramedPathFactory(transportName, CarrierUnknown, &handshakeAdversarialTransport{name: transportName, path: path}); err != nil {
		t.Fatalf("register test transport %q: %v", transportName, err)
	}
	return dialer
}

func TestDialContextCancellationBoundsHelloAckWait(t *testing.T) {
	transportName := nextHandshakeAdversarialTransportName("context-cancel")
	path := newHandshakeAdversarialPath(nil)
	dialer := handshakeAdversarialSessionDialer(t, transportName, path)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		conn, err := dialer.Dial(ctx)
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()

	select {
	case <-path.written:
	case <-time.After(time.Second):
		_ = path.Close()
		t.Fatal("Dial never wrote HELLO to the custom PathConn")
	}
	cancel()

	var (
		err      error
		bounded  = true
		deadline = time.NewTimer(300 * time.Millisecond)
	)
	select {
	case err = <-result:
	case <-deadline.C:
		bounded = false
		_ = path.Close()
		select {
		case err = <-result:
		case <-time.After(time.Second):
			t.Fatal("Dial remained stuck after test cleanup closed the PathConn")
		}
	}
	deadline.Stop()

	if !bounded {
		t.Fatal("canceled Dial context did not bound the HELLO_ACK wait")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial error = %v, want context.Canceled", err)
	}
}

func TestDialPacketRejectsHelloAckWithoutPacketCapability(t *testing.T) {
	transportName := nextHandshakeAdversarialTransportName("packet-capability")
	path := newHandshakeAdversarialPath(func(frame []byte) ([]byte, error) {
		if len(frame) < proto.HeaderSize {
			return nil, fmt.Errorf("short HELLO frame: %d bytes", len(frame))
		}
		hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil {
			return nil, err
		}
		if hdr.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(hdr.Flags) != proto.CtrlHello {
			return nil, fmt.Errorf("got %s, want HELLO", proto.CtrlCodeFromFlags(hdr.Flags))
		}
		hello, err := proto.DecodeHello(frame[proto.HeaderSize:])
		if err != nil {
			return nil, err
		}
		if hello.Caps&proto.CapsPacketMode == 0 {
			return nil, fmt.Errorf("DialPacket HELLO omitted packet-mode capability")
		}

		ackPayload, err := (proto.HelloAckPayload{
			Negotiation:          hello.Negotiation,
			FlowID:               hello.FlowID,
			InstanceID:           proto.InstanceID{1},
			Caps:                 0,
			InitialTargetID:      hello.InitialTargetID,
			AcceptedPeerBinding:  proto.GraphBinding{Revision: hello.GraphRevision, Digest: hello.GraphDigest},
			AcceptedPeerTargetID: hello.InitialTargetID,
			LocalTXManifest:      hello.LocalTXManifest,
		}).Encode()
		if err != nil {
			return nil, err
		}
		ackHeader := proto.Header{
			Version: proto.Version,
			Type:    proto.FrameCtrl,
			Flags:   proto.FlagsForCtrl(proto.CtrlHelloAck),
		}
		response := make([]byte, proto.HeaderSize+len(ackPayload))
		if err := ackHeader.Encode(response[:proto.HeaderSize]); err != nil {
			return nil, err
		}
		copy(response[proto.HeaderSize:], ackPayload)
		return response, nil
	})
	dialer := handshakeAdversarialSessionDialer(t, transportName, path)

	packetConn, err := dialer.DialPacket(context.Background())
	if packetConn != nil {
		_ = packetConn.Close()
	}
	if err == nil {
		t.Fatal("DialPacket accepted HELLO_ACK without CapsPacketMode")
	}
}

func TestDialReportsTypedProtocolNegotiationRejection(t *testing.T) {
	transportName := nextHandshakeAdversarialTransportName("typed-negotiation-reject")
	path := newHandshakeAdversarialPath(func(frame []byte) ([]byte, error) {
		if len(frame) < proto.HeaderSize {
			return nil, fmt.Errorf("short HELLO frame: %d bytes", len(frame))
		}
		hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil {
			return nil, err
		}
		if hdr.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(hdr.Flags) != proto.CtrlHello {
			return nil, fmt.Errorf("got %s, want HELLO", proto.CtrlCodeFromFlags(hdr.Flags))
		}
		response := make([]byte, proto.HeaderSize+1)
		if err := (proto.Header{
			Version: proto.Version,
			Type:    proto.FrameCtrl,
			Flags:   proto.FlagsForCtrl(proto.CtrlBye),
		}).Encode(response[:proto.HeaderSize]); err != nil {
			return nil, err
		}
		response[proto.HeaderSize] = byte(proto.ByeProtoVer)
		return response, nil
	})
	dialer := handshakeAdversarialSessionDialer(t, transportName, path)

	conn, err := dialer.Dial(context.Background())
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, ErrPeerProtoVersion) {
		t.Fatalf("Dial error=%v, want ErrPeerProtoVersion", err)
	}
}

func TestListenerNegotiationRejectEmitsProtocolBye(t *testing.T) {
	graph, err := compileTargetGraph(Path("path", PathSpec{Transport: "test", Address: "peer"}))
	if err != nil {
		t.Fatal(err)
	}
	flowID := [16]byte{1}
	negotiation := proto.NewNegotiation(proto.SessionEpoch(flowID))
	digest, err := graph.manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	negotiation.GraphDigest = digest
	payload, err := (proto.HelloPayload{
		Negotiation:     negotiation,
		FlowID:          flowID,
		InstanceID:      proto.InstanceID{1},
		InitialTargetID: graph.manifest.RootID,
		LocalTXManifest: graph.manifest,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(payload[2:4], proto.ProtocolMinor-1)

	byeObserved := false
	path := newHandshakeAdversarialPath(func(frame []byte) ([]byte, error) {
		if len(frame) != proto.HeaderSize+1 {
			return nil, fmt.Errorf("BYE frame size=%d", len(frame))
		}
		hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil {
			return nil, err
		}
		if hdr.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(hdr.Flags) != proto.CtrlBye ||
			proto.ByeReason(frame[proto.HeaderSize]) != proto.ByeProtoVer {
			return nil, fmt.Errorf("unexpected negotiation rejection frame")
		}
		byeObserved = true
		return nil, nil
	})
	if _, err := decodeHelloForAdmission(path, payload); !errors.Is(err, proto.ErrNegotiationIncompatible) {
		t.Fatalf("decode error=%v, want incompatible negotiation", err)
	}
	if !byeObserved {
		t.Fatal("listener did not emit protocol BYE")
	}
}
