package rendr

import (
	"context"
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

func registerHandshakeAdversarialTransport(t *testing.T, name string, path transport.PathConn) {
	t.Helper()
	if err := transport.Default.Register(&handshakeAdversarialTransport{name: name, path: path}); err != nil {
		t.Fatalf("register test transport %q: %v", name, err)
	}
}

func handshakeAdversarialDialer(transportName string) *Dialer {
	return &Dialer{Root: Path("handshake-path", PathSpec{
		Transport: transportName,
		Address:   "handshake-peer",
	})}
}

func TestDialContextCancellationBoundsHelloAckWait(t *testing.T) {
	transportName := nextHandshakeAdversarialTransportName("context-cancel")
	path := newHandshakeAdversarialPath(nil)
	registerHandshakeAdversarialTransport(t, transportName, path)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		conn, err := handshakeAdversarialDialer(transportName).Dial(ctx)
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
	registerHandshakeAdversarialTransport(t, transportName, path)

	packetConn, err := handshakeAdversarialDialer(transportName).DialPacket(context.Background())
	if packetConn != nil {
		_ = packetConn.Close()
	}
	if err == nil {
		t.Fatal("DialPacket accepted HELLO_ACK without CapsPacketMode")
	}
}
