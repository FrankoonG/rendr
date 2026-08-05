package rendr

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport/tcp"
)

func TestRuntimeListenerNegotiationRejectionConformance(t *testing.T) {
	const unknownRequiredFeature = uint64(1) << 63
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			name: "older minor",
			mutate: func(frame []byte) {
				binary.BigEndian.PutUint16(frame[proto.HeaderSize+2:proto.HeaderSize+4], proto.ProtocolMinor-1)
			},
		},
		{
			name: "unknown required feature",
			mutate: func(frame []byte) {
				supported := binary.BigEndian.Uint64(frame[proto.HeaderSize+8 : proto.HeaderSize+16])
				required := binary.BigEndian.Uint64(frame[proto.HeaderSize+16 : proto.HeaderSize+24])
				binary.BigEndian.PutUint64(frame[proto.HeaderSize+8:proto.HeaderSize+16], supported|unknownRequiredFeature)
				binary.BigEndian.PutUint64(frame[proto.HeaderSize+16:proto.HeaderSize+24], required|unknownRequiredFeature)
			},
		},
		{
			name: "unsupported required mobility",
			mutate: func(frame []byte) {
				binary.BigEndian.PutUint16(frame[proto.HeaderSize+4:proto.HeaderSize+6], uint16(proto.LeafMobilityTCPRepair))
				binary.BigEndian.PutUint16(frame[proto.HeaderSize+6:proto.HeaderSize+8], uint16(proto.LeafMobilityTCPRepair))
			},
		},
		{
			name: "missing terminal-commit feature",
			mutate: func(frame []byte) {
				feature := uint64(proto.FeaturePathAdmissionTerminalCommit)
				supported := binary.BigEndian.Uint64(frame[proto.HeaderSize+8 : proto.HeaderSize+16])
				required := binary.BigEndian.Uint64(frame[proto.HeaderSize+16 : proto.HeaderSize+24])
				binary.BigEndian.PutUint64(frame[proto.HeaderSize+8:proto.HeaderSize+16], supported&^feature)
				binary.BigEndian.PutUint64(frame[proto.HeaderSize+16:proto.HeaderSize+24], required&^feature)
			},
		},
		{
			name: "missing cross-route terminal feature",
			mutate: func(frame []byte) {
				feature := uint64(proto.FeaturePathAdmissionCrossRouteTerminal)
				supported := binary.BigEndian.Uint64(frame[proto.HeaderSize+8 : proto.HeaderSize+16])
				required := binary.BigEndian.Uint64(frame[proto.HeaderSize+16 : proto.HeaderSize+24])
				binary.BigEndian.PutUint64(frame[proto.HeaderSize+8:proto.HeaderSize+16], supported&^feature)
				binary.BigEndian.PutUint64(frame[proto.HeaderSize+16:proto.HeaderSize+24], required&^feature)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rawListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			serverRuntime, err := NewRuntime(RuntimeConfig{})
			if err != nil {
				_ = rawListener.Close()
				t.Fatal(err)
			}
			listener, err := serverRuntime.Listen(ListenConfig{Streams: []StreamSource{{
				Name:     "stream",
				Carrier:  CarrierTCP,
				Listener: rawListener,
			}}})
			if err != nil {
				_ = rawListener.Close()
				t.Fatal(err)
			}
			defer listener.Close()

			clientRuntime, err := NewRuntime(RuntimeConfig{})
			if err != nil {
				t.Fatal(err)
			}
			var wire *runtimeProtocolMutationConn
			err = clientRuntime.RegisterStreamFactory("stream", StreamFactory{
				Carrier: CarrierTCP,
				Dial: func(ctx context.Context, address string) (net.Conn, error) {
					conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
					if err != nil {
						return nil, err
					}
					wire = &runtimeProtocolMutationConn{
						Conn:   conn,
						mutate: runtimeProtocolControlMutation(proto.CtrlHello, proto.HeaderSize+proto.HelloPayloadSize, test.mutate),
					}
					return wire, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, dialErr := clientRuntime.Dial(ctx, SessionConfig{Root: Path("stream", PathSpec{
				Transport: "stream",
				Address:   rawListener.Addr().String(),
			})})
			if conn != nil {
				_ = conn.Close()
				t.Fatal("Runtime.Dial returned a connection for an incompatible negotiation")
			}
			if !errors.Is(dialErr, ErrPeerProtoVersion) {
				t.Errorf("Runtime.Dial error=%v, want ErrPeerProtoVersion", dialErr)
			}
			if wire == nil || !wire.mutationObserved() {
				t.Fatal("test did not mutate the outbound HELLO")
			}
			if reason := runtimeProtocolCapturedByeReason(t, wire.capturedReads()); reason != proto.ByeProtoVer {
				t.Errorf("listener BYE reason=%d, want protocol version", reason)
			}
			assertRuntimeProtocolNoAcceptedSession(t, listener)
		})
	}
}

func TestRuntimeDialMalformedHelloAckIsTypedProtocolFailure(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
		want   error
	}{
		{
			name: "zero instance id",
			mutate: func(frame []byte) {
				instanceOffset := proto.HeaderSize + proto.NegotiationSize + 16
				clear(frame[instanceOffset : instanceOffset+len(proto.InstanceID{})])
			},
			want: ErrPeerProtocol,
		},
		{
			name: "data as first response",
			mutate: func(frame []byte) {
				header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
				if err != nil {
					return
				}
				header.Type = proto.FrameData
				header.Flags = 0
				_ = header.Encode(frame[:proto.HeaderSize])
			},
			want: ErrPeerProtocol,
		},
		{
			name: "unexpected valid control as first response",
			mutate: func(frame []byte) {
				header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
				if err != nil {
					return
				}
				header.Flags = proto.FlagsForCtrl(proto.CtrlHeartbeat)
				_ = header.Encode(frame[:proto.HeaderSize])
			},
			want: ErrPeerProtocol,
		},
		{
			name: "noncanonical first response sequence",
			mutate: func(frame []byte) {
				header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
				if err != nil {
					return
				}
				header.Seq = 1
				_ = header.Encode(frame[:proto.HeaderSize])
			},
			want: ErrPeerProtocol,
		},
		{
			name: "incompatible negotiation",
			mutate: func(frame []byte) {
				binary.BigEndian.PutUint16(frame[proto.HeaderSize+2:proto.HeaderSize+4], proto.ProtocolMinor-1)
			},
			want: ErrPeerProtoVersion,
		},
		{
			name: "unsupported required mobility",
			mutate: func(frame []byte) {
				binary.BigEndian.PutUint16(frame[proto.HeaderSize+4:proto.HeaderSize+6], uint16(proto.LeafMobilityTCPRepair))
				binary.BigEndian.PutUint16(frame[proto.HeaderSize+6:proto.HeaderSize+8], uint16(proto.LeafMobilityTCPRepair))
			},
			want: ErrPeerProtoVersion,
		},
		{
			name: "session kind mismatch",
			mutate: func(frame []byte) {
				offset := proto.HeaderSize + proto.NegotiationSize + 32
				caps := binary.BigEndian.Uint32(frame[offset : offset+4])
				binary.BigEndian.PutUint32(frame[offset:offset+4], caps|proto.CapsPacketMode)
			},
			want: ErrPeerProtocol,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rawListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			mutatingListener := &runtimeProtocolMutationListener{
				Listener: rawListener,
				mutate:   runtimeProtocolControlMutation(proto.CtrlHelloAck, proto.HeaderSize+proto.HelloAckPayloadSize, test.mutate),
			}
			serverRuntime, err := NewRuntime(RuntimeConfig{})
			if err != nil {
				_ = rawListener.Close()
				t.Fatal(err)
			}
			listener, err := serverRuntime.Listen(ListenConfig{Streams: []StreamSource{{
				Name:     "stream",
				Carrier:  CarrierTCP,
				Listener: mutatingListener,
			}}})
			if err != nil {
				_ = rawListener.Close()
				t.Fatal(err)
			}
			defer listener.Close()

			clientRuntime, err := NewRuntime(RuntimeConfig{})
			if err != nil {
				t.Fatal(err)
			}
			err = clientRuntime.RegisterStreamFactory("stream", StreamFactory{
				Carrier: CarrierTCP,
				Dial: func(ctx context.Context, address string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", address)
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, dialErr := clientRuntime.Dial(ctx, SessionConfig{Root: Path("stream", PathSpec{
				Transport: "stream",
				Address:   rawListener.Addr().String(),
			})})
			if conn != nil {
				_ = conn.Close()
				t.Fatal("Runtime.Dial returned a connection for a malformed HELLO_ACK")
			}
			if !errors.Is(dialErr, test.want) {
				t.Errorf("Runtime.Dial error=%v, want %v", dialErr, test.want)
			}
			if test.want == ErrPeerProtocol && errors.Is(dialErr, ErrPeerProtoVersion) {
				t.Errorf("malformed HELLO_ACK was misclassified as ErrPeerProtoVersion: %v", dialErr)
			}
			if wire := mutatingListener.acceptedConn(); wire == nil || !wire.mutationObserved() {
				t.Fatal("test did not mutate the listener's HELLO_ACK")
			}
			assertRuntimeProtocolNoAcceptedSession(t, listener)

			validClient, err := clientRuntime.Dial(ctx, SessionConfig{Root: Path("stream", PathSpec{
				Transport: "stream",
				Address:   rawListener.Addr().String(),
			})})
			if err != nil {
				t.Fatalf("valid retry after rejected HELLO_ACK: %v", err)
			}
			validServer, err := listener.AcceptStream(ctx)
			if err != nil {
				_ = validClient.(*engineBackedConn).e.Close()
				t.Fatalf("accept valid retry after rejected HELLO_ACK: %v", err)
			}
			assertStreamRoundTrip(t, validClient, validServer, []byte("valid-after-protocol-rejection"))
			_ = validClient.Close()
			_ = validServer.Close()
		})
	}
}

type runtimeProtocolMutationConn struct {
	net.Conn
	mutate func([]byte) bool

	mu       sync.Mutex
	mutated  bool
	readWire []byte
}

func (c *runtimeProtocolMutationConn) Write(payload []byte) (int, error) {
	wire := payload
	c.mu.Lock()
	if !c.mutated && c.mutate != nil {
		candidate := append([]byte(nil), payload...)
		if c.mutate(candidate) {
			c.mutated = true
			wire = candidate
		}
	}
	c.mu.Unlock()
	return c.Conn.Write(wire)
}

func (c *runtimeProtocolMutationConn) Read(payload []byte) (int, error) {
	n, err := c.Conn.Read(payload)
	if n > 0 {
		c.mu.Lock()
		c.readWire = append(c.readWire, payload[:n]...)
		c.mu.Unlock()
	}
	return n, err
}

func (c *runtimeProtocolMutationConn) mutationObserved() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mutated
}

func (c *runtimeProtocolMutationConn) capturedReads() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.readWire...)
}

type runtimeProtocolMutationListener struct {
	net.Listener
	mutate func([]byte) bool
	once   sync.Once

	mu       sync.Mutex
	accepted *runtimeProtocolMutationConn
}

func (l *runtimeProtocolMutationListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	var mutate func([]byte) bool
	l.once.Do(func() { mutate = l.mutate })
	wire := &runtimeProtocolMutationConn{Conn: conn, mutate: mutate}
	l.mu.Lock()
	l.accepted = wire
	l.mu.Unlock()
	return wire, nil
}

func (l *runtimeProtocolMutationListener) acceptedConn() *runtimeProtocolMutationConn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.accepted
}

func runtimeProtocolControlMutation(code proto.CtrlCode, minimumSize int, mutate func([]byte)) func([]byte) bool {
	return func(frame []byte) bool {
		if len(frame) < minimumSize {
			return false
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != code {
			return false
		}
		mutate(frame)
		return true
	}
}

func runtimeProtocolCapturedByeReason(t *testing.T, wire []byte) proto.ByeReason {
	t.Helper()
	for offset := 0; offset+tcp.LengthPrefixSize <= len(wire); {
		frameSize := int(binary.BigEndian.Uint16(wire[offset : offset+tcp.LengthPrefixSize]))
		offset += tcp.LengthPrefixSize
		if frameSize == 0 || offset+frameSize > len(wire) {
			break
		}
		frame := wire[offset : offset+frameSize]
		offset += frameSize
		if len(frame) < proto.HeaderSize {
			continue
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlBye {
			continue
		}
		bye, err := proto.DecodeBye(frame[proto.HeaderSize:])
		if err != nil {
			t.Fatalf("decode listener BYE: %v", err)
		}
		return bye.Reason
	}
	t.Fatalf("listener wire did not contain a complete BYE frame: %x", wire)
	return 0
}

func assertRuntimeProtocolNoAcceptedSession(t *testing.T, listener *SessionListener) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		listener.inflightMu.Lock()
		inflight := len(listener.inflight)
		listener.inflightMu.Unlock()
		if inflight == 0 && len(listener.handshakes) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rejected handshake did not quiesce: inflight=%d handshakes=%d", inflight, len(listener.handshakes))
		}
		time.Sleep(time.Millisecond)
	}
	if queued := len(listener.streamAccept); queued != 0 {
		t.Fatalf("rejected handshake queued %d application sessions", queued)
	}
	if slots := len(listener.streamSlots); slots != 0 {
		t.Fatalf("rejected handshake retained %d stream accept slots", slots)
	}
	if flows := listener.FlowIDs(); len(flows) != 0 {
		t.Fatalf("rejected handshake published active flows: %x", flows)
	}
}
