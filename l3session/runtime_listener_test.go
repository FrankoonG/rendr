package l3session

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/virtualif"
)

func TestRuntimeListenerL3IdentityCapabilityIsLocalFact(t *testing.T) {
	for _, tt := range []struct {
		name   string
		accept bool
	}{
		{name: "not-advertised", accept: false},
		{name: "advertised", accept: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
			if err != nil {
				t.Fatal(err)
			}
			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listener, err := serverRuntime.Listen(rendr.ListenConfig{
				AcceptL3Identity: tt.accept,
				Streams:          []rendr.StreamSource{{Name: "tcp", Carrier: rendr.CarrierTCP, Listener: raw}},
			})
			if err != nil {
				_ = raw.Close()
				t.Fatal(err)
			}
			defer listener.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			acceptCtx, cancelAccept := context.WithCancel(ctx)
			defer cancelAccept()
			accepted := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptStream(acceptCtx)
				if conn != nil {
					_ = conn.Close()
				}
				accepted <- err
			}()

			starter := &Starter{}
			session, startErr := starter.Start(ctx, l3ingress.SessionRequest{
				Kind:               l3ingress.SessionKindStream,
				Identity:           testIdentity(l3ingress.ProtocolTCP),
				Peer:               "peer-a",
				Root:               rendr.Path("tcp", rendr.PathSpec{Transport: "tcp", Address: listener.Addr().String()}),
				Egress:             "direct",
				PreserveL3Identity: true,
			})
			if tt.accept {
				if startErr != nil {
					t.Fatalf("Start with factual peer capability: %v", startErr)
				}
				_ = session.Close()
			} else {
				if session != nil {
					_ = session.Close()
					t.Fatal("Start returned a session without peer L3 capability")
				}
				var identityErr *virtualif.Error
				if !errors.As(startErr, &identityErr) || identityErr.Reason != virtualif.ReasonPeerL3IdentityUnsupported {
					t.Fatalf("Start error = %v, want peer L3 identity unsupported", startErr)
				}
			}
			if tt.accept {
				select {
				case err := <-accepted:
					if err != nil {
						t.Fatalf("AcceptStream: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("listener did not complete accepted session")
				}
			} else {
				select {
				case err := <-accepted:
					t.Fatalf("incapable listener published a session: %v", err)
				case <-time.After(50 * time.Millisecond):
				}
				cancelAccept()
				select {
				case err := <-accepted:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("AcceptStream after cancel = %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("unpublished AcceptStream did not cancel")
				}
			}
		})
	}
}

func TestRuntimePacketListenerL3IdentityCapabilityIsLocalFact(t *testing.T) {
	for _, accept := range []bool{false, true} {
		name := "not-advertised"
		if accept {
			name = "advertised"
		}
		t.Run(name, func(t *testing.T) {
			serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
			if err != nil {
				t.Fatal(err)
			}
			raw, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			listener, err := serverRuntime.Listen(rendr.ListenConfig{
				AcceptL3Identity: accept,
				Packets:          []rendr.PacketSource{{Name: "udpflow", Carrier: rendr.CarrierUDP, Conn: raw}},
			})
			if err != nil {
				_ = raw.Close()
				t.Fatal(err)
			}
			defer listener.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			acceptCtx, cancelAccept := context.WithCancel(ctx)
			defer cancelAccept()
			accepted := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptPacket(acceptCtx)
				if conn != nil {
					_ = conn.Close()
				}
				accepted <- err
			}()

			session, startErr := (&Starter{}).Start(ctx, l3ingress.SessionRequest{
				Kind:               l3ingress.SessionKindPacket,
				Identity:           testIdentity(l3ingress.ProtocolUDP),
				Peer:               "peer-a",
				Root:               rendr.Path("udp", rendr.PathSpec{Transport: "udpflow", Address: listener.Addr().String()}),
				Egress:             "direct",
				PreserveL3Identity: true,
			})
			if accept {
				if startErr != nil {
					t.Fatal(startErr)
				}
				_ = session.Close()
				select {
				case err := <-accepted:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("AcceptPacket did not publish capable session")
				}
				return
			}
			if session != nil {
				_ = session.Close()
				t.Fatal("Start returned packet session without peer L3 capability")
			}
			var identityErr *virtualif.Error
			if !errors.As(startErr, &identityErr) || identityErr.Reason != virtualif.ReasonPeerL3IdentityUnsupported {
				t.Fatalf("Start error = %v", startErr)
			}
			select {
			case err := <-accepted:
				t.Fatalf("incapable packet listener published a session: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			cancelAccept()
			select {
			case err := <-accepted:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("AcceptPacket after cancel = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("unpublished AcceptPacket did not cancel")
			}
		})
	}
}

func newTestStreamSessionListener(t *testing.T, sourceName string) *rendr.SessionListener {
	t.Helper()
	runtime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen(rendr.ListenConfig{AcceptL3Identity: true, Streams: []rendr.StreamSource{{
		Name:     sourceName,
		Carrier:  rendr.CarrierTCP,
		Listener: rawListener,
	}}})
	if err != nil {
		_ = rawListener.Close()
		t.Fatal(err)
	}
	return listener
}

func newTestPacketSessionListener(t *testing.T, sourceName string) *rendr.SessionListener {
	t.Helper()
	runtime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	rawPacketConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen(rendr.ListenConfig{AcceptL3Identity: true, Packets: []rendr.PacketSource{{
		Name:    sourceName,
		Carrier: rendr.CarrierUDP,
		Conn:    rawPacketConn,
	}}})
	if err != nil {
		_ = rawPacketConn.Close()
		t.Fatal(err)
	}
	return listener
}
