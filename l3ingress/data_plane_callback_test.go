package l3ingress

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type ingressHostileDataPlaneConn struct {
	operation string
	entered   chan struct{}
	release   <-chan struct{}
	once      sync.Once
}

func (conn *ingressHostileDataPlaneConn) invoke(operation string) {
	if conn.operation != operation {
		return
	}
	conn.once.Do(func() { close(conn.entered) })
	<-conn.release
}

func (conn *ingressHostileDataPlaneConn) Read(payload []byte) (int, error) {
	conn.invoke("Read")
	if len(payload) != 0 {
		payload[0] = 0x41
		return 1, nil
	}
	return 0, nil
}

func (conn *ingressHostileDataPlaneConn) Write(payload []byte) (int, error) {
	conn.invoke("Write")
	return len(payload), nil
}

func (conn *ingressHostileDataPlaneConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	conn.invoke("ReadFrom")
	if len(payload) != 0 {
		payload[0] = 0x42
		return 1, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4200}, nil
	}
	return 0, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4200}, nil
}

func (conn *ingressHostileDataPlaneConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	conn.invoke("WriteTo")
	return len(payload), nil
}

func (conn *ingressHostileDataPlaneConn) CloseWrite() error {
	conn.invoke("CloseWrite")
	return nil
}

func (*ingressHostileDataPlaneConn) Close() error                     { return nil }
func (*ingressHostileDataPlaneConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*ingressHostileDataPlaneConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*ingressHostileDataPlaneConn) SetDeadline(time.Time) error      { return nil }
func (*ingressHostileDataPlaneConn) SetReadDeadline(time.Time) error  { return nil }
func (*ingressHostileDataPlaneConn) SetWriteDeadline(time.Time) error { return nil }

func invokeIngressHostileOperation(
	ctx context.Context,
	executor *l3IngressDataPlaneExecutor,
	conn *ingressHostileDataPlaneConn,
) error {
	stream := newL3IngressDataPlaneTCPWithExecutor(executor, conn, "hostile TCPConn")
	packet := newL3IngressDataPlanePacketWithExecutor(executor, conn, "hostile PacketConn")
	switch conn.operation {
	case "Read":
		_, err := stream.read(ctx, make([]byte, 1))
		return err
	case "Write":
		_, err := stream.write(ctx, []byte{1})
		return err
	case "ReadFrom":
		_, _, err := packet.readFrom(ctx, make([]byte, 1))
		return err
	case "WriteTo":
		_, err := packet.writeTo(ctx, []byte{1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
		return err
	case "CloseWrite":
		return stream.closeWrite()
	default:
		return errors.New("unknown hostile operation")
	}
}

func ingressDataPlaneClassForOperation(operation string) l3IngressDataPlaneClass {
	switch operation {
	case "Read", "ReadFrom":
		return l3IngressDataPlaneRead
	case "Write", "WriteTo":
		return l3IngressDataPlaneWrite
	default:
		return l3IngressDataPlaneControl
	}
}

func assertIngressDataPlaneReason(
	t *testing.T,
	err error,
	reason CallbackFailureReason,
) {
	t.Helper()
	var callbackErr *CallbackError
	if !errors.As(err, &callbackErr) || callbackErr.Reason != reason {
		t.Fatalf("error=%v callback=%+v want reason %s", err, callbackErr, reason)
	}
}

func TestIngressDataPlaneAbandonedCallbacksAreBoundedAndRecover(t *testing.T) {
	const limit = 4
	for _, operation := range []string{"Read", "Write", "ReadFrom", "WriteTo", "CloseWrite"} {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			executor := newL3IngressDataPlaneExecutor(limit)
			release := make(chan struct{})
			results := make(chan error, limit)
			cancels := make([]context.CancelFunc, 0, limit)
			for index := 0; index < limit; index++ {
				conn := &ingressHostileDataPlaneConn{
					operation: operation, entered: make(chan struct{}), release: release,
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancels = append(cancels, cancel)
				go func() { results <- invokeIngressHostileOperation(ctx, executor, conn) }()
				select {
				case <-conn.entered:
				case <-time.After(time.Second):
					t.Fatalf("callback %d did not enter", index)
				}
				_ = conn.SetDeadline(time.Now())
				_ = conn.Close()
			}
			for _, cancel := range cancels {
				cancel()
			}
			for index := 0; index < limit; index++ {
				assertIngressDataPlaneReason(t, <-results, CallbackFailureTimeout)
			}
			class := ingressDataPlaneClassForOperation(operation)
			if got := len(executor.slots[class]); got != limit {
				t.Fatalf("retained callbacks=%d want %d", got, limit)
			}

			overflow := &ingressHostileDataPlaneConn{
				operation: operation, entered: make(chan struct{}), release: release,
			}
			started := time.Now()
			err := invokeIngressHostileOperation(context.Background(), executor, overflow)
			assertIngressDataPlaneReason(t, err, CallbackFailureSaturated)
			if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
				t.Fatalf("capacity failure took %v", elapsed)
			}
			select {
			case <-overflow.entered:
				t.Fatal("saturated callback was invoked")
			default:
			}

			close(release)
			deadline := time.Now().Add(time.Second)
			for len(executor.slots[class]) != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := len(executor.slots[class]); got != 0 {
				t.Fatalf("callback permits did not recover: %d", got)
			}
			cooperative := &ingressHostileDataPlaneConn{
				operation: operation, entered: make(chan struct{}), release: closedIngressSignal(),
			}
			if err := invokeIngressHostileOperation(context.Background(), executor, cooperative); err != nil {
				t.Fatalf("recovered callback failed: %v", err)
			}
		})
	}
}

func closedIngressSignal() <-chan struct{} {
	closed := make(chan struct{})
	close(closed)
	return closed
}

type ingressObservedPipeConn struct {
	net.Conn
	readEntered  chan struct{}
	writeEntered chan struct{}
	readOnce     sync.Once
	writeOnce    sync.Once
}

func (conn *ingressObservedPipeConn) Read(payload []byte) (int, error) {
	conn.readOnce.Do(func() { close(conn.readEntered) })
	return conn.Conn.Read(payload)
}

func (conn *ingressObservedPipeConn) Write(payload []byte) (int, error) {
	conn.writeOnce.Do(func() { close(conn.writeEntered) })
	return conn.Conn.Write(payload)
}

func (*ingressObservedPipeConn) CloseWrite() error { return nil }

func TestIngressDataPlaneMoreThan64IdleNetPipeOperationsResume(t *testing.T) {
	const flows = 96
	for _, operation := range []string{"Read", "Write"} {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			type fixture struct {
				local   net.Conn
				peer    net.Conn
				entered <-chan struct{}
				result  <-chan error
			}
			fixtures := make([]fixture, 0, flows)
			for index := 0; index < flows; index++ {
				local, peer := net.Pipe()
				observed := &ingressObservedPipeConn{
					Conn: local, readEntered: make(chan struct{}), writeEntered: make(chan struct{}),
				}
				stream := newL3IngressDataPlaneTCP(observed, "idle TCPConn")
				result := make(chan error, 1)
				if operation == "Read" {
					go func() {
						payload := make([]byte, 1)
						n, err := stream.read(context.Background(), payload)
						if err == nil && (n != 1 || payload[0] != 0x51) {
							err = errors.New("unexpected net.Pipe read")
						}
						result <- err
					}()
					fixtures = append(fixtures, fixture{
						local: observed, peer: peer, entered: observed.readEntered, result: result,
					})
				} else {
					go func() {
						n, err := stream.write(context.Background(), []byte{0x52})
						if err == nil && n != 1 {
							err = errors.New("unexpected net.Pipe write")
						}
						result <- err
					}()
					fixtures = append(fixtures, fixture{
						local: observed, peer: peer, entered: observed.writeEntered, result: result,
					})
				}
			}
			for index, fixture := range fixtures {
				select {
				case <-fixture.entered:
				case <-time.After(2 * time.Second):
					t.Fatalf("idle operation %d did not enter", index)
				}
			}
			for _, fixture := range fixtures {
				fixture := fixture
				if operation == "Read" {
					go func() { _, _ = fixture.peer.Write([]byte{0x51}) }()
				} else {
					go func() {
						payload := make([]byte, 1)
						_, _ = fixture.peer.Read(payload)
					}()
				}
			}
			for index, fixture := range fixtures {
				if err := <-fixture.result; err != nil {
					t.Fatalf("idle operation %d failed: %v", index, err)
				}
				_ = fixture.local.Close()
				_ = fixture.peer.Close()
			}
		})
	}
}

type ingressObservedUDPConn struct {
	*net.UDPConn
	entered chan struct{}
	once    sync.Once
}

func (conn *ingressObservedUDPConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	conn.once.Do(func() { close(conn.entered) })
	return conn.UDPConn.ReadFrom(payload)
}

func TestIngressDataPlaneMoreThan64IdleUDPSocketsResume(t *testing.T) {
	const flows = 80
	type fixture struct {
		conn   *ingressObservedUDPConn
		result <-chan error
	}
	fixtures := make([]fixture, 0, flows)
	for index := 0; index < flows; index++ {
		raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		observed := &ingressObservedUDPConn{UDPConn: raw, entered: make(chan struct{})}
		packet := newL3IngressDataPlanePacket(observed, "idle PacketConn")
		result := make(chan error, 1)
		go func() {
			payload := make([]byte, 1)
			n, _, err := packet.readFrom(context.Background(), payload)
			if err == nil && (n != 1 || payload[0] != 0x61) {
				err = errors.New("unexpected UDP read")
			}
			result <- err
		}()
		select {
		case <-observed.entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("idle UDP read %d did not enter", index)
		}
		fixtures = append(fixtures, fixture{conn: observed, result: result})
	}
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	for index, fixture := range fixtures {
		if n, err := sender.WriteToUDP([]byte{0x61}, fixture.conn.LocalAddr().(*net.UDPAddr)); err != nil || n != 1 {
			t.Fatalf("UDP send %d=%d, %v", index, n, err)
		}
	}
	for index, fixture := range fixtures {
		if err := <-fixture.result; err != nil {
			t.Fatalf("idle UDP read %d failed: %v", index, err)
		}
		_ = fixture.conn.Close()
	}
}
