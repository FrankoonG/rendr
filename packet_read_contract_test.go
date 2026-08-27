package rendr

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestPacketReadCannotReturnQueuedPayloadAfterClose(t *testing.T) {
	listener, err := listenRuntimeUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan PacketConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := listener.AcceptPacket(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	dialer := &sessionDialer{Root: selectorRoot([]PathSpec{{
		Transport: "udpflow",
		Address:   listener.Addr().String(),
	}})}
	client, err := dialer.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server PacketConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(6 * time.Second):
		t.Fatal("packet session accept timed out")
	}
	acceptedImpl, ok := server.(*acceptedPacketConn)
	if !ok {
		t.Fatalf("accepted packet connection type=%T", server)
	}
	serverImpl, ok := acceptedImpl.PacketConn.(*enginePacketConn)
	if !ok {
		t.Fatalf("accepted packet implementation type=%T", acceptedImpl.PacketConn)
	}

	beforeReturn := make(chan struct{})
	releaseReturn := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseReturn) }) })
	var hookOnce sync.Once
	serverImpl.readPacketBeforeReturn = func() {
		hookOnce.Do(func() { close(beforeReturn) })
		<-releaseReturn
	}
	type readResult struct {
		n    int
		addr net.Addr
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		buffer := make([]byte, 64)
		n, addr, err := server.ReadFrom(buffer)
		readDone <- readResult{n: n, addr: addr, err: err}
	}()
	if _, err := client.WriteTo([]byte("queued-before-close"), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-beforeReturn:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not dequeue the queued packet")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close remained blocked by a packet already dequeued from the engine")
	}
	releaseOnce.Do(func() { close(releaseReturn) })

	select {
	case result := <-readDone:
		if result.n != 0 || result.addr != nil || !errors.Is(result.err, net.ErrClosed) {
			t.Fatalf("ReadFrom after Close = (%d, %v, %v), want (0, nil, net.ErrClosed)", result.n, result.addr, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadFrom did not resolve after Close")
	}
}

func TestPacketReadThatLinearizesBeforeCloseReturnsPayload(t *testing.T) {
	listener, err := listenRuntimeUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan PacketConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := listener.AcceptPacket(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	dialer := &sessionDialer{Root: selectorRoot([]PathSpec{{
		Transport: "udpflow",
		Address:   listener.Addr().String(),
	}})}
	client, err := dialer.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	var server PacketConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(6 * time.Second):
		t.Fatal("packet session accept timed out")
	}
	t.Cleanup(func() { _ = server.Close() })
	acceptedImpl, ok := server.(*acceptedPacketConn)
	if !ok {
		t.Fatalf("accepted packet connection type=%T", server)
	}
	serverImpl, ok := acceptedImpl.PacketConn.(*enginePacketConn)
	if !ok {
		t.Fatalf("accepted packet implementation type=%T", acceptedImpl.PacketConn)
	}

	afterOpenCheck := make(chan struct{})
	releaseRead := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseRead) }) })
	var hookOnce sync.Once
	serverImpl.readPacketAfterOpenCheck = func() {
		hookOnce.Do(func() {
			close(afterOpenCheck)
			<-releaseRead
		})
	}
	type readResult struct {
		n    int
		addr net.Addr
		data string
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		buffer := make([]byte, 64)
		n, addr, err := server.ReadFrom(buffer)
		readDone <- readResult{n: n, addr: addr, data: string(buffer[:n]), err: err}
	}()
	const payload = "read-linearized-before-close"
	if _, err := client.WriteTo([]byte(payload), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-afterOpenCheck:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not reach the read-wins linearization boundary")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before the linearized read completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseRead) })

	select {
	case result := <-readDone:
		if result.err != nil || result.n != len(payload) || result.addr == nil || result.data != payload {
			t.Fatalf("linearized ReadFrom = (%d, %v, %q, %v), want payload", result.n, result.addr, result.data, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("linearized ReadFrom did not return")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not complete after the linearized read returned")
	}
}
