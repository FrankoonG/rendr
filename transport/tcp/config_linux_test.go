//go:build linux

package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
	"golang.org/x/sys/unix"
)

func TestConfiguredTransportAppliesWriteBufferBeforePublishingPath(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peers := make(chan net.Conn, 2)
	go func() {
		for range 2 {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			peers <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lowFactory, err := NewWithConfig(Config{WriteBufferBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	lowValue, err := lowFactory.DialPath(ctx, transport.PathSpec{Address: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	low := lowValue.(*PathConn)
	defer low.Close()
	highFactory, err := NewWithConfig(Config{WriteBufferBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	highValue, err := highFactory.DialPath(ctx, transport.PathSpec{Address: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	high := highValue.(*PathConn)
	defer high.Close()
	for range 2 {
		peer := <-peers
		defer peer.Close()
	}
	lowBytes := tcpPathSendBuffer(t, low)
	highBytes := tcpPathSendBuffer(t, high)
	if lowBytes < 4096 || highBytes < 64<<10 || lowBytes >= highBytes {
		t.Fatalf("SO_SNDBUF low/high=%d/%d, want distinct applied requests", lowBytes, highBytes)
	}
}

func TestConfiguredListenerAppliesWriteBufferBeforePublishingPath(t *testing.T) {
	values := make([]int, 0, 2)
	for _, requested := range []int{4096, 64 << 10} {
		listener, err := ListenWithConfig("tcp4", "127.0.0.1:0", Config{WriteBufferBytes: requested})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		accepted := make(chan transport.PathConn, 1)
		acceptErr := make(chan error, 1)
		go func() {
			path, err := listener.AcceptPath(ctx)
			if err != nil {
				acceptErr <- err
				return
			}
			accepted <- path
		}()
		client, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			cancel()
			_ = listener.Close()
			t.Fatal(err)
		}
		var path transport.PathConn
		select {
		case path = <-accepted:
		case err := <-acceptErr:
			cancel()
			_ = client.Close()
			_ = listener.Close()
			t.Fatal(err)
		case <-ctx.Done():
			cancel()
			_ = client.Close()
			_ = listener.Close()
			t.Fatal(ctx.Err())
		}
		values = append(values, tcpPathSendBuffer(t, path.(*PathConn)))
		_ = path.Close()
		_ = client.Close()
		_ = listener.Close()
		cancel()
	}
	if values[0] < 4096 || values[1] < 64<<10 || values[0] >= values[1] {
		t.Fatalf("accepted SO_SNDBUF low/high=%d/%d, want distinct applied requests", values[0], values[1])
	}
}

func tcpPathSendBuffer(t *testing.T, path *PathConn) int {
	t.Helper()
	endpoint, _, current := path.endpoint.current()
	conn, ok := endpoint.(*net.TCPConn)
	if !current || !ok {
		t.Fatalf("current endpoint=%T current=%t", endpoint, current)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	value := 0
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		value, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	return value
}
