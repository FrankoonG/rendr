//go:build linux

package tcprepair

import (
	"bytes"
	"context"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/transport"
)

func newTransportPair(t *testing.T) (*PathConn, *PathConn) {
	t.Helper()
	if err := Available(); err != nil {
		t.Skipf("tcprepair unavailable: %v", err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type acceptResult struct {
		conn *PathConn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- acceptResult{err: err}
			return
		}
		accepted <- acceptResult{conn: Wrap(c.(*net.TCPConn))}
	}()

	tp := New()
	pc, err := tp.DialPath(context.Background(), transport.PathSpec{Address: ln.Addr().String()})
	if err != nil {
		_ = ln.Close()
		<-accepted
		t.Fatal(err)
	}
	res := <-accepted
	if res.err != nil {
		_ = pc.Close()
		t.Fatalf("accept: %v", res.err)
	}
	t.Cleanup(func() {
		_ = pc.Close()
		_ = res.conn.Close()
	})
	return pc.(*PathConn), res.conn
}

func TestTransportRoundTrip(t *testing.T) {
	client, server := newTransportPair(t)

	frame := bytes.Repeat([]byte{0xCD}, 128)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1<<16)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], frame) {
		t.Fatalf("frame round-trip mismatch: got %x want %x", buf[:n], frame)
	}
}

func TestTransportExposesTCPConn(t *testing.T) {
	client, _ := newTransportPair(t)
	if client.TCPConn() == nil {
		t.Fatal("TCPConn() returned nil")
	}
}

func TestAvailableExpectation(t *testing.T) {
	expect := os.Getenv("RENDR_EXPECT_TCPREPAIR")
	if expect == "" {
		t.Skip("expectation env unset")
	}
	err := Available()
	switch expect {
	case "available":
		if err != nil {
			t.Fatalf("Available(): %v", err)
		}
	case "unavailable":
		if err == nil {
			t.Fatal("Available() unexpectedly succeeded")
		}
		if !strings.Contains(err.Error(), "CAP_NET_ADMIN required") {
			t.Fatalf("unexpected unavailable error: %v", err)
		}
		if !strings.Contains(err.Error(), "gvisor fallback") {
			t.Fatalf("unavailable error does not name gvisor fallback: %v", err)
		}
	default:
		t.Fatalf("unknown expectation %q", expect)
	}
}
