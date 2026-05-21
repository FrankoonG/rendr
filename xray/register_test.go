package xray

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	xinternet "github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestRegisterRendrTransportDialerWithXrayInternetDial(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptContext(ctx)
		if err != nil {
			t.Errorf("AcceptContext: %v", err)
			return
		}
		accepted <- c
	}()

	name := uniqueRendrTransportName(t)
	if err := RegisterRendrTransportDialer(name, &Config{
		Mode:  ModePrime,
		Paths: []PathSpec{{Transport: "tcp", Address: ln.Addr().String()}},
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := xinternet.Dial(ctx, xnet.TCPDestination(xnet.LocalHostIP, 443), &xinternet.MemoryStreamConfig{ProtocolName: name})
	if err != nil {
		t.Fatalf("xray internet.Dial through rendr: %v", err)
	}
	defer c.Close()

	srv := <-accepted
	defer srv.Close()

	want := []byte("xray-core dialer registry over rendr")
	if _, err := c.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("payload got %q want %q", got, want)
	}
}

func TestRegisterRendrTransportListenerWithXrayInternetListen(t *testing.T) {
	name := uniqueRendrTransportName(t)
	if err := RegisterRendrTransportListener(name, nil); err != nil {
		t.Fatal(err)
	}

	accepted := make(chan stat.Connection, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := xinternet.ListenTCP(ctx, xnet.LocalHostIP, 0, &xinternet.MemoryStreamConfig{ProtocolName: name}, func(c stat.Connection) {
		accepted <- c
	})
	if err != nil {
		t.Fatalf("xray internet.ListenTCP through rendr: %v", err)
	}
	defer ln.Close()

	d, err := NewDialer(&Config{
		Mode:  ModePrime,
		Paths: []PathSpec{{Transport: "tcp", Address: ln.Addr().String()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.DialContext(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var srv stat.Connection
	select {
	case srv = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("xray listener handler did not receive accepted conn")
	}
	defer srv.Close()

	want := []byte("xray-core listener registry over rendr")
	if _, err := c.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("payload got %q want %q", got, want)
	}
}

func TestJoinXrayHostPortIPv6(t *testing.T) {
	got := joinXrayHostPort(xnet.LocalHostIPv6, 1234)
	if got != "[::1]:1234" {
		t.Fatalf("join IPv6 got %q", got)
	}
}

func uniqueRendrTransportName(t *testing.T) string {
	t.Helper()
	name := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	return name + "-" + time.Now().Format("150405.000000000")
}
