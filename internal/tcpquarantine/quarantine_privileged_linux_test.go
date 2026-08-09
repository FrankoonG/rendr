//go:build linux

package tcpquarantine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestPrivilegedPreflightInstallAndReleaseDataPlane(t *testing.T) {
	if os.Getenv("RENDR_TCP_QUARANTINE_TEST") != "1" {
		t.Skip("set RENDR_TCP_QUARANTINE_TEST=1 to exercise real nft quarantine")
	}
	if os.Getenv("RENDR_TCP_QUARANTINE_NETNS") != "1" {
		t.Fatal("privileged test must run in a dedicated network namespace")
	}
	client, server := quarantineTCPPair(t)
	defer client.Close()
	defer server.Close()

	manager, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	transactionID, err := NewTransactionID()
	if err != nil {
		t.Fatalf("NewTransactionID: %v", err)
	}
	tuple := Tuple{Local: tcpAddrPort(t, client.LocalAddr()), Remote: tcpAddrPort(t, client.RemoteAddr())}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.Preflight(ctx, transactionID, tuple); err != nil {
		t.Fatalf("Preflight: %v", err)
	}

	preflightPayload := []byte("preflight-left-no-state")
	if _, err := server.Write(preflightPayload); err != nil {
		t.Fatalf("write after Preflight: %v", err)
	}
	got := make([]byte, len(preflightPayload))
	if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, preflightPayload) {
		t.Fatalf("read after Preflight: bytes=%q err=%v", got, err)
	}

	lease, err := manager.Install(ctx, transactionID, tuple)
	if err != nil {
		if lease != nil {
			_ = lease.Release(context.Background())
		}
		t.Fatalf("Install: %v", err)
	}
	released := false
	defer func() {
		if !released {
			_ = lease.Release(context.Background())
		}
	}()

	blockedPayload := []byte("quarantine-must-drop-this-segment")
	if _, err := server.Write(blockedPayload); err != nil {
		t.Fatalf("write while quarantined: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, len(blockedPayload))
	if n, err := client.Read(buffer); err == nil || n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("quarantine read = (%d, %v), want timeout with no bytes", n, err)
	}
	if err := client.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear read deadline: %v", err)
	}
	if err := lease.Release(ctx); err != nil {
		t.Fatalf("Release: %v", err)
	}
	released = true
	if _, err := io.ReadFull(client, buffer); err != nil || !bytes.Equal(buffer, blockedPayload) {
		t.Fatalf("read after Release: bytes=%q err=%v", buffer, err)
	}
}

func quarantineTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()
	type result struct {
		conn *net.TCPConn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		accepted <- result{conn: conn, err: acceptErr}
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	server := <-accepted
	if server.err != nil {
		client.Close()
		t.Fatalf("AcceptTCP: %v", server.err)
	}
	return client, server.conn
}

func tcpAddrPort(t *testing.T, address net.Addr) netip.AddrPort {
	t.Helper()
	tcp, ok := address.(*net.TCPAddr)
	if !ok {
		t.Fatalf("address %T is not *net.TCPAddr", address)
	}
	ip, ok := netip.AddrFromSlice(tcp.IP)
	if !ok || tcp.Port <= 0 || tcp.Port > 65535 {
		t.Fatalf("invalid TCP address %v", tcp)
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(tcp.Port))
}
