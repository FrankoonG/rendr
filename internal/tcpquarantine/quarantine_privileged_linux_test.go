//go:build linux

package tcpquarantine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const restartHelperEnvironment = "RENDR_TCP_QUARANTINE_RESTART_HELPER"

func TestPrivilegedProcessRestartReconcilesStaleQuarantine(t *testing.T) {
	if os.Getenv(restartHelperEnvironment) == "1" {
		runRestartQuarantineHelper()
	}
	if os.Getenv("RENDR_TCP_QUARANTINE_TEST") != "1" {
		t.Skip("set RENDR_TCP_QUARANTINE_TEST=1 to exercise real nft quarantine")
	}
	if os.Getenv("RENDR_TCP_QUARANTINE_NETNS") != "1" {
		t.Fatal("privileged test must run in a dedicated network namespace")
	}

	command := exec.Command(os.Args[0], "-test.run=^TestPrivilegedProcessRestartReconcilesStaleQuarantine$")
	command.Env = append(os.Environ(), restartHelperEnvironment+"=1")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("helper stdin: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("helper stdout: %v", err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	waited := false
	defer func() {
		_ = stdin.Close()
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		_ = stdin.Close()
		waitErr := command.Wait()
		waited = true
		t.Fatalf("helper did not publish table: scan=%v wait=%v stderr=%s", scanner.Err(), waitErr, stderr.String())
	}
	table := strings.TrimPrefix(scanner.Text(), "TABLE=")
	identity, managed, err := parseManagedTableName(table)
	if err != nil || !managed {
		t.Fatalf("helper table %q is not managed: %v", table, err)
	}
	spec := identity.spec()

	manager, err := New(Config{})
	if err != nil {
		t.Fatalf("New parent manager: %v", err)
	}
	report, err := manager.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile live helper: %v", err)
	}
	if report.Live != 1 || report.Removed != 0 || report.Unknown != 0 {
		t.Fatalf("live helper report = %+v", report)
	}
	scope, err := currentNamespaceScope()
	if err != nil {
		t.Fatal(err)
	}
	if observed := manager.observeBounded(context.Background(), scope, spec); observed.state != stateExact {
		t.Fatalf("live helper table observation = %+v", observed)
	}

	if err := stdin.Close(); err != nil {
		t.Fatalf("release helper: %v", err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("helper exit: %v stderr=%s", err, stderr.String())
	}
	waited = true

	report, err = manager.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile exited helper: %v", err)
	}
	if report.Removed != 1 || report.Live != 0 || report.Unknown != 0 {
		t.Fatalf("exited helper report = %+v", report)
	}
	if observed := manager.observeBounded(context.Background(), scope, spec); observed.state != stateAbsent {
		t.Fatalf("stale helper table observation = %+v", observed)
	}
}

func runRestartQuarantineHelper() {
	manager, err := New(Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "new manager: %v\n", err)
		os.Exit(2)
	}
	lease, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if err != nil || lease == nil {
		fmt.Fprintf(os.Stderr, "install quarantine: lease=%v err=%v\n", lease, err)
		os.Exit(2)
	}
	fmt.Printf("TABLE=%s\n", lease.state.spec.table)
	_ = os.Stdout.Sync()
	_, _ = io.Copy(io.Discard, os.Stdin)
	// Deliberately bypass Release to model abrupt process ownership loss.
	os.Exit(0)
}

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
