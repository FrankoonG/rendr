//go:build linux && amd64

package tcprepair

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/tcpquarantine"
	"golang.org/x/sys/unix"
)

const privilegedTestEnvironment = "RENDR_TCP_REPAIR_TEST"

func TestPrivilegedCaptureLeaseResumeIsCopySafeAndDisarmsClose(t *testing.T) {
	if os.Getenv(privilegedTestEnvironment) != "1" {
		t.Skip("set RENDR_TCP_REPAIR_TEST=1 to exercise real TCP_REPAIR")
	}
	if os.Getenv("RENDR_TCP_REPAIR_NETNS") != "1" {
		t.Fatal("privileged test must run in a dedicated network namespace")
	}
	client, server := tcpPair(t)
	defer client.Close()
	defer server.Close()
	lease, err := Capture(client)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	copy := *lease
	if err := copy.Resume(); err != nil {
		t.Fatalf("Resume copy: %v", err)
	}
	if lease.State() != SourceStateNormal {
		t.Fatalf("original lease state=%d want normal", lease.State())
	}
	if err := lease.Resume(); err != nil {
		t.Fatalf("idempotent Resume: %v", err)
	}
	if err := lease.Close(); !errors.Is(err, ErrSourceReleased) {
		t.Fatalf("Close after Resume=%v want ErrSourceReleased", err)
	}
	if _, err := client.Write([]byte("still-live")); err != nil {
		t.Fatalf("write after Resume: %v", err)
	}
	buffer := make([]byte, len("still-live"))
	if _, err := io.ReadFull(server, buffer); err != nil || string(buffer) != "still-live" {
		t.Fatalf("read after Resume=(%q,%v)", buffer, err)
	}
}

func TestPrivilegedRestorePreservesReceiveSentAndUnsentQueues(t *testing.T) {
	if os.Getenv(privilegedTestEnvironment) != "1" {
		t.Skip("set RENDR_TCP_REPAIR_TEST=1 to exercise real TCP_REPAIR")
	}
	if os.Getenv("RENDR_TCP_REPAIR_NETNS") != "1" {
		t.Fatal("privileged test must run in a dedicated network namespace")
	}
	client, server := tcpPair(t)
	defer server.Close()

	inbound := bytes.Repeat([]byte("receive-queue-"), 4096)
	if _, err := server.Write(inbound); err != nil {
		t.Fatalf("seed receive queue: %v", err)
	}
	initial := waitForInspection(t, client, func(value Inspection) bool {
		return value.ReceiveQueueBytes >= uint32(len(inbound))
	})
	setLoopbackLoss(t, true)
	lossActive := true
	defer func() {
		if lossActive {
			setLoopbackLoss(t, false)
		}
	}()

	if err := client.SetWriteBuffer(4 << 20); err != nil {
		t.Fatalf("SetWriteBuffer: %v", err)
	}
	outbound := bytes.Repeat([]byte("send-queue-"), 1<<20)
	if err := client.SetWriteDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	written, writeErr := client.Write(outbound)
	if writeErr != nil && !errors.Is(writeErr, os.ErrDeadlineExceeded) {
		t.Fatalf("seed send queue: wrote %d: %v", written, writeErr)
	}
	if err := client.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clear write deadline: %v", err)
	}
	if written == 0 {
		t.Fatal("send queue seed made no progress")
	}
	outbound = outbound[:written]

	inspection := waitForInspection(t, client, func(value Inspection) bool {
		return value.ReceiveQueueBytes != 0 && value.SendQueueBytes != 0 && value.UnsentBytes != 0
	})
	if inspection.UnsentBytes >= inspection.SendQueueBytes {
		t.Fatalf("test did not create both sent and unsent bytes: %+v", inspection)
	}

	manager, err := tcpquarantine.New(tcpquarantine.Config{})
	if err != nil {
		t.Fatalf("create quarantine manager: %v", err)
	}
	transactionID, err := tcpquarantine.NewTransactionID()
	if err != nil {
		t.Fatalf("create quarantine transaction: %v", err)
	}
	quarantineTuple := tcpquarantine.Tuple{Local: initial.Tuple.Local, Remote: initial.Tuple.Remote}
	lease, err := manager.Install(context.Background(), transactionID, quarantineTuple)
	if err != nil {
		if lease != nil {
			_ = lease.Release(context.Background())
		}
		t.Fatalf("install tuple quarantine: %v", err)
	}
	quarantineActive := true
	defer func() {
		if quarantineActive {
			_ = lease.Release(context.Background())
		}
	}()
	setLoopbackLoss(t, false)
	lossActive = false

	capture, err := Capture(client)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if capture.State() != SourceStateRepair || capture.Snapshot() == nil {
		t.Fatalf("Capture result = (state=%d snapshot=%v), want repair snapshot", capture.State(), capture.Snapshot())
	}
	snapshot := capture.Snapshot()
	receiveBytes, sendBytes, unsentBytes := snapshot.QueueBytes()
	t.Logf("snapshot queues receive=%d send=%d sent=%d unsent=%d SO_SNDBUF=%d", receiveBytes, sendBytes,
		sendBytes-unsentBytes, unsentBytes, snapshot.options.SendBuffer)
	if receiveBytes == 0 || sendBytes == 0 || unsentBytes == 0 || unsentBytes >= sendBytes {
		t.Fatalf("snapshot does not cover all queue classes: receive=%d send=%d unsent=%d", receiveBytes, sendBytes, unsentBytes)
	}
	if err := capture.Close(); err != nil {
		t.Fatalf("close captured source: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	replacement, err := Restore(ctx, snapshot)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	defer replacement.Close()
	if err := lease.Release(ctx); err != nil {
		t.Fatalf("release tuple quarantine: %v", err)
	}
	quarantineActive = false

	gotInbound := make([]byte, len(inbound))
	if _, err := io.ReadFull(replacement, gotInbound); err != nil {
		t.Fatalf("read restored receive queue: %v", err)
	}
	if !bytes.Equal(gotInbound, inbound) {
		t.Fatal("restored receive queue bytes differ")
	}
	gotOutbound := make([]byte, len(outbound))
	if _, err := io.ReadFull(server, gotOutbound); err != nil {
		t.Fatalf("read restored send queue: %v", err)
	}
	if !bytes.Equal(gotOutbound, outbound) {
		t.Fatal("restored send queue bytes differ")
	}

	clientProbe := []byte("replacement-to-peer")
	if _, err := replacement.Write(clientProbe); err != nil {
		t.Fatalf("post-restore client write: %v", err)
	}
	peerProbe := make([]byte, len(clientProbe))
	if _, err := io.ReadFull(server, peerProbe); err != nil || !bytes.Equal(peerProbe, clientProbe) {
		t.Fatalf("post-restore peer read: bytes=%q err=%v", peerProbe, err)
	}
	serverProbe := []byte("peer-to-replacement")
	if _, err := server.Write(serverProbe); err != nil {
		t.Fatalf("post-restore peer write: %v", err)
	}
	replacementProbe := make([]byte, len(serverProbe))
	if _, err := io.ReadFull(replacement, replacementProbe); err != nil || !bytes.Equal(replacementProbe, serverProbe) {
		t.Fatalf("post-restore client read: bytes=%q err=%v", replacementProbe, err)
	}
}

func TestPrivilegedRestoreSurvivesSourceAddressRemoval(t *testing.T) {
	if os.Getenv(privilegedTestEnvironment) != "1" {
		t.Skip("set RENDR_TCP_REPAIR_TEST=1 to exercise real TCP_REPAIR")
	}
	if os.Getenv("RENDR_TCP_REPAIR_NETNS") != "1" {
		t.Fatal("privileged test must run in a dedicated network namespace")
	}
	const clientIP = "198.18.0.1"
	const serverIP = "198.18.0.2"
	runIP(t, "addr", "add", clientIP+"/32", "dev", "lo")
	runIP(t, "addr", "add", serverIP+"/32", "dev", "lo")
	t.Cleanup(func() {
		_ = exec.Command("/usr/sbin/ip", "route", "del", "local", clientIP+"/32", "dev", "lo").Run()
		_ = exec.Command("/usr/sbin/ip", "addr", "del", clientIP+"/32", "dev", "lo").Run()
		_ = exec.Command("/usr/sbin/ip", "addr", "del", serverIP+"/32", "dev", "lo").Run()
	})

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(serverIP)})
	if err != nil {
		t.Fatalf("listen on test address: %v", err)
	}
	defer listener.Close()
	type acceptResult struct {
		conn *net.TCPConn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()
	client, err := net.DialTCP(
		"tcp4",
		&net.TCPAddr{IP: net.ParseIP(clientIP)},
		listener.Addr().(*net.TCPAddr),
	)
	if err != nil {
		t.Fatalf("dial from removable address: %v", err)
	}
	result := <-accepted
	if result.err != nil {
		_ = client.Close()
		t.Fatalf("accept removable-address connection: %v", result.err)
	}
	server := result.conn
	defer server.Close()
	_ = client.SetKeepAlive(false)
	_ = server.SetKeepAlive(false)

	lease, err := Capture(client)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	snapshot := lease.Snapshot()
	if err := lease.Close(); err != nil {
		t.Fatalf("close captured source: %v", err)
	}
	runIP(t, "addr", "del", clientIP+"/32", "dev", "lo")
	runIP(t, "route", "add", "local", clientIP+"/32", "dev", "lo")
	if assigned, err := interfaceHasIPv4(clientIP); err != nil {
		t.Fatalf("verify removed source address: %v", err)
	} else if assigned {
		t.Fatalf("source address %s remained assigned", clientIP)
	}

	replacement, err := Restore(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Restore after source address removal: %v", err)
	}
	defer replacement.Close()
	assertIPTransparentDisabled(t, replacement)
	if replacement.LocalAddr().String() != snapshot.Tuple().Local.String() ||
		replacement.RemoteAddr().String() != snapshot.Tuple().Remote.String() {
		t.Fatalf("restored tuple=%s->%s want=%s->%s",
			replacement.LocalAddr(), replacement.RemoteAddr(), snapshot.Tuple().Local, snapshot.Tuple().Remote)
	}
	deadline := time.Now().Add(2 * time.Second)
	_ = replacement.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	assertTCPPayload(t, replacement, server, []byte("replacement-to-peer"))
	assertTCPPayload(t, server, replacement, []byte("peer-to-replacement"))
}

func assertIPTransparentDisabled(t *testing.T, conn *net.TCPConn) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("replacement SyscallConn: %v", err)
	}
	value := -1
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		value, optionErr = unix.GetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT)
	}); err != nil {
		t.Fatalf("replacement Control: %v", err)
	}
	if optionErr != nil {
		t.Fatalf("replacement IP_TRANSPARENT readback: %v", optionErr)
	}
	if value != 0 {
		t.Fatalf("replacement retained IP_TRANSPARENT=%d", value)
	}
}

func runIP(t *testing.T, arguments ...string) {
	t.Helper()
	command := exec.Command("/usr/sbin/ip", arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ip %v: %v (%s)", arguments, err, output)
	}
}

func interfaceHasIPv4(address string) (bool, error) {
	want := net.ParseIP(address)
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false, err
	}
	for _, candidate := range addresses {
		ip, _, err := net.ParseCIDR(candidate.String())
		if err == nil && ip.Equal(want) {
			return true, nil
		}
	}
	return false, nil
}

func assertTCPPayload(t *testing.T, writer, reader net.Conn, payload []byte) {
	t.Helper()
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload=%q want=%q", got, payload)
	}
}

func setLoopbackLoss(t *testing.T, enabled bool) {
	t.Helper()
	arguments := []string{"qdisc", "replace", "dev", "lo", "root", "netem", "loss", "100%"}
	if !enabled {
		arguments = []string{"qdisc", "del", "dev", "lo", "root"}
	}
	command := exec.Command("/usr/sbin/tc", arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("tc %v: %v (%s)", arguments, err, output)
	}
}

func waitForInspection(t *testing.T, conn *net.TCPConn, ready func(Inspection) bool) Inspection {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		inspection, err := Inspect(conn)
		if err != nil {
			t.Fatalf("Inspect: %v", err)
		}
		if ready(inspection) {
			return inspection
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue condition not reached: %+v", inspection)
		}
		time.Sleep(time.Millisecond)
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()

	type accepted struct {
		conn *net.TCPConn
		err  error
	}
	result := make(chan accepted, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		result <- accepted{conn: conn, err: acceptErr}
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	accept := <-result
	if accept.err != nil {
		client.Close()
		t.Fatalf("AcceptTCP: %v", accept.err)
	}
	if err := client.SetKeepAlive(false); err != nil {
		client.Close()
		accept.conn.Close()
		t.Fatalf("client SetKeepAlive: %v", err)
	}
	if err := accept.conn.SetKeepAlive(false); err != nil {
		client.Close()
		accept.conn.Close()
		t.Fatalf("server SetKeepAlive: %v", err)
	}
	return client, accept.conn
}
