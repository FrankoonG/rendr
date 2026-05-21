//go:build linux

package tcprepair

import (
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// TestSnapshotRestoreServerSide mirrors the M3 spike: dial → write
// payload from client → snapshot the server side → drop the 5-tuple
// via iptables → close server → restore via TCP_REPAIR → remove
// iptables → verify the unread payload is replayable from the new
// server fd, and a fresh post-migration write round-trips OK.
//
// Skipped automatically outside Linux + when CAP_NET_ADMIN is missing
// (no iptables permissions). go test -short skips it too — this
// test installs a stateful iptables rule that's slow to verify.
func TestSnapshotRestoreServerSide(t *testing.T) {
	if testing.Short() {
		t.Skip("TCP_REPAIR end-to-end is heavy; skip under -short")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for TCP_REPAIR + iptables; skip otherwise")
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvAddr := ln.Addr().(*net.TCPAddr)

	srvCh := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		srvCh <- c.(*net.TCPConn)
	}()

	cli, err := net.Dial("tcp4", srvAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cliTCP := cli.(*net.TCPConn)
	srv := <-srvCh
	cliAddr := cli.LocalAddr().(*net.TCPAddr)

	// Pre-migration round-trip to prove the connection works.
	if _, err := cliTCP.Write([]byte("PRE1")); err != nil {
		t.Fatalf("pre1 write: %v", err)
	}
	rbuf := make([]byte, 4)
	if _, err := io.ReadFull(srv, rbuf); err != nil {
		t.Fatalf("pre1 read: %v", err)
	}

	// Client writes UNREAD payload; server does NOT consume. These
	// bytes will end up in the server's recv-queue at snapshot time.
	unread := []byte("UNREAD-BYTES-FOR-RECVQ-XYZ")
	if _, err := cliTCP.Write(unread); err != nil {
		t.Fatalf("unread write: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	snap, err := Snapshot(srv)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if string(snap.RecvQueue) != string(unread) {
		t.Fatalf("recv-queue content mismatch: got %q want %q", snap.RecvQueue, unread)
	}

	// Suppress RSTs during the migration window using the same
	// netfilter abstraction as PathConn.MigratePathLocalAddr.
	cleanupDrop, err := installDropRules(srvAddr, cliAddr)
	if err != nil {
		t.Fatalf("iptables drop: %v", err)
	}
	dropInstalled := true
	defer func() {
		if dropInstalled {
			cleanupDrop()
		}
	}()

	if err := srv.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}

	newFd, err := Restore(snap)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	osFile := os.NewFile(uintptr(newFd), "server-migrated")
	newSrv, err := net.FileConn(osFile)
	if err != nil {
		osFile.Close()
		t.Fatalf("FileConn: %v", err)
	}
	osFile.Close()
	defer newSrv.Close()
	newSrvTCP := newSrv.(*net.TCPConn)

	cleanupDrop()
	dropInstalled = false

	// Replay: the unread bytes should be drainable from the new fd.
	rbuf2 := make([]byte, len(unread))
	if err := newSrvTCP.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(newSrvTCP, rbuf2); err != nil {
		t.Fatalf("post-migration replay read: %v", err)
	}
	if string(rbuf2) != string(unread) {
		t.Fatalf("post-migration replay drift: got %q want %q", rbuf2, unread)
	}

	// Fresh post-migration round-trip.
	if err := newSrvTCP.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := cliTCP.Write([]byte("POST1")); err != nil {
		t.Fatalf("client write post-migration: %v", err)
	}
	postBuf := make([]byte, 5)
	if _, err := io.ReadFull(newSrvTCP, postBuf); err != nil {
		t.Fatalf("post-migration fresh read: %v", err)
	}
	if string(postBuf) != "POST1" {
		t.Fatalf("post-migration fresh content: got %q want POST1", postBuf)
	}

	// Client side should see no error / no EOF — TCP_REPAIR's whole
	// point is the migration is invisible to the peer.
	_ = cliTCP.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	cb := make([]byte, 1)
	if _, err := cliTCP.Read(cb); err != nil {
		ne, ok := err.(net.Error)
		if !ok || !ne.Timeout() {
			t.Fatalf("client side saw non-timeout error: %v", err)
		}
	}
}
