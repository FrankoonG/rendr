//go:build linux

package rendr

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport/tcprepair"
)

func TestTCPRepairAdminPathRebuildSameTuple(t *testing.T) {
	if testing.Short() {
		t.Skip("TCP_REPAIR integration is heavy; skip under -short")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for TCP_REPAIR + iptables")
	}
	if raceDetectorEnabled {
		t.Skip("TCP_REPAIR integration is timing-sensitive under -race; covered by T5")
	}
	if err := tcprepair.Available(); err != nil {
		t.Skipf("tcprepair unavailable: %v", err)
	}

	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- c
	}()

	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{
			{Transport: "tcprepair", Address: ln.Addr().String()},
		})}

	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	adm := client.(testConnectionControl)
	pathID := adm.ActivePath()
	if pathID == 0 {
		t.Fatal("no active path")
	}

	if _, err := client.Write([]byte("pre")); err != nil {
		t.Fatalf("pre write: %v", err)
	}
	buf := make([]byte, 16)
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("pre read: %v", err)
	}
	if string(buf[:n]) != "pre" {
		t.Fatalf("pre payload: got %q", buf[:n])
	}

	if err := adm.MigratePathLocalAddr(pathID, ""); err != nil {
		if strings.Contains(err.Error(), "use gvisor fallback") {
			t.Skipf("tcprepair same-tuple rebuild unsupported on this kernel: %v", err)
		}
		t.Fatalf("MigratePathLocalAddr: %v", err)
	}
	if got := adm.ActivePath(); got != pathID {
		t.Fatalf("active path changed across rebuild: got %d want %d", got, pathID)
	}

	if _, err := client.Write([]byte("post")); err != nil {
		t.Fatalf("post write: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err = server.Read(buf)
	if err != nil {
		t.Fatalf("post read: %v", err)
	}
	if string(buf[:n]) != "post" {
		t.Fatalf("post payload: got %q", buf[:n])
	}

	if _, err := server.Write([]byte("back")); err != nil {
		t.Fatalf("server write back: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("client read back: %v", err)
	}
	if string(buf[:n]) != "back" {
		t.Fatalf("back payload: got %q", buf[:n])
	}

	// No EOF / reset should leak to the server peer as part of the
	// same-tuple rebuild.
	if err := server.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Read(buf); err != nil {
		if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
			return
		}
		if err != io.EOF {
			t.Fatalf("server saw unexpected post-rebuild read error: %v", err)
		}
		t.Fatal("server saw EOF after client path rebuild")
	}
}
