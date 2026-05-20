//go:build linux

package chaos

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestApplyAndCleanup verifies that Apply installs a tc qdisc on lo
// and cleanup removes it. Skipped when not root (tc commands require
// CAP_NET_ADMIN) and under -short.
func TestApplyAndCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("tc qdisc apply/remove is slow under -short")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for tc qdisc")
	}

	// Snapshot pre-state so we can detect leaks.
	preOut, _ := exec.Command("tc", "qdisc", "show", "dev", "lo").CombinedOutput()
	pre := string(preOut)

	cleanup, err := Apply(Realistic50M)
	if err != nil {
		t.Fatalf("Apply(Realistic50M): %v", err)
	}

	// Verify tbf qdisc is installed.
	postApplyOut, err := exec.Command("tc", "qdisc", "show", "dev", "lo").CombinedOutput()
	if err != nil {
		_ = cleanup()
		t.Fatalf("tc show after apply: %v (%s)", err, postApplyOut)
	}
	if !strings.Contains(string(postApplyOut), "tbf") {
		_ = cleanup()
		t.Fatalf("expected tbf qdisc on lo after Apply, got: %s", postApplyOut)
	}

	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	// Verify cleanup removed it (or restored to default).
	postCleanupOut, _ := exec.Command("tc", "qdisc", "show", "dev", "lo").CombinedOutput()
	post := string(postCleanupOut)
	if strings.Contains(post, "tbf") {
		t.Fatalf("tbf still present after cleanup: %s", post)
	}
	if post != pre {
		// Soft warning: cleanup may have replaced the qdisc with
		// pfifo_fast (default) rather than the exact prior state.
		// We tolerate that — the qdisc is now in a known clean state.
		t.Logf("post-cleanup qdisc differs from pre (default restore is OK):\n  pre:  %s  post: %s", pre, post)
	}
}

// TestApplyShapesBandwidth proves the shaper actually limits
// throughput end-to-end on loopback. We measure raw TCP throughput
// over 127.0.0.1:port with vs without the shaper.
func TestApplyShapesBandwidth(t *testing.T) {
	if testing.Short() {
		t.Skip("bandwidth measurement is slow under -short")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for tc qdisc")
	}

	cleanup, err := Apply(Profile{Bandwidth: 10_000_000}) // 10 Mbps for a clear signal
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer func() { _ = cleanup() }()

	const payloadMB = 4 // 4 MB at 10 Mbps = ≥ 3.2 s — well above measurement noise
	got := measureTCPThroughput(t, payloadMB)
	t.Logf("measured throughput at 10 Mbps shaper: %.2f Mbps", got)
	// Allow 50% slack: tbf occasionally permits short bursts.
	if got > 15_000_000 {
		t.Fatalf("measured %.0f bps > 15 Mbps; tbf shaper not engaging", got)
	}
	if got < 5_000_000 {
		t.Fatalf("measured %.0f bps < 5 Mbps; tbf is too aggressive", got)
	}
}

// measureTCPThroughput dials a fresh TCP listener on 127.0.0.1:0,
// streams `mb` MB from client to server, and returns observed bps.
func measureTCPThroughput(t *testing.T, mb int) float64 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	doneRecv := make(chan int64, 1)
	go func() {
		srv, err := ln.Accept()
		if err != nil {
			doneRecv <- -1
			return
		}
		defer srv.Close()
		buf := make([]byte, 64*1024)
		var got int64
		for {
			n, err := srv.Read(buf)
			if n > 0 {
				got += int64(n)
			}
			if err != nil {
				break
			}
		}
		doneRecv <- got
	}()

	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 64*1024)
	start := time.Now()
	remaining := int64(mb) * 1024 * 1024
	for remaining > 0 {
		w := int64(len(payload))
		if w > remaining {
			w = remaining
		}
		n, err := cli.Write(payload[:w])
		if err != nil {
			break
		}
		remaining -= int64(n)
	}
	cli.Close()

	got := <-doneRecv
	if got < 0 {
		t.Fatal("server accept failed")
	}
	elapsed := time.Since(start).Seconds()
	return float64(got*8) / elapsed
}
