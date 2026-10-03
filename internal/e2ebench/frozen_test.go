package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/e2ebench/harness"
)

// TestHarnessIsFrozenCopy proves harness/harness.go is still the verbatim
// copy of the frozen rendr-regress harness (CR bytes stripped, so a CRLF
// checkout hashes the same).
func TestHarnessIsFrozenCopy(t *testing.T) {
	data, err := os.ReadFile("harness/harness.go")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes.ReplaceAll(data, []byte("\r"), nil))
	if got := hex.EncodeToString(sum[:]); got != FrozenHarnessSHA256 {
		t.Fatalf("harness/harness.go sha256 %s, frozen %s: restore the verbatim copy", got, FrozenHarnessSHA256)
	}
}

// TestPairRunsBench runs a small BENCH-E2E-1 over the msess adapter and
// requires every teardown to have completed cleanly.
func TestPairRunsBench(t *testing.T) {
	b, err := newBench()
	if err != nil {
		t.Fatal(err)
	}
	defer b.ln.Close()
	line, err := harness.Run("test", b.pair, 4<<20+77, 2, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(line.RunsMbps) != 2 || line.MedianMbps <= 0 {
		t.Fatalf("line %+v", line)
	}
	if b.failed != nil {
		t.Fatal("teardown:", b.failed)
	}
}

// TestCloseAbortsBlockedRead: the harness's stall watchdog closes the server
// end while a Read is blocked; that Read must return.
func TestCloseAbortsBlockedRead(t *testing.T) {
	b, err := newBench()
	if err != nil {
		t.Fatal(err)
	}
	defer b.ln.Close()
	client, server, _, err := b.pair()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	errc := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 64<<10))
		errc <- err
	}()
	time.Sleep(200 * time.Millisecond) // let the Read block on the session
	server.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("blocked Read returned no error after Close")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not abort the blocked Read")
	}
}
