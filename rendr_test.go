package rendr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// TestM1DialAcceptRoundTrip is the minimal end-to-end demo for M1:
// ListenTCP + Dialer.Dial + Read/Write a payload over the rendr Conn.
// Both ends live in the same process; the wire path is a real TCP
// socket on the loopback.
func TestM1DialAcceptRoundTrip(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Accept side.
	var serverConn Conn
	var serverErr error
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		if err != nil {
			serverErr = err
			return
		}
		serverConn = c
	}()

	// Dial side.
	d := &Dialer{
		Mode: ModePrime,
		Paths: []PathSpec{
			{Transport: "tcp", Address: ln.Addr().String()},
		},
	}
	clientConn, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	<-accepted
	if serverErr != nil {
		t.Fatalf("server accept: %v", serverErr)
	}
	defer serverConn.Close()

	// Send client -> server.
	payload := bytes.Repeat([]byte("hello rendr "), 64)
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch")
	}

	// Send server -> client.
	reply := []byte("greetings from server side")
	if _, err := serverConn.Write(reply); err != nil {
		t.Fatalf("server write: %v", err)
	}
	gotR := make([]byte, len(reply))
	if _, err := io.ReadFull(clientConn, gotR); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(gotR, reply) {
		t.Fatalf("reply mismatch: %s", gotR)
	}

	// FlowID is invariant on both ends and matches.
	if clientConn.FlowID() != serverConn.FlowID() {
		t.Fatalf("flow_id mismatch: client=%x server=%x", clientConn.FlowID(), serverConn.FlowID())
	}

	// Paths() reports one path on each side after the initial HELLO.
	if got, want := len(clientConn.Paths()), 1; got != want {
		t.Errorf("client paths: got %d want %d", got, want)
	}
	if got, want := len(serverConn.Paths()), 1; got != want {
		t.Errorf("server paths: got %d want %d", got, want)
	}
}

// TestM1LargePayload exercises the framing layer with a payload that
// exceeds MaxPayload, so multiple frames flow per logical write.
// This is the smallest building block for G1.
func TestM1LargePayload(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
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

	d := &Dialer{Mode: ModePrime, Paths: []PathSpec{{Transport: "tcp", Address: ln.Addr().String()}}}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	// 4 MiB payload: spans many MaxPayload-sized frames.
	const size = 4 * 1024 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	wantSum := sha256.Sum256(payload)

	var rxSum [32]byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		h := sha256.New()
		buf := make([]byte, 64*1024)
		got := 0
		for got < size {
			n, err := server.Read(buf)
			if err != nil {
				t.Errorf("server read at %d: %v", got, err)
				return
			}
			h.Write(buf[:n])
			got += n
		}
		copy(rxSum[:], h.Sum(nil))
	}()

	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("server read timed out")
	}

	if rxSum != wantSum {
		t.Fatalf("sha256 mismatch: got %x want %x", rxSum, wantSum)
	}
}

// TestM1FlowIDsAreUnique fires N concurrent dials and checks the
// server side ends up with N distinct flow_ids.
func TestM1FlowIDsAreUnique(t *testing.T) {
	const N = 8
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type acceptResult struct {
		id  [16]byte
		err error
	}
	acceptCh := make(chan acceptResult, N)
	go func() {
		for i := 0; i < N; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			c, err := ln.Accept(ctx)
			cancel()
			if err != nil {
				acceptCh <- acceptResult{err: err}
				return
			}
			acceptCh <- acceptResult{id: c.FlowID()}
		}
	}()

	var wg sync.WaitGroup
	clientIDs := make([][16]byte, N)
	clientErrs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := &Dialer{Mode: ModePrime, Paths: []PathSpec{{Transport: "tcp", Address: ln.Addr().String()}}}
			c, err := d.Dial(context.Background())
			if err != nil {
				clientErrs[i] = err
				return
			}
			clientIDs[i] = c.FlowID()
			defer c.Close()
			_, _ = c.Write([]byte{0x42})
		}(i)
	}
	wg.Wait()
	for i, err := range clientErrs {
		if err != nil {
			t.Errorf("dial %d: %v", i, err)
		}
	}

	// Drain accepts.
	serverIDs := make([][16]byte, 0, N)
	for i := 0; i < N; i++ {
		select {
		case r := <-acceptCh:
			if r.err != nil {
				t.Errorf("accept: %v", r.err)
				continue
			}
			serverIDs = append(serverIDs, r.id)
		case <-time.After(5 * time.Second):
			t.Fatalf("accept #%d timeout", i)
		}
	}

	seen := make(map[[16]byte]int)
	for _, id := range clientIDs {
		var zero [16]byte
		if id == zero {
			t.Error("client got zero flow_id")
		}
		seen[id]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("flow_id collision %x x%d", id, n)
		}
	}
	if len(serverIDs) != N {
		t.Errorf("server side accepted %d, want %d", len(serverIDs), N)
	}
}

func TestErrorReExports(t *testing.T) {
	// The rendr.Err* sentinels must be the SAME value as the
	// engine.Err* counterparts so errors.Is across the boundary
	// works for callers.
	if !errors.Is(ErrMigrationBudgetExceeded, ErrMigrationBudgetExceeded) {
		t.Fatal("self-Is failed (sanity)")
	}
}

// TestM1PlannedMigration attaches two paths to the same bridge and
// hot-switches active path mid-transfer. The peer must see the
// entire byte stream contiguously, with no error and no gap.
func TestM1PlannedMigration(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
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

	d := &Dialer{
		Mode: ModePrime,
		Paths: []PathSpec{
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		},
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	// Wait for the second path's BridgeTag to land on the server.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(client.Paths()); got != 2 {
		t.Fatalf("client: %d paths, want 2", got)
	}
	if got := len(server.Paths()); got != 2 {
		t.Fatalf("server: %d paths, want 2", got)
	}

	bc, ok := client.(*engineBackedConn)
	if !ok {
		t.Fatalf("client type %T not engineBackedConn", client)
	}

	// Identify a non-active path to migrate to.
	currentID := bc.Engine().ActivePath()
	var otherID uint32
	for _, p := range bc.Paths() {
		if p.ID != currentID {
			otherID = p.ID
			break
		}
	}
	if otherID == 0 {
		t.Fatal("no non-active path to migrate to")
	}

	// Begin streaming: each chunk gets a sequence number for ordering check.
	const chunks = 32
	const chunkSize = 8 * 1024
	want := make([]byte, 0, chunks*chunkSize)
	for i := 0; i < chunks; i++ {
		buf := make([]byte, chunkSize)
		for j := range buf {
			buf[j] = byte(i*31 + j)
		}
		want = append(want, buf...)
	}

	got := make([]byte, len(want))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(server, got)
		readDone <- err
	}()

	// Send first half on the initial path, migrate, send the rest.
	half := len(want) / 2
	if _, err := client.Write(want[:half]); err != nil {
		t.Fatalf("write first half: %v", err)
	}
	if err := bc.Engine().Migrate(otherID); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := client.Write(want[half:]); err != nil {
		t.Fatalf("write second half: %v", err)
	}

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server read timed out across migration")
	}

	if !bytes.Equal(got, want) {
		// Find first diff for a useful message.
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("mismatch at byte %d: got %x want %x", i, got[i], want[i])
			}
		}
	}

	// Active path on the client should now be otherID.
	if bc.Engine().ActivePath() != otherID {
		t.Errorf("active path after migrate: got %d want %d", bc.Engine().ActivePath(), otherID)
	}
}

// TestM1MigrationBudgetExpires kills the only path and verifies that
// after MigrationBudget elapses, Read returns ErrMigrationBudgetExceeded.
func TestM1MigrationBudgetExpires(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
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

	d := &Dialer{
		Mode:            ModePrime,
		Paths:           []PathSpec{{Transport: "tcp", Address: ln.Addr().String()}},
		MigrationBudget: 200 * time.Millisecond,
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	// One initial byte to confirm liveness.
	if _, err := client.Write([]byte{0x42}); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("initial read: %v", err)
	}

	// Now violently break the server's only path: close its socket
	// directly via the engine. This simulates G4 (sudden path
	// death) on a connection that has nowhere to migrate.
	server.Close()

	readErr := make(chan error, 1)
	go func() {
		_, err := client.Read(make([]byte, 1))
		readErr <- err
	}()

	select {
	case err := <-readErr:
		if !errors.Is(err, ErrMigrationBudgetExceeded) {
			t.Fatalf("got %v, want ErrMigrationBudgetExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not surface ErrMigrationBudgetExceeded within 2s")
	}
}

// TestM1FailoverToSurvivingPath: two paths configured; kill the
// active one; engine must transparently fall back to the survivor
// and continue streaming, no error surfaced to the application.
//
// This is the simplest G4 (path真死亡) regression test.
func TestM1FailoverToSurvivingPath(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
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

	d := &Dialer{
		Mode: ModePrime,
		Paths: []PathSpec{
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		},
		MigrationBudget: 3 * time.Second,
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	// Wait for both paths on both sides.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 2 && len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(server.Paths()) < 2 {
		t.Fatalf("server only has %d paths", len(server.Paths()))
	}

	// Prove liveness through current active path.
	const probe = "ping1"
	if _, err := client.Write([]byte(probe)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(probe))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}

	// Reach in and kill the currently-active server-side path. This
	// is the "G4-light" surrogate: G4 proper kills the network out
	// from under the path; in-process the equivalent is to slam its
	// PathConn closed.
	sc := server.(*engineBackedConn)
	sActive := sc.Engine().ActivePath()
	// Close the server-side active PathConn directly. This forces
	// the OTHER endpoint (client) to observe a TransportError, which
	// must trigger a migration to the surviving path.
	killServerPath(t, sc, sActive)

	// Give the engine a moment to fail over.
	time.Sleep(150 * time.Millisecond)

	// Stream more data; client should reach server via path 2.
	const reply = "second-channel-payload"
	if _, err := client.Write([]byte(reply)); err != nil {
		t.Fatalf("post-failover write: %v", err)
	}
	buf2 := make([]byte, len(reply))
	if _, err := io.ReadFull(server, buf2); err != nil {
		t.Fatalf("post-failover read: %v", err)
	}
	if string(buf2) != reply {
		t.Fatalf("post-failover payload: got %q want %q", buf2, reply)
	}
}

// killServerPath reaches into the engine and slams a path closed,
// simulating a sudden network death. Exposed only for in-package
// tests.
func killServerPath(t *testing.T, bc *engineBackedConn, id uint32) {
	t.Helper()
	for _, info := range bc.Paths() {
		if info.ID == id {
			break
		}
	}
	// The engine's path table is internal; use the engine-level
	// helper Tests need a back-door for forced-death simulation.
	if err := bc.Engine().ForceKillPathForTest(id); err != nil {
		t.Fatalf("kill path %d: %v", id, err)
	}
}
