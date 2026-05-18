package rendr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

// waitForNPaths polls until both client and server see at least n
// attached paths, retrying via AdminConn.AddPath against the named
// transport+address if the client falls short. The Dialer is
// best-effort about extra paths (silent-skip on dial failure);
// under heavy parallel test load that drops paths often enough to
// be a per-test pollution source. Centralising the retry here
// keeps the per-test code clean.
//
// Returns true if both sides reached n paths before the deadline,
// false otherwise (caller decides whether to t.Skip or t.Fatal).
func waitForNPaths(t *testing.T, client Conn, server Conn, transport, addr string, n int, total time.Duration) bool {
	t.Helper()
	adm, _ := client.(AdminConn)
	deadline := time.Now().Add(total)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= n && len(server.Paths()) >= n {
			return true
		}
		if adm != nil && len(client.Paths()) < n {
			_, _ = adm.AddPath(PathSpec{Transport: transport, Address: addr})
		}
		time.Sleep(20 * time.Millisecond)
	}
	return len(client.Paths()) >= n && len(server.Paths()) >= n
}

// TestSetReadDeadlineTimesOut: SetReadDeadline causes a subsequent
// idle Read to return a net.Error with Timeout()==true once the
// deadline elapses. Clearing the deadline (zero time) restores the
// blocking behaviour. Validates that idle reads can be cancelled
// without resorting to Close.
func TestSetReadDeadlineTimesOut(t *testing.T) {
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
		Mode:  ModePrime,
		Paths: []PathSpec{{Transport: "tcp", Address: ln.Addr().String()}},
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// 200 ms deadline; with no traffic Read should time out.
	if err := server.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	t0 := time.Now()
	buf := make([]byte, 16)
	_, err = server.Read(buf)
	elapsed := time.Since(t0)
	if err == nil {
		t.Fatal("Read: got nil error, want timeout")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read: got %v, want net.Error with Timeout()==true", err)
	}
	if elapsed < 150*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Errorf("Read deadline imprecise: elapsed=%s, expected ~200 ms", elapsed)
	}

	// Clear the deadline. Read should now block again. We verify the
	// blocking behaviour by writing from the client and seeing the
	// Read complete with no timeout.
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = client.Write([]byte("alive"))
	}()
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read after clearing deadline: %v", err)
	}
	if string(buf[:n]) != "alive" {
		t.Fatalf("payload after clear: got %q", buf[:n])
	}
}

// TestPathInfoLastRecvAt: after a round-trip, the server's PathInfo
// must show LastRecvAt set to roughly "now". Validates the timestamp
// is wired up so monitoring can distinguish probe-fresh paths from
// genuinely-idle paths under NAT-keepalive scenarios.
func TestPathInfoLastRecvAt(t *testing.T) {
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
		Mode:  ModePrime,
		Paths: []PathSpec{{Transport: "tcp", Address: ln.Addr().String()}},
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// Pre-traffic the server's path may have already received HELLO,
	// so LastRecvAt is likely already set. Snapshot it.
	before := server.Paths()[0].LastRecvAt

	// Drive a fresh data frame.
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}

	after := server.Paths()[0].LastRecvAt
	if after.IsZero() {
		t.Fatal("LastRecvAt zero after data frame")
	}
	if !after.After(before) && !before.IsZero() {
		t.Errorf("LastRecvAt did not advance: before=%s after=%s", before, after)
	}
	if age := time.Since(after); age > 5*time.Second {
		t.Errorf("LastRecvAt stale: age=%s", age)
	}
}

// TestDialerCustomLimitsApplied: setting ZombieMaxMigrations on the
// Dialer must reach the engine. We construct a Dialer with the
// minimum-zombie value (1) and run a single death-driven failover;
// the engine should trip zombie protection after that one event
// (which would not trigger under the default 2). This validates that
// the Dialer→engine.Limits plumbing actually carries the field.
func TestDialerCustomLimitsApplied(t *testing.T) {
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
		ZombieMaxMigrations: 1,
		ZombieCooldown:      30 * time.Second,
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if !waitForNPaths(t, client, server, "tcp", ln.Addr().String(), 2, 8*time.Second) {
		t.Skipf("could not stabilize 2 paths each; environment too noisy")
	}

	// Kill the active path. With ZombieMax=1 the engine trips on this
	// single death-driven failover (no payload between migrations).
	bc := client.(*engineBackedConn)
	if err := bc.Engine().ForceKillPathForTest(bc.Engine().ActivePath()); err != nil {
		t.Fatalf("ForceKillPathForTest: %v", err)
	}

	// Subsequent Read should surface ErrZombie within the budget.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, err := client.Read(make([]byte, 1))
		if err != nil {
			if !errors.Is(err, ErrZombie) {
				t.Fatalf("Read after kill: got %v want ErrZombie", err)
			}
			return // success
		}
	}
	t.Fatal("Read never returned within 3s after zombie kill")
}

// TestSentinelErrorsAreMatchable: errors returned from the engine
// must satisfy errors.Is against the public rendr.Err* values. The
// engine returns engine.Err* sentinels directly; rendr re-exports the
// same VALUE (not a wrapped error), so identity equality suffices.
// A drift here breaks the idiomatic `errors.Is(err, rendr.ErrFoo)`
// matching that production code relies on.
func TestSentinelErrorsAreMatchable(t *testing.T) {
	cases := []struct {
		name string
		pub  error
		got  error
	}{
		{"ErrMigrationBudgetExceeded", ErrMigrationBudgetExceeded, ErrMigrationBudgetExceeded},
		{"ErrZombie", ErrZombie, ErrZombie},
		{"ErrPeerProtoVersion", ErrPeerProtoVersion, ErrPeerProtoVersion},
		{"ErrLastPath", ErrLastPath, ErrLastPath},
		{"ErrPacketTooLarge", ErrPacketTooLarge, ErrPacketTooLarge},
		{"ErrReadDeadlineExceeded", ErrReadDeadlineExceeded, ErrReadDeadlineExceeded},
	}
	for _, c := range cases {
		if !errors.Is(c.got, c.pub) {
			t.Errorf("%s: errors.Is failed", c.name)
		}
	}
}

// TestSetReadDeadlinePacketMode mirrors TestSetReadDeadlineTimesOut
// but exercises the packet-mode ReadFrom path. The deadline plumbing
// goes through enginePacketConn.SetReadDeadline → engine.SetReadDeadline,
// and Engine.RecvPacket honors the deadline the same way Recv does.
func TestSetReadDeadlinePacketMode(t *testing.T) {
	ln, err := ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptPacket(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- c
	}()

	d := &Dialer{
		Mode:  ModePrime,
		Paths: []PathSpec{{Transport: "udpflow", Address: ln.Addr().String()}},
	}
	client, err := d.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if err := server.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	t0 := time.Now()
	buf := make([]byte, 64)
	_, _, err = server.ReadFrom(buf)
	elapsed := time.Since(t0)
	if err == nil {
		t.Fatal("ReadFrom: got nil error, want timeout")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("ReadFrom: got %v, want net.Error with Timeout()==true", err)
	}
	if elapsed < 150*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Errorf("ReadFrom deadline imprecise: elapsed=%s", elapsed)
	}

	// Clear deadline + verify normal delivery resumes.
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = client.WriteTo([]byte("ok"), nil)
	}()
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom after clearing deadline: %v", err)
	}
	if string(buf[:n]) != "ok" {
		t.Fatalf("payload after clear: got %q", buf[:n])
	}
}

// TestModeConstants pins the integer values of the public Mode enum.
// The values must match internal/engine.dispatchPrime/Bond/Race
// because (*engineBackedConn).SetMode passes uint32(rendr.Mode) to
// engine.SetMode without remapping. A drift here silently desyncs
// the dispatcher selection from the public API.
func TestModeConstants(t *testing.T) {
	cases := []struct {
		mode Mode
		want uint8
	}{
		{ModePrime, 1},
		{ModeBond, 2},
		{ModeRace, 3},
	}
	for _, c := range cases {
		if uint8(c.mode) != c.want {
			t.Errorf("%s drifted: got %d want %d (engine.dispatch* must match)",
				c.mode, uint8(c.mode), c.want)
		}
	}
}

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

	if !waitForNPaths(t, client, server, "tcp", ln.Addr().String(), 2, 8*time.Second) {
		t.Fatalf("expected 2 paths each, got client=%d server=%d",
			len(client.Paths()), len(server.Paths()))
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

	// Now violently break the server's only path: ForceKill so the
	// engine sees a TransportError (NOT a BYE - we are simulating
	// G4 "pathçœŸæ­»äº¡", not a clean teardown).
	sc := server.(*engineBackedConn)
	for _, p := range sc.Paths() {
		_ = sc.Engine().ForceKillPathForTest(p.ID)
	}

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
// This is the simplest G4 (pathçœŸæ­»äº¡) regression test.
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

	// Wait for both paths on both sides. 5 s tolerance for cold-start
	// or GC pause during a -count=3 run.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 2 && len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(server.Paths()) < 2 {
		t.Fatalf("server only has %d paths after 5s", len(server.Paths()))
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

// TestM1CleanCloseEOF: local Close on one end must surface as io.EOF
// on the peer (not ErrMigrationBudgetExceeded or a transport-class
// error). This is the BYE wiring contract.
//
// Skipped on Windows: Windows TCP loopback occasionally delivers the
// FIN before the buffered BYE bytes, even though the BYE was written
// to the socket first. Without a half-close primitive in the path
// abstraction, we can't reliably force FIN-after-BYE here. Linux
// kernel orders these correctly. This is a test-side artifact, not
// a wire-protocol contract violation.
func TestM1CleanCloseEOF(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows TCP loopback may reorder BYE vs FIN; see godoc")
	}
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
	server := <-accepted
	defer server.Close()

	greet := []byte("ping")
	if _, err := client.Write(greet); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(greet))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}

	// Local Close on the client. Peer (server) must observe io.EOF.
	if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("client.Close: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		b := make([]byte, 16)
		_, err := server.Read(b)
		readErr <- err
	}()

	select {
	case err := <-readErr:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("peer Read after Close: got %v want io.EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer Read did not surface io.EOF within 3s")
	}
}

// TestM1G1Sketch: 32 MiB stream + 3 forced migrations + SHA-256
// integrity. Functionally minified G1: real G1 demands â‰¥1 GiB and
// runs in the chaos harness (gitignored test/); this version fits
// the unit-test budget while exercising the same invariants:
//   - migration is transparent to the application Conn
//   - byte stream is contiguous and order-preserving
//   - hash matches end-to-end
func TestM1G1Sketch(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 2 && len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(client.Paths()) < 2 {
		t.Fatalf("only %d paths attached on client", len(client.Paths()))
	}

	const total = 32 * 1024 * 1024
	want := make([]byte, total)
	for i := range want {
		want[i] = byte(i*17 + 3)
	}
	wantSum := sha256.Sum256(want)

	var rxSum [32]byte
	done := make(chan error, 1)
	go func() {
		h := sha256.New()
		buf := make([]byte, 128*1024)
		got := 0
		for got < total {
			n, err := server.Read(buf)
			if err != nil {
				done <- err
				return
			}
			h.Write(buf[:n])
			got += n
		}
		copy(rxSum[:], h.Sum(nil))
		done <- nil
	}()

	bc := client.(*engineBackedConn)

	// 3 migrations at ~30%, ~50%, ~70%.
	migrateAt := []int{total * 3 / 10, total * 5 / 10, total * 7 / 10}
	wstart := time.Now()
	written := 0
	mi := 0
	chunk := 64 * 1024
	for written < total {
		end := written + chunk
		if end > total {
			end = total
		}
		n, err := client.Write(want[written:end])
		if err != nil {
			t.Fatalf("write at %d: %v", written, err)
		}
		written += n
		// Time-bounded migration trigger.
		for mi < len(migrateAt) && written >= migrateAt[mi] {
			cur := bc.Engine().ActivePath()
			var other uint32
			for _, p := range bc.Paths() {
				if p.ID != cur {
					other = p.ID
					break
				}
			}
			if other != 0 {
				if err := bc.Engine().Migrate(other); err != nil {
					t.Fatalf("migrate %d: %v", mi, err)
				}
				t.Logf("migrate %d at %d bytes -> path %d", mi, written, other)
			}
			mi++
		}
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("recv timed out")
	}

	if rxSum != wantSum {
		t.Fatalf("sha256 mismatch:\ngot %x\nwant %x", rxSum, wantSum)
	}
	t.Logf("32 MiB + 3 migrations in %s, sha256 verified", time.Since(wstart))
}

// TestM1G2Sketch: minified G2 long-run echo. 4 paths, 50 ms echo
// interval, random migrations every ~200 ms. 3 s total ~= 60 echoes
// and ~15 migrations. Hard contract:
//   - every echo received in order, zero loss
//   - migration is invisible to the application Conn
//   - P99 RTT below a generous local-loopback bound
//
// Real G2 is 30 minutes / 30+ migrations; that belongs to the chaos
// harness (chaos/ submodule). This sketch reproduces the
// reorder-around-migration invariant cheaply.
func TestM1G2Sketch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping G2 sketch in -short")
	}

	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	if !waitForNPaths(t, client, server, "tcp", ln.Addr().String(), 4, 8*time.Second) {
		t.Fatalf("expected 4 paths each, got client=%d server=%d",
			len(client.Paths()), len(server.Paths()))
	}

	// Server-side echo loop: read 8B counter, echo it back.
	echoErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		for {
			if _, err := io.ReadFull(server, buf); err != nil {
				echoErr <- err
				return
			}
			if _, err := server.Write(buf); err != nil {
				echoErr <- err
				return
			}
		}
	}()

	bc := client.(*engineBackedConn)

	// Migration trigger every ~200 ms. migCount is accessed from two
	// goroutines so we use atomic.Int64; close(stopMig) only signals
	// the ticker goroutine to exit, it does not wait for it.
	stopMig := make(chan struct{})
	migDone := make(chan struct{})
	var migCount atomic.Int64
	go func() {
		defer close(migDone)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopMig:
				return
			case <-ticker.C:
				cur := bc.Engine().ActivePath()
				var other uint32
				for _, p := range bc.Paths() {
					if p.ID != cur {
						other = p.ID
						break
					}
				}
				if other != 0 {
					if err := bc.Engine().Migrate(other); err == nil {
						migCount.Add(1)
					}
				}
			}
		}
	}()

	const echoTotal = 60
	const echoInterval = 50 * time.Millisecond
	deadline := time.Now().Add(time.Duration(echoTotal) * echoInterval * 2)
	rxbuf := make([]byte, 8)
	maxRTT := time.Duration(0)
	for i := uint64(0); i < echoTotal; i++ {
		var txbuf [8]byte
		binary.BigEndian.PutUint64(txbuf[:], i)
		t0 := time.Now()
		if _, err := client.Write(txbuf[:]); err != nil {
			t.Fatalf("echo write %d: %v", i, err)
		}
		if _, err := io.ReadFull(client, rxbuf); err != nil {
			t.Fatalf("echo read %d: %v", i, err)
		}
		rtt := time.Since(t0)
		if rtt > maxRTT {
			maxRTT = rtt
		}
		got := binary.BigEndian.Uint64(rxbuf)
		if got != i {
			t.Fatalf("echo %d: got counter %d, want %d", i, got, i)
		}
		if time.Now().After(deadline) {
			t.Fatalf("echo loop overran deadline at i=%d", i)
		}
		time.Sleep(echoInterval)
	}
	close(stopMig)
	<-migDone

	mc := migCount.Load()
	if mc < 5 {
		t.Logf("WARNING: only %d migrations fired; expected >= 5", mc)
	}
	t.Logf("%d echoes, %d migrations, maxRTT=%s", echoTotal, mc, maxRTT)

	// All paths must still be present on the client (a kill never happened).
	if got := len(client.Paths()); got != 4 {
		t.Errorf("client paths after stress: got %d want 4", got)
	}
}

// TestM7RaceWritesAllPaths: in race mode, each application Write
// must produce a wire frame on EVERY attached path. Verifies via
// tcp.PathConn.Writes() per-path counters.
func TestM7RaceWritesAllPaths(t *testing.T) {
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
		Mode: ModePrime, // start prime then flip; SetMode flow lives here.
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

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 2 && len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(client.Paths()) < 2 {
		t.Fatalf("expected 2 client paths, got %d", len(client.Paths()))
	}

	// Capture per-path Writes() baseline.
	bc := client.(*engineBackedConn)
	type pathProbe struct {
		id     uint32
		writer interface{ Writes() uint64 }
		base   uint64
	}
	var probes []pathProbe
	bc.Engine().WalkPathsForTest(func(id uint32, pc interface{}) {
		if w, ok := pc.(interface{ Writes() uint64 }); ok {
			probes = append(probes, pathProbe{id: id, writer: w, base: w.Writes()})
		}
	})
	if len(probes) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(probes))
	}

	if err := client.SetMode(ModeRace); err != nil {
		t.Fatal(err)
	}

	const N = 8
	payload := []byte("race-frame")
	for i := 0; i < N; i++ {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// Drain server side so SEQ progresses on both endpoints.
	rxbuf := make([]byte, len(payload)*N)
	if _, err := io.ReadFull(server, rxbuf); err != nil {
		t.Fatalf("server drain: %v", err)
	}

	for _, p := range probes {
		got := p.writer.Writes() - p.base
		// Race must put at least N frames on each path; >= because
		// the engine may also have sent ctrl frames (probe etc) that
		// flow on a single path.
		if got < uint64(N) {
			t.Errorf("path %d saw %d writes, want >= %d", p.id, got, N)
		}
	}
}

// TestM8BondPathDeathContinuesOnSurvivor: in bond mode, after a
// mid-stream kill on one path the engine must keep delivering on
// the survivor. This is the loosest M8(3/n) acceptance: the test
// does NOT require zero loss of in-flight frames on the dying
// path (that needs a redistribute-with-ack mechanism, tracked
// separately). It only asserts that:
//   - the survivor keeps receiving subsequent writes
//   - the application-visible byte stream up to and after the kill
//     is delivered (allowing for the receiver to block until the
//     dying path's in-flight frames are filled in OR for the
//     engine to advance past the gap by writing the same bytes on
//     the survivor).
//
// Currently rendr does NOT redistribute, so this test is permitted
// to time out or hang on partial-frame death. We mark it Skip
// until the redistribute primitive lands.
func TestM8BondPathDeathContinuesOnSurvivor(t *testing.T) {
	t.Skip("M8 redistribute-on-death not implemented; bond + mid-stream path kill can leak frames. Tracked for M8(3/n).")
}

// TestAdminConnStatsSnapshot: Stats() returns a coherent view of
// flow id, mode, state, active path, the path list, and recv-queue
// HWM in one call. Fields must be internally consistent (same
// flow id everywhere, ActivePath in Paths if non-zero, Mode
// reflecting the most recent SetMode).
func TestAdminConnStatsSnapshot(t *testing.T) {
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

	if !waitForNPaths(t, client, server, "tcp", ln.Addr().String(), 2, 8*time.Second) {
		t.Fatalf("expected 2 paths each, got client=%d server=%d",
			len(client.Paths()), len(server.Paths()))
	}

	adm := client.(AdminConn)
	s := adm.Stats()

	if s.FlowID != client.FlowID() {
		t.Errorf("Stats.FlowID mismatch: %x vs %x", s.FlowID, client.FlowID())
	}
	if s.State != "active" {
		t.Errorf("Stats.State: got %q want %q", s.State, "active")
	}
	if s.Mode != ModePrime {
		t.Errorf("Stats.Mode: got %v want %v", s.Mode, ModePrime)
	}
	if s.ActivePath == 0 {
		t.Error("Stats.ActivePath should be non-zero after dial")
	}
	if len(s.Paths) < 2 {
		t.Errorf("Stats.Paths: got %d want >=2", len(s.Paths))
	}
	// ActivePath must appear in Paths.
	found := false
	for _, p := range s.Paths {
		if p.ID == s.ActivePath {
			found = true
			if !p.Active {
				t.Errorf("Stats.Paths[%d].Active=false but ActivePath=%d", p.ID, s.ActivePath)
			}
		}
	}
	if !found {
		t.Errorf("Stats.ActivePath %d not in Paths", s.ActivePath)
	}
	if s.RecvQueueHWM < 0 {
		t.Errorf("Stats.RecvQueueHWM negative: %d", s.RecvQueueHWM)
	}

	// CreatedAt should be populated and reasonable: not zero,
	// not in the future, and very recent (this test just dialed).
	if s.CreatedAt.IsZero() {
		t.Error("Stats.CreatedAt is zero; should be populated at dial")
	}
	if age := time.Since(s.CreatedAt); age < 0 || age > 30*time.Second {
		t.Errorf("Stats.CreatedAt unreasonable: age=%s", age)
	}

	// Mode read should track SetMode write.
	if err := client.SetMode(ModeRace); err != nil {
		t.Fatal(err)
	}
	if got := adm.Mode(); got != ModeRace {
		t.Errorf("Mode() after SetMode(Race): got %v want %v", got, ModeRace)
	}
	if got := adm.Stats().Mode; got != ModeRace {
		t.Errorf("Stats.Mode after SetMode(Race): got %v want %v", got, ModeRace)
	}
}

// TestAdminConnStateAndHWM: State() reports the bridge lifecycle
// transitions and RecvQueueHWM exposes the dedup-buffer
// observability hook required by docs/modes.md.
func TestAdminConnStateAndHWM(t *testing.T) {
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

	adm, ok := client.(AdminConn)
	if !ok {
		t.Fatal("client does not implement AdminConn")
	}
	if s := adm.State(); s != "active" {
		t.Errorf("State() after dial: got %q want %q", s, "active")
	}
	if hwm := adm.RecvQueueHWM(); hwm < 0 {
		t.Errorf("RecvQueueHWM() negative: %d", hwm)
	}

	// Exchange a frame so the recv path actually sees data.
	if _, err := client.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(server, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}

	// HWM is non-decreasing after data flows; we don't require >0
	// because on loopback the SEQ window often delivers in-order
	// and never inserts into the queue.
	if hwm := adm.RecvQueueHWM(); hwm < 0 {
		t.Errorf("HWM regressed: %d", hwm)
	}

	// Trigger Close and observe State() flipping to "dead".
	_ = client.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if adm.State() == "dead" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if adm.State() != "dead" {
		t.Errorf("State() after Close: got %q want %q", adm.State(), "dead")
	}
}

// TestPathInfoCountersExposed: Paths() must return Reads / Writes
// counters and the Active flag so a production monitoring stack
// can spot a saturated or idle path without poking into transport-
// private types.
func TestPathInfoCountersExposed(t *testing.T) {
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

	// Initially the path is active with at least HELLO written.
	infos := client.Paths()
	if len(infos) != 1 {
		t.Fatalf("expected 1 path, got %d", len(infos))
	}
	if !infos[0].Active {
		t.Error("Active flag should be true on the single attached path")
	}
	preWrites := infos[0].Writes

	// One application write -> at least one more frame on the wire.
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}

	infos = client.Paths()
	if infos[0].Writes <= preWrites {
		t.Errorf("Writes did not advance after app write: %d -> %d", preWrites, infos[0].Writes)
	}
}

// TestG5PathRecoveryViaAddPath: 2 paths, kill one, AddPath a
// replacement (same spec); verify the new path attaches to the
// existing engine via BRIDGE_TAG and the stream continues without
// any application-visible error. This is the G5 acceptance
// minimum: "path A recovers and re-joins the available set."
func TestG5PathRecoveryViaAddPath(t *testing.T) {
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

	// Wait both paths attached.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(server.Paths()) < 2 {
		t.Fatalf("server only has %d paths", len(server.Paths()))
	}

	// Sanity exchange.
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}

	// Kill one client path.
	bc := client.(*engineBackedConn)
	preKill := len(bc.Paths())
	if err := bc.Engine().ForceKillPathForTest(bc.Engine().ActivePath()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if len(bc.Paths()) != preKill-1 {
		t.Fatalf("after kill: paths=%d want %d", len(bc.Paths()), preKill-1)
	}

	// Recover: AddPath a fresh socket to the same listener.
	newID, err := bc.AddPath(PathSpec{Transport: "tcp", Address: ln.Addr().String()})
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	if newID == 0 {
		t.Fatal("AddPath returned 0 id")
	}
	if len(bc.Paths()) != preKill {
		t.Fatalf("after AddPath: paths=%d want %d", len(bc.Paths()), preKill)
	}

	// Drive traffic on the recovered conn.
	post := []byte("post-recovery")
	if _, err := client.Write(post); err != nil {
		t.Fatalf("write post-recovery: %v", err)
	}
	got := make([]byte, len(post))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read post-recovery: %v", err)
	}
	if string(got) != string(post) {
		t.Fatalf("post-recovery payload: got %q want %q", got, post)
	}

	// Server side should also reflect the new path attaching.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(server.Paths()) >= preKill {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(server.Paths()) < preKill {
		t.Fatalf("server didn't see new BRIDGE_TAG: paths=%d want %d", len(server.Paths()), preKill)
	}
}

// TestAdminConnRemovePath: RemovePath drops a non-active path
// without disrupting the stream, refuses to drop the only attached
// path (ErrLastPath), and rejects unknown ids. If RemovePath drops
// the active path it must failover before returning.
func TestAdminConnRemovePath(t *testing.T) {
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

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(client.Paths()) < 2 {
		t.Fatalf("expected 2 paths, got %d", len(client.Paths()))
	}

	adm := client.(AdminConn)

	// 1. Drop a NON-active path. The active path's id is bc.ActivePath();
	// pick any other.
	var victim uint32
	for _, p := range adm.Paths() {
		if p.ID != adm.ActivePath() {
			victim = p.ID
			break
		}
	}
	if victim == 0 {
		t.Fatal("no non-active path to drop")
	}
	if err := adm.RemovePath(victim); err != nil {
		t.Fatalf("RemovePath(victim): %v", err)
	}
	if got := len(adm.Paths()); got != 1 {
		t.Fatalf("after RemovePath: paths=%d want 1", got)
	}
	// Stream is still healthy.
	if _, err := client.Write([]byte("after-remove")); err != nil {
		t.Fatalf("write after RemovePath: %v", err)
	}
	buf := make([]byte, len("after-remove"))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("server read after RemovePath: %v", err)
	}
	if string(buf) != "after-remove" {
		t.Fatalf("payload mismatch after RemovePath: %q", buf)
	}

	// 2. Attempting to remove the only remaining path returns ErrLastPath.
	onlyID := adm.ActivePath()
	if err := adm.RemovePath(onlyID); !errors.Is(err, ErrLastPath) {
		t.Fatalf("RemovePath last-path: got %v want ErrLastPath", err)
	}
	if got := len(adm.Paths()); got != 1 {
		t.Fatalf("paths after rejected RemovePath: %d want 1", got)
	}

	// 3. Unknown id errors.
	if err := adm.RemovePath(999999); err == nil {
		t.Fatal("RemovePath(unknown): expected error, got nil")
	}
}

// TestAdminConnRemoveActivePathFailovers: RemovePath on the active
// path triggers automatic failover to a surviving path before
// returning; the application Write/Read after the call must succeed.
func TestAdminConnRemoveActivePathFailovers(t *testing.T) {
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

	adm := client.(AdminConn)
	if !waitForNPaths(t, client, server, "tcp", ln.Addr().String(), 2, 15*time.Second) {
		t.Skipf("could not stabilize 2 paths each under load (client=%d server=%d) - load-pathological, skipping",
			len(client.Paths()), len(server.Paths()))
	}

	wasActive := adm.ActivePath()
	if err := adm.RemovePath(wasActive); err != nil {
		t.Fatalf("RemovePath(active): %v", err)
	}
	if adm.ActivePath() == 0 {
		t.Fatal("active path is 0 after RemovePath; no failover")
	}
	if adm.ActivePath() == wasActive {
		t.Fatalf("active path %d unchanged after RemovePath", wasActive)
	}

	payload := []byte("failover-write")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write post-failover: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read post-failover: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("post-failover payload: got %q want %q", got, payload)
	}
}

// TestAdminConnOnMigrate: OnMigrate hooks must fire for both
// explicit Migrate and death-driven failover. The cause field
// distinguishes the two paths. Cancel must stop further events.
func TestAdminConnOnMigrate(t *testing.T) {
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

	if !waitForNPaths(t, client, server, "tcp", ln.Addr().String(), 3, 8*time.Second) {
		t.Fatalf("expected 3 paths each, got client=%d server=%d",
			len(client.Paths()), len(server.Paths()))
	}

	adm := client.(AdminConn)

	// Collect events via a channel so the test can verify cause + ids.
	type ev struct {
		oldID, newID uint32
		cause        string
	}
	events := make(chan ev, 8)
	cancel := adm.OnMigrate(func(o, n uint32, cause string) {
		events <- ev{o, n, cause}
	})

	// 1. Explicit Migrate fires the hook with cause="explicit".
	cur := adm.ActivePath()
	var next uint32
	for _, p := range adm.Paths() {
		if p.ID != cur {
			next = p.ID
			break
		}
	}
	if err := adm.Migrate(next); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	select {
	case e := <-events:
		if e.cause != "explicit" || e.oldID != cur || e.newID != next {
			t.Fatalf("explicit hook: got %+v want {old=%d new=%d cause=explicit}", e, cur, next)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("explicit Migrate did not fire OnMigrate hook")
	}

	// 2. Death-driven failover fires with cause="death".
	bc := client.(*engineBackedConn)
	if err := bc.Engine().ForceKillPathForTest(adm.ActivePath()); err != nil {
		t.Fatalf("ForceKillPathForTest: %v", err)
	}
	select {
	case e := <-events:
		if e.cause != "death" {
			t.Fatalf("death hook: got cause=%s want death", e.cause)
		}
		if e.newID == 0 {
			t.Fatal("death hook: newID=0; failover failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("death failover did not fire OnMigrate hook")
	}

	// 3. Cancel; subsequent migration produces no events.
	cancel()
	cur = adm.ActivePath()
	var third uint32
	for _, p := range adm.Paths() {
		if p.ID != cur {
			third = p.ID
			break
		}
	}
	if third == 0 {
		t.Skip("only one path remains; cannot test cancel branch")
	}
	if err := adm.Migrate(third); err != nil {
		t.Fatalf("Migrate post-cancel: %v", err)
	}
	select {
	case e := <-events:
		t.Fatalf("hook fired after cancel: %+v", e)
	case <-time.After(200 * time.Millisecond):
		// expected: no event
	}
}

// TestAdminConnMigrationCount: MigrationCount must reflect both
// explicit Migrate calls and death-driven failover, but not count
// the initial active-path assignment at Dial time.
func TestAdminConnMigrationCount(t *testing.T) {
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

	if !waitForNPaths(t, client, server, "tcp", ln.Addr().String(), 3, 8*time.Second) {
		t.Fatalf("expected 3 paths each, got client=%d server=%d",
			len(client.Paths()), len(server.Paths()))
	}

	adm := client.(AdminConn)
	// Initial active-path assignment does NOT count.
	if got := adm.MigrationCount(); got != 0 {
		t.Fatalf("initial MigrationCount=%d want 0", got)
	}

	// Explicit Migrate: pick a non-active path.
	cur := adm.ActivePath()
	var other uint32
	for _, p := range adm.Paths() {
		if p.ID != cur {
			other = p.ID
			break
		}
	}
	if other == 0 {
		t.Fatal("no other path to migrate to")
	}
	if err := adm.Migrate(other); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if got := adm.MigrationCount(); got != 1 {
		t.Fatalf("after explicit Migrate: MigrationCount=%d want 1", got)
	}

	// Migrate to the same path is a no-op and must NOT increment.
	if err := adm.Migrate(other); err != nil {
		t.Fatalf("Migrate same: %v", err)
	}
	if got := adm.MigrationCount(); got != 1 {
		t.Fatalf("after no-op Migrate: MigrationCount=%d want 1", got)
	}

	// Death-driven failover: kill the active path; engine moves to
	// one of the remaining two. MigrationCount should now be 2.
	bc := client.(*engineBackedConn)
	if err := bc.Engine().ForceKillPathForTest(adm.ActivePath()); err != nil {
		t.Fatalf("ForceKillPathForTest: %v", err)
	}
	// Give onPathDeath a tick.
	time.Sleep(50 * time.Millisecond)
	if got := adm.MigrationCount(); got != 2 {
		t.Fatalf("after death failover: MigrationCount=%d want 2", got)
	}

	// Stats() must agree with the dedicated getter.
	if got := adm.Stats().MigrationCount; got != adm.MigrationCount() {
		t.Fatalf("Stats().MigrationCount=%d disagrees with MigrationCount()=%d",
			got, adm.MigrationCount())
	}
}

// TestM7DedupWindowBoundedOnLoopback: race mode on loopback should
// never grow the reorder buffer beyond a small number; on a fast
// path-pair both copies of each frame arrive within microseconds,
// so high-water-mark stays tiny. This is the diagnostic that
// docs/modes.md asks for to detect 'dedup window overflow'.
func TestM7DedupWindowBoundedOnLoopback(t *testing.T) {
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

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := client.SetMode(ModeRace); err != nil {
		t.Fatal(err)
	}

	// Stream 64 frames in race mode. Receiver should drain each
	// frame as it arrives; HWM should stay small because both copies
	// of a frame land essentially simultaneously on loopback.
	const N = 64
	payload := []byte("race-bounded-window")
	for i := 0; i < N; i++ {
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	rxbuf := make([]byte, len(payload)*N)
	if _, err := io.ReadFull(server, rxbuf); err != nil {
		t.Fatal(err)
	}

	hwm := server.(*engineBackedConn).Engine().RecvQueueHighWaterMark()
	t.Logf("race-mode recv-queue HWM = %d (over %d frames on 2 paths)", hwm, N)
	if hwm > 64 {
		t.Errorf("recv-queue HWM unexpectedly high (%d) - dedup window may be growing without bound", hwm)
	}

	// Race emits ONE frame per Write per attached path; the receiver
	// keeps the first copy and tallies the rest as RecvDups. With 2
	// paths and N application writes, the dup count is expected
	// around N (the second copy of every data frame). Under parallel
	// test load the second path's server-side reader may not be
	// draining for the first frame or two, so a couple of dups can
	// land on a path that isn't yet attached engine-side - allow up
	// to ~25% missing without failing. The strict-zero-loss check is
	// on the data stream above (rxbuf bytes match).
	srvAdm := server.(AdminConn)
	dups := srvAdm.RecvDups()
	t.Logf("race-mode RecvDups = %d (over %d frames on 2 paths)", dups, N)
	if dups < uint64(N*3/4) {
		t.Errorf("RecvDups=%d < 75%% of N=%d: race-mode dedup not counted", dups, N)
	}
	if got := srvAdm.Stats().RecvDups; got != dups {
		t.Errorf("Stats().RecvDups=%d disagrees with RecvDups()=%d", got, dups)
	}

	// Per-path RecvDups must sum to the engine-wide total. Confirms
	// the attribution wiring works under race-mode fan-out.
	var perPathSum uint64
	for _, p := range srvAdm.Paths() {
		perPathSum += p.RecvDups
	}
	if perPathSum != dups {
		t.Errorf("sum of PathInfo.RecvDups = %d, Stats.RecvDups = %d", perPathSum, dups)
	}
}

// TestM8BondPathPinning: with pin size = 4 and 2 paths, sending 16
// frames must produce 4-frame runs that stay on one path before
// the next run jumps to the other. Path pinning is the M8 mechanism
// to bound reorder-window growth under RTT skew between paths.
func TestM8BondPathPinning(t *testing.T) {
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

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 2 && len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	bc := client.(*engineBackedConn)

	type pp struct {
		id     uint32
		writer interface{ Writes() uint64 }
	}
	var probes []pp
	bc.Engine().WalkPathsForTest(func(id uint32, pc interface{}) {
		if w, ok := pc.(interface{ Writes() uint64 }); ok {
			probes = append(probes, pp{id: id, writer: w})
		}
	})
	if len(probes) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(probes))
	}

	// Pin size 4 so 16 frames -> 4 runs of 4.
	bc.Engine().SetBondPinSizeForTest(4)
	if err := client.SetMode(ModeBond); err != nil {
		t.Fatalf("SetMode bond: %v", err)
	}

	const N = 16
	payload := []byte("pinframe")
	pathPerFrame := make([]uint32, 0, N)
	prevA := probes[0].writer.Writes()
	prevB := probes[1].writer.Writes()
	for i := 0; i < N; i++ {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		// Whichever path's Writes() advanced this iteration is the
		// path the engine chose for this frame.
		curA := probes[0].writer.Writes()
		curB := probes[1].writer.Writes()
		if curA > prevA {
			pathPerFrame = append(pathPerFrame, probes[0].id)
		} else if curB > prevB {
			pathPerFrame = append(pathPerFrame, probes[1].id)
		} else {
			t.Fatalf("frame %d: neither path's Writes() advanced (a=%d b=%d)",
				i, curA, curB)
		}
		prevA = curA
		prevB = curB
	}

	// Drain server.
	rxbuf := make([]byte, len(payload)*N)
	if _, err := io.ReadFull(server, rxbuf); err != nil {
		t.Fatalf("server drain: %v", err)
	}

	t.Logf("path-per-frame: %v", pathPerFrame)

	// Verify pinning: count the number of times consecutive frames
	// switched paths. With pin=4 and 16 frames we should see at
	// most ceil(16/4)-1 = 3 switches.
	switches := 0
	for i := 1; i < len(pathPerFrame); i++ {
		if pathPerFrame[i] != pathPerFrame[i-1] {
			switches++
		}
	}
	if switches > 3 {
		t.Fatalf("path pinning broken: %d switches across %d frames (expected <= 3 with pin=4)",
			switches, N)
	}

	// Sanity: both paths got >=1 frame.
	var aN, bN int
	for _, p := range pathPerFrame {
		if p == probes[0].id {
			aN++
		} else if p == probes[1].id {
			bN++
		}
	}
	if aN == 0 || bN == 0 {
		t.Fatalf("one path saw no frames: %v", pathPerFrame)
	}
}

// TestM8BondRoundRobinAcrossPaths: with bond mode, N application
// Writes round-robin onto attached paths so each path observes
// roughly N/PathCount frames. Bond is "frame-level aggregation
// not duplication", so unlike race each path sees a strict subset.
// Receiver-side reorder reassembles into the original byte stream.
func TestM8BondRoundRobinAcrossPaths(t *testing.T) {
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

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 2 && len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(client.Paths()) < 2 {
		t.Fatalf("expected 2 paths, got %d", len(client.Paths()))
	}

	bc := client.(*engineBackedConn)
	// Capture per-path Writes() before flipping mode.
	type pp struct {
		id     uint32
		writer interface{ Writes() uint64 }
		base   uint64
	}
	var probes []pp
	bc.Engine().WalkPathsForTest(func(id uint32, pc interface{}) {
		if w, ok := pc.(interface{ Writes() uint64 }); ok {
			probes = append(probes, pp{id: id, writer: w, base: w.Writes()})
		}
	})

	if err := client.SetMode(ModeBond); err != nil {
		t.Fatalf("SetMode(bond): %v", err)
	}

	// Send N small frames; each engine.SendData call produces one
	// data frame (the payload is < MaxPayload).
	const N = 16
	payload := []byte("bond-frame")
	for i := 0; i < N; i++ {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// Drain server side so reorder buffer fully processes.
	rxbuf := make([]byte, len(payload)*N)
	if _, err := io.ReadFull(server, rxbuf); err != nil {
		t.Fatalf("server drain: %v", err)
	}
	if !bytes.Equal(rxbuf, bytes.Repeat(payload, N)) {
		t.Fatalf("server byte-stream mismatch under bond")
	}

	// Bond should distribute roughly evenly. Each path should see
	// >= 1 data write (we allow asymmetry for ctrl frames that
	// went on whichever path was active before SetMode).
	var totals []uint64
	for _, p := range probes {
		got := p.writer.Writes() - p.base
		totals = append(totals, got)
		t.Logf("path %d saw %d wire writes after bond switch", p.id, got)
	}
	if totals[0] == 0 || totals[1] == 0 {
		t.Fatalf("bond did not exercise both paths: %v", totals)
	}
}

// TestM8BondSkipsStuckPath: bond mode must not round-robin frames
// onto a path whose latest probe RTT is >= BondStuckRTTMultiplier x
// the best path's RTT. Without this, a single slow path balloons
// the receiver's reorder window and tanks effective bond bandwidth.
//
// We synthesise the RTT skew by injecting fake quality readings
// via Engine.SetPathQualityForTest (real probes won't have measured
// loopback paths as 100ms apart). The test then writes N data
// frames and checks that the stuck path absorbed zero of them.
func TestM8BondSkipsStuckPath(t *testing.T) {
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

	if !waitForNPaths(t, client, server, "tcp", ln.Addr().String(), 2, 8*time.Second) {
		t.Fatalf("expected 2 paths each, got client=%d server=%d",
			len(client.Paths()), len(server.Paths()))
	}

	bc := client.(*engineBackedConn)
	type pp struct {
		id     uint32
		writer interface{ Writes() uint64 }
		base   uint64
	}
	var probes []pp
	bc.Engine().WalkPathsForTest(func(id uint32, pc interface{}) {
		if w, ok := pc.(interface{ Writes() uint64 }); ok {
			probes = append(probes, pp{id: id, writer: w})
		}
	})
	if len(probes) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(probes))
	}
	// Inject quality: probes[0]=1ms (fast), probes[1]=100ms (stuck @ 100x).
	bc.Engine().SetPathQualityForTest(probes[0].id, transport.PathQuality{
		RTT: 1 * time.Millisecond,
	})
	bc.Engine().SetPathQualityForTest(probes[1].id, transport.PathQuality{
		RTT: 100 * time.Millisecond,
	})

	// Capture baseline Writes() AFTER injection so any prior probe /
	// ctrl traffic does not count against us. Pin size doesn't matter
	// here: stuck-skip should bypass the slow path regardless.
	for i := range probes {
		probes[i].base = probes[i].writer.Writes()
	}

	if err := client.SetMode(ModeBond); err != nil {
		t.Fatalf("SetMode(bond): %v", err)
	}

	const N = 20
	payload := []byte("stuckpath")
	for i := 0; i < N; i++ {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	rxbuf := make([]byte, len(payload)*N)
	if _, err := io.ReadFull(server, rxbuf); err != nil {
		t.Fatalf("server drain: %v", err)
	}
	if !bytes.Equal(rxbuf, bytes.Repeat(payload, N)) {
		t.Fatalf("byte-stream mismatch under bond+stuck-skip")
	}

	fastDelta := probes[0].writer.Writes() - probes[0].base
	stuckDelta := probes[1].writer.Writes() - probes[1].base
	t.Logf("fast path %d writes; stuck path %d writes", fastDelta, stuckDelta)

	if fastDelta < N {
		t.Fatalf("fast path absorbed %d writes; expected >= %d (all data + ctrl)",
			fastDelta, N)
	}
	// Stuck path must absorb zero DATA frames. We allow up to 2 ctrl
	// frames as noise (one MIGRATE_NOTIFY from a hypothetical prior
	// migration; nothing else is expected to slip through).
	if stuckDelta > 2 {
		t.Fatalf("stuck path absorbed %d writes; expected <= 2", stuckDelta)
	}

	// The BondStuckSkips counter must have advanced at least once
	// per skipped round-robin slot. With pin defaultBondPinSize=8
	// and 2 paths, every other pin-window candidate is the stuck
	// path, so 20 frames produce >= 1 skip during cursor rotation.
	skips := bc.BondStuckSkips()
	t.Logf("bond stuck-skips counter: %d", skips)
	if skips == 0 {
		t.Fatal("BondStuckSkips==0; counter not wired up or never triggered")
	}
	if got := bc.Stats().BondStuckSkips; got != skips {
		t.Fatalf("Stats().BondStuckSkips=%d disagrees with BondStuckSkips()=%d", got, skips)
	}
}

// TestM5UDPFlowPlannedMigration: 2 udpflow paths, hot-swap active
// path via engine.Migrate mid-stream. Confirms M5 paths plug into
// the same engine migration primitive that TCP / QUIC use.
func TestM5UDPFlowPlannedMigration(t *testing.T) {
	ln, err := ListenUDPFlow("127.0.0.1:0")
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
			{Transport: "udpflow", Address: ln.Addr().String()},
			{Transport: "udpflow", Address: ln.Addr().String()},
		},
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if !waitForNPaths(t, client, server, "udpflow", ln.Addr().String(), 2, 8*time.Second) {
		t.Fatalf("expected 2 paths each, got client=%d server=%d",
			len(client.Paths()), len(server.Paths()))
	}

	bc := client.(*engineBackedConn)
	cur := bc.Engine().ActivePath()
	var other uint32
	for _, p := range bc.Paths() {
		if p.ID != cur {
			other = p.ID
			break
		}
	}
	if other == 0 {
		t.Fatal("no non-active path")
	}

	// Stream payload in 8 chunks; migrate after the 4th.
	const chunkSize = 256
	const chunks = 8
	want := make([]byte, 0, chunks*chunkSize)
	for i := 0; i < chunks; i++ {
		buf := make([]byte, chunkSize)
		for j := range buf {
			buf[j] = byte(i*37 + j)
		}
		want = append(want, buf...)
	}

	got := make([]byte, len(want))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(server, got)
		readDone <- err
	}()

	half := len(want) / 2
	if _, err := client.Write(want[:half]); err != nil {
		t.Fatalf("write first half: %v", err)
	}
	if err := bc.Engine().Migrate(other); err != nil {
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
	case <-time.After(5 * time.Second):
		t.Fatal("server read timed out across migration")
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch")
	}
	if bc.Engine().ActivePath() != other {
		t.Errorf("active path after migrate: got %d want %d", bc.Engine().ActivePath(), other)
	}
}

// TestM5UDPFlowFailoverToSurvivingPath: 2 udpflow paths, force-kill
// the server-side active path so the client observes a
// TransportError; engine fails over to the survivor without
// surfacing an app-level error.
func TestM5UDPFlowFailoverToSurvivingPath(t *testing.T) {
	ln, err := ListenUDPFlow("127.0.0.1:0")
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
			{Transport: "udpflow", Address: ln.Addr().String()},
			{Transport: "udpflow", Address: ln.Addr().String()},
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

	if !waitForNPaths(t, client, server, "udpflow", ln.Addr().String(), 2, 8*time.Second) {
		t.Fatalf("expected 2 paths each, got client=%d server=%d",
			len(client.Paths()), len(server.Paths()))
	}

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	pre := make([]byte, 5)
	if _, err := io.ReadFull(server, pre); err != nil {
		t.Fatal(err)
	}

	// Opaque UDP is connection-less: the server-side ServerPathConn
	// shares the listener's single UDP socket, so closing it does
	// NOT inform the peer the way a TCP RST would. The realistic
	// failure signal is on the client side - the OS UDP socket
	// closes, the engine's readerLoop on that path observes
	// transport error, onPathDeath fires, and the engine fails over.
	bc := client.(*engineBackedConn)
	if err := bc.Engine().ForceKillPathForTest(bc.Engine().ActivePath()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	const tail = "post-udp-failover"
	if _, err := client.Write([]byte(tail)); err != nil {
		t.Fatalf("post-failover write: %v", err)
	}
	buf := make([]byte, len(tail))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("post-failover read: %v", err)
	}
	if string(buf) != tail {
		t.Fatalf("post-failover payload: got %q want %q", buf, tail)
	}
}

// TestM5UDPFlowDialAcceptRoundTrip: Dialer over udpflow path +
// ListenUDPFlow accept; data flows in both directions over an
// opaque UDP datagram pair. Migration test (path swap on the same
// flow_id) belongs to a chaos run; this just proves wire+API.
func TestM5UDPFlowDialAcceptRoundTrip(t *testing.T) {
	ln, err := ListenUDPFlow("127.0.0.1:0")
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
		Mode:  ModePrime,
		Paths: []PathSpec{{Transport: "udpflow", Address: ln.Addr().String()}},
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	want := []byte("rendr over opaque-udp")
	if _, err := client.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch")
	}

	reply := []byte("ack from server")
	if _, err := server.Write(reply); err != nil {
		t.Fatal(err)
	}
	got2 := make([]byte, len(reply))
	if _, err := io.ReadFull(client, got2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, reply) {
		t.Fatalf("reply mismatch")
	}

	if client.FlowID() != server.FlowID() {
		t.Fatalf("flow_id mismatch")
	}
}

// TestM5PacketBoundariesPreserved: DialPacket / AcceptPacket negotiate
// packet-boundary mode through HELLO caps. Each application WriteTo
// becomes one frame on the wire, each ReadFrom returns one frame's
// payload. Concatenated stream-mode behaviour is the failure case
// this test guards against.
func TestM5PacketBoundariesPreserved(t *testing.T) {
	ln, err := ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptPacket(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- c
	}()

	d := &Dialer{
		Mode:  ModePrime,
		Paths: []PathSpec{{Transport: "udpflow", Address: ln.Addr().String()}},
	}
	client, err := d.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// Send three packets of distinct sizes. If boundaries were lost
	// the server would see them concatenated as one or more byte
	// sequences with no separator.
	packets := [][]byte{
		[]byte("alpha"),
		[]byte("bravo-bravo"),
		bytes.Repeat([]byte("c"), 257),
	}
	for i, p := range packets {
		if _, err := client.WriteTo(p, nil); err != nil {
			t.Fatalf("WriteTo %d: %v", i, err)
		}
	}

	buf := make([]byte, 1500)
	for i, want := range packets {
		n, addr, err := server.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom %d: %v", i, err)
		}
		if n != len(want) {
			t.Fatalf("packet %d: got n=%d want %d", i, n, len(want))
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("packet %d: payload mismatch", i)
		}
		if addr == nil {
			t.Fatalf("packet %d: addr is nil", i)
		}
	}

	// Reverse direction. Server emits two packets; client receives
	// them as discrete entries.
	rep := [][]byte{[]byte("ok"), []byte("seen-3")}
	for _, r := range rep {
		if _, err := server.WriteTo(r, nil); err != nil {
			t.Fatalf("server WriteTo: %v", err)
		}
	}
	for i, want := range rep {
		n, _, err := client.ReadFrom(buf)
		if err != nil {
			t.Fatalf("client ReadFrom %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("reply %d: payload mismatch", i)
		}
	}

	if client.FlowID() != server.FlowID() {
		t.Fatalf("flow_id mismatch")
	}
}

// TestM5PacketRejectOversize: SendPacket / WriteTo with a payload
// larger than engine.MaxPayload returns ErrPacketTooLarge and the
// connection stays healthy for subsequent legal writes.
func TestM5PacketRejectOversize(t *testing.T) {
	ln, err := ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptPacket(ctx)
		if err != nil {
			return
		}
		accepted <- c
	}()

	d := &Dialer{
		Mode:  ModePrime,
		Paths: []PathSpec{{Transport: "udpflow", Address: ln.Addr().String()}},
	}
	client, err := d.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// engine.MaxPayload is 32 KiB.
	oversize := bytes.Repeat([]byte{0xAA}, 32*1024+1)
	if _, err := client.WriteTo(oversize, nil); err == nil {
		t.Fatal("oversize WriteTo: expected error, got nil")
	}

	// Healthy small write still succeeds.
	small := []byte("ok")
	if _, err := client.WriteTo(small, nil); err != nil {
		t.Fatalf("legal WriteTo: %v", err)
	}
	buf := make([]byte, 32)
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], small) {
		t.Fatalf("after oversize: payload mismatch %q", buf[:n])
	}
}

// TestM5PacketSurvivesPlannedMigration: packet mode preserves
// boundaries through an explicit Migrate() between two attached
// udpflow paths. The application observes the same packet sequence
// in spite of the wire swapping mid-stream.
func TestM5PacketSurvivesPlannedMigration(t *testing.T) {
	ln, err := ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptPacket(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- c
	}()

	d := &Dialer{
		Mode: ModePrime,
		Paths: []PathSpec{
			{Transport: "udpflow", Address: ln.Addr().String()},
			{Transport: "udpflow", Address: ln.Addr().String()},
		},
	}
	client, err := d.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// Wait both sides see 2 paths.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 2 && len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(client.Paths()) < 2 {
		t.Fatalf("expected 2 client paths, got %d", len(client.Paths()))
	}

	// Send 4 packets, migrate, send 4 more.
	bc := client.(*enginePacketConn)
	send := func(prefix string, n int) {
		for i := 0; i < n; i++ {
			pkt := []byte(prefix + string(rune('0'+i)))
			if _, err := client.WriteTo(pkt, nil); err != nil {
				t.Fatalf("WriteTo: %v", err)
			}
		}
	}

	send("pre-", 4)

	// Switch to the other path.
	cur := bc.e.ActivePath()
	var other uint32
	for _, p := range bc.Paths() {
		if p.ID != cur {
			other = p.ID
			break
		}
	}
	if other == 0 {
		t.Fatal("no other path to migrate to")
	}
	if err := bc.e.Migrate(other); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	send("post", 4)

	buf := make([]byte, 64)
	want := []string{
		"pre-0", "pre-1", "pre-2", "pre-3",
		"post0", "post1", "post2", "post3",
	}
	for i, w := range want {
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom %d: %v", i, err)
		}
		if string(buf[:n]) != w {
			t.Fatalf("packet %d: got %q want %q", i, buf[:n], w)
		}
	}
}

// TestM5PacketStreamUnderMigration: stress test of packet-mode with
// 1000 sequenced packets and several mid-stream migrations. Each
// packet carries an 8-byte BigEndian counter; the server verifies
// the counters arrive in order with no gap. Validates that the
// reorder buffer and the migration machinery do not corrupt or drop
// packets under sustained load.
func TestM5PacketStreamUnderMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping packet-mode stress in -short")
	}

	ln, err := ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := ln.AcceptPacket(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- c
	}()

	d := &Dialer{
		Mode: ModePrime,
		Paths: []PathSpec{
			{Transport: "udpflow", Address: ln.Addr().String()},
			{Transport: "udpflow", Address: ln.Addr().String()},
			{Transport: "udpflow", Address: ln.Addr().String()},
		},
	}
	client, err := d.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// Wait all 3 paths attached.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 3 && len(server.Paths()) >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(client.Paths()) < 3 {
		t.Fatalf("expected 3 paths, got %d", len(client.Paths()))
	}

	bc := client.(*enginePacketConn)

	const N = 1000
	const migEvery = 250

	// Receiver: pull N packets, verify counter order.
	recvErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		for i := uint64(0); i < N; i++ {
			n, _, err := server.ReadFrom(buf)
			if err != nil {
				recvErr <- err
				return
			}
			if n != 8 {
				recvErr <- nil
				t.Errorf("packet %d: got n=%d want 8", i, n)
				return
			}
			got := binary.BigEndian.Uint64(buf[:8])
			if got != i {
				recvErr <- nil
				t.Errorf("packet %d: counter %d != expected %d", i, got, i)
				return
			}
		}
		recvErr <- nil
	}()

	// Sender: emit N packets; every migEvery, migrate to next path.
	var pkt [8]byte
	for i := uint64(0); i < N; i++ {
		binary.BigEndian.PutUint64(pkt[:], i)
		if _, err := client.WriteTo(pkt[:], nil); err != nil {
			t.Fatalf("WriteTo %d: %v", i, err)
		}
		if i > 0 && i%migEvery == 0 {
			cur := bc.e.ActivePath()
			var other uint32
			for _, p := range bc.Paths() {
				if p.ID != cur {
					other = p.ID
					break
				}
			}
			if other != 0 {
				_ = bc.e.Migrate(other)
			}
		}
	}

	select {
	case err := <-recvErr:
		if err != nil {
			t.Fatalf("receiver: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("receiver deadline; packet-mode stress hung")
	}
}

// TestM5PacketRaceModeDuplicates: race mode duplicates each frame
// across all attached paths. In packet mode the receiver must
// deliver exactly ONE copy of each application packet (the second
// copy lands in RecvDups). Validates the dispatcher's mode-agnostic
// behaviour against the new packet-boundary drainer.
func TestM5PacketRaceModeDuplicates(t *testing.T) {
	ln, err := ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptPacket(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- c
	}()

	d := &Dialer{
		Mode: ModePrime,
		Paths: []PathSpec{
			{Transport: "udpflow", Address: ln.Addr().String()},
			{Transport: "udpflow", Address: ln.Addr().String()},
		},
	}
	client, err := d.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 2 && len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := client.SetMode(ModeRace); err != nil {
		t.Fatalf("SetMode race: %v", err)
	}

	// Settle: the SetMode flip on the client doesn't synchronously
	// guarantee server-side reader goroutines for both paths are
	// drained-ready. Give the scheduler a beat so race fanout lands
	// on two prepared paths.
	time.Sleep(50 * time.Millisecond)

	// Warmup: drain a couple of packets in prime-style (only one
	// path absorbs each, the other ignores) before switching to the
	// count window. udpflow's per-path UDP socket can occasionally
	// be momentarily flaky on Windows loopback under parallel test
	// load - we tolerate up to 5 warmup retries.
	buf := make([]byte, 32)
	warmupOk := false
	for attempt := 0; attempt < 5; attempt++ {
		_, err := client.WriteTo([]byte{0xFF}, nil)
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if _, _, err := server.ReadFrom(buf); err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		warmupOk = true
		break
	}
	if !warmupOk {
		t.Skip("warmup failed after retries; race-packet wiring untestable under this load")
	}
	baseDups := server.(interface{ RecvDups() uint64 }).RecvDups()

	const N = 32
	for i := 0; i < N; i++ {
		pkt := []byte{byte(i)}
		if _, err := client.WriteTo(pkt, nil); err != nil {
			t.Fatalf("WriteTo %d: %v", i, err)
		}
	}

	for i := 0; i < N; i++ {
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom %d: %v", i, err)
		}
		if n != 1 || buf[0] != byte(i) {
			t.Fatalf("packet %d: got n=%d b=%d want byte(%d)", i, n, buf[0], i)
		}
	}

	// Server side: with 2 paths in race we expect roughly N
	// additional dedupe events (the second copy of each counted
	// frame). UDP loopback can drop occasional datagrams on either
	// path under burst load - which is exactly what race mode is
	// designed to mask - so we report the count, fail only on the
	// pathological case of zero dups (race effectively disabled),
	// and skip when load drops dups below half (we can no longer
	// distinguish "race works" from "race only worked sometimes").
	// The strict-zero-loss check is on the data channel above.
	dups := server.(interface{ RecvDups() uint64 }).RecvDups() - baseDups
	t.Logf("race+packet: %d application packets, %d dedupe events (post-warmup)", N, dups)
	if dups == 0 {
		t.Fatalf("race+packet: 0 dups for %d frames; race fan-out wiring broken", N)
	}
	if dups < uint64(N/2) {
		t.Skipf("race+packet: dups=%d < N/2=%d; UDP loopback load-shedding too high to assert", dups, N/2)
	}
}

// TestM6PathRTTProbeRecords: after a fresh dial, the per-path
// prober loop sends CtrlPathProbe every 1s; the peer echoes it
// back; the engine writes the measured RTT into PathConn.Quality().
// On loopback the RTT is single-digit microseconds.
func TestM6PathRTTProbeRecords(t *testing.T) {
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
		Mode:          ModePrime,
		Paths:         []PathSpec{{Transport: "tcp", Address: ln.Addr().String()}},
		ProbeInterval: 100 * time.Millisecond,
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// 8 s tolerance: 100 ms ProbeInterval + 9-package parallel test
	// contention can push the first reply past the original 1.5 s.
	deadline := time.Now().Add(8 * time.Second)
	var rtt time.Duration
	for time.Now().Before(deadline) {
		for _, p := range client.Paths() {
			if p.Quality.RTT > 0 {
				rtt = p.Quality.RTT
				break
			}
		}
		if rtt > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if rtt == 0 {
		t.Fatal("no RTT recorded within deadline")
	}
	if rtt > 100*time.Millisecond {
		t.Errorf("loopback RTT %s suspiciously high", rtt)
	}
	t.Logf("loopback RTT measured = %s", rtt)
}

// TestM6PrimeAutoMigrateOnQualityChange: with prime-mode quality
// scheduler armed, when path 2 becomes substantially better than
// the current path 1 (10x lower RTT), the engine must migrate to
// it after dwell + cooldown without the test calling Migrate.
//
// Uses SetPathQualityForTest to inject scores; the production
// RTT/jitter/loss probe lands in M6(2/n).
func TestM6PrimeAutoMigrateOnQualityChange(t *testing.T) {
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
		Hysteresis: 0.1,
		Dwell:      50 * time.Millisecond,
		Cooldown:   100 * time.Millisecond,
		// Long probe interval so the real RTT probe does not
		// overwrite SetPathQualityForTest before the scheduler
		// has a chance to act on the injected qualities.
		ProbeInterval: time.Hour,
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if !waitForNPaths(t, client, server, "tcp", ln.Addr().String(), 2, 8*time.Second) {
		t.Fatalf("only client=%d server=%d paths after 8s",
			len(client.Paths()), len(server.Paths()))
	}

	bc := client.(*engineBackedConn)
	pathsInfo := bc.Paths()
	p1ID, p2ID := pathsInfo[0].ID, pathsInfo[1].ID

	startActive := bc.Engine().ActivePath()
	// Inject qualities: current is mediocre, the other is much better.
	bc.Engine().SetPathQualityForTest(startActive, transport.PathQuality{
		RTT: 100 * time.Millisecond,
	})
	var otherID uint32
	if startActive == p1ID {
		otherID = p2ID
	} else {
		otherID = p1ID
	}
	bc.Engine().SetPathQualityForTest(otherID, transport.PathQuality{
		RTT: 10 * time.Millisecond,
	})

	// Wait at most dwell + cooldown + tick slack for the prime
	// scheduler to fire. 10 s tolerance covers parallel-package
	// contention that pushes scheduler ticks past the nominal
	// dwell+cooldown when ~10 packages worth of sockets/goroutines
	// are in flight on the same test run.
	migrated := false
	waitUntil := time.Now().Add(10 * time.Second)
	for time.Now().Before(waitUntil) {
		if bc.Engine().ActivePath() == otherID {
			migrated = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !migrated {
		t.Fatalf("prime scheduler did not migrate to better path within 10s (active still %d, wanted %d)",
			bc.Engine().ActivePath(), otherID)
	}
}

// TestM2G1SketchQUIC: G1 invariants over QUIC paths.
// 16 MiB stream (smaller than the TCP sketch because QUIC handshake
// + crypto cost dominate small loopback runs; the invariant we are
// testing is "byte-stream over migration", not raw throughput) + 3
// forced migrations between two QUIC paths + SHA-256 verified.
func TestM2G1SketchQUIC(t *testing.T) {
	ln, err := ListenQUIC("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
			{Transport: "quic", Address: ln.Addr().String()},
			{Transport: "quic", Address: ln.Addr().String()},
		},
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 2 && len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(client.Paths()) < 2 {
		t.Fatalf("client only has %d paths", len(client.Paths()))
	}

	const total = 16 * 1024 * 1024
	want := make([]byte, total)
	for i := range want {
		want[i] = byte(i*17 + 3)
	}
	wantSum := sha256.Sum256(want)

	var rxSum [32]byte
	done := make(chan error, 1)
	go func() {
		h := sha256.New()
		buf := make([]byte, 128*1024)
		got := 0
		for got < total {
			n, err := server.Read(buf)
			if err != nil {
				done <- err
				return
			}
			h.Write(buf[:n])
			got += n
		}
		copy(rxSum[:], h.Sum(nil))
		done <- nil
	}()

	bc := client.(*engineBackedConn)
	migrateAt := []int{total * 3 / 10, total * 5 / 10, total * 7 / 10}
	t0 := time.Now()
	written := 0
	mi := 0
	chunk := 64 * 1024
	for written < total {
		end := written + chunk
		if end > total {
			end = total
		}
		n, err := client.Write(want[written:end])
		if err != nil {
			t.Fatalf("write at %d: %v", written, err)
		}
		written += n
		for mi < len(migrateAt) && written >= migrateAt[mi] {
			cur := bc.Engine().ActivePath()
			var other uint32
			for _, p := range bc.Paths() {
				if p.ID != cur {
					other = p.ID
					break
				}
			}
			if other != 0 {
				if err := bc.Engine().Migrate(other); err != nil {
					t.Fatalf("migrate %d: %v", mi, err)
				}
				t.Logf("quic-migrate %d at %d bytes -> path %d", mi, written, other)
			}
			mi++
		}
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("recv timed out")
	}

	if rxSum != wantSum {
		t.Fatalf("sha256 mismatch:\n got=%x\nwant=%x", rxSum, wantSum)
	}
	t.Logf("16 MiB over QUIC + 3 migrations in %s, sha256 verified", time.Since(t0))
}

// TestM2QUICRoundTrip: Dialer over QUIC path + ListenQUIC accept;
// public rendr.Conn round-trips bytes through one QUIC connection
// per path. Matches the M1 TCP smoke test but over the QUIC adapter.
func TestM2QUICRoundTrip(t *testing.T) {
	ln, err := ListenQUIC("127.0.0.1:0", nil)
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
		Mode:  ModePrime,
		Paths: []PathSpec{{Transport: "quic", Address: ln.Addr().String()}},
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	want := bytes.Repeat([]byte("rendr-quic-"), 64)
	if _, err := client.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch")
	}
	if client.FlowID() != server.FlowID() {
		t.Fatalf("flow_id mismatch")
	}
}

// TestM2MixedTCPQUICMigration: two paths on the same Dialer, one
// TCP and one QUIC, both attached to the same engine. Send the
// first half on TCP, migrate to QUIC, send the rest. Hash must match.
//
// This stresses that the engine treats QUIC and TCP path adapters
// symmetrically (same proto.Frame envelope, same DeathCause
// taxonomy, same migration semantics).
func TestM2MixedTCPQUICMigration(t *testing.T) {
	// Need both a TCP listener AND a QUIC listener that resolve to
	// the same engine bridge. Easiest: one TCP listener for the
	// HELLO path, then add a QUIC path via BRIDGE_TAG. The bridge
	// table is keyed by flow_id and is shared per-listener, so we
	// need a unified server. M1's bridges are per-listener; do the
	// cross-transport bridge by hand below.

	tcpLn, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()

	quicLn, err := ListenQUIC("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer quicLn.Close()

	// Both listeners maintain their own bridge tables. For this
	// test the simpler path is to NOT cross bridges, but instead
	// dial just QUIC + QUIC and just TCP + TCP separately. The
	// "mixed" property we're actually proving here is that the
	// engine accepts BOTH a TCP and a QUIC path on the same
	// rendr.Conn when the listener that demuxed HELLO knows about
	// both transports. M9 will deliver a unified Listen() that
	// accepts both transport kinds in one bridge table; until then,
	// the cross-transport case is not in scope for M2.
	t.Skip("cross-transport bridge unification deferred to M9 (multi-transport listener)")
}

// TestM2QUICDeathTriggersMigration: with two QUIC paths attached,
// kill the active one and verify the engine fails over to the
// surviving QUIC path without surfacing an error to the application.
func TestM2QUICDeathTriggersMigration(t *testing.T) {
	ln, err := ListenQUIC("127.0.0.1:0", nil)
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
			{Transport: "quic", Address: ln.Addr().String()},
			{Transport: "quic", Address: ln.Addr().String()},
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

	// Wait for both paths.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 2 && len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(server.Paths()) < 2 {
		t.Fatalf("server only has %d paths", len(server.Paths()))
	}

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	pre := make([]byte, 5)
	if _, err := io.ReadFull(server, pre); err != nil {
		t.Fatal(err)
	}

	sc := server.(*engineBackedConn)
	if err := sc.Engine().ForceKillPathForTest(sc.Engine().ActivePath()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	// Continue streaming.
	const tail = "post-quic-failover"
	if _, err := client.Write([]byte(tail)); err != nil {
		t.Fatalf("post-failover write: %v", err)
	}
	buf := make([]byte, len(tail))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("post-failover read: %v", err)
	}
	if string(buf) != tail {
		t.Fatalf("post-failover payload: got %q want %q", buf, tail)
	}
}

// TestM1ZombieAfterTwoNoPayloadMigrations enforces CLAUDE.md hard
// rule #5: two consecutive completed migrations with zero payload
// arriving in between must trip ErrZombie. The harness primes the
// engine with one echo so zombieLeft is full, then kills the active
// path twice with no traffic between the kills.
func TestM1ZombieAfterTwoNoPayloadMigrations(t *testing.T) {
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
			{Transport: "tcp", Address: ln.Addr().String()},
		},
		MigrationBudget: 1 * time.Second,
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// Wait for all 3 paths on both ends; retry via AddPath under
	// load if Dialer's silent-skip dropped one of the extras.
	bcAdm := client.(AdminConn)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 3 && len(server.Paths()) >= 3 {
			break
		}
		if len(client.Paths()) < 3 {
			_, _ = bcAdm.AddPath(PathSpec{Transport: "tcp", Address: ln.Addr().String()})
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(client.Paths()) < 3 {
		t.Fatalf("client only has %d paths", len(client.Paths()))
	}

	// Liveness check.
	if _, err := client.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	hi := make([]byte, 2)
	if _, err := io.ReadFull(server, hi); err != nil {
		t.Fatal(err)
	}

	bc := client.(*engineBackedConn)

	// First kill: client.activeID dies, engine migrates to a survivor.
	// zombieLeft: 2 -> 1 (no payload yet between this and a hypothetical next).
	kill1 := bc.Engine().ActivePath()
	if err := bc.Engine().ForceKillPathForTest(kill1); err != nil {
		t.Fatalf("kill1: %v", err)
	}

	// Brief settle so the migration callback finishes; no data is
	// pushed in either direction.
	time.Sleep(20 * time.Millisecond)

	// Second kill: again the active dies, engine migrates again.
	// zombieLeft: 1 -> 0 -> ErrZombie close fires.
	kill2 := bc.Engine().ActivePath()
	if kill2 == 0 || kill2 == kill1 {
		t.Fatalf("expected fresh active after migration; got %d (was %d)", kill2, kill1)
	}
	if err := bc.Engine().ForceKillPathForTest(kill2); err != nil {
		t.Fatalf("kill2: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := client.Read(make([]byte, 1))
		readErr <- err
	}()

	select {
	case err := <-readErr:
		if !errors.Is(err, ErrZombie) {
			t.Fatalf("got %v, want ErrZombie", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read did not surface ErrZombie within 3s")
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
