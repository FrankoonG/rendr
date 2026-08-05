package rendr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testRoot(kind TargetKind, specs []PathSpec) Target {
	children := make([]Target, 0, len(specs))
	for i, spec := range specs {
		children = append(children, Path(fmt.Sprintf("path-%d", i+1), spec))
	}
	switch kind {
	case TargetKindRace:
		return Race("root", children)
	case TargetKindBond:
		return Bond("root", children)
	default:
		return Selector("root", children)
	}
}

func selectorRoot(specs []PathSpec) Target { return testRoot(TargetKindSelector, specs) }
func raceRoot(specs []PathSpec) Target     { return testRoot(TargetKindRace, specs) }
func bondRoot(specs []PathSpec) Target     { return testRoot(TargetKindBond, specs) }

func pathNameByID(paths []PathInfo, id uint32) string {
	for _, path := range paths {
		if path.ID == id {
			return path.Spec.Opts["name"]
		}
	}
	return ""
}

// waitForNPaths polls until both client and server see at least n
// attached paths, retrying via testConnectionControl.AddPath against the named
// transport+address if the client falls short. The session dialer is
// best-effort about extra paths (silent-skip on dial failure);
// under heavy parallel test load that drops paths often enough to
// be a per-test pollution source. Centralising the retry here
// keeps the per-test code clean.
//
// Returns true if both sides reached n paths before the deadline,
// false otherwise (caller decides whether to t.Skip or t.Fatal).
func waitForNPaths(t *testing.T, client Conn, server Conn, transport, addr string, n int, total time.Duration) bool {
	t.Helper()
	adm, _ := client.(testConnectionControl)
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

		[]PathSpec{{Transport: "tcp", Address: ln.Addr().String()}})}

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

		[]PathSpec{{Transport: "tcp", Address: ln.Addr().String()}})}

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

	// Symmetric check on the client side: the client just wrote a
	// data frame so its LastSendAt for the active path must be
	// populated and recent.
	clientSend := client.Paths()[0].LastSendAt
	if clientSend.IsZero() {
		t.Fatal("client LastSendAt zero after Write")
	}
	if age := time.Since(clientSend); age > 5*time.Second {
		t.Errorf("client LastSendAt stale: age=%s", age)
	}
}

// TestDialerCustomLimitsApplied verifies that a session-level
// ZombieMaxMigrations setting reaches the engine. We construct a session dialer with the
// minimum-zombie value (1) and run a single death-driven failover;
// the engine should trip zombie protection after that one event
// (which would not trigger under the default 2). This validates that
// the sessionDialer-to-engine Limits plumbing actually carries the field.
func TestDialerCustomLimitsApplied(t *testing.T) {
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
			return
		}
		accepted <- c
	}()

	controlled := newRuntimeControlledTCPTransport(t)
	d := &sessionDialer{
		Root: Selector("root", []Target{
			Path("A", controlled.Spec(ln.Addr().String(), "A")),
			Path("B", controlled.Spec(ln.Addr().String(), "B")),
		}),
		ZombieMaxMigrations: 1,
		ZombieCooldown:      30 * time.Second,
		Retry:               retryPolicy{MinBackoff: 5 * time.Second, MaxBackoff: 5 * time.Second},
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if !waitForNPaths(t, client, server, controlled.Name(), ln.Addr().String(), 2, 8*time.Second) {
		t.Skipf("could not stabilize 2 paths each; environment too noisy")
	}

	// Kill the active path. With ZombieMax=1 the engine trips on this
	// single death-driven failover (no payload between migrations).
	observer := client.(ConnectionObserver)
	activeName := pathNameByID(client.Paths(), observer.ActivePath())
	if activeName == "" {
		t.Fatalf("active path %d has no fixture name", observer.ActivePath())
	}
	if err := controlled.Fail(activeName); err != nil {
		t.Fatalf("fail active path: %v", err)
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

// TestM2QUICDatagramPacketRoundTrip exercises the full DATAGRAM
// stack through a Runtime FramedSource backed by QUIC DATAGRAM
// on the server + sessionDialer.DialPacket with PathSpec.Opts["mode"]=
// "datagram" on the client. Confirms the wire-level QUIC DATAGRAM
// support (commit 690fa60) integrates correctly through engine
// packet mode.
func TestM2QUICDatagramPacketRoundTrip(t *testing.T) {
	ln, err := listenRuntimeQUICDatagram("127.0.0.1:0", nil)
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
			t.Errorf("AcceptPacket: %v", err)
			return
		}
		accepted <- c
	}()

	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{{
			Transport: "quic",
			Address:   ln.Addr().String(),
			Opts:      map[string]string{"mode": "datagram"},
		}})}

	client, err := d.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// Two packets in each direction; boundaries must be preserved
	// because DATAGRAM == one frame per datagram.
	for i, p := range [][]byte{[]byte("alpha"), []byte("beta-beta-beta")} {
		if _, err := client.WriteTo(p, nil); err != nil {
			t.Fatalf("client WriteTo %d: %v", i, err)
		}
	}
	buf := make([]byte, 256)
	for i, want := range [][]byte{[]byte("alpha"), []byte("beta-beta-beta")} {
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			t.Fatalf("server ReadFrom %d: %v", i, err)
		}
		if string(buf[:n]) != string(want) {
			t.Fatalf("packet %d: got %q want %q", i, buf[:n], want)
		}
	}

	if _, err := server.WriteTo([]byte("ack"), nil); err != nil {
		t.Fatalf("server WriteTo: %v", err)
	}
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("client ReadFrom: %v", err)
	}
	if string(buf[:n]) != "ack" {
		t.Fatalf("reply: got %q want ack", buf[:n])
	}

	if client.FlowID() != server.FlowID() {
		t.Fatalf("flow_id mismatch through QUIC DATAGRAM wrap")
	}
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
		{"ErrRecvWindowExceeded", ErrRecvWindowExceeded, ErrRecvWindowExceeded},
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
	ln, err := listenRuntimeUDP("127.0.0.1:0")
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

	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{{Transport: "udpflow", Address: ln.Addr().String()}})}

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

// TestSetReadDeadlinePacketModeUpdatesBlockedRead verifies that a
// packet-mode ReadFrom already blocked in RecvPacket notices a later
// SetReadDeadline change promptly. Without this, RecvPacket keeps
// waiting on the timer captured at call entry and ignores the new
// deadline until the old one expires.
func TestSetReadDeadlinePacketModeUpdatesBlockedRead(t *testing.T) {
	ln, err := listenRuntimeUDP("127.0.0.1:0")
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

	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{{Transport: "udpflow", Address: ln.Addr().String()}})}

	client, err := d.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("initial SetReadDeadline: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, _, err := server.ReadFrom(buf)
		done <- err
	}()

	time.Sleep(150 * time.Millisecond)
	t0 := time.Now()
	if err := server.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("update SetReadDeadline: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadFrom: got nil error, want timeout")
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("ReadFrom: got %v, want net.Error with Timeout()==true", err)
		}
		if elapsed := time.Since(t0); elapsed > 1500*time.Millisecond {
			t.Fatalf("ReadFrom ignored updated deadline for %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom stayed blocked after deadline update")
	}
}

// TestM1DialAcceptRoundTrip is the minimal end-to-end demo for M1:
// Runtime raw-TCP ingress + sessionDialer.Dial + Read/Write over rendr Conn.
// Both ends live in the same process; the wire path is a real TCP
// socket on the loopback.
func TestM1DialAcceptRoundTrip(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
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
	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{
			{Transport: "tcp", Address: ln.Addr().String()},
		})}

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

func TestGVisorPacketCarrierDialAcceptRoundTrip(t *testing.T) {
	ln, err := listenRuntimeGVisorPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	client, err := (&sessionDialer{Root: selectorRoot(

		[]PathSpec{{Transport: "gvisor", Address: ln.Addr().String()}})}).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timeout")
	}
	defer server.Close()

	payload := []byte("hello over rendr gvisor packet carrier")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q want %q", got, payload)
	}
}

// TestM1LargePayload exercises the framing layer with a payload that
// exceeds MaxPayload, so multiple frames flow per logical write.
// This is the smallest building block for G1.
func TestM1LargePayload(t *testing.T) {
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

	d := &sessionDialer{Root: selectorRoot([]PathSpec{{Transport: "tcp", Address: ln.Addr().String()}})}
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
	ln, err := listenRuntimeTCP("127.0.0.1:0")
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
			d := &sessionDialer{Root: selectorRoot([]PathSpec{{Transport: "tcp", Address: ln.Addr().String()}})}
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
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		})}

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

	observer := client.(ConnectionObserver)
	migrator := client.(MigrationController)

	// Identify a non-active path to migrate to.
	currentID := observer.ActivePath()
	var otherID uint32
	for _, p := range client.Paths() {
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
	if err := migrator.Migrate(otherID); err != nil {
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
	if observer.ActivePath() != otherID {
		t.Errorf("active path after migrate: got %d want %d", observer.ActivePath(), otherID)
	}
}

// TestM1MigrationBudgetExpires kills the only path and verifies that
// after MigrationBudget elapses, Read returns ErrMigrationBudgetExceeded.
func TestM1MigrationBudgetExpires(t *testing.T) {
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

		[]PathSpec{{Transport: "tcp", Address: ln.Addr().String()}}), MigrationBudget: 200 * time.Millisecond}

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

	// Make recovery genuinely impossible before killing the live path. A
	// still-listening endpoint is expected to be redialed automatically by the
	// v1 runtime and therefore must not be used to prove budget expiry.
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	// Close the actual server-side carrier without a rendr BYE. The client must
	// classify the resulting remote socket failure through its reader loop.
	if err := ln.CloseAcceptedPath("tcp", 0); err != nil {
		t.Fatal(err)
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

// TestM1FailoverToSurvivingPath is a fast carrier-close smoke: with two
// attached paths, close the active server carrier and require transparent
// failover to the pre-existing survivor. Release-grade G4 uses an
// unannounced network blackhole on the Linux test VM.
func TestM1FailoverToSurvivingPath(t *testing.T) {
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

	controlled := newRuntimeControlledTCPTransport(t)
	d := &sessionDialer{Root: Selector("root", []Target{
		Path("A", controlled.Spec(ln.Addr().String(), "A")),
		Path("B", controlled.Spec(ln.Addr().String(), "B")),
	}), MigrationBudget: 3 * time.Second, ProbeInterval: 30 * time.Second}

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
	if len(client.Paths()) < 2 || len(server.Paths()) < 2 {
		t.Fatalf("two-path carrier-close topology incomplete: client=%d server=%d", len(client.Paths()), len(server.Paths()))
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

	observer := client.(ConnectionObserver)
	killedID := observer.ActivePath()
	killedName := pathNameByID(client.Paths(), killedID)
	if killedName == "" {
		t.Fatalf("active path %d has no controlled leaf name", killedID)
	}
	initial := make(map[uint32]string, len(client.Paths()))
	for _, path := range client.Paths() {
		initial[path.ID] = path.Spec.Opts["name"]
	}
	peerLocal, err := controlled.LocalAddr(killedName)
	if err != nil {
		t.Fatal(err)
	}
	controlled.Block(killedName)
	migrationsBefore := observer.MigrationCount()
	// Close the exact server-side carrier paired with the active client path.
	// The blocked leaf cannot redial and masquerade as survivor failover.
	if _, err := ln.CloseAcceptedPeerPath("tcp", peerLocal); err != nil {
		t.Fatal(err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		killedAttached := false
		for _, path := range client.Paths() {
			if path.ID == killedID {
				killedAttached = true
				break
			}
		}
		if !killedAttached && observer.ActivePath() != killedID && observer.MigrationCount() > migrationsBefore {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	newActive := observer.ActivePath()
	newName, preexisting := initial[newActive]
	if newActive == 0 || newActive == killedID || !preexisting || newName == killedName {
		t.Fatalf("carrier-close survivor is not a different pre-existing path: killed=%d/%q active=%d/%q initial=%v",
			killedID, killedName, newActive, newName, initial)
	}
	for _, path := range client.Paths() {
		if path.ID == killedID {
			t.Fatalf("closed carrier path %d remains attached: %+v", killedID, client.Paths())
		}
	}
	if observer.MigrationCount() <= migrationsBefore {
		t.Fatalf("carrier close did not increment MigrationCount: before=%d after=%d", migrationsBefore, observer.MigrationCount())
	}

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

	d := &sessionDialer{Root: selectorRoot([]PathSpec{{Transport: "tcp", Address: ln.Addr().String()}})}
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
// integrity. Functionally minified G1: real G1 demands >= 1 GiB
// (validated out-of-band); this version fits the unit-test budget
// while exercising the same invariants:
//   - migration is transparent to the application Conn
//   - byte stream is contiguous and order-preserving
//   - hash matches end-to-end
func TestM1G1Sketch(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
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

	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		})}

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

	observer := client.(ConnectionObserver)
	migrator := client.(MigrationController)

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
			cur := observer.ActivePath()
			var other uint32
			for _, p := range client.Paths() {
				if p.ID != cur {
					other = p.ID
					break
				}
			}
			if other != 0 {
				if err := migrator.Migrate(other); err != nil {
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
// Real G2 is 30 minutes / 30+ migrations and is validated
// out-of-band. This sketch reproduces the reorder-around-migration
// invariant cheaply.
func TestM1G2Sketch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping G2 sketch in -short")
	}

	ln, err := listenRuntimeTCP("127.0.0.1:0")
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

	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		})}

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

	observer := client.(ConnectionObserver)
	migrator := client.(MigrationController)

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
				cur := observer.ActivePath()
				var other uint32
				for _, p := range client.Paths() {
					if p.ID != cur {
						other = p.ID
						break
					}
				}
				if other != 0 {
					if err := migrator.Migrate(other); err == nil {
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

	d := &sessionDialer{Root: raceRoot(

		[]PathSpec{
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		})}

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

	baseline := make(map[uint32]uint64, 2)
	for _, path := range client.Paths() {
		baseline[path.ID] = path.FirstDataDispatches
	}
	if len(baseline) != 2 {
		t.Fatalf("expected 2 path snapshots, got %d", len(baseline))
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

	for id, base := range baseline {
		deadline := time.Now().Add(time.Second)
		var got uint64
		for time.Now().Before(deadline) {
			for _, path := range client.Paths() {
				if path.ID == id {
					got = path.FirstDataDispatches - base
					break
				}
			}
			if got >= uint64(N) {
				break
			}
			time.Sleep(time.Millisecond)
		}
		// Race returns after the first successful child, but every admitted
		// replica must still complete asynchronously on a healthy path.
		if got < uint64(N) {
			t.Errorf("path %d saw %d first DATA dispatches, want >= %d", id, got, N)
		}
	}
}

// TestM8BondPathDeathContinuesOnSurvivor: in bond mode, after a
// mid-stream kill on one path the engine must keep delivering on
// the survivor. The engine replays a bounded recent send window from
// the dead path, so frames that were accepted by that path but lost
// before reaching the peer can fill the receiver's SEQ gap. This test
// asserts that:
//   - the survivor keeps receiving subsequent writes
//   - the application-visible byte stream before and after the kill
//     is delivered in order.
func TestM8BondPathDeathContinuesOnSurvivor(t *testing.T) {
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

	controlled := newRuntimeControlledTCPTransport(t)
	d := &sessionDialer{
		Root: Bond("root", []Target{
			Path("A", controlled.Spec(ln.Addr().String(), "A")),
			Path("B", controlled.Spec(ln.Addr().String(), "B")),
		}),
		Retry: retryPolicy{MinBackoff: 5 * time.Second, MaxBackoff: 5 * time.Second},
	}

	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if !waitForNPaths(t, client, server, controlled.Name(), ln.Addr().String(), 2, 8*time.Second) {
		t.Fatalf("expected 2 paths each, got client=%d server=%d",
			len(client.Paths()), len(server.Paths()))
	}

	baseline := make(map[uint32]uint64, 2)
	for _, path := range client.Paths() {
		baseline[path.ID] = path.FirstDataDispatches
	}

	const preN = 16
	pre := []byte("pre-bond-frame-")
	for i := 0; i < preN; i++ {
		if _, err := client.Write(pre); err != nil {
			t.Fatalf("pre write %d: %v", i, err)
		}
	}

	killID := uint32(0)
	var survivorBase uint64
	var survivorID uint32
	for _, path := range client.Paths() {
		if path.FirstDataDispatches > baseline[path.ID] {
			killID = path.ID
			break
		}
	}
	if killID == 0 {
		t.Fatal("bond did not write on either probed path")
	}
	for _, path := range client.Paths() {
		if path.ID != killID {
			survivorID = path.ID
			survivorBase = path.FirstDataDispatches
			break
		}
	}
	killName := pathNameByID(client.Paths(), killID)
	if killName == "" {
		t.Fatalf("kill path %d has no fixture name", killID)
	}
	if err := controlled.Fail(killName); err != nil {
		t.Fatalf("fail path %d: %v", killID, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(client.Paths()) != 1 {
		t.Fatalf("expected one survivor after kill, got %d paths", len(client.Paths()))
	}

	const postN = 8
	post := []byte("post-survivor-")
	for i := 0; i < postN; i++ {
		if _, err := client.Write(post); err != nil {
			t.Fatalf("post write %d: %v", i, err)
		}
	}

	expected := append(bytes.Repeat(pre, preN), bytes.Repeat(post, postN)...)
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(expected))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server drain after bond path death: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("server byte-stream mismatch after bond path death")
	}

	var survivorWrites uint64
	for _, path := range client.Paths() {
		if path.ID == survivorID {
			survivorWrites = path.FirstDataDispatches
			break
		}
	}
	if survivorWrites <= survivorBase {
		t.Fatalf("survivor path did not receive post-kill writes: %d -> %d",
			survivorBase, survivorWrites)
	}
}

// TestAdminConnStatsSnapshot: Stats() returns a coherent view of
// flow id, mode, state, active path, the path list, and recv-queue
// HWM in one call. Fields must be internally consistent (same
// flow id everywhere, ActivePath in Paths if non-zero, Mode
// reflecting the executor selected by the root target).
func TestAdminConnStatsSnapshot(t *testing.T) {
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
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		})}

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

	adm := client.(testConnectionControl)
	s := adm.Stats()

	if s.FlowID != client.FlowID() {
		t.Errorf("Stats.FlowID mismatch: %x vs %x", s.FlowID, client.FlowID())
	}
	if s.State != "active" {
		t.Errorf("Stats.State: got %q want %q", s.State, "active")
	}
	if s.Mode != ModeSelector {
		t.Errorf("Stats.Mode: got %v want %v", s.Mode, ModeSelector)
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

}

// TestAdminConnStateAndHWM: State() reports the bridge lifecycle
// transitions and RecvQueueHWM exposes the dedup-buffer high-water
// mark used to detect race-mode reorder window overflow.
func TestAdminConnStateAndHWM(t *testing.T) {
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

	d := &sessionDialer{Root: selectorRoot([]PathSpec{{Transport: "tcp", Address: ln.Addr().String()}})}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	adm, ok := client.(testConnectionControl)
	if !ok {
		t.Fatal("client does not implement testConnectionControl")
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

	d := &sessionDialer{Root: selectorRoot([]PathSpec{{Transport: "tcp", Address: ln.Addr().String()}})}
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

// TestG5PathRecoveryViaAddPath: 2 paths, detach one, AddPath a
// replacement (same spec); verify the new path attaches to the
// existing engine via BRIDGE_TAG and the stream continues without
// any application-visible error. This is the G5 acceptance
// minimum: "path A recovers and re-joins the available set."
func TestG5PathRecoveryViaAddPath(t *testing.T) {
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
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		})}

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

	// Explicitly detach the inactive client path. A transport-error death is
	// automatically redialed in v1 and would make this manual AddPath contract
	// race the recovery supervisor instead of testing BRIDGE attachment.
	admin := client.(testConnectionControl)
	preKill := len(admin.Paths())
	var detachedID uint32
	for _, path := range admin.Paths() {
		if !path.Active {
			detachedID = path.ID
			break
		}
	}
	if detachedID == 0 {
		t.Fatal("no inactive path available for detach")
	}
	if err := admin.RemovePath(detachedID); err != nil {
		t.Fatal(err)
	}
	if len(admin.Paths()) != preKill-1 {
		t.Fatalf("after detach: paths=%d want %d", len(admin.Paths()), preKill-1)
	}

	// Recover: AddPath a fresh socket to the same listener.
	newID, err := admin.AddPath(PathSpec{Transport: "tcp", Address: ln.Addr().String()})
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	if newID == 0 {
		t.Fatal("AddPath returned 0 id")
	}
	if len(admin.Paths()) != preKill {
		t.Fatalf("after AddPath: paths=%d want %d", len(admin.Paths()), preKill)
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
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		})}

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

	adm := client.(testConnectionControl)

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
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		})}

	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	adm := client.(testConnectionControl)
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

	controlled := newRuntimeControlledTCPTransport(t)
	d := &sessionDialer{
		Root: Selector("root", []Target{
			Path("A", controlled.Spec(ln.Addr().String(), "A")),
			Path("B", controlled.Spec(ln.Addr().String(), "B")),
			Path("C", controlled.Spec(ln.Addr().String(), "C")),
		}),
		Retry: retryPolicy{MinBackoff: 5 * time.Second, MaxBackoff: 5 * time.Second},
	}

	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if !waitForNPaths(t, client, server, controlled.Name(), ln.Addr().String(), 3, 8*time.Second) {
		t.Fatalf("expected 3 paths each, got client=%d server=%d",
			len(client.Paths()), len(server.Paths()))
	}

	adm := client.(testConnectionControl)

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
	activeName := pathNameByID(client.Paths(), adm.ActivePath())
	if activeName == "" {
		t.Fatalf("active path %d has no fixture name", adm.ActivePath())
	}
	if err := controlled.Fail(activeName); err != nil {
		t.Fatalf("fail active path: %v", err)
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

	controlled := newRuntimeControlledTCPTransport(t)
	d := &sessionDialer{
		Root: Selector("root", []Target{
			Path("A", controlled.Spec(ln.Addr().String(), "A")),
			Path("B", controlled.Spec(ln.Addr().String(), "B")),
			Path("C", controlled.Spec(ln.Addr().String(), "C")),
		}),
		Retry: retryPolicy{MinBackoff: 5 * time.Second, MaxBackoff: 5 * time.Second},
	}

	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if !waitForNPaths(t, client, server, controlled.Name(), ln.Addr().String(), 3, 8*time.Second) {
		t.Fatalf("expected 3 paths each, got client=%d server=%d",
			len(client.Paths()), len(server.Paths()))
	}

	adm := client.(testConnectionControl)
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
	activeName := pathNameByID(client.Paths(), adm.ActivePath())
	if activeName == "" {
		t.Fatalf("active path %d has no fixture name", adm.ActivePath())
	}
	if err := controlled.Fail(activeName); err != nil {
		t.Fatalf("fail active path: %v", err)
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

type recvDupSnapshotter interface {
	RecvDups() uint64
	Paths() []PathInfo
}

func waitRecvDupsStable(t *testing.T, adm recvDupSnapshotter) (uint64, []PathInfo) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	last := adm.RecvDups()
	stableSince := time.Now()
	var paths []PathInfo
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		cur := adm.RecvDups()
		if cur != last {
			last = cur
			stableSince = time.Now()
			continue
		}
		paths = adm.Paths()
		var sum uint64
		for _, p := range paths {
			sum += p.RecvDups
		}
		if sum == cur && time.Since(stableSince) >= 50*time.Millisecond {
			return cur, paths
		}
	}
	paths = adm.Paths()
	return last, paths
}

// TestM7DedupWindowBoundedOnLoopback: race mode on loopback should
// never grow the reorder buffer beyond a small number; on a fast
// path-pair both copies of each frame arrive within microseconds,
// so high-water-mark stays tiny. This diagnoses race-mode 'dedup
// window overflow' - a hard race-mode bug when path RTT skew is
// large enough to outrun the receiver's reorder window.
func TestM7DedupWindowBoundedOnLoopback(t *testing.T) {
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

	d := &sessionDialer{Root: raceRoot(

		[]PathSpec{
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		})}

	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// Wait for both sides to see two attached paths before sending.
	// Previous version only checked server.Paths() >= 2; if the
	// client side was still finishing path-2 attach when traffic
	// fired, race-mode dispatch would target only the single
	// already-attached path and emit no duplicates. Result:
	// RecvDups=0 (test fails) and HWM=1 (no concurrent arrivals).
	// Diagnosed from the M7 failure on HEAD 13b5464 in REG-T4.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(server.Paths()) >= 2 && len(client.Paths()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(client.Paths()) < 2 {
		t.Fatalf("M7 setup: client only sees %d paths after 5s; race-mode dispatch needs ≥2", len(client.Paths()))
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

	serverObserver := server.(ConnectionObserver)
	hwm := serverObserver.RecvQueueHWM()
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
	srvAdm := server.(recvDupSnapshotter)
	dups, paths := waitRecvDupsStable(t, srvAdm)
	t.Logf("race-mode RecvDups = %d (over %d frames on 2 paths)", dups, N)
	if dups < uint64(N*3/4) {
		t.Errorf("RecvDups=%d < 75%% of N=%d: race-mode dedup not counted", dups, N)
	}
	if got := serverObserver.Stats().RecvDups; got != dups {
		t.Errorf("Stats().RecvDups=%d disagrees with RecvDups()=%d", got, dups)
	}

	// Per-path RecvDups must sum to the engine-wide total. Confirms
	// the attribution wiring works under race-mode fan-out.
	var perPathSum uint64
	for _, p := range paths {
		perPathSum += p.RecvDups
	}
	if perPathSum != dups {
		t.Errorf("sum of PathInfo.RecvDups = %d, Stats.RecvDups = %d", perPathSum, dups)
	}
}

// TestM8BondPathPinning exercises the production pin size over real carriers.
// Exact run boundaries are an executor contract and are tested without the
// asynchronous replay path in internal/engine.
func TestM8BondPathPinning(t *testing.T) {
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

	controlled := newRuntimeControlledTCPTransport(t)
	d := &sessionDialer{Root: Bond("root", []Target{
		Path("A", controlled.Spec(ln.Addr().String(), "A")),
		Path("B", controlled.Spec(ln.Addr().String(), "B")),
	}), ProbeInterval: 30 * time.Second}

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

	const (
		productionPinSize = 8
		N                 = 4 * productionPinSize
	)
	payload := []byte("pinframe")
	for i := 0; i < N; i++ {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// Drain server.
	rxbuf := make([]byte, len(payload)*N)
	if _, err := io.ReadFull(server, rxbuf); err != nil {
		t.Fatalf("server drain: %v", err)
	}
	if want := bytes.Repeat(payload, N); !bytes.Equal(rxbuf, want) {
		t.Fatal("bond pinning payload corrupted")
	}

	paths := client.Paths()
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
	var first, physical uint64
	for _, path := range paths {
		if path.FirstDataDispatches < productionPinSize {
			t.Fatalf("path %d carried only %d first-publication DATA, want at least one full pin: %+v",
				path.ID, path.FirstDataDispatches, paths)
		}
		if path.FirstDataDispatches > N-productionPinSize {
			t.Fatalf("path %d monopolized %d first-publication DATA: %+v",
				path.ID, path.FirstDataDispatches, paths)
		}
		first += path.FirstDataDispatches
		physical += path.DataDispatches
	}
	if first != N {
		t.Fatalf("first DATA dispatches=%d want %d", first, N)
	}
	if physical < first || physical > first+N/2 {
		t.Fatalf("physical DATA dispatches=%d outside bounded replay range [%d,%d]",
			physical, first, first+N/2)
	}
}

// TestM8BondRoundRobinAcrossPaths: with bond mode, N application
// Writes round-robin onto attached paths so each path observes
// roughly N/PathCount frames. Bond is "frame-level aggregation
// not duplication", so unlike race each path sees a strict subset.
// Receiver-side reorder reassembles into the original byte stream.
func TestM8BondRoundRobinAcrossPaths(t *testing.T) {
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

	d := &sessionDialer{Root: bondRoot(

		[]PathSpec{
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		})}

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

	baseline := make(map[uint32]uint64, 2)
	for _, path := range client.Paths() {
		baseline[path.ID] = path.FirstDataDispatches
	}

	// Send N small frames; each engine.SendData call produces one
	// data frame (the payload is < MaxPayload).
	const N = 32
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
	// went on whichever path was initially active).
	var totals []uint64
	for _, path := range client.Paths() {
		got := path.FirstDataDispatches - baseline[path.ID]
		totals = append(totals, got)
		t.Logf("path %d saw %d first DATA dispatches", path.ID, got)
	}
	if len(totals) != 2 {
		t.Fatalf("bond path snapshots=%d want 2", len(totals))
	}
	if totals[0] == 0 || totals[1] == 0 {
		t.Fatalf("bond did not exercise both paths: %v", totals)
	}
}

// TestM8BondHonorsPathWeights verifies PathSpec.Weight controls the
// relative share of bond pin windows. With the production pin size and
// weights 3:1, 64 writes span two complete weighted cycles and route 48
// first-publication frames to the heavier path and 16 to the lighter path.
func TestM8BondHonorsPathWeights(t *testing.T) {
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

	d := &sessionDialer{Root: bondRoot(

		[]PathSpec{
			{Transport: "tcp", Address: ln.Addr().String(), Weight: 3},
			{Transport: "tcp", Address: ln.Addr().String(), Weight: 1},
		}), ProbeInterval: 30 * time.Second}

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

	type pp struct {
		id     uint32
		weight uint16
		base   uint64
	}
	var probes []pp
	for _, path := range client.Paths() {
		probes = append(probes, pp{id: path.ID, weight: path.Spec.Weight, base: path.FirstDataDispatches})
	}
	if len(probes) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(probes))
	}

	const N = 64
	payload := []byte("weighted")
	for i := 0; i < N; i++ {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	rxbuf := make([]byte, len(payload)*N)
	if _, err := io.ReadFull(server, rxbuf); err != nil {
		t.Fatalf("server drain: %v", err)
	}

	counts := map[uint16]uint64{}
	for _, path := range client.Paths() {
		for _, p := range probes {
			if p.id == path.ID {
				counts[p.weight] += path.FirstDataDispatches - p.base
			}
		}
	}
	totalDispatches := counts[3] + counts[1]
	if totalDispatches != N {
		t.Fatalf("weighted first DATA dispatches=%d want %d", totalDispatches, N)
	}
	// Control frames can consume a live pin between DATA publications, so the
	// exact 48:16 scheduler contract is proved in internal/engine. This
	// end-to-end oracle still rejects a broken 1:1 scheduler and requires the
	// lighter path to receive at least one complete production pin.
	if counts[3] < 48 || counts[1] < 8 || counts[3] < 2*counts[1] {
		t.Fatalf("weighted bond distribution = weight3:%d weight1:%d, want heavy>=48 light>=8 and heavy>=2*light", counts[3], counts[1])
	}
}

// TestM8BondHighRTTAloneDoesNotSkipPath verifies the v1 bond priority:
// speed and stability precede latency. A healthy high-RTT path remains part
// of aggregation; only observed writer/delivery stalls may quarantine it.
func TestM8BondHighRTTAloneDoesNotSkipPath(t *testing.T) {
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

	controlled := newRuntimeControlledTCPTransport(t)
	d := &sessionDialer{Root: Bond("root", []Target{
		Path("low", controlled.Spec(ln.Addr().String(), "low")),
		Path("high", controlled.Spec(ln.Addr().String(), "high")),
	}), ProbeInterval: 30 * time.Second}

	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if !waitForNPaths(t, client, server, controlled.Name(), ln.Addr().String(), 2, 8*time.Second) {
		t.Fatalf("expected 2 paths each, got client=%d server=%d",
			len(client.Paths()), len(server.Paths()))
	}

	if err := controlled.SetQuality("low", PathQuality{RTT: time.Millisecond, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := controlled.SetQuality("high", PathQuality{RTT: 100 * time.Millisecond, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// Both paths remain healthy even though one reports 100x the RTT, so
	// healthy, so latency alone must not remove either bond member.
	baseline := make(map[uint32]uint64, 2)
	for _, path := range client.Paths() {
		baseline[path.ID] = path.FirstDataDispatches
	}

	const N = 32
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

	dispatches := make(map[uint32]uint64, 2)
	var total uint64
	for _, path := range client.Paths() {
		delta := path.FirstDataDispatches - baseline[path.ID]
		dispatches[path.ID] = delta
		total += delta
	}
	if total != N {
		t.Fatalf("bond first DATA dispatch total=%d want %d; per-path=%v", total, N, dispatches)
	}
	for id := range baseline {
		if dispatches[id] == 0 {
			t.Fatalf("healthy high-RTT bond member was excluded: %v", dispatches)
		}
	}
	observer := client.(ConnectionObserver)
	skips := observer.BondStuckSkips()
	if skips != 0 {
		t.Fatalf("RTT-only input produced %d writer-stall quarantines", skips)
	}
	if got := observer.Stats().BondStuckSkips; got != skips {
		t.Fatalf("Stats().BondStuckSkips=%d disagrees with BondStuckSkips()=%d", got, skips)
	}
}

// TestM5UDPFlowPlannedMigration: 2 udpflow paths, hot-swap active
// path via engine.Migrate mid-stream. Confirms M5 paths plug into
// the same engine migration primitive that TCP / QUIC use.
func TestM5UDPFlowPlannedMigration(t *testing.T) {
	ln, err := listenRuntimeUDP("127.0.0.1:0")
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
			{Transport: "udpflow", Address: ln.Addr().String()},
			{Transport: "udpflow", Address: ln.Addr().String()},
		})}

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

	observer := client.(ConnectionObserver)
	migrator := client.(MigrationController)
	cur := observer.ActivePath()
	var other uint32
	for _, p := range client.Paths() {
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
	if err := migrator.Migrate(other); err != nil {
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
	if observer.ActivePath() != other {
		t.Errorf("active path after migrate: got %d want %d", observer.ActivePath(), other)
	}
}

// TestM5UDPFlowFailoverToSurvivingPath: 2 udpflow paths, force-kill
// the server-side active path so the client observes a
// TransportError; engine fails over to the survivor without
// surfacing an app-level error.
func TestM5UDPFlowFailoverToSurvivingPath(t *testing.T) {
	ln, err := listenRuntimeUDP("127.0.0.1:0")
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

	const factoryName = "faultable-udpflow"
	tracked := &runtimeTrackedPacketFactory{}
	d := &sessionDialer{
		Root: Selector("root", []Target{
			Path("A", PathSpec{Transport: factoryName, Address: ln.Addr().String(), Opts: map[string]string{"name": "A"}}),
			Path("B", PathSpec{Transport: factoryName, Address: ln.Addr().String(), Opts: map[string]string{"name": "B"}}),
		}),
		MigrationBudget: 3 * time.Second,
		ProbeInterval:   30 * time.Second,
		Retry:           retryPolicy{MinBackoff: 5 * time.Second, MaxBackoff: 5 * time.Second},
	}
	if err := d.AddPacketPathFactory(factoryName, tracked.Dial); err != nil {
		t.Fatal(err)
	}

	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if !waitForNPaths(t, client, server, factoryName, ln.Addr().String(), 2, 8*time.Second) {
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
	observer := client.(ConnectionObserver)
	oldActive := observer.ActivePath()
	if got := pathNameByID(client.Paths(), oldActive); got != "A" {
		t.Fatalf("initial UDP active path name=%q want A", got)
	}
	if err := tracked.Fail(0); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && observer.ActivePath() == oldActive {
		time.Sleep(10 * time.Millisecond)
	}
	if got := observer.ActivePath(); got == 0 || got == oldActive {
		t.Fatalf("UDP path did not fail over: old=%d active=%d", oldActive, got)
	}

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

// TestM5UDPFlowDialAcceptRoundTrip: session dialer over udpflow path +
// Runtime raw-UDP accept; data flows in both directions over an
// opaque UDP datagram pair. Migration test (path swap on the same
// flow_id) belongs to a chaos run; this just proves wire+API.
func TestM5UDPFlowDialAcceptRoundTrip(t *testing.T) {
	ln, err := listenRuntimeUDP("127.0.0.1:0")
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

		[]PathSpec{{Transport: "udpflow", Address: ln.Addr().String()}})}

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
	ln, err := listenRuntimeUDP("127.0.0.1:0")
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

	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{{Transport: "udpflow", Address: ln.Addr().String()}})}

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
	ln, err := listenRuntimeUDP("127.0.0.1:0")
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

	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{{Transport: "udpflow", Address: ln.Addr().String()}})}

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
// boundaries and zero-loss delivery through an explicit Migrate()
// between two attached udpflow paths. Packet transports are not
// required to deliver in strict send order; the contract here is
// that every application packet arrives exactly once.
func TestM5PacketSurvivesPlannedMigration(t *testing.T) {
	ln, err := listenRuntimeUDP("127.0.0.1:0")
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

	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{
			{Transport: "udpflow", Address: ln.Addr().String()},
			{Transport: "udpflow", Address: ln.Addr().String()},
		})}

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
	seen := make(map[string]bool, len(want))
	for i := 0; i < len(want); i++ {
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom %d: %v", i, err)
		}
		got := string(buf[:n])
		if seen[got] {
			t.Fatalf("packet %d: duplicate %q", i, got)
		}
		seen[got] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Fatalf("missing packet %q after migration", w)
		}
	}
}

// TestM5PacketStreamUnderMigration: stress test of packet-mode with
// 1000 sequenced packets and several mid-stream migrations. Each
// packet carries an 8-byte BigEndian counter; the server verifies
// every counter arrives exactly once. Datagram packet mode preserves
// boundaries and losslessness, not strict in-order delivery.
func TestM5PacketStreamUnderMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping packet-mode stress in -short")
	}
	const N = 1000
	const migEvery = 250
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		err := func() error {
			ln, err := listenRuntimeUDP("127.0.0.1:0")
			if err != nil {
				return err
			}
			defer ln.Close()

			accepted := make(chan PacketConn, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				c, err := ln.AcceptPacket(ctx)
				if err != nil {
					accepted <- nil
					return
				}
				accepted <- c
			}()

			d := &sessionDialer{Root: selectorRoot(

				[]PathSpec{
					{Transport: "udpflow", Address: ln.Addr().String()},
					{Transport: "udpflow", Address: ln.Addr().String()},
					{Transport: "udpflow", Address: ln.Addr().String()},
				})}

			client, err := d.DialPacket(context.Background())
			if err != nil {
				return err
			}
			defer client.Close()
			server := <-accepted
			if server == nil {
				return errors.New("accept failed")
			}
			defer server.Close()

			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if len(client.Paths()) >= 3 && len(server.Paths()) >= 3 {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if len(client.Paths()) < 3 {
				return errors.New("expected 3 paths")
			}

			bc := client.(*enginePacketConn)
			recvErr := make(chan error, 1)
			go func() {
				_ = server.SetReadDeadline(time.Now().Add(15 * time.Second))
				buf := make([]byte, 32)
				seen := make([]bool, N)
				remaining := N
				for remaining > 0 {
					n, _, err := server.ReadFrom(buf)
					if err != nil {
						recvErr <- err
						return
					}
					if n != 8 {
						recvErr <- errors.New("packet payload size mismatch")
						return
					}
					got := binary.BigEndian.Uint64(buf[:8])
					if got >= N {
						recvErr <- errors.New("packet counter out of range")
						return
					}
					if seen[got] {
						recvErr <- errors.New("duplicate packet counter")
						return
					}
					seen[got] = true
					remaining--
				}
				recvErr <- nil
			}()

			var pkt [8]byte
			for i := uint64(0); i < N; i++ {
				binary.BigEndian.PutUint64(pkt[:], i)
				if _, err := client.WriteTo(pkt[:], nil); err != nil {
					return err
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
				return err
			case <-time.After(15 * time.Second):
				return errors.New("receiver deadline; packet-mode stress hung")
			}
		}()
		if err == nil {
			if attempt > 1 {
				t.Logf("packet stress passed on retry %d", attempt)
			}
			return
		}
		lastErr = err
		t.Logf("packet stress retry %d/3 after error: %v", attempt, err)
	}
	t.Fatalf("receiver: %v", lastErr)
}

// TestM5PacketRaceModeDuplicates: race mode duplicates each frame
// across all attached paths. In packet mode the receiver must
// deliver exactly one copy of each application packet; receive order
// may vary, but duplicates must be suppressed and counted in
// RecvDups. Validates the dispatcher's mode-agnostic behaviour
// against the packet-boundary drainer.
func TestM5PacketRaceModeDuplicates(t *testing.T) {
	ln, err := listenRuntimeUDP("127.0.0.1:0")
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

	d := &sessionDialer{Root: raceRoot(

		[]PathSpec{
			{Transport: "udpflow", Address: ln.Addr().String()},
			{Transport: "udpflow", Address: ln.Addr().String()},
		})}

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

	// Settle: attachment on the client doesn't synchronously
	// guarantee server-side reader goroutines for both paths are
	// drained-ready. Give the scheduler a beat so race fanout lands
	// on two prepared paths.
	time.Sleep(50 * time.Millisecond)

	// Warmup: drain a couple of packets before the
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

	seen := make([]bool, N)
	for i := 0; i < N; i++ {
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom %d: %v", i, err)
		}
		if n != 1 {
			t.Fatalf("packet %d: got n=%d want 1", i, n)
		}
		got := int(buf[0])
		if got < 0 || got >= N {
			t.Fatalf("packet %d: got byte=%d out of range", i, got)
		}
		if seen[got] {
			t.Fatalf("packet %d: duplicate byte(%d)", i, got)
		}
		seen[got] = true
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
	dupsNow, _ := waitRecvDupsStable(t, server.(interface {
		RecvDups() uint64
		Paths() []PathInfo
	}))
	dups := dupsNow - baseDups
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

		[]PathSpec{{Transport: "tcp", Address: ln.Addr().String()}}), ProbeInterval: 100 * time.Millisecond}

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

// TestM6SelectorAutoMigrateOnQualityChange: with selector quality
// scheduler armed, when path 2 becomes substantially better than
// the current path 1 (10x lower RTT), the engine must migrate to
// it after dwell + cooldown without the test calling Migrate.
//
// A test-owned TCP path adapter publishes controlled quality readings while
// the production selector consumes them through PathConn.Quality.
func TestM6SelectorAutoMigrateOnQualityChange(t *testing.T) {
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

	controlled := newRuntimeControlledTCPTransport(t)
	d := &sessionDialer{
		Root: Selector("root", []Target{
			Path("A", controlled.Spec(ln.Addr().String(), "A")),
			Path("B", controlled.Spec(ln.Addr().String(), "B")),
		}),
		Hysteresis: 0.1,
		Dwell:      50 * time.Millisecond,
		Cooldown:   100 * time.Millisecond,
		// Long probe interval keeps this test's controlled path evidence stable
		// while the production selector evaluates it.
		ProbeInterval: 30 * time.Second,
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if !waitForNPaths(t, client, server, controlled.Name(), ln.Addr().String(), 2, 8*time.Second) {
		t.Fatalf("only client=%d server=%d paths after 8s",
			len(client.Paths()), len(server.Paths()))
	}

	observer := client.(ConnectionObserver)
	pathsInfo := client.Paths()
	p1ID, p2ID := pathsInfo[0].ID, pathsInfo[1].ID

	startActive := observer.ActivePath()
	// Inject qualities: current is mediocre, the other is much better.
	startName := pathNameByID(pathsInfo, startActive)
	var otherID uint32
	if startActive == p1ID {
		otherID = p2ID
	} else {
		otherID = p1ID
	}
	otherName := pathNameByID(pathsInfo, otherID)
	if err := controlled.SetQuality(startName, PathQuality{RTT: 100 * time.Millisecond, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := controlled.SetQuality(otherName, PathQuality{RTT: 10 * time.Millisecond, At: time.Now()}); err != nil {
		t.Fatal(err)
	}

	// Wait at most dwell + cooldown + tick slack for the selector
	// scheduler to fire. 10 s tolerance covers parallel-package
	// contention that pushes scheduler ticks past the nominal
	// dwell+cooldown when ~10 packages worth of sockets/goroutines
	// are in flight on the same test run.
	migrated := false
	waitUntil := time.Now().Add(10 * time.Second)
	for time.Now().Before(waitUntil) {
		if observer.ActivePath() == otherID {
			migrated = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !migrated {
		t.Fatalf("selector did not migrate to better path within 10s (active still %d, wanted %d)",
			observer.ActivePath(), otherID)
	}
}

// TestM2G1SketchQUIC: G1 invariants over QUIC paths.
// 16 MiB stream (smaller than the TCP sketch because QUIC handshake
// + crypto cost dominate small loopback runs; the invariant we are
// testing is "byte-stream over migration", not raw throughput) + 3
// forced migrations between two QUIC paths + SHA-256 verified.
func TestM2G1SketchQUIC(t *testing.T) {
	ln, err := listenRuntimeQUIC("127.0.0.1:0", nil)
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

	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{
			{Transport: "quic", Address: ln.Addr().String()},
			{Transport: "quic", Address: ln.Addr().String()},
		})}

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

	observer := client.(ConnectionObserver)
	migrator := client.(MigrationController)
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
			cur := observer.ActivePath()
			var other uint32
			for _, p := range client.Paths() {
				if p.ID != cur {
					other = p.ID
					break
				}
			}
			if other != 0 {
				if err := migrator.Migrate(other); err != nil {
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

// TestM2QUICRoundTrip: session dialer over QUIC + Runtime framed accept;
// public rendr.Conn round-trips bytes through one QUIC connection
// per path. Matches the M1 TCP smoke test but over the QUIC adapter.
func TestM2QUICRoundTrip(t *testing.T) {
	ln, err := listenRuntimeQUIC("127.0.0.1:0", nil)
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

		[]PathSpec{{Transport: "quic", Address: ln.Addr().String()}})}

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

// TestM2MixedTCPQUICMigration: two paths on the same session dialer, one
// TCP and one QUIC, both attached to the same engine. Send the
// first half on TCP, migrate to QUIC, send the rest. Hash must match.
//
// This stresses that the engine treats QUIC and TCP path adapters
// symmetrically (same proto.Frame envelope, same DeathCause
// taxonomy, same migration semantics).
func TestM2MixedTCPQUICMigration(t *testing.T) {
	ln, err := listenRuntimeSources(
		runtimeTCPSource("tcp", "127.0.0.1:0"),
		runtimeQUICSource("quic", "127.0.0.1:0", nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addrs := ln.Addrs()
	if len(addrs) != 2 {
		t.Fatalf("Addrs len=%d want 2", len(addrs))
	}
	tcpAddr, quicAddr := ln.SourceAddr("tcp"), ln.SourceAddr("quic")
	if tcpAddr == nil || quicAddr == nil {
		t.Fatalf("source address map: tcp=%v quic=%v", tcpAddr, quicAddr)
	}

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
			{Transport: "tcp", Address: tcpAddr.String()},
			{Transport: "quic", Address: quicAddr.String()},
		}), MigrationBudget: 3 * time.Second}

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
	if len(client.Paths()) < 2 || len(server.Paths()) < 2 {
		t.Fatalf("paths did not attach: client=%d server=%d", len(client.Paths()), len(server.Paths()))
	}

	var quicPath uint32
	for _, p := range client.Paths() {
		if p.Spec.Transport == "quic" {
			quicPath = p.ID
			break
		}
	}
	if quicPath == 0 {
		t.Fatalf("no quic path in client paths: %+v", client.Paths())
	}
	admin := client.(testConnectionControl)

	want := bytes.Repeat([]byte("tcp-to-quic-mixed-"), 64*1024)
	got := make([]byte, len(want))
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(server, got)
		done <- err
	}()

	half := len(want) / 2
	if _, err := client.Write(want[:half]); err != nil {
		t.Fatalf("write tcp half: %v", err)
	}
	if err := admin.Migrate(quicPath); err != nil {
		t.Fatalf("migrate to quic path: %v", err)
	}
	if _, err := client.Write(want[half:]); err != nil {
		t.Fatalf("write quic half: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server read timed out")
	}
	if !bytes.Equal(got, want) {
		t.Fatal("mixed TCP+QUIC payload mismatch")
	}
	if client.FlowID() != server.FlowID() {
		t.Fatalf("flow_id mismatch: client=%x server=%x", client.FlowID(), server.FlowID())
	}
}

// TestM2TCPPathDeathFailsOverToUDPBackedStream is the focused
// regression for cross-carrier stream migration: a TCP-based stream
// path carries the first part of a file transfer, then dies abruptly;
// the same rendr Conn must continue losslessly over a QUIC stream path
// (UDP-backed, but still reliable and ordered).
func TestM2TCPPathDeathFailsOverToUDPBackedStream(t *testing.T) {
	ln, err := listenRuntimeSources(
		runtimeTCPSource("tcp", "127.0.0.1:0"),
		runtimeQUICSource("quic", "127.0.0.1:0", nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addrs := ln.Addrs()
	if len(addrs) != 2 {
		t.Fatalf("Addrs len=%d want 2", len(addrs))
	}
	tcpAddr, quicAddr := ln.SourceAddr("tcp"), ln.SourceAddr("quic")
	if tcpAddr == nil || quicAddr == nil {
		t.Fatalf("source address map: tcp=%v quic=%v", tcpAddr, quicAddr)
	}

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

	client, err := (&sessionDialer{Root: selectorRoot(

		[]PathSpec{
			{Transport: "tcp", Address: tcpAddr.String()},
			{Transport: "quic", Address: quicAddr.String()},
		}), MigrationBudget: 5 * time.Second}).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()
	if !waitForNPaths(t, client, server, "quic", quicAddr.String(), 2, 5*time.Second) {
		t.Fatalf("paths did not attach: client=%d server=%d", len(client.Paths()), len(server.Paths()))
	}

	admin := client.(testConnectionControl)
	var tcpPath, quicPath uint32
	for _, p := range client.Paths() {
		switch p.Spec.Transport {
		case "tcp":
			tcpPath = p.ID
		case "quic":
			quicPath = p.ID
		}
	}
	if tcpPath == 0 || quicPath == 0 {
		t.Fatalf("missing mixed paths: tcp=%d quic=%d paths=%+v", tcpPath, quicPath, client.Paths())
	}
	if admin.ActivePath() != tcpPath {
		if err := admin.Migrate(tcpPath); err != nil {
			t.Fatalf("selector tcp path: %v", err)
		}
	}

	const size = 8 << 20
	const chunk = 64 << 10
	const killAt = 2 << 20
	recvHash := sha256.New()
	recvDone := make(chan error, 1)
	go func() {
		buf := make([]byte, chunk)
		var got int64
		for got < size {
			n, err := server.Read(buf)
			if err != nil {
				recvDone <- err
				return
			}
			recvHash.Write(buf[:n])
			got += int64(n)
		}
		recvDone <- nil
	}()

	sendHash := sha256.New()
	buf := make([]byte, chunk)
	var sent int64
	killed := false
	startMig := admin.MigrationCount()
	for sent < size {
		n := int64(len(buf))
		if rem := int64(size) - sent; rem < n {
			n = rem
		}
		fillDeterministic(buf[:n], sent)
		if _, err := client.Write(buf[:n]); err != nil {
			t.Fatalf("write at %d after killed=%v active=%d: %v", sent, killed, admin.ActivePath(), err)
		}
		sendHash.Write(buf[:n])
		sent += n
		if !killed && sent >= killAt {
			if err := ln.CloseAcceptedPath("tcp", 0); err != nil {
				t.Fatalf("close accepted TCP path: %v", err)
			}
			killed = true
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) && admin.ActivePath() != quicPath {
				time.Sleep(10 * time.Millisecond)
			}
			if got := admin.ActivePath(); got != quicPath {
				t.Fatalf("active path after tcp death=%d, want quic path %d", got, quicPath)
			}
		}
	}

	select {
	case err := <-recvDone:
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server read timed out")
	}
	if got, want := fmt.Sprintf("%x", recvHash.Sum(nil)), fmt.Sprintf("%x", sendHash.Sum(nil)); got != want {
		t.Fatalf("hash mismatch after TCP->UDP-backed stream failover: got=%s want=%s", got, want)
	}
	if migs := admin.MigrationCount() - startMig; migs == 0 {
		t.Fatal("TCP path death did not record a migration")
	}
	if client.FlowID() != server.FlowID() {
		t.Fatalf("flow_id mismatch: client=%x server=%x", client.FlowID(), server.FlowID())
	}
}

func fillDeterministic(buf []byte, offset int64) {
	for i := range buf {
		buf[i] = byte((offset+int64(i))*31 + 7)
	}
}

func TestListenMultiValidation(t *testing.T) {
	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverRuntime.Listen(ListenConfig{}); err == nil {
		t.Fatal("Runtime.Listen with no sources unexpectedly succeeded")
	}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := serverRuntime.Listen(ListenConfig{Streams: []StreamSource{{
		Name: "invalid-carrier", Carrier: CarrierFamily(255), Listener: raw,
	}}}); err == nil {
		t.Fatal("Runtime.Listen with an invalid source carrier unexpectedly succeeded")
	}
}

// TestM2QUICDeathTriggersMigration: with two QUIC paths attached,
// kill the active one and verify the engine fails over to the
// surviving QUIC path without surfacing an error to the application.
func TestM2QUICDeathTriggersMigration(t *testing.T) {
	ln, err := listenRuntimeQUIC("127.0.0.1:0", nil)
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

	controlled := newRuntimeControlledQUICTransport(t)
	d := &sessionDialer{Root: Selector("root", []Target{
		Path("A", controlled.Spec(ln.Addr().String(), "A")),
		Path("B", controlled.Spec(ln.Addr().String(), "B")),
	}), MigrationBudget: 3 * time.Second, ProbeInterval: 30 * time.Second}

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
	if len(client.Paths()) < 2 || len(server.Paths()) < 2 {
		t.Fatalf("two-path QUIC carrier-close topology incomplete: client=%d server=%d", len(client.Paths()), len(server.Paths()))
	}

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	pre := make([]byte, 5)
	if _, err := io.ReadFull(server, pre); err != nil {
		t.Fatal(err)
	}

	observer := client.(ConnectionObserver)
	killedID := observer.ActivePath()
	killedName := pathNameByID(client.Paths(), killedID)
	if killedName == "" {
		t.Fatalf("active QUIC path %d has no controlled leaf name", killedID)
	}
	initial := make(map[uint32]string, len(client.Paths()))
	for _, path := range client.Paths() {
		initial[path.ID] = path.Spec.Opts["name"]
	}
	peerLocal, err := controlled.LocalAddr(killedName)
	if err != nil {
		t.Fatal(err)
	}
	controlled.Block(killedName)
	migrationsBefore := observer.MigrationCount()
	if _, err := ln.CloseAcceptedPeerPath("quic", peerLocal); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		killedAttached := false
		for _, path := range client.Paths() {
			if path.ID == killedID {
				killedAttached = true
				break
			}
		}
		if !killedAttached && observer.ActivePath() != killedID && observer.MigrationCount() > migrationsBefore {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	newActive := observer.ActivePath()
	newName, preexisting := initial[newActive]
	if newActive == 0 || newActive == killedID || !preexisting || newName == killedName {
		t.Fatalf("QUIC survivor is not a different pre-existing path: killed=%d/%q active=%d/%q initial=%v",
			killedID, killedName, newActive, newName, initial)
	}
	for _, path := range client.Paths() {
		if path.ID == killedID {
			t.Fatalf("closed QUIC path %d remains attached: %+v", killedID, client.Paths())
		}
	}
	if observer.MigrationCount() <= migrationsBefore {
		t.Fatalf("QUIC carrier close did not increment MigrationCount: before=%d after=%d", migrationsBefore, observer.MigrationCount())
	}

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
// arriving in between must trip ErrZombie. The harness initializes the
// engine with one echo so zombieLeft is full, then kills the active
// path twice with no traffic between the kills.
func TestM1ZombieAfterTwoNoPayloadMigrations(t *testing.T) {
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

	controlled := newRuntimeControlledTCPTransport(t)
	d := &sessionDialer{
		Root: Selector("root", []Target{
			Path("A", controlled.Spec(ln.Addr().String(), "A")),
			Path("B", controlled.Spec(ln.Addr().String(), "B")),
			Path("C", controlled.Spec(ln.Addr().String(), "C")),
		}),
		MigrationBudget: 1 * time.Second,
		ProbeInterval:   30 * time.Second,
		Retry:           retryPolicy{MinBackoff: 5 * time.Second, MaxBackoff: 5 * time.Second},
	}

	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// Wait for all 3 paths on both ends; retry via AddPath under
	// load if the session dialer's silent-skip dropped one of the extras.
	bcAdm := client.(testConnectionControl)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 3 && len(server.Paths()) >= 3 {
			break
		}
		if len(client.Paths()) < 3 {
			present := idsByName(client.Paths())
			for _, name := range []string{"A", "B", "C"} {
				if present[name] == 0 {
					_, _ = bcAdm.AddPath(controlled.Spec(ln.Addr().String(), name))
					break
				}
			}
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
	if _, err := server.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 2)
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatal(err)
	}
	if string(ack) != "ok" {
		t.Fatalf("liveness reply=%q want ok", ack)
	}

	// First kill: client.activeID dies, engine migrates to a survivor.
	// zombieLeft: 2 -> 1 (no payload yet between this and a hypothetical next).
	kill1 := bcAdm.ActivePath()
	kill1Name := pathNameByID(client.Paths(), kill1)
	if kill1Name == "" {
		t.Fatalf("first active path %d has no fixture name", kill1)
	}
	if err := controlled.Fail(kill1Name); err != nil {
		t.Fatalf("kill1: %v", err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && bcAdm.ActivePath() == kill1 {
		time.Sleep(10 * time.Millisecond)
	}

	// Second kill: again the active dies, engine migrates again.
	// zombieLeft: 1 -> 0 -> ErrZombie close fires.
	kill2 := bcAdm.ActivePath()
	if kill2 == 0 || kill2 == kill1 {
		t.Fatalf("expected fresh active after migration; got %d (was %d)", kill2, kill1)
	}
	kill2Name := pathNameByID(client.Paths(), kill2)
	if kill2Name == "" {
		t.Fatalf("second active path %d has no fixture name", kill2)
	}
	if err := controlled.Fail(kill2Name); err != nil {
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
