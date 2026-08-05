package gvisor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
	basetcp "github.com/FrankoonG/rendr/transport/tcp"
)

const testTimeout = 5 * time.Second

func TestGVisorTransportRoundTrip(t *testing.T) {
	ln, err := NewDomain().Listen("")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pc, err := ln.AcceptPath(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- pc
	}()

	client, err := ln.Factory().DialPath(context.Background(), transport.PathSpec{
		Transport: "gvisor",
		Address:   ln.Addr().String(),
	})
	if err != nil {
		t.Fatalf("DialPath: %v", err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	want := []byte("hello over gvisor tcp")
	if _, err := client.Write(want); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGVisorDomainsIsolateSameAddress(t *testing.T) {
	firstDomain := NewDomain()
	secondDomain := NewDomain()
	first, err := firstDomain.Listen("shared-name")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := secondDomain.Listen("shared-name")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	firstClient, firstServer := dialAndAccept(t, first)
	defer firstClient.Close()
	defer firstServer.Close()
	secondClient, secondServer := dialAndAccept(t, second)
	defer secondClient.Close()
	defer secondServer.Close()

	assertRoundTrip(t, firstClient, firstServer, []byte("first domain"))
	assertRoundTrip(t, secondClient, secondServer, []byte("second domain"))
}

func TestGVisorAdapterPublishesScopedOwnershipClaims(t *testing.T) {
	tests := []struct {
		name        string
		listen      func() (*Listener, error)
		clientScope leafmobility.Scope
		serverScope leafmobility.Scope
	}{
		{
			name:        "process-local",
			listen:      func() (*Listener, error) { return NewDomain().Listen("") },
			clientScope: leafmobility.ScopeProcessLocal,
			serverScope: leafmobility.ScopeProcessLocal,
		},
		{
			name:        "packet-carried",
			listen:      func() (*Listener, error) { return ListenPacket("127.0.0.1:0") },
			clientScope: leafmobility.ScopeEndpoint,
			serverScope: leafmobility.ScopeSharedLink,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener, err := test.listen()
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, server := dialAndAccept(t, listener)
			defer client.Close()
			defer server.Close()
			assertGVisorClaim(t, client, leafmobility.RoleDialer, test.clientScope)
			assertGVisorClaim(t, server, leafmobility.RoleAcceptor, test.serverScope)
			clientClaim := client.(leafmobility.Provider).LeafMobilityClaim()
			serverClaim := server.(leafmobility.Provider).LeafMobilityClaim()
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			if !clientClaim.Retired() || !serverClaim.Retired() {
				t.Fatalf("direct close retirement client/server=%t/%t", clientClaim.Retired(), serverClaim.Retired())
			}
		})
	}
}

func assertGVisorClaim(t *testing.T, path transport.PathConn, role leafmobility.Role, scope leafmobility.Scope) {
	t.Helper()
	provider, ok := path.(leafmobility.Provider)
	if !ok || provider.LeafMobilityClaim() == nil {
		t.Fatal("gVisor adapter path has no sealed ownership claim")
	}
	facts := provider.LeafMobilityClaim().Snapshot()
	if facts.Kind != leafmobility.KindGVisor || facts.Role != role || facts.Scope != scope ||
		facts.Session != leafmobility.SessionAny || facts.Operations != 0 || facts.Generation == 0 {
		t.Fatalf("gVisor ownership facts=%+v", facts)
	}
}

func TestGVisorDomainConcurrentDuplicateListen(t *testing.T) {
	domain := NewDomain()
	start := make(chan struct{})
	type result struct {
		listener *Listener
		err      error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			listener, err := domain.Listen("duplicate")
			results <- result{listener: listener, err: err}
		}()
	}
	close(start)

	var successes, failures int
	for range 2 {
		result := <-results
		if result.err != nil {
			failures++
			continue
		}
		successes++
		defer result.listener.Close()
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("concurrent duplicate Listen successes=%d failures=%d, want 1/1", successes, failures)
	}
}

func TestGVisorNilDomainFactoryFailsClosed(t *testing.T) {
	var domain *Domain
	_, err := domain.Factory().DialPath(context.Background(), transport.PathSpec{Address: "127.0.0.1:1"})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("nil Domain")) {
		t.Fatalf("nil Domain DialPath error=%v, want explicit nil Domain failure", err)
	}
	var factory *Transport
	if _, err := factory.DialPath(context.Background(), transport.PathSpec{Address: "127.0.0.1:1"}); err == nil || !bytes.Contains([]byte(err.Error()), []byte("nil Transport")) {
		t.Fatalf("nil Transport DialPath error=%v, want explicit nil Transport failure", err)
	}
}

func TestGVisorListenerCloseUnblocksAcceptPath(t *testing.T) {
	tests := map[string]func() (*Listener, error){
		"process-local":  func() (*Listener, error) { return NewDomain().Listen("") },
		"packet-carried": func() (*Listener, error) { return ListenPacket("127.0.0.1:0") },
	}
	for name, listen := range tests {
		t.Run(name, func(t *testing.T) {
			ln, err := listen()
			if err != nil {
				t.Fatal(err)
			}

			accepted := make(chan error, 1)
			go func() {
				pc, err := ln.AcceptPath(context.Background())
				if pc != nil {
					_ = pc.Close()
				}
				accepted <- err
			}()
			if err := ln.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			select {
			case err := <-accepted:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("AcceptPath error = %v, want net.ErrClosed", err)
				}
			case <-time.After(testTimeout):
				t.Fatal("Close did not unblock AcceptPath")
			}
			waitForCleanup(t, ln)
		})
	}
}

func TestGVisorProcessLocalAcceptedPathsSurviveListenerClose(t *testing.T) {
	domain := NewDomain()
	ln, err := domain.Listen("")
	if err != nil {
		t.Fatal(err)
	}
	client1, server1 := dialAndAccept(t, ln)
	defer client1.Close()
	defer server1.Close()
	client2, server2 := dialAndAccept(t, ln)
	defer client2.Close()
	defer server2.Close()

	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if path, err := ln.Factory().DialPath(context.Background(), transport.PathSpec{
		Transport: "gvisor",
		Address:   ln.Addr().String(),
	}); err == nil {
		_ = path.Close()
		t.Fatal("DialPath succeeded through a closed process-local Domain entry")
	}
	if replacement, err := domain.Listen(ln.Addr().String()); err == nil {
		_ = replacement.Close()
		t.Fatal("Domain key was reused while accepted paths still retained the old listener")
	}
	assertNotCleaned(t, ln)
	assertRoundTrip(t, client1, server1, []byte("first path after listener close"))
	assertRoundTrip(t, server2, client2, []byte("second path reverse direction"))

	if err := server1.Close(); err != nil {
		t.Fatalf("close first accepted path: %v", err)
	}
	assertNotCleaned(t, ln)
	assertRoundTrip(t, client2, server2, []byte("last accepted path remains live"))

	if err := server2.Close(); err != nil {
		t.Fatalf("close last accepted path: %v", err)
	}
	waitForCleanup(t, ln)
	replacement, err := domain.Listen(ln.Addr().String())
	if err != nil {
		t.Fatalf("Domain key was not released after final cleanup: %v", err)
	}
	_ = replacement.Close()
}

func TestGVisorAcceptCloseRaceCleansUp(t *testing.T) {
	ln, err := NewDomain().Listen("")
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		path transport.PathConn
		err  error
	}
	accepted := make(chan result, 1)
	dialed := make(chan result, 1)
	start := make(chan struct{})
	go func() {
		<-start
		path, err := ln.AcceptPath(context.Background())
		accepted <- result{path: path, err: err}
	}()
	go func() {
		<-start
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		path, err := ln.Factory().DialPath(ctx, transport.PathSpec{
			Transport: "gvisor",
			Address:   ln.Addr().String(),
		})
		dialed <- result{path: path, err: err}
	}()
	close(start)
	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for name, results := range map[string]<-chan result{
		"AcceptPath": accepted,
		"DialPath":   dialed,
	} {
		select {
		case result := <-results:
			if result.path != nil {
				_ = result.path.Close()
			}
		case <-time.After(testTimeout):
			t.Fatalf("%s did not finish after listener close", name)
		}
	}
	waitForCleanup(t, ln)
}

func TestGVisorPacketAcceptedPathSurvivesListenerClose(t *testing.T) {
	ln, err := ListenPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	client, server := dialAndAccept(t, ln)
	defer client.Close()
	defer server.Close()

	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertNotCleaned(t, ln)
	assertRoundTrip(t, client, server, []byte("packet carrier after listener close"))
	assertRoundTrip(t, server, client, []byte("packet carrier reverse direction"))

	if probe, err := net.ListenPacket("udp", addr); err == nil {
		_ = probe.Close()
		t.Fatal("listener UDP address was released while an accepted path was active")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("close accepted path: %v", err)
	}
	waitForCleanup(t, ln)

	probe, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("listener UDP address not released after cleanup: %v", err)
	}
	_ = probe.Close()
}

func TestGVisorAcceptedPathDeathReleasesListener(t *testing.T) {
	ln, err := NewDomain().Listen("")
	if err != nil {
		t.Fatal(err)
	}
	client, server := dialAndAccept(t, ln)
	defer client.Close()
	defer server.Close()
	death := make(chan struct{}, 1)
	server.OnDeath(func(transport.DeathCause, error) { death <- struct{}{} })

	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertNotCleaned(t, ln)
	if err := client.Close(); err != nil {
		t.Fatalf("close peer path: %v", err)
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = server.Read(make([]byte, basetcp.MaxFrameSize))
	}()

	select {
	case <-death:
	case <-time.After(testTimeout):
		t.Fatal("accepted path did not report terminal death")
	}
	waitForCleanup(t, ln)
	select {
	case <-readDone:
	case <-time.After(testTimeout):
		t.Fatal("terminal read did not return")
	}
}

func TestRetainedPathConnReleasesOnceAndPreservesOptionalMethods(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	var releases atomic.Int32
	path := newRetainedPathConn(basetcp.Wrap(left), func() { releases.Add(1) })

	type engineOptionalMethods interface {
		Reads() uint64
		Writes() uint64
		SetQuality(transport.PathQuality)
		MarkByeSeen()
		MarkQuiesced()
		CloseWrite() error
	}
	if _, ok := any(path).(engineOptionalMethods); !ok {
		t.Fatal("retained path lost basetcp optional methods")
	}
	quality := transport.PathQuality{RTT: time.Millisecond, At: time.Now()}
	path.SetQuality(quality)
	if got := path.Quality(); got != quality {
		t.Fatalf("Quality = %+v, want %+v", got, quality)
	}

	death := make(chan struct{}, 1)
	path.OnDeath(func(transport.DeathCause, error) { death <- struct{}{} })
	if err := right.Close(); err != nil {
		t.Fatal(err)
	}
	_, _ = path.Read(make([]byte, basetcp.MaxFrameSize))
	select {
	case <-death:
	case <-time.After(testTimeout):
		t.Fatal("retained path did not forward OnDeath")
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = path.Close()
		}()
	}
	wg.Wait()
	if got := releases.Load(); got != 1 {
		t.Fatalf("release count = %d, want 1", got)
	}
}

func TestGVisorListenerSessionKind(t *testing.T) {
	ln, err := NewDomain().Listen("")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if got := ln.SessionKind(); got != transport.PathSessionAny {
		t.Fatalf("SessionKind = %d, want PathSessionAny", got)
	}
}

func dialAndAccept(t *testing.T, ln *Listener) (transport.PathConn, transport.PathConn) {
	t.Helper()
	type result struct {
		path transport.PathConn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		path, err := ln.AcceptPath(context.Background())
		accepted <- result{path: path, err: err}
	}()
	client, err := ln.Factory().DialPath(context.Background(), transport.PathSpec{
		Transport: "gvisor",
		Address:   ln.Addr().String(),
	})
	if err != nil {
		t.Fatalf("DialPath: %v", err)
	}
	select {
	case result := <-accepted:
		if result.err != nil {
			_ = client.Close()
			t.Fatalf("AcceptPath: %v", result.err)
		}
		return client, result.path
	case <-time.After(testTimeout):
		_ = client.Close()
		t.Fatal("AcceptPath timed out")
		return nil, nil
	}
}

func assertRoundTrip(t *testing.T, sender, receiver transport.PathConn, want []byte) {
	t.Helper()
	if _, err := sender.Write(want); err != nil {
		t.Fatalf("write %q: %v", want, err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatalf("read %q: %v", want, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func assertNotCleaned(t *testing.T, ln *Listener) {
	t.Helper()
	select {
	case <-ln.cleanupDone:
		t.Fatal("listener cleaned shared resources while an accepted path was active")
	default:
	}
}

func waitForCleanup(t *testing.T, ln *Listener) {
	t.Helper()
	select {
	case <-ln.cleanupDone:
	case <-time.After(testTimeout):
		t.Fatal("listener shared-resource cleanup timed out")
	}
}

func TestGVisorPacketCarrierRoundTrip(t *testing.T) {
	ln, err := ListenPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pc, err := ln.Accept(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- pc
	}()

	client, err := ln.Factory().DialPath(context.Background(), transport.PathSpec{
		Transport: "gvisor",
		Address:   ln.Addr().String(),
	})
	if err != nil {
		t.Fatalf("DialPath: %v", err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	want := []byte("hello over gvisor udp packet carrier")
	if _, err := client.Write(want); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGVisorAcceptTimeoutDoesNotPoisonListener(t *testing.T) {
	ln, err := NewDomain().Listen("")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := ln.Accept(ctx); err == nil {
		t.Fatal("Accept unexpectedly succeeded without a dial")
	}

	client, err := ln.Factory().DialPath(context.Background(), transport.PathSpec{
		Transport: "gvisor",
		Address:   ln.Addr().String(),
	})
	if err != nil {
		t.Fatalf("DialPath after timed-out Accept: %v", err)
	}
	defer client.Close()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	server, err := ln.Accept(ctx2)
	if err != nil {
		t.Fatalf("Accept after timeout: %v", err)
	}
	defer server.Close()

	want := []byte("still accepts")
	if _, err := client.Write(want); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
