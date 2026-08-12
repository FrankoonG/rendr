package quic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	qg "github.com/FrankoonG/quic-go"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type fakeCIDConnection struct {
	ctx       context.Context
	cancel    context.CancelCauseFunc
	local     net.Addr
	remote    net.Addr
	addCalls  atomic.Int64
	closeCall atomic.Int64

	mu    sync.Mutex
	paths []*fakeCIDPath
}

func newFakeCIDConnection() *fakeCIDConnection {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &fakeCIDConnection{
		ctx: ctx, cancel: cancel,
		local:  &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000},
		remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
	}
}

func (c *fakeCIDConnection) AddPath(transport *qg.Transport) (cidPath, error) {
	if transport == nil {
		return nil, errors.New("nil transport")
	}
	path := &fakeCIDPath{id: c.addCalls.Add(1)}
	c.mu.Lock()
	c.paths = append(c.paths, path)
	c.mu.Unlock()
	return path, nil
}

func (c *fakeCIDConnection) Context() context.Context { return c.ctx }
func (c *fakeCIDConnection) LocalAddr() net.Addr      { return c.local }
func (c *fakeCIDConnection) RemoteAddr() net.Addr     { return c.remote }
func (c *fakeCIDConnection) CloseWithError(qg.ApplicationErrorCode, string) error {
	c.closeCall.Add(1)
	c.cancel(net.ErrClosed)
	return nil
}

type fakeCIDPath struct {
	id       int64
	probed   atomic.Bool
	switched atomic.Bool
	closed   atomic.Bool
}

type fakeRouteChangeWatcher struct {
	events    chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeRouteChangeWatcher() *fakeRouteChangeWatcher {
	return &fakeRouteChangeWatcher{events: make(chan struct{}, 1), closed: make(chan struct{})}
}

func (w *fakeRouteChangeWatcher) Events() <-chan struct{} { return w.events }

func (w *fakeRouteChangeWatcher) Close() {
	w.closeOnce.Do(func() { close(w.closed) })
}

func (w *fakeRouteChangeWatcher) signal() {
	select {
	case w.events <- struct{}{}:
	default:
	}
}

func (p *fakeCIDPath) Probe(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.closed.Load() {
		return qg.ErrPathClosed
	}
	p.probed.Store(true)
	return nil
}

func (p *fakeCIDPath) Switch() error {
	if p.closed.Load() {
		return qg.ErrPathClosed
	}
	if !p.probed.Load() {
		return qg.ErrPathNotValidated
	}
	p.switched.Store(true)
	return nil
}

func (p *fakeCIDPath) Close() error {
	p.closed.Store(true)
	return nil
}

func TestCIDDriverTransactionalLifecycleAndBoundedStandby(t *testing.T) {
	conn := newFakeCIDConnection()
	firstSource := &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}
	secondSource := &net.UDPAddr{IP: net.ParseIP("192.0.2.11")}
	first := testRouteObservation(firstSource, "first")
	second := testRouteObservation(secondSource, "second")
	var opened, closed atomic.Int64
	active := fakeCIDTransport(firstSource, &closed)
	opened.Store(1)
	owner, err := newCIDOwner(conn, leafmobility.RoleDialer, leafmobility.SessionStream, active, first, nil)
	if err != nil {
		t.Fatal(err)
	}
	owner.transportOpen = func(_ context.Context, source *net.UDPAddr) (*cidTransport, error) {
		opened.Add(1)
		return fakeCIDTransport(source, &closed), nil
	}
	setCIDObservation(owner, second)

	attempt, request := prepareCIDAttempt(t, owner, leafmobility.SessionStream, 1)
	if _, err := attempt.Stage(context.Background(), request); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	path1 := attempt.candidate.(*fakeCIDPath)
	if !path1.probed.Load() || path1.switched.Load() {
		t.Fatalf("staged path state probed=%v switched=%v", path1.probed.Load(), path1.switched.Load())
	}
	if owner.LeafMobilityIncarnation() != 1 {
		t.Fatal("Stage changed the visible endpoint incarnation")
	}
	if err := attempt.Publish(context.Background(), request); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !path1.switched.Load() || owner.LeafMobilityIncarnation() != 2 {
		t.Fatalf("Publish did not switch one path: switched=%v incarnation=%d", path1.switched.Load(), owner.LeafMobilityIncarnation())
	}
	if err := attempt.Activate(context.Background(), request); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if opened.Load() != 2 || closed.Load() != 0 {
		t.Fatalf("first commit transports opened=%d closed=%d, want 2/0", opened.Load(), closed.Load())
	}

	owner.mu.Lock()
	owner.baseline = second
	owner.current = second
	owner.mu.Unlock()
	setCIDObservation(owner, first)
	attempt2, request2 := prepareCIDAttempt(t, owner, leafmobility.SessionStream, 2)
	if _, err := attempt2.Stage(context.Background(), request2); err != nil {
		t.Fatalf("second Stage: %v", err)
	}
	if err := attempt2.Publish(context.Background(), request2); err != nil {
		t.Fatalf("second Publish: %v", err)
	}
	if err := attempt2.Activate(context.Background(), request2); err != nil {
		t.Fatalf("second Activate: %v", err)
	}
	if !path1.closed.Load() {
		t.Fatal("Activate did not retire the old nonactive path")
	}
	if opened.Load() != 2 || conn.addCalls.Load() != 2 {
		t.Fatalf("second commit opened=%d AddPath=%d, want 2/2", opened.Load(), conn.addCalls.Load())
	}

	owner.mu.Lock()
	owner.baseline = first
	owner.current = first
	owner.mu.Unlock()
	setCIDObservation(owner, second)
	for cycle := 0; cycle < 100; cycle++ {
		rollback, rollbackRequest := prepareCIDAttempt(t, owner, leafmobility.SessionStream, uint64(100+cycle))
		if _, err := rollback.Stage(context.Background(), rollbackRequest); err != nil {
			t.Fatalf("rollback cycle %d Stage: %v", cycle, err)
		}
		candidate := rollback.candidate.(*fakeCIDPath)
		if err := rollback.Rollback(context.Background(), rollbackRequest); err != nil {
			t.Fatalf("rollback cycle %d: %v", cycle, err)
		}
		if !candidate.closed.Load() || candidate.switched.Load() {
			t.Fatalf("rollback cycle %d path closed=%v switched=%v", cycle, candidate.closed.Load(), candidate.switched.Load())
		}
	}
	if opened.Load() != 2 {
		t.Fatalf("100 rollbacks opened %d transports, want exactly 2", opened.Load())
	}
	if owner.LeafMobilityIncarnation() != 3 {
		t.Fatalf("rollbacks changed incarnation to %d", owner.LeafMobilityIncarnation())
	}
	if err := owner.releaseResources(); err != nil {
		t.Fatal(err)
	}
	if closed.Load() != 2 {
		t.Fatalf("connection close released %d transports, want 2", closed.Load())
	}
}

func TestCIDDriverEvidenceIsExactAndServerIsPeerOnly(t *testing.T) {
	conn := newFakeCIDConnection()
	source := &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}
	baseline := testRouteObservation(source, "baseline")
	owner, err := newCIDOwner(
		conn, leafmobility.RoleAcceptor, leafmobility.SessionPacket,
		fakeCIDTransport(source, new(atomic.Int64)), baseline, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	preflight := cidPreflightRequest(owner, leafmobility.SessionPacket, 1)
	driver := &cidDriver{owner: owner}
	attempt, result, err := driver.Preflight(context.Background(), preflight)
	if err != nil || !result.Eligible || attempt == nil {
		t.Fatalf("acceptor factual preflight attempt=%T result=%+v err=%v", attempt, result, err)
	}
	changed := preflight
	changed.TransactionID[15]++
	_, changedResult, err := driver.Preflight(context.Background(), changed)
	if err != nil || !changedResult.Eligible {
		t.Fatalf("changed preflight result=%+v err=%v", changedResult, err)
	}
	if changedResult.EvidenceDigest == result.EvidenceDigest {
		t.Fatal("attempt evidence did not bind the exact transaction ID")
	}

	request := cidExecutionRequest(preflight)
	if err := attempt.Prepare(context.Background(), request); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("server cannot initiate")) {
		t.Fatalf("acceptor Prepare error=%v, want unsupported server initiation", err)
	}
	if _, err := owner.subscribeRefresh(context.Background(), func(leafmobility.RefreshEvidence) {}); err == nil {
		t.Fatal("acceptor exposed an automatic migration refresh source")
	}
	if conn.addCalls.Load() != 0 {
		t.Fatalf("acceptor attempted %d AddPath calls", conn.addCalls.Load())
	}
	facts := owner.claim.Snapshot()
	if facts.Operations != leafmobility.OperationQUICCIDRebind || facts.Role != leafmobility.RoleAcceptor {
		t.Fatalf("acceptor facts=%+v", facts)
	}
}

func TestCIDRefreshAutomaticallyPublishesFactualRouteSourceChange(t *testing.T) {
	conn := newFakeCIDConnection()
	source := &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}
	baseline := testRouteObservation(source, "refresh-baseline")
	candidate := testRouteObservation(source, "refresh-candidate")
	owner, err := newCIDOwner(
		conn, leafmobility.RoleDialer, leafmobility.SessionStream,
		fakeCIDTransport(source, new(atomic.Int64)), baseline, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	preflight := cidPreflightRequest(owner, leafmobility.SessionStream, 77)
	issuer := leafmobility.NewAuthorityIssuer()
	if err := issuer.BindClaim(owner.claim, preflight.Binding); err != nil {
		t.Fatal(err)
	}
	var observation atomic.Pointer[routeObservation]
	observation.Store(&baseline)
	owner.mu.Lock()
	owner.observeRoute = func(context.Context, *net.UDPAddr) (routeObservation, error) {
		return *observation.Load(), nil
	}
	owner.mu.Unlock()
	events := make(chan leafmobility.RefreshEvidence, 2)
	cancel, err := owner.subscribeRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
		events <- evidence
	})
	if err != nil {
		t.Fatal(err)
	}
	observation.Store(&candidate)
	var evidence leafmobility.RefreshEvidence
	select {
	case evidence = <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("automatic route/source monitor did not publish a refresh")
	}
	snapshot, err := evidence.ValidateFor(owner.claim, 0)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Reason != leafmobility.RefreshReasonRouteSourceChanged || !snapshot.SourceUsable ||
		snapshot.Incarnation != owner.LeafMobilityIncarnation() {
		t.Fatalf("refresh snapshot=%+v", snapshot)
	}
	if err := owner.commitRefresh(evidence); err != nil {
		t.Fatal(err)
	}
	owner.mu.Lock()
	committed := owner.baseline.digest
	owner.mu.Unlock()
	if committed != candidate.digest {
		t.Fatal("refresh commit did not advance the physical comparison baseline")
	}
	cancel()
	if err := owner.releaseResources(); err != nil {
		t.Fatal(err)
	}
}

func TestCIDRefreshRouteEventWakesBeforePollingFallback(t *testing.T) {
	conn := newFakeCIDConnection()
	source := &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}
	baseline := testRouteObservation(source, "event-baseline")
	candidate := testRouteObservation(source, "event-candidate")
	owner, err := newCIDOwner(
		conn, leafmobility.RoleDialer, leafmobility.SessionPacket,
		fakeCIDTransport(source, new(atomic.Int64)), baseline, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	bindCIDRefreshClaim(t, owner, leafmobility.SessionPacket, 101)
	watcher := newFakeRouteChangeWatcher()
	var observation atomic.Pointer[routeObservation]
	observation.Store(&baseline)
	owner.mu.Lock()
	owner.observeRoute = func(context.Context, *net.UDPAddr) (routeObservation, error) {
		return *observation.Load(), nil
	}
	owner.watchRoute = func(context.Context) (routeChangeWatcher, error) { return watcher, nil }
	owner.refreshPoll = 10 * time.Second
	owner.refreshDelay = 10 * time.Millisecond
	owner.mu.Unlock()

	events := make(chan leafmobility.RefreshEvidence, 1)
	cancel, err := owner.subscribeRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
		events <- evidence
	})
	if err != nil {
		t.Fatal(err)
	}
	observation.Store(&candidate)
	started := time.Now()
	watcher.signal()
	select {
	case evidence := <-events:
		snapshot, validateErr := evidence.ValidateFor(owner.claim, 0)
		if validateErr != nil || snapshot.Reason != leafmobility.RefreshReasonRouteSourceChanged {
			t.Fatalf("event evidence=%+v err=%v", snapshot, validateErr)
		}
		if elapsed := time.Since(started); elapsed >= time.Second {
			t.Fatalf("event-driven refresh took %s and appears to have waited for polling", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("route event did not wake the factual observer")
	}
	cancel()
	if err := owner.releaseResources(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-watcher.closed:
	case <-time.After(time.Second):
		t.Fatal("route watcher was not closed with the owner")
	}
}

func TestCIDRefreshEventBurstDoesNotExtendFirstDebounceDeadline(t *testing.T) {
	conn := newFakeCIDConnection()
	source := &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}
	baseline := testRouteObservation(source, "burst-baseline")
	candidate := testRouteObservation(source, "burst-candidate")
	owner, err := newCIDOwner(
		conn, leafmobility.RoleDialer, leafmobility.SessionPacket,
		fakeCIDTransport(source, new(atomic.Int64)), baseline, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	bindCIDRefreshClaim(t, owner, leafmobility.SessionPacket, 102)
	watcher := newFakeRouteChangeWatcher()
	var observation atomic.Pointer[routeObservation]
	observation.Store(&baseline)
	owner.mu.Lock()
	owner.observeRoute = func(context.Context, *net.UDPAddr) (routeObservation, error) {
		return *observation.Load(), nil
	}
	owner.watchRoute = func(context.Context) (routeChangeWatcher, error) { return watcher, nil }
	owner.refreshPoll = 10 * time.Second
	owner.refreshDelay = 60 * time.Millisecond
	owner.mu.Unlock()

	events := make(chan leafmobility.RefreshEvidence, 1)
	cancel, err := owner.subscribeRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
		events <- evidence
	})
	if err != nil {
		t.Fatal(err)
	}
	observation.Store(&candidate)
	started := time.Now()
	watcher.signal()
	burstDone := make(chan struct{})
	go func() {
		defer close(burstDone)
		deadline := time.Now().Add(250 * time.Millisecond)
		for time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
			watcher.signal()
		}
	}()
	select {
	case <-events:
		if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
			t.Fatalf("event burst extended the first debounce deadline to %s", elapsed)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("event burst kept postponing the factual route observation")
	}
	<-burstDone
	cancel()
	if err := owner.releaseResources(); err != nil {
		t.Fatal(err)
	}
}

func TestCIDRefreshWatcherFailureRetainsPollingFallback(t *testing.T) {
	conn := newFakeCIDConnection()
	source := &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}
	baseline := testRouteObservation(source, "fallback-baseline")
	candidate := testRouteObservation(source, "fallback-candidate")
	owner, err := newCIDOwner(
		conn, leafmobility.RoleDialer, leafmobility.SessionPacket,
		fakeCIDTransport(source, new(atomic.Int64)), baseline, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	bindCIDRefreshClaim(t, owner, leafmobility.SessionPacket, 103)
	var observation atomic.Pointer[routeObservation]
	observation.Store(&baseline)
	owner.mu.Lock()
	owner.observeRoute = func(context.Context, *net.UDPAddr) (routeObservation, error) {
		return *observation.Load(), nil
	}
	owner.watchRoute = func(context.Context) (routeChangeWatcher, error) {
		return nil, errors.New("injected watcher failure")
	}
	owner.refreshPoll = 10 * time.Millisecond
	owner.mu.Unlock()

	events := make(chan leafmobility.RefreshEvidence, 1)
	cancel, err := owner.subscribeRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
		events <- evidence
	})
	if err != nil {
		t.Fatal(err)
	}
	observation.Store(&candidate)
	select {
	case <-events:
	case <-time.After(time.Second):
		t.Fatal("polling fallback did not survive route watcher failure")
	}
	cancel()
	if err := owner.releaseResources(); err != nil {
		t.Fatal(err)
	}
}

func bindCIDRefreshClaim(t *testing.T, owner *cidOwner, session leafmobility.Session, nonce uint64) {
	t.Helper()
	preflight := cidPreflightRequest(owner, session, nonce)
	issuer := leafmobility.NewAuthorityIssuer()
	if err := issuer.BindClaim(owner.claim, preflight.Binding); err != nil {
		t.Fatal(err)
	}
}

func TestObserveRouteSourceLoopbackIsStable(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, err := observeRouteSource(ctx, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	second, err := observeRouteSource(ctx, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if !first.valid() || first.digest != second.digest || !first.source.IP.IsLoopback() {
		t.Fatalf("route observations first=%+v second=%+v", first, second)
	}
}

func TestQUICImplementationEvidenceAndNoPublicMobilitySelector(t *testing.T) {
	for name, provider := range map[string]leafmobility.ImplementationProvider{
		"transport": &Transport{},
		"listener":  &Listener{},
		"datagram":  &DatagramListener{},
	} {
		capabilities, err := leafmobility.CapabilitiesForImplementationProvider(provider)
		if err != nil {
			t.Fatalf("%s evidence: %v", name, err)
		}
		if len(capabilities) != 1 || capabilities[0].Operation() != leafmobility.OperationQUICCIDRebind {
			t.Fatalf("%s capabilities=%v", name, capabilities)
		}
	}

	for _, value := range []any{&Transport{}, &PathConn{}, &Listener{}, &DatagramListener{}} {
		typeOf := reflect.TypeOf(value)
		for _, forbidden := range []string{
			"AddPath", "MigratePathLocalAddr", "SetPreferredPath", "SetMobility", "ForceMobility",
		} {
			if _, ok := typeOf.MethodByName(forbidden); ok {
				t.Fatalf("%s exposes public mobility selector %s", typeOf, forbidden)
			}
		}
	}
}

func TestCIDRebindRealLoopbackStreamContinuity(t *testing.T) {
	pair := newPair(t)
	if _, err := pair.client.Write([]byte("before migration")); err != nil {
		t.Fatal(err)
	}
	server := pair.awaitServer(t)
	assertPathRead(t, server, []byte("before migration"))
	assertPathTransfer(t, server, pair.client, []byte("stream baseline reply"))
	beforeConn := pair.client.conn
	beforeLocal := pair.client.LocalAddr()
	candidate := nextCIDObservation(pair.client.owner, "stream-migration")
	runRealCIDCommit(t, pair.client.owner, leafmobility.SessionStream, candidate, 1)
	if pair.client.conn != beforeConn {
		t.Fatal("stream migration replaced the quic-go connection")
	}
	assertPathTransfer(t, pair.client, server, []byte("stream after validated switch"))
	assertPathTransfer(t, server, pair.client, []byte("stream reverse after switch"))
	waitLocalAddrChange(t, pair.client.LocalAddr, beforeLocal)
	if pair.client.owner.probes.Load() != 1 || pair.client.owner.switches.Load() != 1 {
		t.Fatalf("stream migration probes=%d switches=%d", pair.client.owner.probes.Load(), pair.client.owner.switches.Load())
	}
}

func TestCIDRebindRealLoopbackDatagramContinuity(t *testing.T) {
	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := ListenDatagram("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan pathAcceptResult, 1)
	go func() {
		path, acceptErr := listener.AcceptPath(context.Background())
		accepted <- pathAcceptResult{path: path, err: acceptErr}
	}()
	path, err := (&Transport{ClientTLS: clientTLS}).DialPath(context.Background(), transport.PathSpec{
		Address: listener.Addr().String(), Opts: map[string]string{"mode": "datagram"},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := path.(*datagramPathConn)
	t.Cleanup(func() { _ = client.Close() })
	server := awaitPathAccept(t, accepted)
	t.Cleanup(func() { _ = server.path.Close() })
	assertPathTransfer(t, client, server.path, []byte("datagram baseline"))

	beforeConn := client.conn
	beforeLocal := client.LocalAddr()
	candidate := nextCIDObservation(client.owner, "datagram-migration")
	runRealCIDCommit(t, client.owner, leafmobility.SessionPacket, candidate, 2)
	if client.conn != beforeConn {
		t.Fatal("DATAGRAM migration replaced the quic-go connection")
	}
	assertPathTransfer(t, client, server.path, []byte("datagram after validated switch"))
	assertPathTransfer(t, server.path, client, []byte("datagram reverse after switch"))
	waitLocalAddrChange(t, client.LocalAddr, beforeLocal)
	if client.owner.probes.Load() != 1 || client.owner.switches.Load() != 1 {
		t.Fatalf("DATAGRAM migration probes=%d switches=%d", client.owner.probes.Load(), client.owner.switches.Load())
	}
}

func TestCIDRebindRealLoopbackRollbackPreservesActivePath(t *testing.T) {
	pair := newPair(t)
	if _, err := pair.client.Write([]byte("admit rollback path")); err != nil {
		t.Fatal(err)
	}
	server := pair.awaitServer(t)
	assertPathRead(t, server, []byte("admit rollback path"))
	beforeConn := pair.client.conn
	beforeLocal := pair.client.LocalAddr()
	candidate := nextCIDObservation(pair.client.owner, "rollback-candidate")
	setCIDObservation(pair.client.owner, candidate)
	attempt, request := prepareCIDAttempt(t, pair.client.owner, leafmobility.SessionStream, 91)
	stageCtx, cancelStage := context.WithTimeout(context.Background(), 5*time.Second)
	publication, err := attempt.Stage(stageCtx, request)
	cancelStage()
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if publication.Digest == (leafmobility.EvidenceDigest{}) || attempt.candidate == nil {
		t.Fatal("Stage did not validate a private candidate path")
	}
	if err := attempt.Rollback(context.Background(), request); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if pair.client.conn != beforeConn || pair.client.LocalAddr() != beforeLocal ||
		pair.client.owner.LeafMobilityIncarnation() != 1 {
		t.Fatalf("rollback changed connection/local/incarnation: sameConn=%v local=%s incarnation=%d",
			pair.client.conn == beforeConn, pair.client.LocalAddr(), pair.client.owner.LeafMobilityIncarnation())
	}
	assertPathTransfer(t, pair.client, server, []byte("stream after real rollback"))
	assertPathTransfer(t, server, pair.client, []byte("reverse after real rollback"))
	if pair.client.owner.probes.Load() != 1 || pair.client.owner.switches.Load() != 0 {
		t.Fatalf("rollback probes=%d switches=%d", pair.client.owner.probes.Load(), pair.client.owner.switches.Load())
	}
}

func TestCIDRebindRealLoopbackRepeatedCyclesRemainBounded(t *testing.T) {
	baselineGoroutines := runtime.NumGoroutine()
	pair := newPair(t)
	if _, err := pair.client.Write([]byte("admit")); err != nil {
		t.Fatal(err)
	}
	server := pair.awaitServer(t)
	assertPathRead(t, server, []byte("admit"))
	owner := pair.client.owner
	addresses := make(map[string]struct{})
	for cycle := 0; cycle < 10; cycle++ {
		candidate := nextCIDObservation(owner, fmt.Sprintf("commit-%d", cycle))
		runRealCIDCommit(t, owner, leafmobility.SessionStream, candidate, uint64(1000+cycle))
		owner.mu.Lock()
		owner.baseline = candidate
		owner.current = candidate
		addresses[addrString(owner.active.localAddr())] = struct{}{}
		if owner.standby != nil {
			addresses[addrString(owner.standby.localAddr())] = struct{}{}
		}
		owner.mu.Unlock()
		assertPathTransfer(t, pair.client, server, []byte(fmt.Sprintf("commit payload %d", cycle)))
		time.Sleep(100 * time.Millisecond)
	}
	if len(addresses) != 2 {
		t.Fatalf("repeated commits used %d UDP endpoints, want 2: %v", len(addresses), addresses)
	}
	owner.mu.Lock()
	if owner.active == nil || owner.standby == nil {
		owner.mu.Unlock()
		t.Fatal("bounded owner did not retain active and standby transports")
	}
	owner.mu.Unlock()
	if err := pair.client.Close(); err != nil {
		t.Fatal(err)
	}
	for address := range addresses {
		awaitUDPAddressReusable(t, address)
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > baselineGoroutines+20 && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baselineGoroutines+20 {
		t.Fatalf("goroutines after repeated migration=%d baseline=%d", got, baselineGoroutines)
	}
}

func fakeCIDTransport(source *net.UDPAddr, closed *atomic.Int64) *cidTransport {
	local := cloneUDPAddr(source)
	local.Port = 40000 + int(closed.Load())
	return &cidTransport{
		transport: &qg.Transport{}, source: cloneUDPAddr(source), local: local, owned: true,
		closeFn: func() error { closed.Add(1); return nil },
	}
}

func testRouteObservation(source *net.UDPAddr, label string) routeObservation {
	digest := sha256.Sum256([]byte(label))
	return routeObservation{source: cloneUDPAddr(source), digest: digest}
}

func setCIDObservation(owner *cidOwner, observation routeObservation) {
	owner.mu.Lock()
	owner.observeRoute = func(context.Context, *net.UDPAddr) (routeObservation, error) {
		return observation, nil
	}
	owner.current = observation
	owner.mu.Unlock()
}

func nextCIDObservation(owner *cidOwner, label string) routeObservation {
	owner.mu.Lock()
	source := cloneUDPAddr(owner.active.source)
	if owner.standby != nil {
		source = cloneUDPAddr(owner.standby.source)
	}
	if source == nil || source.IP.IsUnspecified() {
		source = addrAsUDP(owner.active.localAddr())
	}
	owner.mu.Unlock()
	if source == nil {
		source = &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}
	}
	source.Port = 0
	return testRouteObservation(source, label)
}

func cidPreflightRequest(owner *cidOwner, session leafmobility.Session, sequence uint64) leafmobility.PreflightRequest {
	var transaction leafmobility.TransactionID
	transaction[0] = byte(sequence>>8) + 1
	transaction[15] = byte(sequence) + 1
	var flow, localTarget, peerTarget [16]byte
	flow[0], localTarget[0], peerTarget[0] = 1, 2, 3
	return leafmobility.PreflightRequest{
		PlanRequest: leafmobility.PlanRequest{
			TransactionID: transaction,
			Binding: leafmobility.Binding{
				FlowID: flow, LocalTargetID: localTarget, PeerTargetID: peerTarget, PathID: 7, Owner: 9,
			},
			Direction: proto.SenderDirectionClientToServer, Session: session,
			Deadline:     time.Now().Add(10 * time.Second),
			LocalSupport: leafmobility.OperationQUICCIDRebind,
			PeerSupport:  leafmobility.OperationQUICCIDRebind,
		},
		Facts: owner.claim.Snapshot(), ContextDigest: leafmobility.ContextDigest{1},
	}
}

func cidExecutionRequest(preflight leafmobility.PreflightRequest) leafmobility.ExecutionRequest {
	return leafmobility.ExecutionRequest{
		Plan: leafmobility.Plan{
			TransactionID: preflight.TransactionID, Binding: preflight.Binding,
			EndpointGeneration: preflight.Facts.Generation,
			Direction:          preflight.Direction, Session: preflight.Session,
			Operation: leafmobility.OperationQUICCIDRebind, Deadline: preflight.Deadline,
		},
		Facts: preflight.Facts,
		Agreement: leafmobility.PeerAgreement{
			ActorEndpointGeneration: preflight.Facts.Generation,
			AgreementDigest:         proto.LeafMobilityAgreementDigest{1},
		},
	}
}

func prepareCIDAttempt(
	t *testing.T,
	owner *cidOwner,
	session leafmobility.Session,
	sequence uint64,
) (*cidAttempt, leafmobility.ExecutionRequest) {
	t.Helper()
	preflight := cidPreflightRequest(owner, session, sequence)
	driver := &cidDriver{owner: owner}
	attemptValue, result, err := driver.Preflight(context.Background(), preflight)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if !result.Eligible || result.EvidenceDigest == (leafmobility.EvidenceDigest{}) {
		t.Fatalf("Preflight result=%+v", result)
	}
	attempt, ok := attemptValue.(*cidAttempt)
	if !ok {
		t.Fatalf("Preflight attempt=%T", attemptValue)
	}
	request := cidExecutionRequest(preflight)
	if err := attempt.Prepare(context.Background(), request); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return attempt, request
}

func runRealCIDCommit(
	t *testing.T,
	owner *cidOwner,
	session leafmobility.Session,
	candidate routeObservation,
	sequence uint64,
) {
	t.Helper()
	setCIDObservation(owner, candidate)
	before := owner.LeafMobilityIncarnation()
	attempt, request := prepareCIDAttempt(t, owner, session, sequence)
	stageCtx, cancelStage := context.WithTimeout(context.Background(), 5*time.Second)
	publication, err := attempt.Stage(stageCtx, request)
	cancelStage()
	if err != nil {
		t.Fatalf("Stage sequence %d: %v", sequence, err)
	}
	if publication.Digest == (leafmobility.EvidenceDigest{}) {
		t.Fatal("Stage returned zero publication evidence")
	}
	if owner.LeafMobilityIncarnation() != before {
		t.Fatal("Stage published the private path")
	}
	if err := attempt.Publish(context.Background(), request); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if owner.LeafMobilityIncarnation() == before {
		t.Fatal("Publish did not change physical incarnation")
	}
	if err := attempt.Activate(context.Background(), request); err != nil {
		t.Fatalf("Activate: %v", err)
	}
}

func waitLocalAddrChange(t *testing.T, address func() string, before string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for address() == before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := address(); got == before {
		t.Fatalf("QUIC path local address remained %s after Switch", got)
	}
}

func awaitUDPAddressReusable(t *testing.T, address string) {
	t.Helper()
	udpAddress, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, listenErr := net.ListenUDP("udp", udpAddress)
		if listenErr == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP address %s was not released: %v", address, listenErr)
		}
		time.Sleep(time.Millisecond)
	}
}
