//go:build linux && amd64

package tcp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/internal/tcpquarantine"
	"github.com/FrankoonG/rendr/internal/tcprepair"
	"github.com/FrankoonG/rendr/proto"
)

type repairDriverTrace struct {
	mu     sync.Mutex
	events []string
}

func (trace *repairDriverTrace) add(event string) {
	trace.mu.Lock()
	trace.events = append(trace.events, event)
	trace.mu.Unlock()
}

func (trace *repairDriverTrace) snapshot() []string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return append([]string(nil), trace.events...)
}

type fakeRepairKernel struct {
	trace *repairDriverTrace

	inspection tcprepair.Inspection
	snapshot   *tcprepair.Snapshot
	source     *fakeRepairSource
	inspectFn  func(*net.TCPConn) (tcprepair.Inspection, error)
	captureFn  func(*net.TCPConn) (repairSource, error)
	restoreFn  func(context.Context, *tcprepair.Snapshot) (*net.TCPConn, error)
	enterFn    func(*net.TCPConn) error
}

type fakeRepairSource struct {
	trace    *repairDriverTrace
	conn     *net.TCPConn
	snapshot *tcprepair.Snapshot
	state    tcprepair.SourceState
	resumeFn func() error
	closeFn  func() error
}

func (source *fakeRepairSource) State() tcprepair.SourceState { return source.state }

func (source *fakeRepairSource) Snapshot() *tcprepair.Snapshot { return source.snapshot }

func (source *fakeRepairSource) Resume() error {
	if source.state == tcprepair.SourceStateNormal {
		return nil
	}
	source.trace.add("resume")
	if source.resumeFn != nil {
		if err := source.resumeFn(); err != nil {
			return err
		}
	}
	source.state = tcprepair.SourceStateNormal
	return nil
}

func (source *fakeRepairSource) Close() error {
	if source.state == tcprepair.SourceStateClosed {
		return nil
	}
	if source.closeFn != nil {
		if err := source.closeFn(); err != nil {
			return err
		}
	}
	if source.conn != nil {
		if err := source.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
	}
	source.state = tcprepair.SourceStateClosed
	return nil
}

type inlineRepairExecutor struct{}

func (inlineRepairExecutor) Do(ctx context.Context, run func(context.Context) error) error {
	return run(ctx)
}

func (inlineRepairExecutor) Close(context.Context) error { return nil }

func newInlineRepairExecutor(
	context.Context,
	*net.TCPConn,
	leafmobility.ContextDigest,
) (repairAttemptExecutor, error) {
	return inlineRepairExecutor{}, nil
}

func (kernel *fakeRepairKernel) Inspect(conn *net.TCPConn) (tcprepair.Inspection, error) {
	kernel.trace.add("inspect")
	if kernel.inspectFn != nil {
		return kernel.inspectFn(conn)
	}
	return kernel.inspection, nil
}

func (kernel *fakeRepairKernel) Capture(conn *net.TCPConn) (repairSource, error) {
	kernel.trace.add("capture")
	if kernel.captureFn != nil {
		return kernel.captureFn(conn)
	}
	if kernel.source == nil {
		kernel.source = &fakeRepairSource{
			trace: kernel.trace, conn: conn, snapshot: kernel.snapshot, state: tcprepair.SourceStateRepair,
		}
	} else if kernel.source.conn == nil {
		kernel.source.conn = conn
	}
	return kernel.source, nil
}

func (kernel *fakeRepairKernel) Restore(
	ctx context.Context,
	snapshot *tcprepair.Snapshot,
) (*net.TCPConn, error) {
	kernel.trace.add("restore")
	if kernel.restoreFn != nil {
		return kernel.restoreFn(ctx, snapshot)
	}
	return nil, errors.New("unexpected fake TCP_REPAIR restore")
}

func (kernel *fakeRepairKernel) Enter(conn *net.TCPConn) error {
	kernel.trace.add("enter")
	if kernel.enterFn != nil {
		return kernel.enterFn(conn)
	}
	return nil
}

type fakeQuarantineManager struct {
	trace       *repairDriverTrace
	preflightFn func(context.Context, tcpquarantine.TransactionID, tcpquarantine.Tuple) error
	installFn   func(context.Context, tcpquarantine.TransactionID, tcpquarantine.Tuple) (quarantineLease, error)
}

func (manager *fakeQuarantineManager) Preflight(
	ctx context.Context,
	transaction tcpquarantine.TransactionID,
	tuple tcpquarantine.Tuple,
) error {
	manager.trace.add("preflight")
	if manager.preflightFn != nil {
		return manager.preflightFn(ctx, transaction, tuple)
	}
	return nil
}

func (manager *fakeQuarantineManager) Install(
	ctx context.Context,
	transaction tcpquarantine.TransactionID,
	tuple tcpquarantine.Tuple,
) (quarantineLease, error) {
	manager.trace.add("install")
	if manager.installFn != nil {
		return manager.installFn(ctx, transaction, tuple)
	}
	return nil, errors.New("unexpected fake quarantine install")
}

type fakeQuarantineLease struct {
	mu        sync.Mutex
	trace     *repairDriverTrace
	releaseFn func(context.Context, int) error
	calls     int
}

func (lease *fakeQuarantineLease) Release(ctx context.Context) error {
	lease.trace.add("release")
	lease.mu.Lock()
	lease.calls++
	call := lease.calls
	lease.mu.Unlock()
	if lease.releaseFn != nil {
		return lease.releaseFn(ctx, call)
	}
	return nil
}

func (lease *fakeQuarantineLease) releaseCalls() int {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return lease.calls
}

type repairDriverFixture struct {
	trace   *repairDriverTrace
	path    *PathConn
	source  *net.TCPConn
	peer    *net.TCPConn
	kernel  *fakeRepairKernel
	manager *fakeQuarantineManager
	lease   *fakeQuarantineLease
	attempt *tcpRepairAttempt
	request leafmobility.ExecutionRequest
}

func newRepairDriverFixture(t *testing.T) *repairDriverFixture {
	t.Helper()
	source, peer := newRepairDriverTCPPair(t)
	path := Wrap(source)
	t.Cleanup(func() { _ = path.Close() })

	trace := &repairDriverTrace{}
	lease := &fakeQuarantineLease{trace: trace}
	manager := &fakeQuarantineManager{trace: trace}
	manager.installFn = func(
		context.Context,
		tcpquarantine.TransactionID,
		tcpquarantine.Tuple,
	) (quarantineLease, error) {
		return lease, nil
	}
	kernel := &fakeRepairKernel{
		trace:      trace,
		inspection: tcprepair.Inspection{},
		snapshot:   &tcprepair.Snapshot{},
	}
	_, ownerGeneration, available := path.endpoint.current()
	if !available {
		t.Fatal("new TCP endpoint is unavailable")
	}

	facts := leafmobility.Facts{
		Kind:       leafmobility.KindRawTCP,
		Role:       leafmobility.RoleDialer,
		Scope:      leafmobility.ScopeEndpoint,
		Session:    leafmobility.SessionStream,
		Operations: leafmobility.OperationTCPRepair,
		Generation: 41,
		ResourceID: leafmobility.ResourceID{0x21},
	}
	binding := leafmobility.Binding{
		FlowID:        [16]byte{0x31},
		LocalTargetID: [16]byte{0x32},
		PeerTargetID:  [16]byte{0x33},
		PathID:        7,
		Owner:         11,
	}
	transaction := leafmobility.TransactionID{0x41}
	preflight := leafmobility.PreflightRequest{
		PlanRequest: leafmobility.PlanRequest{
			TransactionID: transaction,
			Binding:       binding,
			Direction:     proto.SenderDirectionClientToServer,
			Session:       leafmobility.SessionStream,
			Deadline:      time.Now().Add(time.Minute),
		},
		Facts: facts,
	}
	request := leafmobility.ExecutionRequest{
		Plan: leafmobility.Plan{
			TransactionID:      transaction,
			Binding:            binding,
			EndpointGeneration: facts.Generation,
			Direction:          preflight.Direction,
			Session:            preflight.Session,
			Operation:          leafmobility.OperationTCPRepair,
		},
		Facts: facts,
		Agreement: leafmobility.PeerAgreement{
			ActorEndpointGeneration: facts.Generation,
		},
	}
	driver := &tcpRepairDriver{
		endpoint: path.endpoint, kernel: kernel, quarantine: manager, newExecutor: newInlineRepairExecutor,
	}
	attempt := &tcpRepairAttempt{
		driver:          driver,
		preflight:       preflight,
		inspection:      kernel.inspection,
		ownerGeneration: ownerGeneration,
		stage:           repairAttemptPreflight,
	}
	return &repairDriverFixture{
		trace: trace, path: path, source: source, peer: peer,
		kernel: kernel, manager: manager, lease: lease,
		attempt: attempt, request: request,
	}
}

func newRepairDriverTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen TCP pair: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan struct {
		conn *net.TCPConn
		err  error
	}, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		accepted <- struct {
			conn *net.TCPConn
			err  error
		}{conn: conn, err: acceptErr}
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("dial TCP pair: %v", err)
	}
	result := <-accepted
	if result.err != nil {
		_ = client.Close()
		t.Fatalf("accept TCP pair: %v", result.err)
	}
	_ = listener.Close()
	t.Cleanup(func() {
		_ = client.Close()
		_ = result.conn.Close()
	})
	return client, result.conn
}

func prepareAndCutoverRepairAttempt(t *testing.T, fixture *repairDriverFixture) {
	t.Helper()
	if err := fixture.attempt.Prepare(context.Background(), fixture.request); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := fixture.attempt.Cutover(context.Background(), fixture.request); err != nil {
		t.Fatalf("Cutover: %v", err)
	}
}

func assertRepairDriverEvents(t *testing.T, trace *repairDriverTrace, want ...string) {
	t.Helper()
	got := trace.snapshot()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func repairEndpointState(owner *endpointOwner) (net.Conn, uint64, bool, bool) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.conn, owner.generation, owner.maintenance, owner.closed || owner.failed
}

func assertRepairPathRoundTrip(t *testing.T, path *PathConn, peer net.Conn) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	if err := peer.SetDeadline(deadline); err != nil {
		t.Fatalf("set peer deadline: %v", err)
	}

	outbound := []byte("framed-after-repair")
	writeDone := make(chan error, 1)
	go func() {
		n, err := path.Write(outbound)
		if err == nil && n != len(outbound) {
			err = fmt.Errorf("path write = %d, want %d", n, len(outbound))
		}
		writeDone <- err
	}()
	wire := make([]byte, LengthPrefixSize+len(outbound))
	if _, err := io.ReadFull(peer, wire); err != nil {
		t.Fatalf("read framed outbound: %v", err)
	}
	if size := int(binary.BigEndian.Uint16(wire[:LengthPrefixSize])); size != len(outbound) {
		t.Fatalf("outbound frame size = %d, want %d", size, len(outbound))
	}
	if string(wire[LengthPrefixSize:]) != string(outbound) {
		t.Fatalf("outbound payload = %q, want %q", wire[LengthPrefixSize:], outbound)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("path Write after repair: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("path Write remained fenced after repair")
	}

	inbound := []byte("framed-back-to-owner")
	readDone := make(chan struct {
		n   int
		buf []byte
		err error
	}, 1)
	go func() {
		buf := make([]byte, len(inbound))
		n, err := path.Read(buf)
		readDone <- struct {
			n   int
			buf []byte
			err error
		}{n: n, buf: buf, err: err}
	}()
	prefix := make([]byte, LengthPrefixSize)
	binary.BigEndian.PutUint16(prefix, uint16(len(inbound)))
	if _, err := peer.Write(append(prefix, inbound...)); err != nil {
		t.Fatalf("write framed inbound: %v", err)
	}
	select {
	case result := <-readDone:
		if result.err != nil {
			t.Fatalf("path Read after repair: %v", result.err)
		}
		if result.n != len(inbound) || string(result.buf[:result.n]) != string(inbound) {
			t.Fatalf("path Read = (%d,%q), want (%d,%q)", result.n, result.buf[:result.n], len(inbound), inbound)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("path Read remained fenced after repair")
	}
}

func TestTCPRepairAttemptPrepareInstallsQuarantineUnderMaintenance(t *testing.T) {
	fixture := newRepairDriverFixture(t)
	if err := fixture.attempt.Prepare(context.Background(), fixture.request); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if fixture.attempt.stage != repairAttemptPrepared || fixture.attempt.maintenance == nil ||
		fixture.attempt.source != fixture.source || fixture.attempt.quarantine != fixture.lease {
		t.Fatalf("prepared attempt = %+v", fixture.attempt)
	}
	conn, generation, maintenance, terminal := repairEndpointState(fixture.path.endpoint)
	if conn != fixture.source || generation != fixture.attempt.ownerGeneration || !maintenance || terminal {
		t.Fatalf("endpoint during Prepare = (%T,%d,maintenance=%t,terminal=%t)", conn, generation, maintenance, terminal)
	}
	assertRepairDriverEvents(t, fixture.trace, "inspect", "install")

	if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
		t.Fatalf("Rollback prepared attempt: %v", err)
	}
	assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "release")
	assertRepairPathRoundTrip(t, fixture.path, fixture.peer)
}

func TestTCPRepairAttemptPrepareFailuresRollbackMaintenance(t *testing.T) {
	prepareFailure := errors.New("prepare failure")
	tests := []struct {
		name      string
		configure func(*repairDriverFixture) context.Context
		want      []string
	}{
		{
			name: "canceled maintenance",
			configure: func(*repairDriverFixture) context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
		},
		{
			name: "stale owner generation",
			configure: func(fixture *repairDriverFixture) context.Context {
				fixture.attempt.ownerGeneration++
				return context.Background()
			},
		},
		{
			name: "inspect failure",
			configure: func(fixture *repairDriverFixture) context.Context {
				fixture.kernel.inspectFn = func(*net.TCPConn) (tcprepair.Inspection, error) {
					return tcprepair.Inspection{}, prepareFailure
				}
				return context.Background()
			},
			want: []string{"inspect"},
		},
		{
			name: "inspection drift",
			configure: func(fixture *repairDriverFixture) context.Context {
				fixture.kernel.inspection.OptionsMask = 1
				return context.Background()
			},
			want: []string{"inspect"},
		},
		{
			name: "install failure without lease",
			configure: func(fixture *repairDriverFixture) context.Context {
				fixture.manager.installFn = func(
					context.Context,
					tcpquarantine.TransactionID,
					tcpquarantine.Tuple,
				) (quarantineLease, error) {
					return nil, prepareFailure
				}
				return context.Background()
			},
			want: []string{"inspect", "install"},
		},
		{
			name: "install failure with partial lease",
			configure: func(fixture *repairDriverFixture) context.Context {
				fixture.manager.installFn = func(
					context.Context,
					tcpquarantine.TransactionID,
					tcpquarantine.Tuple,
				) (quarantineLease, error) {
					return fixture.lease, prepareFailure
				}
				return context.Background()
			},
			want: []string{"inspect", "install", "release"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRepairDriverFixture(t)
			ctx := test.configure(fixture)
			if err := fixture.attempt.Prepare(ctx, fixture.request); err == nil {
				t.Fatal("Prepare unexpectedly succeeded")
			}
			if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
				t.Fatalf("Rollback after failed Prepare: %v", err)
			}
			if fixture.attempt.stage != repairAttemptRolledBack {
				t.Fatalf("stage = %d, want rolled back", fixture.attempt.stage)
			}
			assertRepairDriverEvents(t, fixture.trace, test.want...)
			assertRepairPathRoundTrip(t, fixture.path, fixture.peer)
		})
	}

	t.Run("non TCP source", func(t *testing.T) {
		fixture := newRepairDriverFixture(t)
		local, peer := net.Pipe()
		path := Wrap(local)
		t.Cleanup(func() {
			_ = path.Close()
			_ = peer.Close()
		})
		_, generation, available := path.endpoint.current()
		if !available {
			t.Fatal("pipe endpoint is unavailable")
		}
		fixture.attempt.driver = &tcpRepairDriver{
			endpoint: path.endpoint,
			kernel:   fixture.kernel, quarantine: fixture.manager, newExecutor: newInlineRepairExecutor,
		}
		fixture.attempt.ownerGeneration = generation
		if err := fixture.attempt.Prepare(context.Background(), fixture.request); err == nil {
			t.Fatal("Prepare unexpectedly accepted non-TCP source")
		}
		if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
			t.Fatalf("Rollback non-TCP source: %v", err)
		}
		assertRepairDriverEvents(t, fixture.trace)
		assertRepairPathRoundTrip(t, path, peer)
	})
}

func TestTCPRepairAttemptCutoverCapturesAndRollsBackOriginalEndpoint(t *testing.T) {
	fixture := newRepairDriverFixture(t)
	originalGeneration := fixture.attempt.ownerGeneration
	prepareAndCutoverRepairAttempt(t, fixture)
	if fixture.attempt.stage != repairAttemptCutover || fixture.attempt.snapshot != fixture.kernel.snapshot ||
		fixture.attempt.sourceLease == nil || fixture.attempt.sourceLease.State() != tcprepair.SourceStateRepair {
		t.Fatalf("cutover attempt = %+v", fixture.attempt)
	}
	assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture")

	if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
		t.Fatalf("Rollback cutover: %v", err)
	}
	conn, generation, maintenance, terminal := repairEndpointState(fixture.path.endpoint)
	if conn != fixture.source || generation != originalGeneration || maintenance || terminal {
		t.Fatalf("rolled-back endpoint = (%T,%d,maintenance=%t,terminal=%t)", conn, generation, maintenance, terminal)
	}
	if fixture.attempt.EndpointGenerationChanged() {
		t.Fatal("ordinary cutover rollback changed endpoint generation")
	}
	assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture", "resume", "release")
	assertRepairPathRoundTrip(t, fixture.path, fixture.peer)
}

func TestTCPRepairAttemptCutoverFailureReleasesMaintenance(t *testing.T) {
	t.Run("capture error", func(t *testing.T) {
		captureFailure := errors.New("capture failed")
		fixture := newRepairDriverFixture(t)
		fixture.kernel.captureFn = func(conn *net.TCPConn) (repairSource, error) {
			return &fakeRepairSource{trace: fixture.trace, conn: conn, state: tcprepair.SourceStateNormal}, captureFailure
		}
		if err := fixture.attempt.Prepare(context.Background(), fixture.request); err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		if err := fixture.attempt.Cutover(context.Background(), fixture.request); !errors.Is(err, captureFailure) {
			t.Fatalf("Cutover = %v, want capture failure", err)
		}
		if fixture.attempt.sourceLease == nil || fixture.attempt.sourceLease.State() != tcprepair.SourceStateNormal ||
			fixture.attempt.snapshot != nil {
			t.Fatalf("failed capture retained repair state: %+v", fixture.attempt)
		}
		if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
			t.Fatalf("Rollback failed Cutover: %v", err)
		}
		assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture", "release")
		assertRepairPathRoundTrip(t, fixture.path, fixture.peer)
	})

	t.Run("capture unwind is unknown", func(t *testing.T) {
		captureFailure := errors.New("capture failed and repair-off was unverified")
		fixture := newRepairDriverFixture(t)
		fixture.kernel.captureFn = func(conn *net.TCPConn) (repairSource, error) {
			return &fakeRepairSource{trace: fixture.trace, conn: conn, state: tcprepair.SourceStateUnknown}, captureFailure
		}
		if err := fixture.attempt.Prepare(context.Background(), fixture.request); err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		if err := fixture.attempt.Cutover(context.Background(), fixture.request); !errors.Is(err, captureFailure) {
			t.Fatalf("Cutover = %v, want capture failure", err)
		}
		if fixture.attempt.sourceLease == nil || fixture.attempt.sourceLease.State() != tcprepair.SourceStateUnknown ||
			fixture.attempt.snapshot != nil {
			t.Fatalf("failed capture state = %+v, want unknown without snapshot", fixture.attempt)
		}
		if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
			t.Fatalf("Rollback unknown capture: %v", err)
		}
		assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture", "resume", "release")
		assertRepairPathRoundTrip(t, fixture.path, fixture.peer)
	})

	t.Run("snapshot tuple drift", func(t *testing.T) {
		fixture := newRepairDriverFixture(t)
		fixture.kernel.inspection.Tuple = tcprepair.Tuple{
			Local:  netip.MustParseAddrPort("127.0.0.1:12001"),
			Remote: netip.MustParseAddrPort("127.0.0.1:12002"),
		}
		fixture.attempt.inspection = fixture.kernel.inspection
		if err := fixture.attempt.Prepare(context.Background(), fixture.request); err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		if err := fixture.attempt.Cutover(context.Background(), fixture.request); err == nil {
			t.Fatal("Cutover accepted a snapshot with a changed tuple")
		}
		if fixture.attempt.sourceLease == nil || fixture.attempt.sourceLease.State() != tcprepair.SourceStateRepair ||
			fixture.attempt.snapshot == nil {
			t.Fatalf("tuple drift lost exact repair ownership: %+v", fixture.attempt)
		}
		if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
			t.Fatalf("Rollback tuple drift: %v", err)
		}
		assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture", "resume", "release")
		assertRepairPathRoundTrip(t, fixture.path, fixture.peer)
	})
}

func TestTCPRepairAttemptCommitOrdersCloseRestoreReplaceReleaseResume(t *testing.T) {
	fixture := newRepairDriverFixture(t)
	replacement, replacementPeer := newRepairDriverTCPPair(t)
	originalGeneration := fixture.attempt.ownerGeneration
	fixture.kernel.restoreFn = func(
		context.Context,
		*tcprepair.Snapshot,
	) (*net.TCPConn, error) {
		if _, err := fixture.source.Write([]byte("source-must-be-closed")); err == nil {
			return nil, errors.New("restore ran before captured source closed")
		}
		return replacement, nil
	}
	fixture.lease.releaseFn = func(context.Context, int) error {
		conn, generation, maintenance, terminal := repairEndpointState(fixture.path.endpoint)
		if conn != replacement || generation == originalGeneration || !maintenance || terminal {
			return fmt.Errorf(
				"release before replacement publication: conn=%T generation=%d maintenance=%t terminal=%t",
				conn, generation, maintenance, terminal,
			)
		}
		return nil
	}
	prepareAndCutoverRepairAttempt(t, fixture)

	if err := fixture.attempt.Commit(context.Background(), fixture.request); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	conn, generation, maintenance, terminal := repairEndpointState(fixture.path.endpoint)
	if conn != replacement || generation == originalGeneration || maintenance || terminal {
		t.Fatalf("committed endpoint = (%T,%d,maintenance=%t,terminal=%t)", conn, generation, maintenance, terminal)
	}
	if fixture.attempt.stage != repairAttemptCommitted || !fixture.attempt.EndpointGenerationChanged() {
		t.Fatalf("committed attempt stage=%d changed=%t", fixture.attempt.stage, fixture.attempt.EndpointGenerationChanged())
	}
	assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture", "restore", "release")
	assertRepairPathRoundTrip(t, fixture.path, replacementPeer)
}

func TestTCPRepairAttemptRestoreFailureRollsBackFromSnapshot(t *testing.T) {
	restoreFailure := errors.New("first restore failed")
	fixture := newRepairDriverFixture(t)
	replacement, replacementPeer := newRepairDriverTCPPair(t)
	originalGeneration := fixture.attempt.ownerGeneration
	restoreCalls := 0
	fixture.kernel.restoreFn = func(
		context.Context,
		*tcprepair.Snapshot,
	) (*net.TCPConn, error) {
		restoreCalls++
		if restoreCalls == 1 {
			if _, err := fixture.source.Write([]byte("source-must-be-closed")); err == nil {
				return nil, errors.New("restore ran before source close")
			}
			return nil, restoreFailure
		}
		return replacement, nil
	}
	prepareAndCutoverRepairAttempt(t, fixture)

	if err := fixture.attempt.Commit(context.Background(), fixture.request); !errors.Is(err, restoreFailure) {
		t.Fatalf("Commit = %v, want restore failure", err)
	}
	if _, generation, maintenance, terminal := repairEndpointState(fixture.path.endpoint); generation != originalGeneration || !maintenance || terminal {
		t.Fatalf("endpoint after failed restore = generation %d maintenance=%t terminal=%t", generation, maintenance, terminal)
	}
	if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
		t.Fatalf("Rollback from snapshot: %v", err)
	}
	if restoreCalls != 2 || !fixture.attempt.EndpointGenerationChanged() {
		t.Fatalf("rollback restores=%d changed=%t, want 2/true", restoreCalls, fixture.attempt.EndpointGenerationChanged())
	}
	conn, generation, maintenance, terminal := repairEndpointState(fixture.path.endpoint)
	if conn != replacement || generation == originalGeneration || maintenance || terminal {
		t.Fatalf("rebuilt endpoint = (%T,%d,maintenance=%t,terminal=%t)", conn, generation, maintenance, terminal)
	}
	assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture", "restore", "restore", "release")
	assertRepairPathRoundTrip(t, fixture.path, replacementPeer)
}

func TestTCPRepairAttemptUnknownRestoreCleanupNeverRetriesTupleOrReleasesQuarantine(t *testing.T) {
	restoreFailure := errors.New("restore failed with an unowned descriptor")
	fixture := newRepairDriverFixture(t)
	restoreCalls := 0
	fixture.kernel.restoreFn = func(context.Context, *tcprepair.Snapshot) (*net.TCPConn, error) {
		restoreCalls++
		return nil, errors.Join(restoreFailure, tcprepair.ErrRestoreCleanupUnknown)
	}
	prepareAndCutoverRepairAttempt(t, fixture)

	if err := fixture.attempt.Commit(context.Background(), fixture.request); !errors.Is(err, restoreFailure) || !errors.Is(err, tcprepair.ErrRestoreCleanupUnknown) {
		t.Fatalf("Commit = %v, want restore cleanup unknown", err)
	}
	if err := fixture.attempt.Rollback(context.Background(), fixture.request); !errors.Is(err, tcprepair.ErrRestoreCleanupUnknown) {
		t.Fatalf("Rollback = %v, want cleanup unknown", err)
	}
	if restoreCalls != 1 || fixture.lease.releaseCalls() != 0 {
		t.Fatalf("restore/release calls=%d/%d want 1/0", restoreCalls, fixture.lease.releaseCalls())
	}
	if err := fixture.attempt.FailClosed(context.Background(), fixture.request); !errors.Is(err, tcprepair.ErrRestoreCleanupUnknown) {
		t.Fatalf("FailClosed = %v, want cleanup unknown", err)
	}
	if !fixture.attempt.endpointTerminated || fixture.attempt.quarantine == nil || fixture.attempt.executor == nil {
		t.Fatalf("unknown cleanup lost fail-closed ownership: %+v", fixture.attempt)
	}
	assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture", "restore")
}

func TestTCPRepairAttemptReleaseFailureRollsBackPublishedReplacement(t *testing.T) {
	releaseFailure := errors.New("release failed after replace")
	fixture := newRepairDriverFixture(t)
	replacement, replacementPeer := newRepairDriverTCPPair(t)
	originalGeneration := fixture.attempt.ownerGeneration
	restoreCalls := 0
	fixture.kernel.restoreFn = func(context.Context, *tcprepair.Snapshot) (*net.TCPConn, error) {
		restoreCalls++
		return replacement, nil
	}
	fixture.lease.releaseFn = func(_ context.Context, call int) error {
		if call == 1 {
			return releaseFailure
		}
		return nil
	}
	prepareAndCutoverRepairAttempt(t, fixture)

	if err := fixture.attempt.Commit(context.Background(), fixture.request); !errors.Is(err, releaseFailure) {
		t.Fatalf("Commit = %v, want release failure", err)
	}
	conn, generation, maintenance, terminal := repairEndpointState(fixture.path.endpoint)
	if conn != replacement || generation == originalGeneration || !maintenance || terminal {
		t.Fatalf("endpoint after failed release = (%T,%d,maintenance=%t,terminal=%t)", conn, generation, maintenance, terminal)
	}
	if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
		t.Fatalf("Rollback published replacement: %v", err)
	}
	if restoreCalls != 1 || fixture.lease.releaseCalls() != 2 || !fixture.attempt.EndpointGenerationChanged() {
		t.Fatalf(
			"restore=%d release=%d changed=%t, want 1/2/true",
			restoreCalls, fixture.lease.releaseCalls(), fixture.attempt.EndpointGenerationChanged(),
		)
	}
	assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture", "restore", "release", "release")
	assertRepairPathRoundTrip(t, fixture.path, replacementPeer)
}

func TestTCPRepairAttemptRollbackFailuresAreRetryable(t *testing.T) {
	t.Run("kernel Resume", func(t *testing.T) {
		resumeFailure := errors.New("resume failed")
		fixture := newRepairDriverFixture(t)
		resumeCalls := 0
		fixture.kernel.source = &fakeRepairSource{
			trace: fixture.trace, snapshot: fixture.kernel.snapshot, state: tcprepair.SourceStateRepair,
		}
		fixture.kernel.source.resumeFn = func() error {
			resumeCalls++
			if resumeCalls == 1 {
				return resumeFailure
			}
			return nil
		}
		prepareAndCutoverRepairAttempt(t, fixture)

		if err := fixture.attempt.Rollback(context.Background(), fixture.request); !errors.Is(err, resumeFailure) {
			t.Fatalf("first Rollback = %v, want Resume failure", err)
		}
		if fixture.lease.releaseCalls() != 0 {
			t.Fatalf("release calls after failed Resume = %d, want 0", fixture.lease.releaseCalls())
		}
		if _, _, available := fixture.path.endpoint.current(); available {
			t.Fatal("failed Resume exposed endpoint before retry")
		}
		if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
			t.Fatalf("retry Rollback: %v", err)
		}
		if resumeCalls != 2 || fixture.lease.releaseCalls() != 1 {
			t.Fatalf("resume/release calls = %d/%d, want 2/1", resumeCalls, fixture.lease.releaseCalls())
		}
		assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture", "resume", "resume", "release")
		assertRepairPathRoundTrip(t, fixture.path, fixture.peer)
	})

	t.Run("quarantine Release", func(t *testing.T) {
		releaseFailure := errors.New("release retry required")
		fixture := newRepairDriverFixture(t)
		fixture.lease.releaseFn = func(_ context.Context, call int) error {
			if call == 1 {
				return releaseFailure
			}
			return nil
		}
		prepareAndCutoverRepairAttempt(t, fixture)

		if err := fixture.attempt.Rollback(context.Background(), fixture.request); !errors.Is(err, releaseFailure) {
			t.Fatalf("first Rollback = %v, want Release failure", err)
		}
		if _, _, available := fixture.path.endpoint.current(); available {
			t.Fatal("failed Release exposed endpoint before retry")
		}
		if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
			t.Fatalf("retry Rollback: %v", err)
		}
		if fixture.lease.releaseCalls() != 2 {
			t.Fatalf("release calls = %d, want 2", fixture.lease.releaseCalls())
		}
		assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture", "resume", "release", "release")
		assertRepairPathRoundTrip(t, fixture.path, fixture.peer)
	})
}

func TestTCPRepairAttemptFailClosedTerminatesEndpointBeforeQuarantineRelease(t *testing.T) {
	fixture := newRepairDriverFixture(t)
	prepareAndCutoverRepairAttempt(t, fixture)
	fixture.lease.releaseFn = func(context.Context, int) error {
		_, _, maintenance, terminal := repairEndpointState(fixture.path.endpoint)
		if !terminal || maintenance {
			return fmt.Errorf("release observed endpoint terminal=%t maintenance=%t", terminal, maintenance)
		}
		return nil
	}

	if err := fixture.attempt.FailClosed(context.Background(), fixture.request); err != nil {
		t.Fatalf("FailClosed: %v", err)
	}
	if fixture.attempt.stage != repairAttemptFailedClosed || !fixture.attempt.endpointTerminated ||
		fixture.attempt.quarantine != nil || fixture.attempt.executor != nil {
		t.Fatalf("fail-closed attempt = %+v", fixture.attempt)
	}
	_, _, maintenance, terminal := repairEndpointState(fixture.path.endpoint)
	if !terminal || maintenance {
		t.Fatalf("endpoint terminal=%t maintenance=%t", terminal, maintenance)
	}
	assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture", "release")
}

func TestTCPRepairAttemptFailClosedReleaseFailureIsRetryable(t *testing.T) {
	releaseFailure := errors.New("fail-closed release failed")
	fixture := newRepairDriverFixture(t)
	prepareAndCutoverRepairAttempt(t, fixture)
	fixture.lease.releaseFn = func(_ context.Context, call int) error {
		if call == 1 {
			return releaseFailure
		}
		return nil
	}

	if err := fixture.attempt.FailClosed(context.Background(), fixture.request); !errors.Is(err, releaseFailure) {
		t.Fatalf("first FailClosed = %v, want release failure", err)
	}
	if !fixture.attempt.endpointTerminated || fixture.attempt.quarantine == nil || fixture.attempt.executor == nil {
		t.Fatalf("failed cleanup lost ownership: %+v", fixture.attempt)
	}
	if err := fixture.attempt.FailClosed(context.Background(), fixture.request); err != nil {
		t.Fatalf("retry FailClosed: %v", err)
	}
	if fixture.lease.releaseCalls() != 2 || fixture.attempt.stage != repairAttemptFailedClosed {
		t.Fatalf("release/stage=%d/%d want 2/failed-closed", fixture.lease.releaseCalls(), fixture.attempt.stage)
	}
	assertRepairDriverEvents(t, fixture.trace, "inspect", "install", "capture", "release", "release")
}

func TestTCPRepairAttemptFailClosedRetainsReplacementUntilCloseIsProven(t *testing.T) {
	releaseFailure := errors.New("hold quarantine after replacement publication")
	closeFailure := errors.New("replacement close state unknown")
	fixture := newRepairDriverFixture(t)
	replacement, _ := newRepairDriverTCPPair(t)
	fixture.kernel.restoreFn = func(context.Context, *tcprepair.Snapshot) (*net.TCPConn, error) {
		return replacement, nil
	}
	fixture.lease.releaseFn = func(_ context.Context, call int) error {
		if call == 1 {
			return releaseFailure
		}
		return nil
	}
	prepareAndCutoverRepairAttempt(t, fixture)
	if err := fixture.attempt.Commit(context.Background(), fixture.request); !errors.Is(err, releaseFailure) {
		t.Fatalf("Commit = %v, want release failure", err)
	}

	closeCalls := 0
	fixture.attempt.closeReplacement = func(conn *net.TCPConn) error {
		closeCalls++
		if closeCalls == 1 {
			return closeFailure
		}
		return conn.Close()
	}
	if err := fixture.attempt.FailClosed(context.Background(), fixture.request); !errors.Is(err, closeFailure) {
		t.Fatalf("first FailClosed = %v, want close failure", err)
	}
	if fixture.attempt.replacement != replacement || fixture.attempt.endpointTerminated ||
		fixture.attempt.quarantine == nil || fixture.lease.releaseCalls() != 1 {
		t.Fatalf("failed close lost ownership: replacement=%p terminated=%t quarantine=%T releases=%d",
			fixture.attempt.replacement, fixture.attempt.endpointTerminated,
			fixture.attempt.quarantine, fixture.lease.releaseCalls())
	}
	if err := fixture.attempt.FailClosed(context.Background(), fixture.request); err != nil {
		t.Fatalf("retry FailClosed: %v", err)
	}
	if closeCalls != 2 || fixture.attempt.replacement != nil || !fixture.attempt.endpointTerminated ||
		fixture.attempt.quarantine != nil || fixture.lease.releaseCalls() != 2 {
		t.Fatalf("retry cleanup = calls:%d replacement:%p terminated:%t quarantine:%T releases:%d",
			closeCalls, fixture.attempt.replacement, fixture.attempt.endpointTerminated,
			fixture.attempt.quarantine, fixture.lease.releaseCalls())
	}
}

func TestTCPRepairAttemptDiscardRetainsUnprovenReplacementHandle(t *testing.T) {
	closeFailure := errors.New("discard close state unknown")
	fixture := newRepairDriverFixture(t)
	replacement, _ := newRepairDriverTCPPair(t)
	fixture.attempt.replacement = replacement
	closeCalls := 0
	fixture.attempt.closeReplacement = func(conn *net.TCPConn) error {
		closeCalls++
		if closeCalls == 1 {
			return closeFailure
		}
		return conn.Close()
	}
	if err := fixture.attempt.discardReplacement(); !errors.Is(err, closeFailure) {
		t.Fatalf("first discard = %v, want close failure", err)
	}
	if fixture.attempt.replacement != replacement {
		t.Fatal("discard dropped a replacement whose close was not proven")
	}
	if err := fixture.attempt.discardReplacement(); err != nil {
		t.Fatalf("retry discard: %v", err)
	}
	if closeCalls != 2 || fixture.attempt.replacement != nil {
		t.Fatalf("retry discard calls/replacement=%d/%p want 2/nil", closeCalls, fixture.attempt.replacement)
	}
}

func TestTCPRepairAttemptRequestMismatchDoesNotMutate(t *testing.T) {
	t.Run("all bound fields before Prepare", func(t *testing.T) {
		mutations := []struct {
			name   string
			mutate func(*leafmobility.ExecutionRequest)
		}{
			{"facts", func(request *leafmobility.ExecutionRequest) { request.Facts.Generation++ }},
			{"transaction", func(request *leafmobility.ExecutionRequest) { request.Plan.TransactionID[0]++ }},
			{"binding", func(request *leafmobility.ExecutionRequest) { request.Plan.Binding.Owner++ }},
			{"endpoint generation", func(request *leafmobility.ExecutionRequest) { request.Plan.EndpointGeneration++ }},
			{"direction", func(request *leafmobility.ExecutionRequest) {
				request.Plan.Direction = proto.SenderDirectionServerToClient
			}},
			{"session", func(request *leafmobility.ExecutionRequest) { request.Plan.Session = leafmobility.SessionPacket }},
			{"operation", func(request *leafmobility.ExecutionRequest) {
				request.Plan.Operation = leafmobility.OperationQUICCIDRebind
			}},
			{"agreement generation", func(request *leafmobility.ExecutionRequest) { request.Agreement.ActorEndpointGeneration++ }},
		}
		for _, mutation := range mutations {
			t.Run(mutation.name, func(t *testing.T) {
				fixture := newRepairDriverFixture(t)
				bad := fixture.request
				mutation.mutate(&bad)
				if err := fixture.attempt.Prepare(context.Background(), bad); err == nil {
					t.Fatal("Prepare accepted mismatched request")
				}
				if fixture.attempt.stage != repairAttemptPreflight || fixture.attempt.maintenance != nil {
					t.Fatalf("mismatched Prepare mutated attempt: %+v", fixture.attempt)
				}
				assertRepairDriverEvents(t, fixture.trace)
				assertRepairPathRoundTrip(t, fixture.path, fixture.peer)
			})
		}
	})

	t.Run("every execution stage", func(t *testing.T) {
		tests := []struct {
			name      string
			setup     func(*testing.T, *repairDriverFixture)
			call      func(*tcpRepairAttempt, context.Context, leafmobility.ExecutionRequest) error
			wantStage repairAttemptStage
		}{
			{
				name:  "Prepare",
				setup: func(*testing.T, *repairDriverFixture) {},
				call:  (*tcpRepairAttempt).Prepare, wantStage: repairAttemptPreflight,
			},
			{
				name: "Cutover",
				setup: func(t *testing.T, fixture *repairDriverFixture) {
					if err := fixture.attempt.Prepare(context.Background(), fixture.request); err != nil {
						t.Fatalf("Prepare: %v", err)
					}
				},
				call: (*tcpRepairAttempt).Cutover, wantStage: repairAttemptPrepared,
			},
			{
				name:  "Commit",
				setup: prepareAndCutoverRepairAttempt,
				call:  (*tcpRepairAttempt).Commit, wantStage: repairAttemptCutover,
			},
			{
				name:  "Rollback",
				setup: prepareAndCutoverRepairAttempt,
				call:  (*tcpRepairAttempt).Rollback, wantStage: repairAttemptCutover,
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				fixture := newRepairDriverFixture(t)
				test.setup(t, fixture)
				before := fixture.trace.snapshot()
				bad := fixture.request
				bad.Plan.TransactionID[0]++
				if err := test.call(fixture.attempt, context.Background(), bad); err == nil {
					t.Fatalf("%s accepted mismatched request", test.name)
				}
				if fixture.attempt.stage != test.wantStage {
					t.Fatalf("stage after mismatched %s = %d, want %d", test.name, fixture.attempt.stage, test.wantStage)
				}
				if got := fixture.trace.snapshot(); fmt.Sprint(got) != fmt.Sprint(before) {
					t.Fatalf("mismatched %s calls = %v, want unchanged %v", test.name, got, before)
				}
				if fixture.attempt.maintenance != nil {
					if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
						t.Fatalf("cleanup Rollback: %v", err)
					}
				}
				assertRepairPathRoundTrip(t, fixture.path, fixture.peer)
			})
		}
	})
}
