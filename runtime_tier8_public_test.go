package rendr_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
)

const tier8RuntimeEvidenceMarker = "RENDR_T8_EVIDENCE_JSON="

func TestRuntimeTier8OrderedFallbackRedialAttachPublicContract(t *testing.T) {
	testCtx, testCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer testCancel()

	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	aListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fallbackListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = aListener.Close()
		t.Fatal(err)
	}
	sessionListener, err := serverRuntime.Listen(rendr.ListenConfig{Streams: []rendr.StreamSource{
		{Name: "source-a", Carrier: rendr.CarrierTCP, Listener: aListener},
		{Name: "source-fallback", Carrier: rendr.CarrierTCP, Listener: fallbackListener},
	}})
	if err != nil {
		_ = aListener.Close()
		_ = fallbackListener.Close()
		t.Fatal(err)
	}

	factory := newTier8RuntimeFactory(aListener.Addr().String(), fallbackListener.Addr().String())
	clientRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		_ = sessionListener.Close()
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterStreamFactory("tier8-stream", rendr.StreamFactory{
		Carrier: rendr.CarrierTCP,
		Dial:    factory.dial,
	}); err != nil {
		_ = sessionListener.Close()
		t.Fatal(err)
	}

	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("A", tier8PathSpec("A")),
		rendr.Bond("fallback", []rendr.Target{
			rendr.Path("B", tier8PathSpec("B")),
			rendr.Race("fallback-race", []rendr.Target{
				rendr.Path("C", tier8PathSpec("C")),
				rendr.Path("D", tier8PathSpec("D")),
			}),
		}),
	})

	type acceptResult struct {
		conn rendr.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := sessionListener.AcceptStream(testCtx)
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()

	dialCtx, cancelDial := context.WithCancel(testCtx)
	type dialResult struct {
		conn rendr.Conn
		err  error
		at   time.Time
	}
	dialStarted := time.Now()
	dialed := make(chan dialResult, 1)
	go func() {
		conn, dialErr := clientRuntime.Dial(dialCtx, rendr.SessionConfig{Root: root})
		dialed <- dialResult{conn: conn, err: dialErr, at: time.Now()}
	}()

	if err := tier8WaitSignal(testCtx, factory.aOptionalStalled, "stalled optional A recovery attempt"); err != nil {
		factory.unblock()
		_ = sessionListener.Close()
		t.Fatal(err)
	}
	var dialOutcome dialResult
	select {
	case dialOutcome = <-dialed:
	case <-time.After(time.Second):
		factory.unblock()
		_ = sessionListener.Close()
		select {
		case <-dialed:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("Dial remained blocked on optional A after B established the session")
	}
	if dialOutcome.err != nil || dialOutcome.conn == nil {
		factory.unblock()
		_ = sessionListener.Close()
		t.Fatalf("Dial outcome conn=%v err=%v", dialOutcome.conn, dialOutcome.err)
	}
	client := dialOutcome.conn
	var server rendr.Conn
	cleanupComplete := false
	t.Cleanup(func() {
		factory.unblock()
		_ = client.Close()
		if server != nil {
			_ = server.Close()
		}
		_ = sessionListener.Close()
		if !cleanupComplete {
			testCancel()
		}
	})
	if elapsed := dialOutcome.at.Sub(dialStarted); elapsed >= 2*time.Second {
		t.Fatalf("Dial elapsed=%s, want prompt return after fallback B", elapsed)
	}
	if got := factory.callPrefix(2); !reflect.DeepEqual(got, []string{"A#1", "B#1"}) {
		t.Fatalf("initial factory order=%v want [A#1 B#1]", got)
	}

	select {
	case outcome := <-accepted:
		if outcome.err != nil || outcome.conn == nil {
			t.Fatalf("AcceptStream outcome conn=%v err=%v", outcome.conn, outcome.err)
		}
		server = outcome.conn
	case <-testCtx.Done():
		t.Fatal("server did not publish the fallback session")
	}
	echoDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(server, server)
		echoDone <- copyErr
	}()

	clientToken := tier8ObjectToken(t, client)
	flowBefore := client.FlowID()
	createdBefore := client.(rendr.ConnectionObserver).Stats().CreatedAt
	if flowBefore == ([16]byte{}) || server.FlowID() != flowBefore {
		t.Fatalf("initial flow IDs client=%x server=%x", flowBefore, server.FlowID())
	}

	// This transfer completes while A's first optional recovery dial is still
	// blocked, proving the optional leaf cannot backpressure application data.
	fallbackPayload := tier8Payload(0x31, 128<<10)
	if err := tier8RoundTrip(client, fallbackPayload); err != nil {
		t.Fatalf("fallback payload: %v", err)
	}
	cancelDial()
	factory.releaseOptionalStall()
	if err := tier8WaitSignal(testCtx, factory.aFourthStarted, "fourth A factory attempt"); err != nil {
		t.Fatal(err)
	}
	if got := factory.aAttempts.Load(); got != 4 {
		t.Fatalf("A attempts before availability=%d want 4", got)
	}
	factory.enableA()

	if err := tier8Wait(testCtx, func() (bool, string) {
		status := client.Status()
		attached := tier8AttachedStatusByName(status)
		for _, name := range []string{"A", "B", "C", "D"} {
			path, ok := attached[name]
			if !ok || path.State != rendr.PathAttached || path.Carrier != rendr.CarrierTCP || path.ID == 0 {
				return false, fmt.Sprintf("status paths=%+v", status.Paths)
			}
		}
		return true, ""
	}); err != nil {
		t.Fatal(err)
	}
	if got := factory.attemptsFor("B", "C", "D"); !reflect.DeepEqual(got, map[string]uint32{"B": 1, "C": 1, "D": 1}) {
		t.Fatalf("fallback leaf factory attempts=%v", got)
	}

	statusBeforeSelect := client.Status()
	if len(statusBeforeSelect.Paths) != 4 {
		t.Fatalf("attached path status count=%d want 4: %+v", len(statusBeforeSelect.Paths), statusBeforeSelect.Paths)
	}
	if got := tier8EffectivePathNames(statusBeforeSelect); !reflect.DeepEqual(got, []string{"B", "C", "D"}) {
		t.Fatalf("fallback bond/race effective paths=%v want [B C D]", got)
	}
	controller, ok := client.(rendr.MigrationController)
	if !ok {
		t.Fatal("public Conn does not implement MigrationController")
	}
	observer := client.(rendr.ConnectionObserver)
	migrationsBefore := observer.MigrationCount()
	if err := controller.SelectTarget("root", "A"); err != nil {
		t.Fatalf("SelectTarget(root, A): %v", err)
	}
	var aPathID uint32
	if err := tier8Wait(testCtx, func() (bool, string) {
		status := client.Status()
		for _, path := range status.Paths {
			if path.Name == "A" && path.State == rendr.PathAttached && path.Active {
				aPathID = path.ID
				return len(status.EffectivePaths) == 1 && status.EffectivePaths[0] == path.ID,
					fmt.Sprintf("effective=%v A=%+v", status.EffectivePaths, path)
			}
		}
		return false, fmt.Sprintf("status=%+v", status)
	}); err != nil {
		t.Fatal(err)
	}

	beforeWrites := tier8DataWritesByName(client.Paths())
	aPayload := tier8Payload(0x79, 1<<20)
	if err := tier8RoundTrip(client, aPayload); err != nil {
		t.Fatalf("A payload: %v", err)
	}
	afterWrites := tier8DataWritesByName(client.Paths())
	if afterWrites["A"] <= beforeWrites["A"] {
		t.Fatalf("A carried no DATA: before=%v after=%v", beforeWrites, afterWrites)
	}
	for _, name := range []string{"B", "C", "D"} {
		if afterWrites[name] != beforeWrites[name] {
			t.Fatalf("unselected path %s carried DATA during A transfer: before=%v after=%v", name, beforeWrites, afterWrites)
		}
	}
	if client.FlowID() != flowBefore || server.FlowID() != flowBefore ||
		client.(rendr.ConnectionObserver).Stats().CreatedAt != createdBefore || tier8ObjectToken(t, client) != clientToken {
		t.Fatal("application connection identity changed across fallback, attachment, or migration")
	}
	if observer.MigrationCount() <= migrationsBefore {
		t.Fatalf("migration count=%d want >%d", observer.MigrationCount(), migrationsBefore)
	}
	convergedStatus := client.Status()
	if got := tier8EffectivePathNames(convergedStatus); !reflect.DeepEqual(got, []string{"A"}) {
		t.Fatalf("post-selection effective paths=%v want [A]", got)
	}

	if err := factory.closeAPath(); err != nil {
		t.Fatalf("close active A carrier: %v", err)
	}
	if err := tier8WaitSignal(testCtx, factory.aCloseRecoveryStarted, "post-death A recovery attempt"); err != nil {
		t.Fatal(err)
	}
	clientClosed := make(chan error, 1)
	go func() { clientClosed <- client.Close() }()
	if err := tier8WaitSignal(testCtx, factory.aCloseRecoveryCanceled, "Close cancellation of A recovery"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-clientClosed:
		factory.releaseCloseRecovery()
		t.Fatalf("client Close returned before delayed recovery cleanup: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	factory.releaseCloseRecovery()
	if err := tier8WaitSignal(testCtx, factory.aCloseRecoveryExited, "joined A recovery worker"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-clientClosed:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("client Close: %v", err)
		}
	case <-testCtx.Done():
		t.Fatal("client Close did not join delayed recovery cleanup")
	}
	if active := factory.active.Load(); active != 0 {
		t.Fatalf("client Close returned with %d factory workers still active", active)
	}
	if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("server Close: %v", err)
	}
	if err := sessionListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("listener Close: %v", err)
	}
	select {
	case copyErr := <-echoDone:
		if copyErr != nil && !errors.Is(copyErr, net.ErrClosed) && !errors.Is(copyErr, io.ErrClosedPipe) {
			t.Fatalf("echo loop: %v", copyErr)
		}
	case <-testCtx.Done():
		t.Fatal("echo loop did not stop")
	}
	if err := tier8Wait(testCtx, func() (bool, string) {
		return factory.active.Load() == 0 && factory.open.Load() == 0,
			fmt.Sprintf("active_factory_calls=%d open_factory_conns=%d", factory.active.Load(), factory.open.Load())
	}); err != nil {
		t.Fatal(err)
	}
	if got := factory.attemptsFor("A", "B", "C", "D"); !reflect.DeepEqual(got, map[string]uint32{"A": 5, "B": 1, "C": 1, "D": 1}) {
		t.Fatalf("final factory attempts=%v", got)
	}
	cleanupComplete = true

	negativeOrder, negativeLeaf := tier8AllLeavesFailControl(t, testCtx)
	if !reflect.DeepEqual(negativeOrder, []string{"A", "B"}) || negativeLeaf != "B" {
		t.Fatalf("all-leaves-fail control order=%v terminal leaf=%q", negativeOrder, negativeLeaf)
	}

	statusNames := make([]string, 0, len(statusBeforeSelect.Paths))
	for _, path := range statusBeforeSelect.Paths {
		statusNames = append(statusNames, fmt.Sprintf("%s:%d", path.Name, path.Carrier))
	}
	sort.Strings(statusNames)
	tier8EmitRuntimeEvidence(t, map[string]string{
		"all_leaves_fail_order":              strings.Join(negativeOrder, ","),
		"all_leaves_fail_terminal_typed":     "true",
		"application_errors":                 "0",
		"application_object_stable":          "true",
		"automatic_attempts_before_attach":   "4",
		"bond_race_leaves_attached":          "true",
		"caller_context_canceled_before_a":   "true",
		"case_id":                            "T8.runtime.ordered-fallback-redial-attach",
		"close_canceled_optional_recovery":   "true",
		"created_at_stable":                  "true",
		"deterministic_factory_order":        "A#1,B#1",
		"dial_returned_while_a_stalled":      "true",
		"evidence_schema":                    "tier8-runtime-ordered-fallback-redial-attach-v1",
		"factory_calls_active_after_cleanup": "0",
		"factory_connections_after_cleanup":  "0",
		"fallback_payload_bytes":             "131072",
		"fallback_sha256_match":              "true",
		"flow_id_stable":                     "true",
		"later_a_attached":                   "true",
		"negative_control_id":                "all-leaves-fail-v1",
		"path_a_data_observed":               "true",
		"path_a_id_nonzero":                  fmt.Sprintf("%t", aPathID != 0),
		"path_a_payload_bytes":               "1048576",
		"path_a_sha256_match":                "true",
		"path_status_converged":              "true",
		"public_select_target_migration":     "true",
		"resolver_factory_attempts":          "A=5,B=1,C=1,D=1",
		"status_carrier_evidence":            strings.Join(statusNames, ","),
		"structured_evidence":                "true",
		"delayed_recovery_worker_joined":     "true",
		"zero_app_error":                     "true",
	})
}

type tier8RuntimeFactory struct {
	aAddress        string
	fallbackAddress string

	mu       sync.Mutex
	attempts map[string]uint32
	calls    []string
	aConn    net.Conn

	aAttempts atomic.Uint32
	active    atomic.Int32
	open      atomic.Int32

	aOptionalStalled       chan struct{}
	aFourthStarted         chan struct{}
	aCloseRecoveryStarted  chan struct{}
	aCloseRecoveryCanceled chan struct{}
	aCloseRecoveryExited   chan struct{}
	aCloseRecoveryRelease  chan struct{}
	releaseA               chan struct{}
	availableA             chan struct{}
	releaseOnce            sync.Once
	availableOnce          sync.Once
	stalledOnce            sync.Once
	fourthOnce             sync.Once
	closeStartedOnce       sync.Once
	closeCanceledOnce      sync.Once
	closeExitedOnce        sync.Once
	closeReleaseOnce       sync.Once
}

func newTier8RuntimeFactory(aAddress, fallbackAddress string) *tier8RuntimeFactory {
	return &tier8RuntimeFactory{
		aAddress: aAddress, fallbackAddress: fallbackAddress,
		attempts:         make(map[string]uint32),
		aOptionalStalled: make(chan struct{}), aFourthStarted: make(chan struct{}),
		aCloseRecoveryStarted: make(chan struct{}), aCloseRecoveryCanceled: make(chan struct{}),
		aCloseRecoveryExited: make(chan struct{}), aCloseRecoveryRelease: make(chan struct{}),
		releaseA: make(chan struct{}), availableA: make(chan struct{}),
	}
}

func (f *tier8RuntimeFactory) dial(ctx context.Context, leaf string) (net.Conn, error) {
	f.active.Add(1)
	defer f.active.Add(-1)

	f.mu.Lock()
	f.attempts[leaf]++
	attempt := f.attempts[leaf]
	f.calls = append(f.calls, fmt.Sprintf("%s#%d", leaf, attempt))
	f.mu.Unlock()

	if leaf != "A" {
		return f.dialTracked(ctx, f.fallbackAddress)
	}
	f.aAttempts.Store(attempt)
	switch attempt {
	case 1:
		return nil, &tier8RuntimeFactoryError{Leaf: leaf, Attempt: attempt, Stage: "initial-unavailable"}
	case 2:
		f.stalledOnce.Do(func() { close(f.aOptionalStalled) })
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.releaseA:
			return nil, &tier8RuntimeFactoryError{Leaf: leaf, Attempt: attempt, Stage: "optional-stall-released"}
		}
	case 3:
		return nil, &tier8RuntimeFactoryError{Leaf: leaf, Attempt: attempt, Stage: "automatic-retry"}
	case 4:
		f.fourthOnce.Do(func() { close(f.aFourthStarted) })
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.availableA:
		}
		conn, err := f.dialTracked(ctx, f.aAddress)
		if err == nil {
			f.mu.Lock()
			f.aConn = conn
			f.mu.Unlock()
		}
		return conn, err
	default:
		f.closeStartedOnce.Do(func() { close(f.aCloseRecoveryStarted) })
		<-ctx.Done()
		f.closeCanceledOnce.Do(func() { close(f.aCloseRecoveryCanceled) })
		<-f.aCloseRecoveryRelease
		f.closeExitedOnce.Do(func() { close(f.aCloseRecoveryExited) })
		return nil, ctx.Err()
	}
}

func (f *tier8RuntimeFactory) dialTracked(ctx context.Context, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	if err != nil {
		return nil, err
	}
	f.open.Add(1)
	return &tier8TrackedConn{Conn: conn, open: &f.open}, nil
}

func (f *tier8RuntimeFactory) callPrefix(count int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if count > len(f.calls) {
		count = len(f.calls)
	}
	return append([]string(nil), f.calls[:count]...)
}

func (f *tier8RuntimeFactory) attemptsFor(names ...string) map[string]uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make(map[string]uint32, len(names))
	for _, name := range names {
		result[name] = f.attempts[name]
	}
	return result
}

func (f *tier8RuntimeFactory) releaseOptionalStall() { f.releaseOnce.Do(func() { close(f.releaseA) }) }
func (f *tier8RuntimeFactory) enableA()              { f.availableOnce.Do(func() { close(f.availableA) }) }
func (f *tier8RuntimeFactory) releaseCloseRecovery() {
	f.closeReleaseOnce.Do(func() { close(f.aCloseRecoveryRelease) })
}
func (f *tier8RuntimeFactory) unblock() {
	f.releaseOptionalStall()
	f.enableA()
	f.releaseCloseRecovery()
}

func (f *tier8RuntimeFactory) closeAPath() error {
	f.mu.Lock()
	conn := f.aConn
	f.mu.Unlock()
	if conn == nil {
		return errors.New("A factory connection is missing")
	}
	return conn.Close()
}

type tier8TrackedConn struct {
	net.Conn
	open *atomic.Int32
	once sync.Once
}

func (c *tier8TrackedConn) Close() (err error) {
	c.once.Do(func() {
		err = c.Conn.Close()
		c.open.Add(-1)
	})
	return err
}

type tier8RuntimeFactoryError struct {
	Leaf    string
	Attempt uint32
	Stage   string
}

func (e *tier8RuntimeFactoryError) Error() string {
	return fmt.Sprintf("tier8 factory leaf %s attempt %d failed at %s", e.Leaf, e.Attempt, e.Stage)
}

func tier8AllLeavesFailControl(t *testing.T, parent context.Context) ([]string, string) {
	t.Helper()
	runtime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var order []string
	if err := runtime.RegisterStreamFactory("tier8-all-fail", rendr.StreamFactory{
		Carrier: rendr.CarrierTCP,
		Dial: func(_ context.Context, leaf string) (net.Conn, error) {
			mu.Lock()
			order = append(order, leaf)
			mu.Unlock()
			return nil, &tier8RuntimeFactoryError{Leaf: leaf, Attempt: 1, Stage: "negative-control"}
		},
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	conn, dialErr := runtime.Dial(ctx, rendr.SessionConfig{Root: rendr.Selector("negative-root", []rendr.Target{
		rendr.Selector("negative-normalized", []rendr.Target{
			rendr.Path("negative-A", rendr.PathSpec{Transport: "tier8-all-fail", Address: "A"}),
		}),
		rendr.Path("negative-B", rendr.PathSpec{Transport: "tier8-all-fail", Address: "B"}),
	})})
	if conn != nil {
		_ = conn.Close()
		t.Fatal("all-leaves-fail negative control returned a connection")
	}
	var typed *tier8RuntimeFactoryError
	if !errors.As(dialErr, &typed) || typed.Leaf != "B" || typed.Stage != "negative-control" ||
		errors.Is(dialErr, context.DeadlineExceeded) {
		t.Fatalf("all-leaves-fail error=%v typed=%+v", dialErr, typed)
	}
	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()
	return got, typed.Leaf
}

func tier8PathSpec(leaf string) rendr.PathSpec {
	return rendr.PathSpec{Transport: "tier8-stream", Address: leaf}
}

func tier8RoundTrip(conn net.Conn, payload []byte) error {
	deadline := time.Now().Add(5 * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})
	written := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, bytes.NewReader(payload))
		written <- err
	}()
	received := make([]byte, len(payload))
	_, readErr := io.ReadFull(conn, received)
	writeErr := <-written
	if writeErr != nil {
		return fmt.Errorf("write: %w", writeErr)
	}
	if readErr != nil {
		return fmt.Errorf("read: %w", readErr)
	}
	if sha256.Sum256(received) != sha256.Sum256(payload) {
		return errors.New("payload SHA-256 mismatch")
	}
	return nil
}

func tier8Payload(salt byte, size int) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte((index*43 + int(salt)) % 251)
	}
	return payload
}

func tier8AttachedStatusByName(status rendr.Status) map[string]rendr.PathStatus {
	result := make(map[string]rendr.PathStatus, len(status.Paths))
	for _, path := range status.Paths {
		if path.State == rendr.PathAttached {
			result[path.Name] = path
		}
	}
	return result
}

func tier8DataWritesByName(paths []rendr.PathInfo) map[string]uint64 {
	result := make(map[string]uint64, len(paths))
	for _, path := range paths {
		result[path.Spec.Opts["name"]] = path.DataWrites
	}
	return result
}

func tier8EffectivePathNames(status rendr.Status) []string {
	byID := make(map[uint32]string, len(status.Paths))
	for _, path := range status.Paths {
		byID[path.ID] = path.Name
	}
	names := make([]string, 0, len(status.EffectivePaths))
	for _, id := range status.EffectivePaths {
		names = append(names, byID[id])
	}
	sort.Strings(names)
	return names
}

func tier8ObjectToken(t *testing.T, value any) uintptr {
	t.Helper()
	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.Pointer || reflected.IsNil() {
		t.Fatalf("application object has non-pointer dynamic type %T", value)
	}
	return reflected.Pointer()
}

func tier8WaitSignal(ctx context.Context, signal <-chan struct{}, description string) error {
	select {
	case <-signal:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for %s: %w", description, ctx.Err())
	}
}

func tier8Wait(ctx context.Context, condition func() (bool, string)) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	last := "condition not observed"
	for {
		if ok, detail := condition(); ok {
			return nil
		} else if detail != "" {
			last = detail
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for condition (%s): %w", last, ctx.Err())
		case <-ticker.C:
		}
	}
}

func tier8EmitRuntimeEvidence(t *testing.T, evidence map[string]string) {
	t.Helper()
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(tier8RuntimeEvidenceMarker + string(encoded))
}
