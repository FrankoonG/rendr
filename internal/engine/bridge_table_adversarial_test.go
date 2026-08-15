package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type observedDoneContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func TestBridgeTableConcurrentDuplicateReserve(t *testing.T) {
	table := NewBridgeTableWithCapacity(1)
	id := [16]byte{0x11}
	const contenders = 64
	start := make(chan struct{})
	var successes atomic.Int32
	var duplicates atomic.Int32
	var wg sync.WaitGroup
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := table.Reserve(id)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrBridgeDuplicate):
				duplicates.Add(1)
			default:
				t.Errorf("Reserve returned unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful reservations = %d, want 1", got)
	}
	if got := duplicates.Load(); got != contenders-1 {
		t.Fatalf("duplicate rejections = %d, want %d", got, contenders-1)
	}
	if got := table.Len(); got != 1 {
		t.Fatalf("table length = %d, want 1", got)
	}
}

func TestBridgeTableReservationPublicationAndCapacityCleanup(t *testing.T) {
	table := NewBridgeTableWithCapacity(1)
	firstID := [16]byte{0x21}
	secondID := [16]byte{0x22}
	reservation, err := table.Reserve(firstID)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := table.Lookup(firstID); ok || e != nil {
		t.Fatalf("reserved entry leaked engine: (%p, %v)", e, ok)
	}
	if got := table.Snapshot(); len(got) != 0 {
		t.Fatalf("reserved entry leaked through Snapshot: %v", got)
	}
	if _, err := table.Reserve(secondID); !errors.Is(err, ErrBridgeTableFull) {
		t.Fatalf("Reserve beyond capacity error = %v, want %v", err, ErrBridgeTableFull)
	}
	if !table.Abort(reservation) {
		t.Fatal("matching abort did not release reservation")
	}
	if table.Abort(reservation) {
		t.Fatal("repeated abort reported a second transition")
	}

	replacement, err := table.Reserve(secondID)
	if err != nil {
		t.Fatalf("capacity was not reclaimed after abort: %v", err)
	}
	e := new(Engine)
	if err := table.Activate(replacement, e); err != nil {
		t.Fatal(err)
	}
	if got, ok := table.Lookup(secondID); !ok || got != e {
		t.Fatalf("active lookup = (%p, %v), want (%p, true)", got, ok, e)
	}
	if !table.RemoveActive(replacement, e) {
		t.Fatal("matching active removal failed")
	}
	if got := table.Len(); got != 0 {
		t.Fatalf("table length after cleanup = %d, want 0", got)
	}
}

func TestBridgeTableStaleOperationsCannotCrossGeneration(t *testing.T) {
	table := NewBridgeTableWithCapacity(1)
	proposal := [16]byte{0x31}
	firstSession := [16]byte{0x32}
	secondSession := [16]byte{0x33}
	stale, err := table.Reserve(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if !table.Abort(stale) {
		t.Fatal("initial abort failed")
	}
	current, err := table.Reserve(proposal)
	if err != nil {
		t.Fatal(err)
	}
	staleEngine := new(Engine)
	currentEngine := new(Engine)
	if err := table.Activate(stale, staleEngine); !errors.Is(err, ErrBridgeStaleReservation) {
		t.Fatalf("stale Activate error = %v, want %v", err, ErrBridgeStaleReservation)
	}
	if table.Abort(stale) {
		t.Fatal("stale Abort removed current reservation")
	}
	if err := table.ActivateSession(current, firstSession, currentEngine); err != nil {
		t.Fatal(err)
	}
	if table.RemoveActive(current, staleEngine) {
		t.Fatal("wrong-engine removal succeeded")
	}
	if table.RemoveActive(stale, staleEngine) {
		t.Fatal("stale-generation removal succeeded")
	}
	if got, ok := table.Lookup(proposal); !ok || got != currentEngine {
		t.Fatalf("current engine was disturbed: (%p, %v)", got, ok)
	}
	if got, ok := table.Lookup(firstSession); !ok || got != currentEngine {
		t.Fatalf("final session lookup = (%p, %v), want (%p, true)", got, ok, currentEngine)
	}
	if !table.RemoveActive(current, currentEngine) {
		t.Fatal("current generation removal failed")
	}
	if _, ok := table.Lookup(firstSession); ok {
		t.Fatal("removed final session remains published")
	}
	next, err := table.Reserve(proposal)
	if err != nil {
		t.Fatalf("proposal reuse: %v", err)
	}
	nextEngine := new(Engine)
	if err := table.ActivateSession(next, secondSession, nextEngine); err != nil {
		t.Fatalf("activate replacement session: %v", err)
	}
	if table.RemoveActive(current, currentEngine) {
		t.Fatal("repeated old cleanup removed replacement session")
	}
	if got, ok := table.Lookup(secondSession); !ok || got != nextEngine {
		t.Fatalf("replacement final lookup = (%p, %v), want (%p, true)", got, ok, nextEngine)
	}
}

func TestBridgeTableServerAssignedSessionEpochPreventsResurrection(t *testing.T) {
	table := NewBridgeTableWithCapacity(1)
	proposal := [16]byte{0x41}
	firstSession := [16]byte{0x42}
	secondSession := [16]byte{0x43}
	first, err := table.Reserve(proposal)
	if err != nil {
		t.Fatal(err)
	}
	firstEngine := new(Engine)
	if err := table.ActivateSession(first, firstSession, firstEngine); err != nil {
		t.Fatal(err)
	}
	for _, id := range [][16]byte{proposal, firstSession} {
		if got, ok := table.Lookup(id); !ok || got != firstEngine {
			t.Fatalf("first lookup %x = (%p, %v), want (%p, true)", id, got, ok, firstEngine)
		}
	}
	if !table.RemoveActive(first, firstEngine) {
		t.Fatal("first removal failed")
	}
	second, err := table.Reserve(proposal)
	if err != nil {
		t.Fatalf("proposal reuse: %v", err)
	}
	secondEngine := new(Engine)
	if err := table.ActivateSession(second, secondSession, secondEngine); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(firstSession); ok {
		t.Fatal("old final epoch resolved after proposal reuse")
	}
	if got, ok := table.Lookup(secondSession); !ok || got != secondEngine {
		t.Fatalf("second final lookup = (%p, %v), want (%p, true)", got, ok, secondEngine)
	}
	if table.RemoveActive(first, firstEngine) {
		t.Fatal("stale reservation removed replacement session")
	}
}

func TestBridgeTableAssignSessionReservesFinalEpochBeforeActivation(t *testing.T) {
	table := NewBridgeTableWithCapacity(2)
	first, err := table.Reserve([16]byte{0x51})
	if err != nil {
		t.Fatal(err)
	}
	second, err := table.Reserve([16]byte{0x52})
	if err != nil {
		t.Fatal(err)
	}
	final := [16]byte{0x53}
	if err := table.AssignSession(first, final); err != nil {
		t.Fatal(err)
	}
	if err := table.AssignSession(first, final); err != nil {
		t.Fatalf("idempotent assignment: %v", err)
	}
	if err := table.AssignSession(second, final); !errors.Is(err, ErrBridgeSessionConflict) {
		t.Fatalf("colliding assignment error=%v want=%v", err, ErrBridgeSessionConflict)
	}
	if !table.Abort(first) {
		t.Fatal("abort assigned reservation failed")
	}
	if err := table.AssignSession(second, final); err != nil {
		t.Fatalf("released final epoch remained reserved: %v", err)
	}
}

func TestBridgeTableWaitActiveFollowsReservedFinalEpoch(t *testing.T) {
	table := NewBridgeTableWithCapacity(1)
	proposal := [16]byte{0x61}
	final := [16]byte{0x62}
	reservation, err := table.Reserve(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if err := table.AssignSession(reservation, final); err != nil {
		t.Fatal(err)
	}
	type waitResult struct {
		engine *Engine
		state  BridgeEntryState
		err    error
	}
	result := make(chan waitResult, 1)
	baseCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx := &observedDoneContext{Context: baseCtx, observed: make(chan struct{})}
	go func() {
		engine, state, err := table.WaitActive(ctx, final)
		result <- waitResult{engine: engine, state: state, err: err}
	}()
	<-ctx.observed
	active := new(Engine)
	if err := table.ActivateSession(reservation, final, active); err != nil {
		t.Fatal(err)
	}
	got := <-result
	if got.err != nil || got.state != BridgeEntryActive || got.engine != active {
		t.Fatalf("final wait=(%p,%v,%v), want (%p,%v,nil)", got.engine, got.state, got.err, active, BridgeEntryActive)
	}
}

func TestBridgeTableWaitActiveWakeCancelAndUnknown(t *testing.T) {
	table := NewBridgeTableWithCapacity(3)
	unknownID := [16]byte{0x41}
	if e, state, err := table.WaitActive(context.Background(), unknownID); err != nil || state != BridgeEntryAbsent || e != nil {
		t.Fatalf("unknown wait = (%p, %v, %v), want (nil, absent, nil)", e, state, err)
	}

	activateID := [16]byte{0x42}
	activateReservation, err := table.Reserve(activateID)
	if err != nil {
		t.Fatal(err)
	}
	type waitResult struct {
		e     *Engine
		state BridgeEntryState
		err   error
	}
	result := make(chan waitResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		e, state, err := table.WaitActive(ctx, activateID)
		result <- waitResult{e: e, state: state, err: err}
	}()
	select {
	case got := <-result:
		t.Fatalf("wait returned before activation: %+v", got)
	case <-time.After(20 * time.Millisecond):
	}
	activeEngine := new(Engine)
	if err := table.Activate(activateReservation, activeEngine); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got.err != nil || got.state != BridgeEntryActive || got.e != activeEngine {
			t.Fatalf("activation wait = (%p, %v, %v)", got.e, got.state, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("activation did not wake waiter")
	}

	cancelID := [16]byte{0x43}
	if _, err := table.Reserve(cancelID); err != nil {
		t.Fatal(err)
	}
	canceled, cancelWait := context.WithCancel(context.Background())
	cancelWait()
	if e, state, err := table.WaitActive(canceled, cancelID); !errors.Is(err, context.Canceled) || state != BridgeEntryReserved || e != nil {
		t.Fatalf("canceled reserved wait = (%p, %v, %v)", e, state, err)
	}
	if e, ok := table.Lookup(cancelID); ok || e != nil {
		t.Fatalf("canceled wait published reservation: (%p, %v)", e, ok)
	}
}

func TestBridgeTableAbortWakesWaiterWithoutFollowingABA(t *testing.T) {
	table := NewBridgeTableWithCapacity(1)
	id := [16]byte{0x51}
	first, err := table.Reserve(id)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	baseCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx := &observedDoneContext{Context: baseCtx, observed: make(chan struct{})}
	go func() {
		e, state, err := table.WaitActive(ctx, id)
		if e != nil {
			result <- errors.New("wait exposed an Engine from another generation")
			return
		}
		if err == nil && state != BridgeEntryAbsent {
			result <- errors.New("aborted wait returned a non-absent state")
			return
		}
		if err != nil && !errors.Is(err, ErrBridgeReservationReplaced) {
			result <- err
			return
		}
		result <- nil
	}()
	<-ctx.observed
	if !table.Abort(first) {
		t.Fatal("abort failed")
	}
	second, err := table.Reserve(id)
	if err != nil {
		t.Fatal(err)
	}
	secondEngine := new(Engine)
	if err := table.Activate(second, secondEngine); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("abort did not wake waiter")
	}
	if got, ok := table.Lookup(id); !ok || got != secondEngine {
		t.Fatalf("replacement engine was disturbed: (%p, %v)", got, ok)
	}
}

func TestBridgeTableRejectsForeignAndZeroReservations(t *testing.T) {
	first := NewBridgeTableWithCapacity(1)
	second := NewBridgeTableWithCapacity(1)
	id := [16]byte{0x71}
	reservation, err := first.Reserve(id)
	if err != nil {
		t.Fatal(err)
	}
	e := new(Engine)
	if err := second.Activate(reservation, e); !errors.Is(err, ErrBridgeStaleReservation) {
		t.Fatalf("foreign Activate error = %v, want %v", err, ErrBridgeStaleReservation)
	}
	if err := first.Activate(BridgeReservation{}, e); !errors.Is(err, ErrBridgeStaleReservation) {
		t.Fatalf("zero-token Activate error = %v, want %v", err, ErrBridgeStaleReservation)
	}
	if err := first.Activate(reservation, nil); !errors.Is(err, ErrBridgeInvalidEngine) {
		t.Fatalf("nil-engine Activate error = %v, want %v", err, ErrBridgeInvalidEngine)
	}
	if !first.Abort(reservation) {
		t.Fatal("cleanup abort failed")
	}
}

func TestBridgeTableCancellationWinsOverConcurrentActivation(t *testing.T) {
	for iteration := 0; iteration < 1000; iteration++ {
		table := NewBridgeTableWithCapacity(1)
		flowID := [16]byte{byte(iteration), byte(iteration >> 8), 1}
		reservation, err := table.Reserve(flowID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		type result struct {
			engine *Engine
			state  BridgeEntryState
			err    error
		}
		resultCh := make(chan result, 1)
		go func() {
			engine, state, err := table.WaitActive(ctx, flowID)
			resultCh <- result{engine: engine, state: state, err: err}
		}()
		cancel()
		active := &Engine{}
		if err := table.Activate(reservation, active); err != nil {
			t.Fatal(err)
		}
		got := <-resultCh
		if !errors.Is(got.err, context.Canceled) || got.engine != nil {
			t.Fatalf("iteration %d result=(%p,%v,%v), want cancellation without engine", iteration, got.engine, got.state, got.err)
		}
		if !table.RemoveActive(reservation, active) {
			t.Fatalf("iteration %d failed active cleanup", iteration)
		}
	}
}
