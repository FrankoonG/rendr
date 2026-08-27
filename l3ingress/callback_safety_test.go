package l3ingress

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type hostileL3PanicPayload struct{}

func (hostileL3PanicPayload) String() string { panic("panic payload was formatted") }

func TestFlowTableRouterAbnormalExitsAreTyped(t *testing.T) {
	tests := []struct {
		name   string
		router FlowDecisionFunc
		reason CallbackFailureReason
	}{
		{
			name: "panic",
			router: func(context.Context, FlowMeta) (FlowDecision, error) {
				panic(hostileL3PanicPayload{})
			},
			reason: CallbackFailurePanic,
		},
		{
			name: "goexit",
			router: func(context.Context, FlowMeta) (FlowDecision, error) {
				runtime.Goexit()
				return FlowDecision{}, nil
			},
			reason: CallbackFailureGoexit,
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			table := NewFlowTable(test.router, FlowTableOptions{})
			_, created, _, err := table.Resolve(context.Background(), FlowMeta{
				L3Identity: flowTableTestIdentity(uint16(12000 + index)),
				Direction:  DirectionIngress,
			}, 1)
			if created {
				t.Fatal("abnormal router callback created a flow")
			}
			var callbackErr *CallbackError
			if !errors.As(err, &callbackErr) || callbackErr.Reason != test.reason {
				t.Fatalf("error=%v callback=%+v want reason %q", err, callbackErr, test.reason)
			}
			if test.reason == CallbackFailurePanic && callbackErr.PanicType != "l3ingress.hostileL3PanicPayload" {
				t.Fatalf("panic type=%q", callbackErr.PanicType)
			}
			_ = callbackErr.Error()
			table.mu.Lock()
			active, pending := len(table.active), len(table.pending)
			table.mu.Unlock()
			if active != 0 || pending != 0 {
				t.Fatalf("abnormal callback retained table state active=%d pending=%d", active, pending)
			}
		})
	}
}

func TestFlowTableRouterTimeoutBoundsWorkersAndRejectsLateResult(t *testing.T) {
	const timeout = 15 * time.Millisecond
	release := make(chan struct{})
	var calls atomic.Int32
	table := NewFlowTable(func(context.Context, FlowMeta) (FlowDecision, error) {
		if calls.Add(1) == 1 {
			<-release
			return FlowDecision{Peer: "stale"}, nil
		}
		return FlowDecision{Peer: "fresh"}, nil
	}, FlowTableOptions{
		routerConcurrency: 8,
		RouterTimeout:     timeout,
	})
	id := flowTableTestIdentity(12100)
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, created, _, err := table.Resolve(canceledCtx, FlowMeta{
		L3Identity: flowTableTestIdentity(12099),
		Direction:  DirectionIngress,
	}, 1)
	if created || !errors.Is(err, context.Canceled) || calls.Load() != 0 {
		t.Fatalf("pre-canceled resolve created/calls/error=%t/%d/%v", created, calls.Load(), err)
	}

	started := time.Now()
	_, created, _, err = table.Resolve(context.Background(), FlowMeta{
		L3Identity: id,
		Direction:  DirectionIngress,
	}, 1)
	if created {
		t.Fatal("timed-out callback created a flow")
	}
	assertL3CallbackReason(t, err, CallbackFailureTimeout)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("router timeout took %v", elapsed)
	}
	otherID := flowTableTestIdentity(12101)
	decision, otherCreated, _, otherErr := table.Resolve(context.Background(), FlowMeta{
		L3Identity: otherID,
		Direction:  DirectionIngress,
	}, 1)
	if otherErr != nil || !otherCreated || decision.Peer != "fresh" {
		t.Fatalf("different-flow resolve decision=%+v created=%t error=%v", decision, otherCreated, otherErr)
	}
	table.Close(otherID, FlowCloseManual)

	for i := 0; i < 256; i++ {
		_, created, _, err = table.Resolve(context.Background(), FlowMeta{
			L3Identity: id,
			Direction:  DirectionIngress,
		}, 1)
		if created {
			t.Fatalf("saturated callback %d created a flow", i)
		}
		assertL3CallbackReason(t, err, CallbackFailureSaturated)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("router calls=%d want blocked flow + independent flow", got)
	}
	table.mu.Lock()
	active, pending := len(table.active), len(table.pending)
	table.mu.Unlock()
	if active != 0 || pending != 0 {
		t.Fatalf("timed-out callback retained state active=%d pending=%d", active, pending)
	}

	close(release)
	waitForL3Condition(t, time.Second, func() bool { return len(table.routerSlots) == 0 }, "router slot release")
	decision, created, snapshot, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: id,
		Direction:  DirectionIngress,
	}, 2)
	if err != nil || !created || decision.Peer != "fresh" {
		t.Fatalf("replacement resolve decision=%+v created=%v snapshot=%+v err=%v", decision, created, snapshot, err)
	}
	if snapshot.Ref.Generation <= 1 || snapshot.Packets != 1 || snapshot.Bytes != 2 {
		t.Fatalf("late callback polluted replacement snapshot: %+v", snapshot)
	}
}

func TestFlowTableSameFlowWaitersShareFailedRoutingOutcome(t *testing.T) {
	const waiterCount = 32
	routerEntered := make(chan struct{})
	releaseRouter := make(chan struct{})
	wantErr := errors.New("route rejected")
	var calls atomic.Int32
	table := NewFlowTable(func(context.Context, FlowMeta) (FlowDecision, error) {
		if calls.Add(1) == 1 {
			close(routerEntered)
		}
		<-releaseRouter
		return FlowDecision{}, wantErr
	}, FlowTableOptions{})
	id := flowTableTestIdentity(12150)
	results := make(chan error, waiterCount+1)
	resolve := func() {
		_, _, _, err := table.Resolve(context.Background(), FlowMeta{
			L3Identity: id,
			Direction:  DirectionIngress,
		}, 1)
		results <- err
	}
	go resolve()
	select {
	case <-routerEntered:
	case <-time.After(time.Second):
		t.Fatal("router did not start")
	}
	for range waiterCount {
		go resolve()
	}
	waitForL3Condition(t, time.Second, func() bool {
		table.mu.Lock()
		pending := table.pending[id]
		table.mu.Unlock()
		return pending != nil && pending.waiters.Load() == waiterCount
	}, "same-flow waiters")
	close(releaseRouter)
	for range waiterCount + 1 {
		if err := <-results; !errors.Is(err, wantErr) {
			t.Fatalf("shared routing error=%v want %v", err, wantErr)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("router calls=%d want 1", got)
	}
}

func TestFlowObserverAbnormalAndBlockedCallbacksAreContained(t *testing.T) {
	const timeout = 15 * time.Millisecond
	release := make(chan struct{})
	var calls atomic.Int32
	table := NewFlowTable(nil, FlowTableOptions{
		ObserverTimeout: timeout,
		Observer: FlowObserverFunc(func(FlowSnapshot) {
			switch calls.Add(1) {
			case 1:
				<-release
			case 2:
				runtime.Goexit()
			case 3:
				panic(hostileL3PanicPayload{})
			}
		}),
	})
	id := flowTableTestIdentity(12200)
	started := time.Now()
	_, _, snapshot, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: id,
		Direction:  DirectionIngress,
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("blocked observer delayed Resolve for %v", elapsed)
	}
	if _, ok := table.RecordPathSelectionRef(snapshot.Ref, []string{"a"}); !ok {
		t.Fatal("blocked observer prevented state update")
	}
	status := table.CallbackStatus()
	if status.Timeouts != 1 || status.Drops != 1 || calls.Load() != 1 {
		t.Fatalf("blocked observer status=%+v calls=%d", status, calls.Load())
	}

	close(release)
	waitForL3Condition(t, time.Second, func() bool { return !table.observerBusy.Load() }, "observer release")
	if _, ok := table.RecordMigrationRef(snapshot.Ref, []string{"b"}); !ok {
		t.Fatal("Goexit observer prevented migration record")
	}
	status = table.CallbackStatus()
	if status.Goexits != 1 || table.observerBusy.Load() {
		t.Fatalf("Goexit observer status=%+v busy=%v", status, table.observerBusy.Load())
	}
	if _, ok := table.RecordMigrationRef(snapshot.Ref, []string{"c"}); !ok {
		t.Fatal("panic observer prevented migration record")
	}
	status = table.CallbackStatus()
	if status.Panics != 1 || status.LastFailure.PanicType != "l3ingress.hostileL3PanicPayload" {
		t.Fatalf("panic observer status=%+v", status)
	}
	_ = status.LastFailure.Error()
	if _, ok := table.RecordMigrationRef(snapshot.Ref, []string{"d"}); !ok || calls.Load() != 4 {
		t.Fatalf("observer slot was not reusable ok=%v calls=%d", ok, calls.Load())
	}
}

func TestAuthoritativeCallbackConcurrencyIsProcessBoundedAcrossObjects(t *testing.T) {
	const processLimit = l3IngressProcessCallbackLimit
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseCallbacks := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseCallbacks()

	var started atomic.Int32
	var returned sync.WaitGroup
	returned.Add(processLimit)
	type resolveResult struct {
		index int
		err   error
	}
	results := make(chan resolveResult, processLimit)
	cancels := make([]context.CancelFunc, processLimit/2)
	for i := 0; i < processLimit; i++ {
		ctx := context.Background()
		if i < len(cancels) {
			ctx, cancels[i] = context.WithCancel(ctx)
		}
		table := NewFlowTable(func(context.Context, FlowMeta) (FlowDecision, error) {
			started.Add(1)
			defer returned.Done()
			<-release
			return FlowDecision{Peer: "late"}, nil
		}, FlowTableOptions{RouterTimeout: 200 * time.Millisecond})
		go func(index int, table *FlowTable, ctx context.Context) {
			_, _, _, err := table.Resolve(ctx, FlowMeta{
				L3Identity: flowTableTestIdentity(uint16(13000 + index)),
				Direction:  DirectionIngress,
			}, 1)
			results <- resolveResult{index: index, err: err}
		}(i, table, ctx)
	}
	waitForL3Condition(t, 2*time.Second, func() bool {
		return started.Load() == processLimit
	}, "process-wide authoritative callback saturation")
	for _, cancel := range cancels {
		cancel()
	}
	for i := 0; i < processLimit; i++ {
		result := <-results
		if result.index < len(cancels) {
			if !errors.Is(result.err, context.Canceled) {
				t.Fatalf("canceled resolve %d error=%v", result.index, result.err)
			}
			continue
		}
		assertL3CallbackReason(t, result.err, CallbackFailureTimeout)
	}

	var extraCalls atomic.Int32
	extraPump := &Pump{}
	executor := newPacketHandlerExecutor(PacketHandlerFunc(func(context.Context, PacketEvent) error {
		extraCalls.Add(1)
		return nil
	}), &extraPump.handlerBusy)
	defer executor.Close()
	err := extraPump.invokePacketHandler(context.Background(), executor, PacketEvent{}, time.Second)
	assertL3CallbackReason(t, err, CallbackFailureSaturated)
	if extraCalls.Load() != 0 {
		t.Fatalf("callback ran beyond process limit: calls=%d", extraCalls.Load())
	}

	releaseCallbacks()
	returned.Wait()
	waitForL3Condition(t, time.Second, func() bool {
		err = extraPump.invokePacketHandler(context.Background(), executor, PacketEvent{}, time.Second)
		return err == nil
	}, "authoritative process permit release")
	if extraCalls.Load() != 1 {
		t.Fatalf("callback permit was not reusable: calls=%d", extraCalls.Load())
	}
}

func TestPacketHandlerConcurrencyIsProcessBoundedAcrossPumps(t *testing.T) {
	const processLimit = l3IngressProcessCallbackLimit
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseCallbacks := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseCallbacks()

	var started atomic.Int32
	var returned sync.WaitGroup
	returned.Add(processLimit)
	type handlerResult struct {
		index int
		err   error
	}
	results := make(chan handlerResult, processLimit)
	cancels := make([]context.CancelFunc, processLimit/2)
	executors := make([]*packetHandlerExecutor, 0, processLimit)
	for i := 0; i < processLimit; i++ {
		ctx := context.Background()
		if i < len(cancels) {
			ctx, cancels[i] = context.WithCancel(ctx)
		}
		pump := &Pump{}
		executor := newPacketHandlerExecutor(PacketHandlerFunc(func(context.Context, PacketEvent) error {
			started.Add(1)
			defer returned.Done()
			<-release
			return nil
		}), &pump.handlerBusy)
		executors = append(executors, executor)
		go func(index int, pump *Pump, executor *packetHandlerExecutor, ctx context.Context) {
			err := pump.invokePacketHandler(ctx, executor, PacketEvent{}, 200*time.Millisecond)
			results <- handlerResult{index: index, err: err}
		}(i, pump, executor, ctx)
	}
	defer func() {
		for _, executor := range executors {
			executor.Close()
		}
	}()
	waitForL3Condition(t, 2*time.Second, func() bool {
		return started.Load() == processLimit
	}, "process-wide packet handler saturation")
	for _, cancel := range cancels {
		cancel()
	}
	for i := 0; i < processLimit; i++ {
		result := <-results
		if result.index < len(cancels) {
			if !errors.Is(result.err, context.Canceled) {
				t.Fatalf("canceled handler %d error=%v", result.index, result.err)
			}
			continue
		}
		assertL3CallbackReason(t, result.err, CallbackFailureTimeout)
	}

	var routerCalls atomic.Int32
	extraTable := NewFlowTable(func(context.Context, FlowMeta) (FlowDecision, error) {
		routerCalls.Add(1)
		return FlowDecision{Peer: "available"}, nil
	}, FlowTableOptions{})
	flow := FlowMeta{
		L3Identity: flowTableTestIdentity(13500),
		Direction:  DirectionIngress,
	}
	_, created, _, err := extraTable.Resolve(context.Background(), flow, 1)
	if created {
		t.Fatal("router created a flow beyond the process callback limit")
	}
	assertL3CallbackReason(t, err, CallbackFailureSaturated)
	if routerCalls.Load() != 0 {
		t.Fatalf("router ran beyond process limit: calls=%d", routerCalls.Load())
	}

	releaseCallbacks()
	returned.Wait()
	waitForL3Condition(t, time.Second, func() bool {
		_, created, _, err = extraTable.Resolve(context.Background(), flow, 1)
		return err == nil && created
	}, "packet handler process permit release")
	if routerCalls.Load() != 1 {
		t.Fatalf("authoritative permit was not reusable: calls=%d", routerCalls.Load())
	}
}

func TestOptionalCallbackConcurrencyIsProcessBoundedAndSeparateFromAuthority(t *testing.T) {
	const processLimit = l3IngressProcessCallbackLimit
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseCallbacks := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseCallbacks()

	var started atomic.Int32
	var returned sync.WaitGroup
	returned.Add(processLimit)
	resolved := make(chan error, processLimit)
	for i := 0; i < processLimit; i++ {
		table := NewFlowTable(nil, FlowTableOptions{
			ObserverTimeout: 100 * time.Millisecond,
			Observer: FlowObserverFunc(func(FlowSnapshot) {
				started.Add(1)
				defer returned.Done()
				<-release
			}),
		})
		go func(index int, table *FlowTable) {
			_, _, _, err := table.Resolve(context.Background(), FlowMeta{
				L3Identity: flowTableTestIdentity(uint16(14000 + index)),
				Direction:  DirectionIngress,
			}, 1)
			resolved <- err
		}(i, table)
	}
	waitForL3Condition(t, 2*time.Second, func() bool {
		return started.Load() == processLimit
	}, "process-wide optional callback saturation")
	for i := 0; i < processLimit; i++ {
		if err := <-resolved; err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
	}

	var extraCalls atomic.Int32
	extraTable := NewFlowTable(nil, FlowTableOptions{
		Observer: FlowObserverFunc(func(FlowSnapshot) { extraCalls.Add(1) }),
	})
	_, _, snapshot, err := extraTable.Resolve(context.Background(), FlowMeta{
		L3Identity: flowTableTestIdentity(15000),
		Direction:  DirectionIngress,
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	status := extraTable.CallbackStatus()
	if extraCalls.Load() != 0 || status.Drops != 1 || status.LastFailure.Reason != CallbackFailureSaturated {
		t.Fatalf("optional process bound calls=%d status=%+v", extraCalls.Load(), status)
	}
	var parseCalls atomic.Int32
	var failureCalls atomic.Int32
	extraPump := &Pump{}
	extraPump.observeParseError(func([]byte, error) { parseCalls.Add(1) }, []byte{0}, errors.New("invalid"), time.Second)
	extraPump.recordPacketFailure(func(PacketFailure) { failureCalls.Add(1) }, PacketFailure{
		Stage: PacketFailureHandle,
		Err:   errors.New("failed"),
	})
	pumpStatus := extraPump.Status()
	if parseCalls.Load() != 0 || failureCalls.Load() != 0 ||
		pumpStatus.ParseObserver.Drops != 1 || pumpStatus.FailureObserver.Drops != 1 {
		t.Fatalf("optional Pump callbacks escaped process bound parse=%d failure=%d status=%+v",
			parseCalls.Load(), failureCalls.Load(), pumpStatus)
	}

	authoritative := NewFlowTable(func(context.Context, FlowMeta) (FlowDecision, error) {
		return FlowDecision{Peer: "available"}, nil
	}, FlowTableOptions{})
	decision, created, _, err := authoritative.Resolve(context.Background(), FlowMeta{
		L3Identity: flowTableTestIdentity(15001),
		Direction:  DirectionIngress,
	}, 1)
	if err != nil || !created || decision.Peer != "available" {
		t.Fatalf("optional saturation starved authority decision=%+v created=%v err=%v", decision, created, err)
	}

	releaseCallbacks()
	returned.Wait()
	waitForL3Condition(t, time.Second, func() bool {
		_, ok := extraTable.RecordMigrationRef(snapshot.Ref, []string{"reused"})
		return ok && extraCalls.Load() == 1
	}, "optional process permit release")
}

func TestPumpPacketHandlerAbnormalExitsArePacketLocal(t *testing.T) {
	packet := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 1234, 53)
	var calls atomic.Int32
	pump := &Pump{
		Device: &fakeDevice{packets: [][]byte{packet, packet, packet}},
		Handler: PacketHandlerFunc(func(context.Context, PacketEvent) error {
			switch calls.Add(1) {
			case 1:
				panic(hostileL3PanicPayload{})
			case 2:
				runtime.Goexit()
			}
			return nil
		}),
	}
	if err := pump.Run(context.Background()); err != nil {
		t.Fatalf("Run stopped on packet-local callback failure: %v", err)
	}
	status := pump.Status()
	if calls.Load() != 3 || status.PacketFailures != 2 {
		t.Fatalf("calls=%d status=%+v", calls.Load(), status)
	}
	assertL3CallbackReason(t, status.LastFailure.Err, CallbackFailureGoexit)
}

func TestPumpBlockedPacketHandlerHasOneOrphanAndNoLatePublication(t *testing.T) {
	packet := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 1234, 53)
	release := make(chan struct{})
	var calls atomic.Int32
	pump := &Pump{}
	executor := newPacketHandlerExecutor(PacketHandlerFunc(func(_ context.Context, event PacketEvent) error {
		calls.Add(1)
		<-release
		event.Packet[0] = 0
		return nil
	}), &pump.handlerBusy)
	event := PacketEvent{Packet: packet}
	started := time.Now()
	err := pump.invokePacketHandler(context.Background(), executor, event, 15*time.Millisecond)
	assertL3CallbackReason(t, err, CallbackFailureTimeout)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("blocked handler delayed invocation for %v", elapsed)
	}
	for i := 0; i < 256; i++ {
		err = pump.invokePacketHandler(context.Background(), executor, event, time.Second)
		assertL3CallbackReason(t, err, CallbackFailureSaturated)
	}
	if calls.Load() != 1 {
		t.Fatalf("blocked handler calls=%d want 1", calls.Load())
	}
	close(release)
	waitForL3Condition(t, time.Second, func() bool { return !pump.handlerBusy.Load() }, "handler release")
	executor.Close()
	if packet[0]>>4 != 4 {
		t.Fatalf("late handler mutated Pump-owned packet: version=%d", packet[0]>>4)
	}
}

func TestPumpHandlerTimeoutTerminatesRunAndCancelsCallback(t *testing.T) {
	packet := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 1234, 53)
	canceled := make(chan struct{})
	var calls atomic.Int32
	pump := &Pump{
		Device:         &fakeDevice{packets: [][]byte{packet, packet}},
		HandlerTimeout: 15 * time.Millisecond,
		Handler: PacketHandlerFunc(func(ctx context.Context, _ PacketEvent) error {
			calls.Add(1)
			<-ctx.Done()
			close(canceled)
			return ctx.Err()
		}),
	}
	err := pump.Run(context.Background())
	assertL3CallbackReason(t, err, CallbackFailureTimeout)
	status := pump.Status()
	if calls.Load() != 1 || status.PacketFailures != 1 {
		t.Fatalf("timed-out handler calls=%d status=%+v", calls.Load(), status)
	}
	assertL3CallbackReason(t, status.LastFailure.Err, CallbackFailureTimeout)
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("timed-out handler did not receive Pump cancellation")
	}
	waitForL3Condition(t, time.Second, func() bool { return !pump.handlerBusy.Load() }, "handler release")
}

func TestPumpPacketHandlerContextRetainsFlowLifetimeAfterReturn(t *testing.T) {
	packet := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 1234, 53)
	retained := make(chan context.Context, 1)
	device := &onePacketThenBlockDevice{packet: packet, waiting: make(chan struct{}, 1)}
	pump := &Pump{
		Device: device,
		Handler: PacketHandlerFunc(func(ctx context.Context, _ PacketEvent) error {
			retained <- ctx
			return nil
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pump.Run(ctx) }()
	callbackCtx := <-retained
	select {
	case <-device.waiting:
	case <-time.After(time.Second):
		t.Fatal("Pump did not continue after handler returned")
	}
	if err := callbackCtx.Err(); err != nil {
		t.Fatalf("successful handler return canceled retained flow context: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error=%v want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Pump did not stop after cancellation")
	}
	select {
	case <-callbackCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("retained handler context did not follow Pump lifetime")
	}
}

type onePacketThenBlockDevice struct {
	packet    []byte
	waiting   chan struct{}
	delivered bool
}

func (d *onePacketThenBlockDevice) Read(p []byte) (int, error) {
	return d.ReadContext(context.Background(), p)
}

func (d *onePacketThenBlockDevice) ReadContext(ctx context.Context, p []byte) (int, error) {
	if !d.delivered {
		d.delivered = true
		return copy(p, d.packet), nil
	}
	select {
	case d.waiting <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return 0, ctx.Err()
}

func (*onePacketThenBlockDevice) Write(p []byte) (int, error) { return len(p), nil }
func (*onePacketThenBlockDevice) Close() error                { return nil }
func (*onePacketThenBlockDevice) Name() string                { return "callback-lifetime0" }
func (*onePacketThenBlockDevice) MTU() int                    { return 1500 }

func TestPumpParseErrorObserverAbnormalAndBlockedCallbacksAreContained(t *testing.T) {
	t.Run("panic-and-goexit", func(t *testing.T) {
		var calls atomic.Int32
		pump := &Pump{
			Device: &fakeDevice{packets: [][]byte{{0}, {0}, {0}}},
			Handler: PacketHandlerFunc(func(context.Context, PacketEvent) error {
				t.Fatal("handler received an invalid packet")
				return nil
			}),
			OnParseError: func([]byte, error) {
				switch calls.Add(1) {
				case 1:
					panic(hostileL3PanicPayload{})
				case 2:
					runtime.Goexit()
				}
			},
		}
		if err := pump.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		status := pump.Status().ParseObserver
		if calls.Load() != 3 || status.Panics != 1 || status.Goexits != 1 ||
			status.LastFailure.Reason != CallbackFailureGoexit {
			t.Fatalf("calls=%d status=%+v", calls.Load(), status)
		}
	})

	t.Run("blocked", func(t *testing.T) {
		const packetCount = 256
		packets := make([][]byte, packetCount)
		for i := range packets {
			packets[i] = []byte{0}
		}
		release := make(chan struct{})
		var calls atomic.Int32
		pump := &Pump{
			Device:          &fakeDevice{packets: packets},
			ObserverTimeout: 15 * time.Millisecond,
			Handler:         PacketHandlerFunc(func(context.Context, PacketEvent) error { return nil }),
			OnParseError: func([]byte, error) {
				calls.Add(1)
				<-release
			},
		}
		if err := pump.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		status := pump.Status().ParseObserver
		if calls.Load() != 1 || status.Timeouts != 1 || status.Drops != packetCount-1 {
			t.Fatalf("calls=%d status=%+v", calls.Load(), status)
		}
		close(release)
		waitForL3Condition(t, time.Second, func() bool { return !pump.parseObserverBusy.Load() }, "parse observer release")
	})
}

func TestPumpFailureObserverGoexitIsTrackedAndSlotReused(t *testing.T) {
	var calls atomic.Int32
	observer := func(PacketFailure) {
		if calls.Add(1) == 1 {
			runtime.Goexit()
		}
	}
	pump := &Pump{}
	failure := PacketFailure{Stage: PacketFailureHandle, Err: errors.New("failed")}
	pump.recordPacketFailure(observer, failure)
	waitForL3Condition(t, time.Second, func() bool {
		return pump.Status().ObserverGoexits == 1 && !pump.observerBusy.Load()
	}, "failure observer Goexit")
	pump.recordPacketFailure(observer, failure)
	waitForL3Condition(t, time.Second, func() bool {
		return calls.Load() == 2 && !pump.observerBusy.Load()
	}, "failure observer slot reuse")
	status := pump.Status()
	if status.FailureObserver.Goexits != 1 || status.ObserverGoexits != 1 {
		t.Fatalf("failure observer status=%+v", status)
	}
}

func assertL3CallbackReason(t *testing.T, err error, want CallbackFailureReason) {
	t.Helper()
	var callbackErr *CallbackError
	if !errors.As(err, &callbackErr) || callbackErr.Reason != want {
		t.Fatalf("error=%v callback=%+v want reason %q", err, callbackErr, want)
	}
}

func waitForL3Condition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}
