package l3stack

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/l3session"
)

func TestFlowLifetimeTuningDefaultsValidationImmutabilityAndCadence(t *testing.T) {
	defaults := DefaultFlowLifetimeTuning()
	if defaults.UDPIdle != 30*time.Second ||
		defaults.TCPUnestablishedIdle != 10*time.Second ||
		defaults.ClosedRetention != 5*time.Minute {
		t.Fatalf("defaults=%+v", defaults)
	}
	device := newGatewayTestDevice(1500)
	gateway, err := New(Config{
		Device: device,
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Deny: true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gateway.flowLifetime != defaults || gateway.reapCadence != time.Second {
		t.Fatalf("normalized lifetime=%+v cadence=%s", gateway.flowLifetime, gateway.reapCadence)
	}
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	_ = device.Close()

	tuning := FlowLifetimeTuning{
		UDPIdle: 2 * time.Second, TCPUnestablishedIdle: 3 * time.Second, ClosedRetention: 4 * time.Second,
	}
	device = newGatewayTestDevice(1500)
	gateway, err = New(Config{
		Device: device,
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Deny: true}, nil
		},
		FlowLifetime: tuning,
	})
	if err != nil {
		t.Fatal(err)
	}
	tuning.UDPIdle = time.Hour
	if gateway.flowLifetime.UDPIdle != 2*time.Second {
		t.Fatalf("gateway lifetime changed with caller value: %+v", gateway.flowLifetime)
	}
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	_ = device.Close()

	for _, tt := range []struct {
		name   string
		tuning FlowLifetimeTuning
	}{
		{name: "udp", tuning: FlowLifetimeTuning{UDPIdle: -time.Nanosecond}},
		{name: "tcp", tuning: FlowLifetimeTuning{TCPUnestablishedIdle: -time.Nanosecond}},
		{name: "closed", tuning: FlowLifetimeTuning{ClosedRetention: -time.Nanosecond}},
	} {
		t.Run("negative-"+tt.name, func(t *testing.T) {
			_, err := New(Config{
				Device: newGatewayTestDevice(1500),
				Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
					return l3ingress.FlowDecision{}, nil
				},
				FlowLifetime: tt.tuning,
			})
			if err == nil {
				t.Fatal("negative lifetime was accepted")
			}
		})
	}

	for _, tt := range []struct {
		name     string
		shortest time.Duration
		want     time.Duration
	}{
		{name: "minimum", shortest: 4 * time.Millisecond, want: 10 * time.Millisecond},
		{name: "quarter", shortest: 200 * time.Millisecond, want: 50 * time.Millisecond},
		{name: "maximum", shortest: 8 * time.Second, want: time.Second},
	} {
		t.Run("cadence-"+tt.name, func(t *testing.T) {
			got := flowReapCadence(FlowLifetimeTuning{
				UDPIdle: tt.shortest, TCPUnestablishedIdle: time.Minute, ClosedRetention: time.Hour,
			})
			if got != tt.want {
				t.Fatalf("cadence=%s want %s", got, tt.want)
			}
		})
	}
}

func TestGatewayUDPIdleReapUsesIngressReplyAndInFlightActivity(t *testing.T) {
	base := time.Unix(30_000, 0)
	now := base
	table := l3ingress.NewFlowTable(nil, l3ingress.FlowTableOptions{Now: func() time.Time { return now }})
	gateway := newIdleUnitGateway(table, DefaultFlowLifetimeTuning())
	ingressID := idleReapTestIdentity(l3ingress.ProtocolUDP, 45000)
	replyID := idleReapTestIdentity(l3ingress.ProtocolUDP, 45001)
	inFlightID := idleReapTestIdentity(l3ingress.ProtocolUDP, 45002)

	refs := make(map[l3ingress.L3Identity]l3ingress.FlowRef)
	for _, id := range []l3ingress.L3Identity{ingressID, replyID, inFlightID} {
		_, _, snapshot, err := table.Resolve(context.Background(), l3ingress.FlowMeta{
			L3Identity: id, Direction: l3ingress.DirectionIngress,
		}, 10)
		if err != nil {
			t.Fatal(err)
		}
		refs[id] = snapshot.Ref
	}
	now = base.Add(20 * time.Second)
	if !gateway.beginUDPReply(refs[replyID]) {
		t.Fatal("reply activity did not begin")
	}
	gateway.endFlowOperation(refs[replyID], true)
	now = base.Add(25 * time.Second)
	if _, created, _, err := table.Resolve(context.Background(), l3ingress.FlowMeta{
		L3Identity: ingressID, Direction: l3ingress.DirectionIngress,
	}, 4); err != nil || created {
		t.Fatalf("ingress refresh created=%v err=%v", created, err)
	}
	started, err := gateway.beginFlowOperation(context.Background(), refs[inFlightID])
	if err != nil || !started {
		t.Fatalf("in-flight operation started=%v err=%v", started, err)
	}

	now = base.Add(49 * time.Second)
	if reaped := gateway.reapFlowLifetimes(now); len(reaped) != 0 {
		t.Fatalf("active UDP flows reaped early: %+v", reaped)
	}
	now = base.Add(50 * time.Second)
	reaped := gateway.reapFlowLifetimes(now)
	if len(reaped) != 1 || reaped[0].Ref != refs[replyID] {
		t.Fatalf("exact reply cutoff reaped=%+v", reaped)
	}
	now = base.Add(100 * time.Second)
	reaped = gateway.reapFlowLifetimes(now)
	if len(reaped) != 1 || reaped[0].Ref != refs[ingressID] {
		t.Fatalf("stale ingress reap=%+v", reaped)
	}
	if _, ok := table.Snapshot(inFlightID); !ok {
		t.Fatal("in-flight UDP operation was reaped")
	}
	gateway.endFlowOperation(refs[inFlightID], false)
	reaped = gateway.reapFlowLifetimes(now)
	if len(reaped) != 1 || reaped[0].Ref != refs[inFlightID] {
		t.Fatalf("completed idle operation reap=%+v", reaped)
	}
}

func TestGatewayResolvedFlowCannotEnterInFlightAfterCompletedReap(t *testing.T) {
	base := time.Unix(30_500, 0)
	id := idleReapTestIdentity(l3ingress.ProtocolUDP, 45500)
	firstResolved := make(chan l3ingress.FlowSnapshot, 1)
	releaseResolve := make(chan struct{})
	var firstObservation sync.Once
	var releaseResolveOnce sync.Once
	defer releaseResolveOnce.Do(func() { close(releaseResolve) })
	root := rendr.Path("idle-reap-test", rendr.PathSpec{Transport: "tcp", Address: "unused"})
	routerCalls := 0
	table := l3ingress.NewFlowTable(func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
		routerCalls++
		return l3ingress.FlowDecision{Peer: "peer", Root: root, Egress: "direct"}, nil
	}, l3ingress.FlowTableOptions{
		Now: func() time.Time { return base },
		Observer: l3ingress.FlowObserverFunc(func(snapshot l3ingress.FlowSnapshot) {
			if snapshot.Closed {
				return
			}
			block := false
			firstObservation.Do(func() { block = true })
			if block {
				firstResolved <- snapshot
				<-releaseResolve
			}
		}),
	})
	gateway := newIdleUnitGateway(table, DefaultFlowLifetimeTuning())
	device := newGatewayTestDevice(1500)
	defer device.Close()
	gateway.udp.Device = device
	handlerEntered := make(chan l3ingress.FlowRef, 1)
	releaseHandler := make(chan struct{})
	var releaseHandlerOnce sync.Once
	defer releaseHandlerOnce.Do(func() { close(releaseHandler) })
	handlerErr := errors.New("stop after generation observation")
	gateway.manager.Starter = &l3session.Starter{
		ConfigureSession: func(req l3ingress.SessionRequest, _ *rendr.SessionConfig) error {
			handlerEntered <- req.Ref
			<-releaseHandler
			return handlerErr
		},
	}
	packet, err := l3ingress.BuildUDPPacket(id, []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := l3ingress.ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	handleDone := make(chan error, 1)
	go func() {
		handleDone <- gateway.HandlePacket(context.Background(), l3ingress.PacketEvent{
			Packet: packet,
			Meta:   meta,
			Flow: l3ingress.FlowMeta{
				L3Identity: id, Direction: l3ingress.DirectionIngress,
			},
		})
	}()

	var stale l3ingress.FlowSnapshot
	select {
	case stale = <-firstResolved:
	case <-time.After(time.Second):
		t.Fatal("HandlePacket did not pause after Resolve")
	}
	reaped := gateway.ReapIdle(base.Add(time.Second))
	if len(reaped) != 1 || reaped[0].Ref != stale.Ref {
		t.Fatalf("completed reap=%+v want stale ref %+v", reaped, stale.Ref)
	}
	gateway.flowState.mu.Lock()
	claim := gateway.flowState.reaping[id]
	staleInFlight := gateway.flowState.inFlight[stale.Ref]
	gateway.flowState.mu.Unlock()
	if claim != nil || staleInFlight != 0 {
		t.Fatalf("completed reap retained claim=%v stale in-flight=%d", claim != nil, staleInFlight)
	}
	releaseResolveOnce.Do(func() { close(releaseResolve) })

	var currentRef l3ingress.FlowRef
	select {
	case currentRef = <-handlerEntered:
	case <-time.After(time.Second):
		t.Fatal("HandlePacket did not re-resolve into the handler")
	}
	if currentRef == stale.Ref || currentRef.Generation == 0 {
		t.Fatalf("handler received stale generation: stale=%+v current=%+v", stale.Ref, currentRef)
	}
	current, ok := table.Snapshot(id)
	if !ok || current.Ref != currentRef {
		t.Fatalf("re-resolved table generation=%+v ok=%v want %+v", current.Ref, ok, currentRef)
	}
	gateway.flowState.mu.Lock()
	staleInFlight = gateway.flowState.inFlight[stale.Ref]
	currentInFlight := gateway.flowState.inFlight[currentRef]
	gateway.flowState.mu.Unlock()
	if staleInFlight != 0 || currentInFlight != 1 {
		t.Fatalf("in-flight stale/current=%d/%d want 0/1", staleInFlight, currentInFlight)
	}
	releaseHandlerOnce.Do(func() { close(releaseHandler) })
	select {
	case err := <-handleDone:
		if err != nil {
			t.Fatalf("flow-local handler failure escaped HandlePacket: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HandlePacket did not finish")
	}
	if routerCalls != 2 {
		t.Fatalf("router calls=%d want stale and replacement generations", routerCalls)
	}
	closed, ok := table.ClosedSnapshot(id)
	if !ok || closed.Ref != currentRef || closed.CloseReason != l3ingress.FlowCloseManual {
		t.Fatalf("replacement close=%+v ok=%v", closed, ok)
	}
}

func TestGatewayIdleReapRetainsEstablishedTCPAndCleansOtherStates(t *testing.T) {
	base := time.Unix(31_000, 0)
	now := base
	pendingID := idleReapTestIdentity(l3ingress.ProtocolTCP, 46000)
	deniedID := idleReapTestIdentity(l3ingress.ProtocolTCP, 46001)
	orphanID := idleReapTestIdentity(l3ingress.ProtocolTCP, 46002)
	establishedID := idleReapTestIdentity(l3ingress.ProtocolTCP, 46003)
	reusedID := idleReapTestIdentity(l3ingress.ProtocolTCP, 46004)
	table := l3ingress.NewFlowTable(func(_ context.Context, flow l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
		return l3ingress.FlowDecision{Deny: flow.L3Identity == deniedID}, nil
	}, l3ingress.FlowTableOptions{Now: func() time.Time { return now }})
	gateway := newIdleUnitGateway(table, DefaultFlowLifetimeTuning())
	refs := make(map[l3ingress.L3Identity]l3ingress.FlowRef)
	for _, id := range []l3ingress.L3Identity{pendingID, deniedID, orphanID, establishedID, reusedID} {
		decision, _, snapshot, err := table.Resolve(context.Background(), l3ingress.FlowMeta{
			L3Identity: id, Direction: l3ingress.DirectionIngress,
		}, 40)
		if err != nil {
			t.Fatal(err)
		}
		refs[id] = snapshot.Ref
		if id == pendingID {
			gateway.pending[snapshot.Ref] = l3ingress.PacketEvent{Ref: snapshot.Ref, Decision: decision}
		}
	}
	canceled := make(chan struct{})
	gateway.admissions[refs[pendingID]] = &tcpAdmission{cancel: func() { close(canceled) }}
	flowLock := gateway.tcpFlowLock(establishedID)
	flowLock.Lock()
	if !gateway.markTCPEstablishedLocked(refs[establishedID]) {
		t.Fatal("failed to mark TCP established")
	}
	flowLock.Unlock()

	oldReused := refs[reusedID]
	closed, ok := table.CloseRef(oldReused, l3ingress.FlowCloseManual)
	if !ok {
		t.Fatal("failed to close predecessor generation")
	}
	gateway.closeReapedSession(closed)
	_, _, replacement, err := table.Resolve(context.Background(), l3ingress.FlowMeta{
		L3Identity: reusedID, Direction: l3ingress.DirectionIngress,
	}, 40)
	if err != nil {
		t.Fatal(err)
	}
	gateway.flowState.mu.Lock()
	if gateway.flowState.established == nil {
		gateway.flowState.established = make(map[l3ingress.FlowRef]struct{})
	}
	gateway.flowState.established[oldReused] = struct{}{}
	gateway.flowState.mu.Unlock()

	now = base.Add(11 * time.Second)
	reaped := gateway.reapFlowLifetimes(now)
	if len(reaped) != 4 {
		t.Fatalf("unestablished reaped=%d want 4: %+v", len(reaped), reaped)
	}
	if current, ok := table.Snapshot(establishedID); !ok || current.Ref != refs[establishedID] {
		t.Fatalf("silent established TCP was reaped: current=%+v ok=%v", current, ok)
	}
	for _, id := range []l3ingress.L3Identity{pendingID, deniedID, orphanID, reusedID} {
		if _, ok := table.Snapshot(id); ok {
			t.Fatalf("unestablished TCP survived: %s", id)
		}
	}
	if closed, ok := table.ClosedSnapshot(reusedID); !ok || closed.Ref != replacement.Ref {
		t.Fatalf("replacement generation was not reaped exactly: %+v ok=%v", closed, ok)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("idle pending admission was not canceled")
	}
	if len(gateway.pending) != 0 || len(gateway.admissions) != 0 {
		t.Fatalf("pending lifecycle retained pending=%d admissions=%d", len(gateway.pending), len(gateway.admissions))
	}
	gateway.flowState.mu.Lock()
	_, staleEstablished := gateway.flowState.established[oldReused]
	gateway.flowState.mu.Unlock()
	if staleEstablished {
		t.Fatal("stale established generation remained in activity state")
	}
}

func TestGatewayTCPAdmissionAndIdleClaimLinearize(t *testing.T) {
	for _, tt := range []struct {
		name            string
		establishFirst  bool
		wantClaim       bool
		wantEstablished bool
	}{
		{name: "idle-claim-first", wantClaim: true},
		{name: "establishment-first", establishFirst: true, wantEstablished: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Unix(32_000, 0)
			table := l3ingress.NewFlowTable(nil, l3ingress.FlowTableOptions{Now: func() time.Time { return now }})
			gateway := newIdleUnitGateway(table, DefaultFlowLifetimeTuning())
			id := idleReapTestIdentity(l3ingress.ProtocolTCP, 47000)
			_, _, snapshot, err := table.Resolve(context.Background(), l3ingress.FlowMeta{
				L3Identity: id, Direction: l3ingress.DirectionIngress,
			}, 40)
			if err != nil {
				t.Fatal(err)
			}
			flowLock := gateway.tcpFlowLock(id)
			if tt.establishFirst {
				flowLock.Lock()
				if !gateway.markTCPEstablishedLocked(snapshot.Ref) {
					t.Fatal("establishment unexpectedly lost")
				}
				flowLock.Unlock()
			}
			claimed := gateway.claimIdleFlow(snapshot.Ref)
			if claimed != tt.wantClaim {
				t.Fatalf("claim=%v want %v", claimed, tt.wantClaim)
			}
			if claimed {
				flowLock.Lock()
				established := gateway.markTCPEstablishedLocked(snapshot.Ref)
				flowLock.Unlock()
				if established {
					t.Fatal("admission established after idle claim")
				}
				closed, ok := table.CloseIdleRef(snapshot.Ref, now)
				if !ok {
					t.Fatal("claimed exact-cutoff flow did not close")
				}
				gateway.closeReapedSession(closed)
				gateway.finishIdleClaim(snapshot.Ref, true)
				flowLock.Lock()
				lateEstablished := gateway.markTCPEstablishedLocked(snapshot.Ref)
				flowLock.Unlock()
				if lateEstablished {
					t.Fatal("stale admission established after idle close completed")
				}
			}
			gateway.flowState.mu.Lock()
			_, established := gateway.flowState.established[snapshot.Ref]
			gateway.flowState.mu.Unlock()
			if established != tt.wantEstablished {
				t.Fatalf("established=%v want %v", established, tt.wantEstablished)
			}
		})
	}
}

func TestGatewayClosedRetentionUsesExactCutoff(t *testing.T) {
	base := time.Unix(33_000, 0)
	now := base
	table := l3ingress.NewFlowTable(nil, l3ingress.FlowTableOptions{Now: func() time.Time { return now }})
	gateway := newIdleUnitGateway(table, DefaultFlowLifetimeTuning())
	firstID := idleReapTestIdentity(l3ingress.ProtocolUDP, 48000)
	secondID := idleReapTestIdentity(l3ingress.ProtocolUDP, 48001)
	_, _, first, err := table.Resolve(context.Background(), l3ingress.FlowMeta{L3Identity: firstID}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := table.CloseRef(first.Ref, l3ingress.FlowCloseManual); !ok {
		t.Fatal("first close failed")
	}
	now = base.Add(time.Nanosecond)
	_, _, second, err := table.Resolve(context.Background(), l3ingress.FlowMeta{L3Identity: secondID}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := table.CloseRef(second.Ref, l3ingress.FlowCloseManual); !ok {
		t.Fatal("second close failed")
	}

	now = base.Add(5 * time.Minute)
	gateway.reapFlowLifetimes(now)
	if _, ok := table.ClosedSnapshot(firstID); ok {
		t.Fatal("closed snapshot at exact retention cutoff survived")
	}
	if _, ok := table.ClosedSnapshot(secondID); !ok {
		t.Fatal("newer closed snapshot was reaped early")
	}
	now = base.Add(5*time.Minute + time.Nanosecond)
	gateway.reapFlowLifetimes(now)
	if _, ok := table.ClosedSnapshot(secondID); ok {
		t.Fatal("second exact-cutoff snapshot survived")
	}
}

func TestGatewayRunReusesOneTimerAndStopsSchedulingOnExit(t *testing.T) {
	device := newGatewayTestDevice(1500)
	gateway, err := New(Config{
		Device: device,
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Deny: true}, nil
		},
		FlowLifetime: FlowLifetimeTuning{
			UDPIdle: 20 * time.Millisecond, TCPUnestablishedIdle: 20 * time.Millisecond,
			ClosedRetention: 20 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gateway.Run(ctx) }()

	const flowCount = 64
	ids := make([]l3ingress.L3Identity, 0, flowCount)
	for index := 0; index < flowCount; index++ {
		id := idleReapTestIdentity(l3ingress.ProtocolUDP, uint16(49000+index))
		ids = append(ids, id)
		if _, _, _, err := gateway.table.Resolve(context.Background(), l3ingress.FlowMeta{
			L3Identity: id, Direction: l3ingress.DirectionIngress,
		}, 1); err != nil {
			t.Fatal(err)
		}
	}
	waitIdleReapCondition(t, 3*time.Second, func() bool {
		if len(gateway.table.Snapshots()) != 0 {
			return false
		}
		for _, id := range ids {
			if _, ok := gateway.table.ClosedSnapshot(id); ok {
				return false
			}
		}
		return true
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Gateway.Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Gateway.Run did not stop")
	}
	gateway.flowState.mu.Lock()
	inFlight := len(gateway.flowState.inFlight)
	established := len(gateway.flowState.established)
	reaping := len(gateway.flowState.reaping)
	gateway.flowState.mu.Unlock()
	if inFlight != 0 || established != 0 || reaping != 0 {
		t.Fatalf("flow activity state retained inFlight=%d established=%d reaping=%d", inFlight, established, reaping)
	}

	postRunID := idleReapTestIdentity(l3ingress.ProtocolUDP, 49999)
	if _, _, _, err := gateway.table.Resolve(context.Background(), l3ingress.FlowMeta{
		L3Identity: postRunID, Direction: l3ingress.DirectionIngress,
	}, 1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * gateway.reapCadence)
	if _, ok := gateway.table.Snapshot(postRunID); !ok {
		t.Fatal("flow was reaped after Run stopped its timer")
	}
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
}

func newIdleUnitGateway(table *l3ingress.FlowTable, tuning FlowLifetimeTuning) *Gateway {
	normalized, err := normalizeFlowLifetimeTuning(tuning)
	if err != nil {
		panic(err)
	}
	manager := &l3session.Manager{FlowTable: table}
	gateway := &Gateway{
		table: table, manager: manager,
		flowLifetime: normalized, reapCadence: flowReapCadence(normalized),
		pending:    make(map[l3ingress.FlowRef]l3ingress.PacketEvent),
		admissions: make(map[l3ingress.FlowRef]*tcpAdmission),
	}
	gateway.udp = &l3session.UDPRelay{Manager: manager, ReplyActivity: gatewayUDPReplyActivity{gateway: gateway}}
	return gateway
}

func idleReapTestIdentity(protocol l3ingress.Protocol, srcPort uint16) l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto: protocol,
		SrcIP: netip.MustParseAddr("192.0.2.30"), SrcPort: srcPort,
		DstIP: netip.MustParseAddr("198.51.100.30"), DstPort: 443,
	}
}

func waitIdleReapCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for idle-reap condition")
		}
		time.Sleep(time.Millisecond)
	}
}
