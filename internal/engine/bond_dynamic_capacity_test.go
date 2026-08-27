package engine

import (
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type bondTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newBondTestClock(now time.Time) *bondTestClock {
	return &bondTestClock{now: now}
}

func (c *bondTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *bondTestClock) Advance(elapsed time.Duration) time.Time {
	c.mu.Lock()
	c.now = c.now.Add(elapsed)
	now := c.now
	c.mu.Unlock()
	return now
}

func (c *bondTestClock) Set(now time.Time) {
	c.mu.Lock()
	if now.Before(c.now) {
		c.mu.Unlock()
		panic("bond test clock moved backwards")
	}
	c.now = now
	c.mu.Unlock()
}

type bondControlledWrite struct {
	sequence uint64
	release  chan struct{}
}

type bondPhysicalPath struct {
	name       string
	clock      *bondTestClock
	service    time.Duration
	autoACK    bool
	controlled bool
	engine     *Engine

	closed    chan struct{}
	closeOnce sync.Once
	started   chan bondControlledWrite

	mu        sync.Mutex
	sequences []uint64
	ackErrors int
	onDeath   func(transport.DeathCause, error)
}

func newBondPhysicalPath(name string, clock *bondTestClock, service time.Duration) *bondPhysicalPath {
	return &bondPhysicalPath{
		name: name, clock: clock, service: service,
		closed: make(chan struct{}), started: make(chan bondControlledWrite, pathDispatchQueueSize),
	}
}

func (p *bondPhysicalPath) Read([]byte) (int, error) {
	<-p.closed
	return 0, io.EOF
}

func (p *bondPhysicalPath) Write(frame []byte) (int, error) {
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return 0, err
	}
	if p.controlled && header.Type == proto.FrameData {
		attempt := bondControlledWrite{sequence: header.Seq, release: make(chan struct{})}
		select {
		case p.started <- attempt:
		case <-p.closed:
			return 0, io.ErrClosedPipe
		}
		select {
		case <-attempt.release:
		case <-p.closed:
			return 0, io.ErrClosedPipe
		}
	} else if p.service > 0 {
		p.clock.Advance(p.service)
	}

	p.mu.Lock()
	p.sequences = append(p.sequences, header.Seq)
	p.mu.Unlock()
	if p.autoACK && header.Type == proto.FrameData {
		p.acknowledge(header.Seq, p.clock.Now())
	}
	return len(frame), nil
}

func (p *bondPhysicalPath) acknowledge(sequence uint64, at time.Time) {
	if p.engine == nil {
		return
	}
	p.engine.sendHistMu.Lock()
	entry := p.engine.sendHistoryEntryLocked(sequence)
	if entry == nil {
		p.engine.sendHistMu.Unlock()
		return
	}
	proof := entry.proof
	p.engine.sendHistMu.Unlock()
	valid, application := p.engine.acknowledgeSendFramesAt(sequence+1, proof, at)
	if !valid || !application {
		p.mu.Lock()
		p.ackErrors++
		p.mu.Unlock()
	}
}

func (p *bondPhysicalPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *bondPhysicalPath) Quality() transport.PathQuality { return transport.PathQuality{} }
func (*bondPhysicalPath) MaxFrameSize() int                { return 1<<16 - 1 }

func (p *bondPhysicalPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.mu.Lock()
	p.onDeath = fn
	p.mu.Unlock()
}

func (p *bondPhysicalPath) LocalAddr() string  { return "bond-test-local-" + p.name }
func (p *bondPhysicalPath) RemoteAddr() string { return "bond-test-remote-" + p.name }

func (p *bondPhysicalPath) snapshot() ([]uint64, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]uint64(nil), p.sequences...), p.ackErrors
}

type bondPhysicalPathSpec struct {
	weight     uint16
	service    time.Duration
	autoACK    bool
	controlled bool
}

type bondPhysicalFixture struct {
	engine  *Engine
	runtime *executionRuntime
	ids     map[string]proto.TargetID
	paths   map[string]*bondPhysicalPath
	slots   map[string]*pathSlot
}

func bondGraphNode(kind proto.GraphNodeKind, name string, children ...proto.GraphNode) proto.GraphNode {
	node := proto.GraphNode{ID: proto.DeriveTargetID(kind, name), Kind: kind, Name: name}
	for _, child := range children {
		node.Children = append(node.Children, child.ID)
	}
	return node
}

func bondGraphManifest(t *testing.T, root proto.GraphNode, nodes ...proto.GraphNode) (proto.GraphManifest, map[string]proto.TargetID) {
	t.Helper()
	all := append([]proto.GraphNode{root}, nodes...)
	manifest := proto.GraphManifest{RootID: root.ID, Nodes: all}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("invalid bond graph: %v", err)
	}
	ids := make(map[string]proto.TargetID, len(all))
	for _, node := range all {
		ids[node.Name] = node.ID
	}
	return manifest, ids
}

func newBondPhysicalFixture(
	t *testing.T,
	clock *bondTestClock,
	manifest proto.GraphManifest,
	ids map[string]proto.TargetID,
	specs map[string]bondPhysicalPathSpec,
) bondPhysicalFixture {
	t.Helper()
	// Capacity tests publish their own deterministic health and service
	// evidence. Keep the independent liveness prober from changing projection
	// epochs merely because race instrumentation stretches a test past 1s.
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 30 * time.Second}.Clamp())
	e.probeStartOnce.Do(func() {})
	e.SetPacketMode()
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatalf("configure local bond graph: %v", err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatalf("configure peer bond graph: %v", err)
	}
	paths := make(map[string]*bondPhysicalPath, len(specs))
	for name, spec := range specs {
		path := newBondPhysicalPath(name, clock, spec.service)
		path.engine = e
		path.autoACK = spec.autoACK
		path.controlled = spec.controlled
		attachFixturePath(t, e, path, transport.PathSpec{
			Transport: "bond-test", Address: name, Weight: spec.weight,
		}, ids[name])
		paths[name] = path
	}
	t.Cleanup(func() { _ = e.Close() })
	slots := make(map[string]*pathSlot, len(specs))
	e.pathsMu.RLock()
	for _, slot := range e.paths {
		for name := range specs {
			if slot.localTXTargetID == ids[name] {
				slots[name] = slot
			}
		}
	}
	e.pathsMu.RUnlock()
	return bondPhysicalFixture{
		engine: e, runtime: e.localExecutionRuntime(), ids: ids, paths: paths, slots: slots,
	}
}

type productionBondPath struct {
	name   string
	weight uint16
}

type productionBondFixture struct {
	engine  *Engine
	runtime *executionRuntime
	ids     map[string]proto.TargetID
	slots   map[string]*pathSlot
	order   []string
}

func newProductionBondFixture(t *testing.T, paths ...productionBondPath) productionBondFixture {
	t.Helper()
	if len(paths) < 2 {
		t.Fatal("production bond fixture requires at least two paths")
	}
	names := make([]string, 0, len(paths))
	for _, path := range paths {
		names = append(names, path.name)
	}
	// The fluid service model owns its clock and evidence. Ambient probes would
	// make its result depend on host scheduling rather than modeled service.
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 30 * time.Second}.Clamp())
	e.probeStartOnce.Do(func() {})
	ids := configureLeafGroupRuntime(t, e, proto.GraphNodeKindBond, names...)
	peers := make([]*memoryPathConn, 0, len(paths))
	for _, path := range paths {
		local, peer := newMemoryPathPair()
		peers = append(peers, peer)
		attachFixturePath(t, e, local, transport.PathSpec{
			Transport: "memory", Address: path.name, Weight: path.weight,
		}, ids[path.name])
	}
	t.Cleanup(func() {
		_ = e.Close()
		for _, peer := range peers {
			_ = peer.Close()
		}
	})

	slots := make(map[string]*pathSlot, len(paths))
	e.pathsMu.RLock()
	for _, slot := range e.paths {
		for _, path := range paths {
			if slot.localTXTargetID == ids[path.name] {
				slots[path.name] = slot
			}
		}
	}
	e.pathsMu.RUnlock()
	if len(slots) != len(paths) {
		t.Fatalf("attached slots=%d want %d", len(slots), len(paths))
	}
	return productionBondFixture{
		engine: e, runtime: e.localExecutionRuntime(), ids: ids, slots: slots, order: names,
	}
}

type productionBondRound struct {
	assigned map[string]int
	served   map[string]int
	backlog  map[string]int
	weights  map[string]uint64
}

type productionBondServiceModel struct {
	capacity map[string]int
	backlog  map[string]int
}

func newProductionBondServiceModel(capacity map[string]int) *productionBondServiceModel {
	return &productionBondServiceModel{
		capacity: capacity,
		backlog:  make(map[string]int, len(capacity)),
	}
}

// runProductionBondServiceRound wraps the production ticket and replay-ledger
// paths in a deterministic fluid service model. Tickets allocate all offered
// demand, while excess units remain in modeled sender backlog. Only the
// serviceable prefix is published and ACKed, so every evidence byte was both
// physically serviceable and confirmed by the real cumulative ACK API.
func runProductionBondServiceRound(
	t *testing.T,
	fixture productionBondFixture,
	clock *bondTestClock,
	demandUnits int,
	service *productionBondServiceModel,
) productionBondRound {
	t.Helper()
	if demandUnits <= 0 || service == nil {
		t.Fatal("bond service round needs positive demand")
	}
	assigned := make(map[string]int, len(fixture.order))
	weights := make(map[string]uint64, len(fixture.order))
	for unit := 0; unit < demandUnits; unit++ {
		ticket, snapshot, err := fixture.engine.recursiveDispatchTicket(
			fixture.runtime, false, clock.Now(),
		)
		if err != nil {
			t.Fatalf("demand ticket %d: %v", unit, err)
		}
		if len(ticket.routes) != 1 {
			t.Fatalf("demand ticket %d routes=%v want one", unit, ticket.routes)
		}
		node, ok := fixture.runtime.plan.node(ticket.routes[0].targetID)
		if !ok {
			t.Fatalf("demand ticket %d target=%x is absent", unit, ticket.routes[0].targetID)
		}
		assigned[node.name]++
		for _, name := range fixture.order {
			weights[name] = snapshot.capacities[fixture.ids[name]]
		}
	}

	sequence := fixture.engine.sendPublishedNext.Load()
	receipts := make([]*batchDispatchAttributionReceipt, 0)
	served := make(map[string]int, len(fixture.order))
	ackFrontiers := make(map[string]uint64, len(fixture.order))
	for _, name := range fixture.order {
		capacity, ok := service.capacity[name]
		if !ok || capacity <= 0 {
			t.Fatalf("path %q service capacity=%d", name, capacity)
		}
		service.backlog[name] += assigned[name]
		served[name] = service.backlog[name]
		if served[name] > capacity {
			served[name] = capacity
		}
		pressured := service.backlog[name] >= capacity
		service.backlog[name] -= served[name]
		var perFrameService, serviceRemainder time.Duration
		serviceCursor := clock.Now()
		if pressured {
			perFrameService = selectorGoodputMinimumWindow / time.Duration(served[name])
			serviceRemainder = selectorGoodputMinimumWindow % time.Duration(served[name])
		}
		for unit := 0; unit < served[name]; unit++ {
			frame := make([]byte, proto.HeaderSize+MaxPayload)
			if err := (proto.Header{
				Version: proto.Version, Type: proto.FrameData, Seq: sequence,
			}).Encode(frame[:proto.HeaderSize]); err != nil {
				t.Fatal(err)
			}
			if err := fixture.engine.acquireSendSlot(false, len(frame)); err != nil {
				t.Fatal(err)
			}
			if err := fixture.engine.reserveOwnedSendFrame(frame); err != nil {
				t.Fatal(err)
			}
			fixture.engine.publishSendSeq(sequence + 1)
			receipt := fixture.engine.beginApplicationBatchDispatch(
				frame, fixture.slots[name], fixture.engine.currentPathTopologyEpoch(),
			)
			if receipt == nil {
				t.Fatalf("path %q did not create an attribution receipt", name)
			}
			if pressured {
				serviceDuration := perFrameService
				if unit == 0 {
					serviceDuration += serviceRemainder
				}
				serviceStarted := serviceCursor
				serviceCursor = serviceCursor.Add(serviceDuration)
				receipt.noteCapacityPressure(applicationDispatchPressureObservation{
					startedAt: serviceStarted, completedAt: serviceCursor,
					serviceDuration: serviceDuration,
				})
			}
			receipts = append(receipts, receipt)
			sequence++
		}
		if served[name] != 0 {
			ackFrontiers[name] = sequence
		}
	}
	if len(receipts) == 0 {
		t.Fatal("service round produced no ACKable frames")
	}
	acknowledgedAt := clock.Advance(selectorGoodputMinimumWindow)
	fixture.engine.resolveApplicationBatchDispatch(receipts, len(receipts))
	for _, name := range fixture.order {
		frontier := ackFrontiers[name]
		if frontier == 0 {
			continue
		}
		fixture.engine.sendHistMu.Lock()
		proofEntry := fixture.engine.sendHistoryEntryLocked(frontier - 1)
		if proofEntry == nil {
			fixture.engine.sendHistMu.Unlock()
			t.Fatalf("path %q ACK frontier is absent from replay history", name)
		}
		proof := proofEntry.proof
		fixture.engine.sendHistMu.Unlock()
		valid, application := fixture.engine.acknowledgeSendFramesAt(frontier, proof, acknowledgedAt)
		if !valid || !application {
			t.Fatalf("path %q service ACK valid/application=%t/%t", name, valid, application)
		}
	}
	backlog := make(map[string]int, len(service.backlog))
	for name, queued := range service.backlog {
		backlog[name] = queued
	}
	return productionBondRound{assigned: assigned, served: served, backlog: backlog, weights: weights}
}

func productionBondDistribution(
	t *testing.T,
	fixture productionBondFixture,
	now time.Time,
	tickets int,
) map[string]int {
	t.Helper()
	counts := make(map[string]int, len(fixture.ids))
	for index := 0; index < tickets; index++ {
		ticket, _, err := fixture.engine.recursiveDispatchTicket(fixture.runtime, false, now)
		if err != nil {
			t.Fatalf("ticket %d: %v", index, err)
		}
		if len(ticket.routes) != 1 {
			t.Fatalf("ticket %d routes=%v want one", index, ticket.routes)
		}
		node, ok := fixture.runtime.plan.node(ticket.routes[0].targetID)
		if !ok {
			t.Fatalf("ticket %d target=%x is absent", index, ticket.routes[0].targetID)
		}
		counts[node.name]++
	}
	return counts
}

func productionBondCapacitySnapshot(
	t *testing.T,
	fixture productionBondFixture,
	now time.Time,
) map[string]uint64 {
	t.Helper()
	topologyEpoch := fixture.engine.currentPathTopologyEpoch()
	latest := make(map[proto.TargetID]*pathSlot, len(fixture.slots))
	fixture.engine.pathsMu.RLock()
	for _, slot := range fixture.engine.paths {
		if slot.localTXTargetID == (proto.TargetID{}) || slot.dispatchStalled.Load() {
			continue
		}
		if previous := latest[slot.localTXTargetID]; previous == nil || slot.gen > previous.gen {
			latest[slot.localTXTargetID] = slot
		}
	}
	fixture.engine.pathsMu.RUnlock()
	delivered, acknowledged, valid := fixture.engine.targetBondSchedulingEvidenceAtEpoch(
		now, topologyEpoch,
	)
	if !valid {
		t.Fatal("capacity snapshot crossed a topology epoch")
	}
	scheduling := bondDispatchScheduling(
		latest, delivered, acknowledged, now, topologyEpoch,
	)
	out := make(map[string]uint64, len(fixture.order))
	for _, name := range fixture.order {
		out[name] = scheduling.effectiveWeights[fixture.ids[name]]
	}
	return out
}

func TestProductionBondDynamicCapacityScheduling(t *testing.T) {
	t.Run("static weights remain cold-start authority", func(t *testing.T) {
		clock := time.Unix(10_000, 0)
		installEngineNowForTest(t, func() time.Time { return clock })
		fixture := newProductionBondFixture(t,
			productionBondPath{name: "slow", weight: 5},
			productionBondPath{name: "fast", weight: 100},
		)
		capacities := productionBondCapacitySnapshot(t, fixture, clock)
		if capacities["slow"] != 5 || capacities["fast"] != 100 {
			t.Fatalf("cold-start capacities=%v", capacities)
		}
		counts := productionBondDistribution(t, fixture, clock, 4*(5+100))
		if counts["slow"] < 16 || counts["slow"] > 24 || counts["fast"]+counts["slow"] != 420 {
			t.Fatalf("cold-start distribution=%v want 5:100 within one four-frame pin", counts)
		}
	})

	t.Run("demand-limited windows never become capacity evidence", func(t *testing.T) {
		clock := newBondTestClock(time.Unix(40_000, 0))
		installEngineNowForTest(t, clock.Now)
		fixture := newProductionBondFixture(t,
			productionBondPath{name: "a", weight: 3},
			productionBondPath{name: "b", weight: 2},
		)
		service := newProductionBondServiceModel(map[string]int{"a": 64, "b": 64})
		for window := 0; window < 8; window++ {
			round := runProductionBondServiceRound(t, fixture, clock, 16, service)
			if round.backlog["a"] != 0 || round.backlog["b"] != 0 {
				t.Fatalf("window %d was not demand-limited: %+v", window, round)
			}
			capacities := productionBondCapacitySnapshot(t, fixture, clock.Now())
			if capacities["a"] != 3 || capacities["b"] != 2 {
				t.Fatalf("window %d mislabeled offered load as capacity: %v", window, capacities)
			}
		}
		if evidence, valid := fixture.engine.targetCapacitySpeedsAtEpoch(
			clock.Now(), fixture.engine.currentPathTopologyEpoch(),
		); !valid || len(evidence) != 0 {
			t.Fatalf("demand-limited capacity evidence valid=%t evidence=%+v", valid, evidence)
		}
	})

	t.Run("cached estimate expires independently of cache ttl", func(t *testing.T) {
		clock := time.Unix(50_000, 0)
		installEngineNowForTest(t, func() time.Time { return clock })
		fixture := newProductionBondFixture(t,
			productionBondPath{name: "slow", weight: 100},
			productionBondPath{name: "fast", weight: 1},
		)
		seedBondCapacityEvidence(fixture.engine, clock, map[proto.TargetID]uint64{
			fixture.ids["slow"]: 8, fixture.ids["fast"]: 64,
		})
		sampledAt := clock
		nearExpiry := sampledAt.Add(selectorEvidenceFreshFor - 100*time.Millisecond)
		_, fresh, err := fixture.engine.recursiveDispatchTicket(fixture.runtime, false, nearExpiry)
		if err != nil || fresh.capacities[fixture.ids["fast"]] <= fresh.capacities[fixture.ids["slow"]] {
			t.Fatalf("fresh dynamic capacities=%v err=%v", fresh.capacities, err)
		}
		// Cache age is only 100ms+1ns here, but each estimate is already stale.
		_, expired, err := fixture.engine.recursiveDispatchTicket(
			fixture.runtime, false, sampledAt.Add(selectorEvidenceFreshFor+time.Nanosecond),
		)
		if err != nil || expired.capacities[fixture.ids["slow"]] != 100 ||
			expired.capacities[fixture.ids["fast"]] != 1 {
			t.Fatalf("expired cached evidence still steered=%v err=%v", expired.capacities, err)
		}
	})

	t.Run("topology reset rejects old evidence", func(t *testing.T) {
		clock := time.Unix(60_000, 0)
		installEngineNowForTest(t, func() time.Time { return clock })
		fixture := newProductionBondFixture(t,
			productionBondPath{name: "slow", weight: 2},
			productionBondPath{name: "fast", weight: 7},
		)
		seedBondCapacityEvidence(fixture.engine, clock, map[proto.TargetID]uint64{
			fixture.ids["slow"]: 8, fixture.ids["fast"]: 64,
		})
		fixture.engine.pathsMu.Lock()
		fixture.engine.advancePathTopologyEpochLocked()
		fixture.engine.pathsMu.Unlock()
		capacities := productionBondCapacitySnapshot(t, fixture, clock)
		if capacities["slow"] != 2 || capacities["fast"] != 7 {
			t.Fatalf("topology-reset capacities=%v", capacities)
		}
	})
}

func TestScaleBondCapacityWeightIsBoundedAndOverflowSafe(t *testing.T) {
	tests := []struct {
		value, maximum uint64
		want           uint64
	}{
		{value: 1, maximum: math.MaxUint64, want: 1},
		{value: math.MaxUint64 - 1, maximum: math.MaxUint64, want: bondCapacityWeightScale},
		{value: math.MaxUint64, maximum: math.MaxUint64, want: bondCapacityWeightScale},
		{value: 5, maximum: 100, want: 3277},
	}
	for _, test := range tests {
		if got := scaleBondCapacityWeight(test.value, test.maximum, bondCapacityWeightScale); got != test.want {
			t.Fatalf("scale(%d,%d)=%d want %d", test.value, test.maximum, got, test.want)
		}
	}
}

func TestBondObservedCapacityRatiosAreNotClippedByExploration(t *testing.T) {
	now := time.Unix(65_000, 0)
	slow := bondGraphNode(proto.GraphNodeKindPath, "slow")
	fast := bondGraphNode(proto.GraphNodeKindPath, "fast")
	root := bondGraphNode(proto.GraphNodeKindBond, "root", slow, fast)
	manifest, ids := bondGraphManifest(t, root, slow, fast)
	latest := map[proto.TargetID]*pathSlot{
		ids["slow"]: {spec: transport.PathSpec{Weight: 1}},
		ids["fast"]: {spec: transport.PathSpec{Weight: 1}},
	}
	attached := map[proto.TargetID]bool{ids["slow"]: true, ids["fast"]: true}
	for _, ratio := range []uint64{100, 1000} {
		delivered := map[proto.TargetID]speedEstimate{
			ids["slow"]: {
				state: qualityStateFresh, bytesPerSecond: 1,
				confidence: evidenceConfidenceFull, source: speedSourceDelivered,
				sampleTime: now, sampleCount: 1,
			},
			ids["fast"]: {
				state: qualityStateFresh, bytesPerSecond: ratio,
				confidence: evidenceConfidenceFull, source: speedSourceDelivered,
				sampleTime: now, sampleCount: 1,
			},
		}
		scheduling := bondDispatchScheduling(latest, delivered, nil, now, 1)
		slowWeight := scheduling.effectiveWeights[ids["slow"]]
		fastWeight := scheduling.effectiveWeights[ids["fast"]]
		if slowWeight == 0 || fastWeight/slowWeight < ratio*98/100 {
			t.Fatalf("ratio 1:%d clipped to weights %d:%d", ratio, slowWeight, fastWeight)
		}

		runtime := mustExecutionRuntime(t, manifest)
		counts := map[proto.TargetID]int{}
		for ticketIndex := uint64(0); ticketIndex < ratio+1; ticketIndex++ {
			ticket, err := runtime.buildTicketScheduledPresence(
				attached, attached, nil, scheduling, true, 1, 0,
			)
			if err != nil || len(ticket.routes) != 1 {
				t.Fatalf("ratio 1:%d ticket %d routes=%+v err=%v", ratio, ticketIndex, ticket.routes, err)
			}
			counts[ticket.routes[0].targetID]++
		}
		if counts[ids["slow"]] < 1 || counts[ids["slow"]] > 2 ||
			counts[ids["fast"]] < int(ratio)-1 {
			t.Fatalf("ratio 1:%d scheduled distribution=%v", ratio, counts)
		}
	}
}

func TestBondUnknownQualificationIsACKGatedAndInterleaved(t *testing.T) {
	known := bondGraphNode(proto.GraphNodeKindPath, "known")
	unknown := bondGraphNode(proto.GraphNodeKindPath, "unknown")
	root := bondGraphNode(proto.GraphNodeKindBond, "root", known, unknown)
	manifest, ids := bondGraphManifest(t, root, known, unknown)
	runtime := mustExecutionRuntime(t, manifest)
	attached := map[proto.TargetID]bool{ids["known"]: true, ids["unknown"]: true}
	scheduling := bondSchedulingContext{
		now: time.Unix(66_000, 0), topologyEpoch: 1,
		staticWeights: map[proto.TargetID]uint64{
			ids["known"]: 1, ids["unknown"]: 1,
		},
		effectiveWeights: map[proto.TargetID]uint64{
			ids["known"]: bondCapacityWeightScale, ids["unknown"]: 1,
		},
		observed:      map[proto.TargetID]bool{ids["known"]: true},
		acknowledged:  map[proto.TargetID]uint64{},
		evidenceAware: true,
	}

	routeTickets := func(tickets int) []dispatchRoute {
		routes := make([]dispatchRoute, 0, tickets)
		for index := 0; index < tickets; index++ {
			ticket, err := runtime.buildTicketScheduledPresence(
				attached, attached, nil, scheduling, true, 1, 0,
			)
			if err != nil || len(ticket.routes) != 1 {
				t.Fatalf("qualification ticket %d routes=%+v err=%v", index, ticket.routes, err)
			}
			routes = append(routes, ticket.routes[0])
		}
		return routes
	}
	countRoutes := func(tickets int) map[proto.TargetID]int {
		counts := map[proto.TargetID]int{}
		for _, route := range routeTickets(tickets) {
			counts[route.targetID]++
		}
		return counts
	}

	withoutACK := countRoutes(64)
	if withoutACK[ids["unknown"]] != 1 || withoutACK[ids["known"]] != 63 {
		t.Fatalf("no-ACK qualification consumed unbounded DATA: %v", withoutACK)
	}
	scheduling.acknowledged[ids["unknown"]] = MaxPayload
	withProgress := countRoutes(16)
	if withProgress[ids["unknown"]] != 2 || withProgress[ids["known"]] != 14 {
		t.Fatalf("ACK-gated qualification was not a bounded interleaved burst: %v", withProgress)
	}
	withoutMoreProgress := countRoutes(64)
	if withoutMoreProgress[ids["unknown"]] != 1 {
		t.Fatalf("qualification did not retain bounded no-ACK maintenance: %v", withoutMoreProgress)
	}

	totalUnknown := withoutACK[ids["unknown"]] + withProgress[ids["unknown"]] +
		withoutMoreProgress[ids["unknown"]]
	pressureFrames := 0
	completeFrames := 0
	episodeComplete := false
	for generation := 0; generation < 16 && !episodeComplete; generation++ {
		scheduling.acknowledged[ids["unknown"]] += MaxPayload
		routes := routeTickets(int(bondQualificationMaximumCredit*2 + 16))
		unknownCount := 0
		currentRun := 0
		longestRun := 0
		for _, route := range routes {
			if route.targetID != ids["unknown"] {
				currentRun = 0
				continue
			}
			if episodeComplete {
				continue
			}
			unknownCount++
			if route.capacityQualificationPressure {
				pressureFrames++
			}
			if route.capacityQualificationComplete {
				completeFrames++
				episodeComplete = true
			}
			currentRun++
			if currentRun > longestRun {
				longestRun = currentRun
			}
		}
		if longestRun > int(bondQualificationMaximumBurst) {
			t.Fatalf("generation %d qualification burst=%d limit=%d", generation, longestRun, bondQualificationMaximumBurst)
		}
		totalUnknown += unknownCount
	}
	if totalUnknown != int(bondQualificationMaximumTokens) {
		t.Fatalf("cross-ACK qualification tokens=%d want=%d", totalUnknown, bondQualificationMaximumTokens)
	}
	wantPressure := int(bondQualificationMaximumTokens-bondQualificationPressureThreshold) + 1
	if pressureFrames != wantPressure {
		t.Fatalf("sender-pressure qualification frames=%d want=%d", pressureFrames, wantPressure)
	}
	if completeFrames != 1 {
		t.Fatalf("qualification completion markers=%d want=1", completeFrames)
	}
	maintenance := 0
	maintenanceCalls := 0
	for generation := 0; generation < 8; generation++ {
		scheduling.acknowledged[ids["unknown"]] += MaxPayload
		routes := routeTickets(128)
		maintenanceCalls += len(routes)
		previousUnknown := false
		for _, route := range routes {
			if route.targetID != ids["unknown"] {
				previousUnknown = false
				continue
			}
			if !route.capacityQualification || !route.capacityQualificationComplete {
				t.Fatalf("maintenance probe lacks completed pressure marker: %+v", route)
			}
			if previousUnknown {
				t.Fatal("maintenance qualification formed a burst")
			}
			previousUnknown = true
			maintenance++
		}
	}
	maximumMaintenance := maintenanceCalls/int(bondQualificationMaintenanceFrames) + 1
	if maintenance == 0 || maintenance > maximumMaintenance {
		t.Fatalf("post-budget maintenance probes=%d limit=%d", maintenance, maximumMaintenance)
	}
}

func TestBondLostFirstQualificationProbeRepairsBeforeStarvation(t *testing.T) {
	known := bondGraphNode(proto.GraphNodeKindPath, "known")
	unknown := bondGraphNode(proto.GraphNodeKindPath, "unknown")
	root := bondGraphNode(proto.GraphNodeKindBond, "root", known, unknown)
	manifest, ids := bondGraphManifest(t, root, known, unknown)
	runtime := mustExecutionRuntime(t, manifest)
	attached := map[proto.TargetID]bool{ids["known"]: true, ids["unknown"]: true}
	scheduling := bondSchedulingContext{
		now: time.Unix(66_500, 0), topologyEpoch: 1,
		staticWeights: map[proto.TargetID]uint64{
			ids["known"]: 1, ids["unknown"]: 1,
		},
		effectiveWeights: map[proto.TargetID]uint64{
			ids["known"]: bondCapacityWeightScale, ids["unknown"]: 1,
		},
		observed:      map[proto.TargetID]bool{ids["known"]: true},
		acknowledged:  map[proto.TargetID]uint64{},
		evidenceAware: true,
	}
	next := func(index int) dispatchRoute {
		ticket, err := runtime.buildTicketScheduledPresence(
			attached, attached, nil, scheduling, true, 1, 0,
		)
		if err != nil || len(ticket.routes) != 1 {
			t.Fatalf("qualification ticket %d routes=%+v err=%v", index, ticket.routes, err)
		}
		return ticket.routes[0]
	}

	if route := next(0); route.targetID != ids["unknown"] || !route.capacityQualification {
		t.Fatalf("initial qualification route=%+v want unknown probe", route)
	}
	probeAt := []int{0}
	for index := 1; index <= 2*int(bondQualificationMaintenanceFrames)+4; index++ {
		if route := next(index); route.targetID == ids["unknown"] {
			probeAt = append(probeAt, index)
			if len(probeAt) == 3 {
				break
			}
		}
	}
	if len(probeAt) != 3 {
		t.Fatalf("lost first probe was permanently starved: probes=%v", probeAt)
	}
	for index := 1; index < len(probeAt); index++ {
		gap := probeAt[index] - probeAt[index-1]
		if gap < int(bondQualificationMaintenanceFrames) ||
			gap > int(bondQualificationMaintenanceFrames)+2 {
			t.Fatalf("maintenance gap %d=%d outside bounded low duty: %v", index, gap, probeAt)
		}
	}

	// The second maintenance copy survives after the path recovers. Subsequent
	// cumulative ACK progress may reopen bounded bursts, but the domain still
	// cannot consume more than its original token allowance.
	scheduling.acknowledged[ids["unknown"]] = MaxPayload
	qualified := false
	probeCount := len(probeAt)
	for index := 0; index < 1024; index++ {
		route := next(index + probeAt[len(probeAt)-1] + 1)
		if route.targetID != ids["unknown"] {
			continue
		}
		probeCount++
		scheduling.acknowledged[ids["unknown"]] += MaxPayload
		if route.capacityQualificationComplete {
			qualified = true
			break
		}
	}
	if !qualified {
		t.Fatal("recovered unknown path never completed qualification")
	}
	if probeCount != int(bondQualificationMaximumTokens) {
		t.Fatalf("repair consumed %d probes want domain budget %d", probeCount, bondQualificationMaximumTokens)
	}
}

func TestBondQualificationResetsForSelectorGenerationAndACKRollback(t *testing.T) {
	a := bondGraphNode(proto.GraphNodeKindPath, "a")
	b := bondGraphNode(proto.GraphNodeKindPath, "b")
	c := bondGraphNode(proto.GraphNodeKindPath, "c")
	choice := bondGraphNode(proto.GraphNodeKindSelector, "choice", a, b)
	root := bondGraphNode(proto.GraphNodeKindBond, "root", choice, c)
	manifest, ids := bondGraphManifest(t, root, choice, a, b, c)
	runtime := mustExecutionRuntime(t, manifest)
	attached := map[proto.TargetID]bool{
		ids["a"]: true, ids["b"]: true, ids["c"]: true,
	}
	if err := runtime.commitSelectorChild(ids["choice"], ids["a"], attached, nil); err != nil {
		t.Fatalf("select a: %v", err)
	}
	scheduling := bondSchedulingContext{
		now: time.Unix(67_000, 0), topologyEpoch: 1,
		staticWeights: map[proto.TargetID]uint64{
			ids["a"]: 1, ids["b"]: 1, ids["c"]: 1,
		},
		effectiveWeights: map[proto.TargetID]uint64{
			ids["a"]: 1, ids["b"]: 1, ids["c"]: 100,
		},
		observed: map[proto.TargetID]bool{ids["c"]: true},
		acknowledged: map[proto.TargetID]uint64{
			ids["a"]: 100, ids["b"]: 10,
		},
		evidenceAware: true,
	}
	next := func() dispatchRoute {
		ticket, err := runtime.buildTicketScheduledPresence(
			attached, attached, nil, scheduling, true, 1, 0,
		)
		if err != nil || len(ticket.routes) != 1 {
			t.Fatalf("qualification ticket routes=%+v err=%v", ticket.routes, err)
		}
		return ticket.routes[0]
	}
	if route := next(); route.targetID != ids["a"] {
		t.Fatalf("initial selector qualification target=%x want a", route.targetID)
	}
	for index := 0; index < 32; index++ {
		if route := next(); route.targetID == ids["a"] {
			t.Fatalf("selector reused qualification without ACK at ticket %d", index)
		}
	}

	if err := runtime.commitSelectorChild(ids["choice"], ids["b"], attached, nil); err != nil {
		t.Fatalf("select b: %v", err)
	}
	if route := next(); route.targetID != ids["b"] {
		t.Fatalf("selector generation did not reset qualification target=%x want b", route.targetID)
	}
	for index := 0; index < 32; index++ {
		_ = next()
	}

	// First grow the B frontier, then move it backwards without changing the
	// selector. A replacement leaf generation may legitimately restart at a
	// lower cumulative counter and must receive a fresh bounded probe.
	scheduling.acknowledged[ids["b"]] = 200
	if route := next(); route.targetID != ids["b"] {
		t.Fatalf("ACK progress did not reopen qualification target=%x want b", route.targetID)
	}
	for index := 0; index < 32; index++ {
		_ = next()
	}
	scheduling.acknowledged[ids["b"]] = 20
	if route := next(); route.targetID != ids["b"] {
		t.Fatalf("ACK rollback did not reset qualification target=%x want b", route.targetID)
	}
}

func TestBondQualificationIdentityChurnCannotRefreshDomainDuty(t *testing.T) {
	a := bondGraphNode(proto.GraphNodeKindPath, "a")
	b := bondGraphNode(proto.GraphNodeKindPath, "b")
	c := bondGraphNode(proto.GraphNodeKindPath, "c")
	choice := bondGraphNode(proto.GraphNodeKindSelector, "choice", a, b)
	root := bondGraphNode(proto.GraphNodeKindBond, "root", choice, c)
	manifest, ids := bondGraphManifest(t, root, choice, a, b, c)
	runtime := mustExecutionRuntime(t, manifest)
	attached := map[proto.TargetID]bool{
		ids["a"]: true, ids["b"]: true, ids["c"]: true,
	}
	scheduling := bondSchedulingContext{
		now: time.Unix(67_500, 0), topologyEpoch: 1,
		staticWeights: map[proto.TargetID]uint64{
			ids["a"]: 1, ids["b"]: 1, ids["c"]: 1,
		},
		effectiveWeights: map[proto.TargetID]uint64{
			ids["a"]: 1, ids["b"]: 1, ids["c"]: bondCapacityWeightScale,
		},
		observed: map[proto.TargetID]bool{ids["c"]: true},
		acknowledged: map[proto.TargetID]uint64{
			ids["a"]: 0, ids["b"]: 0,
		},
		evidenceAware: true,
	}
	next := func(index int) dispatchRoute {
		ticket, err := runtime.buildTicketScheduledPresence(
			attached, attached, nil, scheduling, true, 1, 0,
		)
		if err != nil || len(ticket.routes) != 1 {
			t.Fatalf("churn ticket %d routes=%+v err=%v", index, ticket.routes, err)
		}
		return ticket.routes[0]
	}

	const churnTickets = 4096
	unknownRoutes := 0
	selected := ids["a"]
	for index := 0; index < churnTickets; index++ {
		if index%2 == 0 {
			if (index/2)%2 == 0 {
				selected = ids["a"]
			} else {
				selected = ids["b"]
			}
			if err := runtime.commitSelectorChild(ids["choice"], selected, attached, nil); err != nil {
				t.Fatalf("churn selector ticket %d: %v", index, err)
			}
			scheduling.acknowledged[selected] = uint64(index + 1024)
		} else {
			// Roll the selected leaf's ACK frontier behind the just-observed
			// value. This resets causality without changing the bond domain.
			scheduling.acknowledged[selected] = 0
		}
		if route := next(index); route.targetID == selected {
			if !route.capacityQualification {
				t.Fatalf("churn ticket %d unknown route lacks qualification marker", index)
			}
			unknownRoutes++
		}
	}
	globalBound := int(bondQualificationMaximumTokens) +
		(churnTickets+int(bondQualificationMaintenanceFrames)-1)/int(bondQualificationMaintenanceFrames)
	if unknownRoutes > globalBound {
		t.Fatalf("identity churn sustained %d unknown routes above global bound %d", unknownRoutes, globalBound)
	}
	if unknownRoutes >= churnTickets/8 {
		t.Fatalf("identity churn retained near-burst duty: unknown=%d total=%d", unknownRoutes, churnTickets)
	}

	// Once identity stops moving, sparse ACK-backed maintenance must still
	// qualify that identity even though churn exhausted the global burst budget.
	if err := runtime.commitSelectorChild(ids["choice"], ids["b"], attached, nil); err != nil {
		t.Fatalf("stabilize through b: %v", err)
	}
	if err := runtime.commitSelectorChild(ids["choice"], ids["a"], attached, nil); err != nil {
		t.Fatalf("stabilize on a: %v", err)
	}
	scheduling.acknowledged[ids["a"]] = 1
	maintenanceProbes := 0
	qualified := false
	maximumCalls := int(bondQualificationMaintenanceFrames) *
		(int(bondQualificationPressureThreshold) + 2)
	for index := 0; index < maximumCalls; index++ {
		route := next(churnTickets + index)
		if route.targetID != ids["a"] {
			continue
		}
		maintenanceProbes++
		scheduling.acknowledged[ids["a"]] += MaxPayload
		if route.capacityQualificationComplete {
			qualified = true
			break
		}
	}
	if !qualified {
		t.Fatalf("stable identity did not qualify after %d maintenance probes", maintenanceProbes)
	}
	if maintenanceProbes != int(bondQualificationPressureThreshold) {
		t.Fatalf("stable identity qualified after %d probes want %d", maintenanceProbes, bondQualificationPressureThreshold)
	}
}

func TestBondCapacityNormalizationExcludesGhostEvidence(t *testing.T) {
	now := time.Unix(68_000, 0)
	slow := bondGraphNode(proto.GraphNodeKindPath, "slow")
	fast := bondGraphNode(proto.GraphNodeKindPath, "fast")
	root := bondGraphNode(proto.GraphNodeKindBond, "root", slow, fast)
	manifest, ids := bondGraphManifest(t, root, slow, fast)
	ghost := proto.DeriveTargetID(proto.GraphNodeKindPath, "stalled-ghost")
	latest := map[proto.TargetID]*pathSlot{
		ids["slow"]: {spec: transport.PathSpec{Weight: 1}},
		ids["fast"]: {spec: transport.PathSpec{Weight: 1}},
	}
	delivered := map[proto.TargetID]speedEstimate{
		ids["slow"]: freshBondCapacity(now, 1),
		ids["fast"]: freshBondCapacity(now, 100),
		ghost:       freshBondCapacity(now, math.MaxUint64),
	}
	scheduling := bondDispatchScheduling(latest, delivered, nil, now, 1)
	if scheduling.observed[ghost] || scheduling.effectiveWeights[ghost] != 0 {
		t.Fatalf("stalled ghost entered scheduling context: %+v", scheduling)
	}
	runtime := mustExecutionRuntime(t, manifest)
	attached := map[proto.TargetID]bool{ids["slow"]: true, ids["fast"]: true}
	counts := map[proto.TargetID]int{}
	for index := 0; index < 1010; index++ {
		ticket, err := runtime.buildTicketScheduledPresence(
			attached, attached, nil, scheduling, true, 1, 0,
		)
		if err != nil || len(ticket.routes) != 1 {
			t.Fatalf("ticket %d routes=%+v err=%v", index, ticket.routes, err)
		}
		counts[ticket.routes[0].targetID]++
	}
	if counts[ids["slow"]] < 8 || counts[ids["slow"]] > 12 ||
		counts[ids["fast"]] != 1010-counts[ids["slow"]] {
		t.Fatalf("ghost compressed active 1:100 domain: %v", counts)
	}
}

func TestBondCapacityNormalizationIgnoresUnselectedSelectorSibling(t *testing.T) {
	now := time.Unix(69_000, 0)
	a := bondGraphNode(proto.GraphNodeKindPath, "a")
	b := bondGraphNode(proto.GraphNodeKindPath, "b")
	c := bondGraphNode(proto.GraphNodeKindPath, "c")
	choice := bondGraphNode(proto.GraphNodeKindSelector, "choice", a, b)
	root := bondGraphNode(proto.GraphNodeKindBond, "root", choice, c)
	manifest, ids := bondGraphManifest(t, root, choice, a, b, c)
	runtime := mustExecutionRuntime(t, manifest)
	attached := map[proto.TargetID]bool{
		ids["a"]: true, ids["b"]: true, ids["c"]: true,
	}
	if err := runtime.commitSelectorChild(ids["choice"], ids["a"], attached, nil); err != nil {
		t.Fatalf("select a: %v", err)
	}
	latest := map[proto.TargetID]*pathSlot{
		ids["a"]: {spec: transport.PathSpec{Weight: 1}},
		ids["b"]: {spec: transport.PathSpec{Weight: 1}},
		ids["c"]: {spec: transport.PathSpec{Weight: 1}},
	}
	scheduling := bondDispatchScheduling(latest, map[proto.TargetID]speedEstimate{
		ids["a"]: freshBondCapacity(now, 1),
		ids["b"]: freshBondCapacity(now, math.MaxUint64),
		ids["c"]: freshBondCapacity(now, 100),
	}, nil, now, 1)
	counts := map[proto.TargetID]int{}
	for index := 0; index < 1010; index++ {
		ticket, err := runtime.buildTicketScheduledPresence(
			attached, attached, nil, scheduling, true, 1, 0,
		)
		if err != nil || len(ticket.routes) != 1 {
			t.Fatalf("ticket %d routes=%+v err=%v", index, ticket.routes, err)
		}
		counts[ticket.routes[0].targetID]++
	}
	if counts[ids["b"]] != 0 || counts[ids["a"]] < 8 || counts[ids["a"]] > 12 ||
		counts[ids["c"]] != 1010-counts[ids["a"]] {
		t.Fatalf("unselected selector sibling compressed parent domain: %v", counts)
	}
}

func freshBondCapacity(at time.Time, rate uint64) speedEstimate {
	return speedEstimate{
		state: qualityStateFresh, bytesPerSecond: rate,
		confidence: evidenceConfidenceFull, source: speedSourceDelivered,
		sampleTime: at, sampleCount: 1,
	}
}

func TestBondCapacityWindowPressureGate(t *testing.T) {
	window := selectorGoodputMinimumWindow
	if bondCapacityWindowPressured(window, uint64(window/4)-1) {
		t.Fatal("minority writer occupancy mislabeled a demand-limited window")
	}
	if !bondCapacityWindowPressured(window, uint64(window/4)) {
		t.Fatal("qualification duty threshold rejected a capacity-limited window")
	}
	if bondCapacityWindowPressured(window, 0) {
		t.Fatal("zero writer occupancy became capacity evidence")
	}
}

func TestBondQualificationSenderPressureConvergesWithoutWriterOccupancy(t *testing.T) {
	base := time.Unix(69_500, 0)
	clock := newBondTestClock(base)
	installEngineNowForTest(t, clock.Now)
	known := bondGraphNode(proto.GraphNodeKindPath, "known")
	unknown := bondGraphNode(proto.GraphNodeKindPath, "unknown")
	root := bondGraphNode(proto.GraphNodeKindBond, "root", known, unknown)
	manifest, ids := bondGraphManifest(t, root, known, unknown)
	fixture := newBondPhysicalFixture(t, clock, manifest, ids, map[string]bondPhysicalPathSpec{
		"known":   {weight: 100, autoACK: true},
		"unknown": {weight: 1, autoACK: true},
	})
	seedBondCapacityEvidence(fixture.engine, base, map[proto.TargetID]uint64{
		ids["known"]: 1,
	})
	payload := make([]byte, MaxPayload)
	convergedAt := -1
	for index := 0; index < 512; index++ {
		if err := fixture.engine.SendPacket(payload); err != nil {
			t.Fatalf("packet %d: %v", index, err)
		}
		clock.Advance(time.Millisecond)
		evidence, valid := fixture.engine.targetCapacitySpeedsAtEpoch(
			clock.Now(), fixture.engine.currentPathTopologyEpoch(),
		)
		if !valid {
			t.Fatalf("packet %d crossed topology epoch", index)
		}
		if evidence[ids["unknown"]].observed() {
			convergedAt = index
			break
		}
	}
	if convergedAt < 0 {
		t.Fatal("bounded qualification never produced ACK-confirmed sender-pressure capacity")
	}
	maximumEpisodeFrames := bondQualificationMaximumTokens +
		(bondQualificationMaximumTokens/bondQualificationMaximumBurst+1)*bondQualificationInterleaveFrames
	if convergedAt >= int(maximumEpisodeFrames)+16 {
		t.Fatalf("sender-pressure convergence packet=%d exceeded bounded token episode", convergedAt)
	}
	unknownSeq, unknownACKErrors := fixture.paths["unknown"].snapshot()
	if unknownACKErrors != 0 || len(unknownSeq) < int(bondQualificationPressureThreshold)+1 {
		t.Fatalf("unknown path pressure cohort seq=%d ACK errors=%d", len(unknownSeq), unknownACKErrors)
	}
}

func TestBondQualificationMaintenanceConvergesForSmallPackets(t *testing.T) {
	base := time.Unix(69_750, 0)
	clock := newBondTestClock(base)
	installEngineNowForTest(t, clock.Now)
	known := bondGraphNode(proto.GraphNodeKindPath, "known")
	unknown := bondGraphNode(proto.GraphNodeKindPath, "unknown")
	root := bondGraphNode(proto.GraphNodeKindBond, "root", known, unknown)
	manifest, ids := bondGraphManifest(t, root, known, unknown)
	fixture := newBondPhysicalFixture(t, clock, manifest, ids, map[string]bondPhysicalPathSpec{
		"known":   {weight: 100, autoACK: true},
		"unknown": {weight: 1, autoACK: true},
	})
	seedBondCapacityEvidence(fixture.engine, base, map[proto.TargetID]uint64{
		ids["known"]: 1,
	})
	payload := make([]byte, 256)
	convergedAt := -1
	for index := 0; index < 8192; index++ {
		if err := fixture.engine.SendPacket(payload); err != nil {
			t.Fatalf("packet %d: %v", index, err)
		}
		clock.Advance(100 * time.Microsecond)
		evidence, valid := fixture.engine.targetCapacitySpeedsAtEpoch(
			clock.Now(), fixture.engine.currentPathTopologyEpoch(),
		)
		if !valid {
			t.Fatalf("packet %d crossed topology epoch", index)
		}
		if evidence[ids["unknown"]].observed() {
			convergedAt = index
			break
		}
	}
	if convergedAt < 0 {
		t.Fatal("small-packet qualification did not converge through bounded maintenance")
	}
	unknownSeq, ackErrors := fixture.paths["unknown"].snapshot()
	maximumProbes := int(bondQualificationMaximumTokens) +
		convergedAt/int(bondQualificationMaintenanceFrames) + 2
	if ackErrors != 0 || len(unknownSeq) > maximumProbes {
		t.Fatalf("small-packet probes=%d limit=%d ACK errors=%d", len(unknownSeq), maximumProbes, ackErrors)
	}
}

func TestBondUnknownPathQualificationDoesNotSelfLockAtExactDemand(t *testing.T) {
	base := time.Unix(70_000, 0)
	clock := newBondTestClock(base)
	installEngineNowForTest(t, clock.Now)
	slow := bondGraphNode(proto.GraphNodeKindPath, "slow")
	fast := bondGraphNode(proto.GraphNodeKindPath, "fast")
	root := bondGraphNode(proto.GraphNodeKindBond, "root", slow, fast)
	manifest, ids := bondGraphManifest(t, root, slow, fast)
	fixture := newBondPhysicalFixture(t, clock, manifest, ids, map[string]bondPhysicalPathSpec{
		"slow": {weight: 100},
		"fast": {weight: 1},
	})
	seedBondCapacityEvidence(fixture.engine, clock.Now(), map[proto.TargetID]uint64{
		ids["slow"]: 8, ids["fast"]: 64,
	})
	payload := make([]byte, MaxPayload)
	for index := 0; index < 72; index++ {
		if err := fixture.engine.SendPacket(payload); err != nil {
			t.Fatalf("packet %d: %v", index, err)
		}
	}
	slowSeq, slowACKErrors := fixture.paths["slow"].snapshot()
	fastSeq, fastACKErrors := fixture.paths["fast"].snapshot()
	if slowACKErrors != 0 || fastACKErrors != 0 {
		t.Fatalf("physical ACK errors slow/fast=%d/%d", slowACKErrors, fastACKErrors)
	}
	if len(slowSeq) != 8 || len(fastSeq) != 64 {
		t.Fatalf("exact 8:64 demand self-locked: slow=%d fast=%d", len(slowSeq), len(fastSeq))
	}
	evidence, valid := fixture.engine.targetCapacitySpeedsAtEpoch(
		clock.Now(), fixture.engine.currentPathTopologyEpoch(),
	)
	if !valid || evidence[ids["slow"]].bytesPerSecond == 0 ||
		evidence[ids["fast"]].bytesPerSecond < 7*evidence[ids["slow"]].bytesPerSecond {
		t.Fatalf("physical 8:64 capacity evidence valid=%t evidence=%+v", valid, evidence)
	}
}

func TestBondSparseTwoMillisecondWritesAreDemandLimited(t *testing.T) {
	base := time.Unix(80_000, 0)
	clock := newBondTestClock(base)
	installEngineNowForTest(t, clock.Now)
	path := bondGraphNode(proto.GraphNodeKindPath, "sparse")
	root := bondGraphNode(proto.GraphNodeKindBond, "root", path)
	manifest, ids := bondGraphManifest(t, root, path)
	fixture := newBondPhysicalFixture(t, clock, manifest, ids, map[string]bondPhysicalPathSpec{
		"sparse": {weight: 7, service: 2 * time.Millisecond, autoACK: true},
	})
	payload := make([]byte, 1024)
	for index := 0; index < selectorGoodputMinimumBytes/len(payload); index++ {
		if err := fixture.engine.SendPacket(payload); err != nil {
			t.Fatalf("sparse packet %d: %v", index, err)
		}
		if index+1 < selectorGoodputMinimumBytes/len(payload) {
			clock.Advance(14 * time.Millisecond)
		}
	}
	if elapsed := clock.Now().Sub(base); elapsed < selectorGoodputMinimumWindow {
		t.Fatalf("sparse observation span=%v want >=%v", elapsed, selectorGoodputMinimumWindow)
	}
	evidence, valid := fixture.engine.targetCapacitySpeedsAtEpoch(
		clock.Now(), fixture.engine.currentPathTopologyEpoch(),
	)
	if !valid || len(evidence) != 0 {
		t.Fatalf("sparse fixed Write overhead became capacity valid=%t evidence=%+v", valid, evidence)
	}
}

func TestBondCapacityRejectsACKAfterFailedSameLeafReplayAttempt(t *testing.T) {
	clock := newBondTestClock(time.Unix(85_000, 0))
	installEngineNowForTest(t, clock.Now)
	fixture := newProductionBondFixture(t,
		productionBondPath{name: "a", weight: 1},
		productionBondPath{name: "b", weight: 1},
	)
	topologyEpoch := fixture.engine.currentPathTopologyEpoch()
	now := clock.Now()
	fixture.engine.sendHistMu.Lock()
	fixture.engine.addTargetCapacityDeliveryLocked(
		fixture.ids["a"], topologyEpoch,
		targetCapacityObservation{
			seen: true, attributable: true, bytes: MaxPayload,
			serviceNanos: uint64(selectorGoodputMinimumWindow),
			started:      now.Add(-2 * selectorGoodputMinimumWindow),
			completed:    now.Add(-selectorGoodputMinimumWindow),
		},
		now.Add(-selectorGoodputMinimumWindow),
	)
	if state := fixture.engine.sendHist.targetDelivery[fixture.ids["a"]]; state.capacityWindowACKSamples != 1 {
		fixture.engine.sendHistMu.Unlock()
		t.Fatalf("capacity anchor samples=%d want 1", state.capacityWindowACKSamples)
	}
	fixture.engine.sendHistMu.Unlock()
	frame := make([]byte, proto.HeaderSize+MaxPayload)
	if err := (proto.Header{
		Version: proto.Version, Type: proto.FrameData, Seq: 0,
	}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	if err := fixture.engine.acquireSendSlot(false, len(frame)); err != nil {
		t.Fatal(err)
	}
	if err := fixture.engine.reserveOwnedSendFrame(frame); err != nil {
		t.Fatal(err)
	}
	fixture.engine.publishSendSeq(1)
	failed := fixture.engine.beginApplicationBatchDispatch(
		frame, fixture.slots["a"], fixture.engine.currentPathTopologyEpoch(),
	)
	if failed == nil {
		t.Fatal("failed physical attempt did not reserve attribution")
	}
	// Ordinary path dispatch records a physical route attempt even when Write
	// fails; it has no successful service observation.
	fixture.engine.resolveApplicationBatchDispatch(
		[]*batchDispatchAttributionReceipt{failed}, 1,
	)
	replay := fixture.engine.beginApplicationBatchDispatch(
		frame, fixture.slots["a"], fixture.engine.currentPathTopologyEpoch(),
	)
	if replay == nil {
		t.Fatal("same-leaf replay did not reserve attribution")
	}
	replay.noteCapacityPressure(applicationDispatchPressureObservation{
		startedAt: now, completedAt: now.Add(selectorGoodputMinimumWindow),
		serviceDuration: selectorGoodputMinimumWindow,
	})
	now = clock.Advance(selectorGoodputMinimumWindow)
	fixture.engine.resolveApplicationBatchDispatch(
		[]*batchDispatchAttributionReceipt{replay}, 1,
	)
	fixture.engine.sendHistMu.Lock()
	entry := fixture.engine.sendHistoryEntryLocked(0)
	if entry == nil {
		fixture.engine.sendHistMu.Unlock()
		t.Fatal("replayed frame absent from ledger")
	}
	proof := entry.proof
	fixture.engine.sendHistMu.Unlock()
	if valid, application := fixture.engine.acknowledgeSendFramesAt(1, proof, now); !valid || !application {
		t.Fatalf("replay ACK valid/application=%t/%t", valid, application)
	}
	fixture.engine.sendHistMu.Lock()
	capacityState := fixture.engine.sendHist.targetDelivery[fixture.ids["a"]]
	fixture.engine.sendHistMu.Unlock()
	if capacityState.capacityWindowACKSamples != 0 {
		t.Fatalf("ambiguous same-leaf replay retained capacity cohort: %+v", capacityState)
	}
	evidence, valid := fixture.engine.targetCapacitySpeedsAtEpoch(
		now, fixture.engine.currentPathTopologyEpoch(),
	)
	if !valid || len(evidence) != 0 {
		t.Fatalf("ambiguous failed replay produced capacity valid=%t evidence=%+v", valid, evidence)
	}
}

func publishControlledBondFrame(
	t *testing.T,
	fixture bondPhysicalFixture,
	sequence uint64,
	pathName string,
	capacityQualification bool,
	capacityQualificationPressure bool,
	capacityQualificationComplete bool,
	results chan pathDispatchResult,
) {
	t.Helper()
	frame := make([]byte, proto.HeaderSize+MaxPayload)
	if err := (proto.Header{
		Version: proto.Version, Type: proto.FrameData, Seq: sequence,
	}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	if err := fixture.engine.acquireSendSlot(false, len(frame)); err != nil {
		t.Fatal(err)
	}
	if err := fixture.engine.reserveOwnedSendFrame(frame); err != nil {
		t.Fatal(err)
	}
	fixture.engine.publishSendSeq(sequence + 1)
	admission, err := fixture.engine.admitFrameDispatch(frame, true)
	if err != nil {
		t.Fatalf("admit sequence %d: %v", sequence, err)
	}
	if !fixture.slots[pathName].submitDispatch(pathDispatchJob{
		frame: frame, bonded: true, capacityQualification: capacityQualification,
		capacityQualificationPressure: capacityQualificationPressure,
		capacityQualificationComplete: capacityQualificationComplete,
		topologyEpoch:                 fixture.engine.currentPathTopologyEpoch(),
		firstPublication:              true, admission: admission, result: results,
	}) {
		t.Fatalf("submit sequence %d to %s", sequence, pathName)
	}
}

func awaitControlledBondWrite(t *testing.T, path *bondPhysicalPath, want uint64) bondControlledWrite {
	t.Helper()
	select {
	case attempt := <-path.started:
		if attempt.sequence != want {
			t.Fatalf("path %s started sequence=%d want %d", path.name, attempt.sequence, want)
		}
		return attempt
	case <-time.After(2 * time.Second):
		t.Fatalf("path %s did not start sequence %d", path.name, want)
		return bondControlledWrite{}
	}
}

func awaitControlledBondResult(t *testing.T, results <-chan pathDispatchResult, pathName string) {
	t.Helper()
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("physical dispatch on %s: %v", pathName, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("physical dispatch on %s did not complete", pathName)
	}
}

type orderedBondCompletion struct {
	pathName string
	sequence uint64
	at       time.Time
}

type orderedBondRound struct {
	counts            map[string]int
	holObserved       bool
	maxCompletedAhead int
}

// runOrderedControlledBondRound preserves the scheduler's route order as the
// global SEQ order. Per-path service completes independently, while ACK only
// advances over the contiguous receiver frontier, so HOL and cross-leaf
// cumulative ACKs exercise the same attribution path as production.
func runOrderedControlledBondRound(
	t *testing.T,
	fixture bondPhysicalFixture,
	clock *bondTestClock,
	frames int,
	service map[string]time.Duration,
) orderedBondRound {
	t.Helper()
	if frames <= 0 || frames > pathDispatchQueueSize {
		t.Fatalf("ordered round frames=%d outside 1..%d", frames, pathDispatchQueueSize)
	}
	base := clock.Now()
	sequence := fixture.engine.sendPublishedNext.Load()
	counts := make(map[string]int, len(service))
	results := make(map[string]chan pathDispatchResult, len(service))
	pathSequences := make(map[string][]uint64, len(service))
	events := make([]orderedBondCompletion, 0, frames)
	for index := 0; index < frames; index++ {
		ticket, _, err := fixture.engine.recursiveDispatchTicket(
			fixture.runtime, false, clock.Now(),
		)
		if err != nil || len(ticket.routes) != 1 {
			t.Fatalf("ordered ticket %d routes=%+v err=%v", index, ticket.routes, err)
		}
		node, ok := fixture.runtime.plan.node(ticket.routes[0].targetID)
		if !ok {
			t.Fatalf("ordered ticket %d target=%x absent", index, ticket.routes[0].targetID)
		}
		duration := service[node.name]
		if duration <= 0 {
			t.Fatalf("ordered ticket %d path %q service=%v", index, node.name, duration)
		}
		counts[node.name]++
		result := results[node.name]
		if result == nil {
			result = make(chan pathDispatchResult, frames)
			results[node.name] = result
		}
		publishControlledBondFrame(
			t, fixture, sequence+uint64(index), node.name,
			ticket.routes[0].capacityQualification,
			ticket.routes[0].capacityQualificationPressure,
			ticket.routes[0].capacityQualificationComplete, result,
		)
		pathSequences[node.name] = append(pathSequences[node.name], sequence+uint64(index))
		events = append(events, orderedBondCompletion{
			pathName: node.name,
			sequence: sequence + uint64(index),
			at:       base.Add(time.Duration(counts[node.name]) * duration),
		})
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].at.Equal(events[j].at) {
			return events[i].sequence < events[j].sequence
		}
		return events[i].at.Before(events[j].at)
	})
	completed := make(map[uint64]bool, frames)
	pending := make(map[string]bondControlledWrite, len(pathSequences))
	completedByPath := make(map[string]int, len(pathSequences))
	for pathName, sequences := range pathSequences {
		pending[pathName] = awaitControlledBondWrite(t, fixture.paths[pathName], sequences[0])
	}
	frontier := sequence
	holObserved := false
	maxCompletedAhead := 0
	for _, event := range events {
		clock.Set(event.at)
		attempt := pending[event.pathName]
		if attempt.sequence != event.sequence {
			t.Fatalf("path %s pending sequence=%d want=%d", event.pathName, attempt.sequence, event.sequence)
		}
		close(attempt.release)
		awaitControlledBondResult(t, results[event.pathName], event.pathName)
		completedByPath[event.pathName]++
		if next := completedByPath[event.pathName]; next < len(pathSequences[event.pathName]) {
			pending[event.pathName] = awaitControlledBondWrite(
				t, fixture.paths[event.pathName], pathSequences[event.pathName][next],
			)
		} else {
			delete(pending, event.pathName)
		}
		completed[event.sequence] = true
		if event.sequence > frontier {
			holObserved = true
		}
		completedAhead := 0
		for completedSequence := range completed {
			if completedSequence > frontier {
				completedAhead++
			}
		}
		if completedAhead > maxCompletedAhead {
			maxCompletedAhead = completedAhead
		}
		for completed[frontier] {
			frontier++
		}
		if frontier == fixture.engine.sendAckNext.Load() {
			continue
		}
		fixture.engine.sendHistMu.Lock()
		entry := fixture.engine.sendHistoryEntryLocked(frontier - 1)
		if entry == nil {
			fixture.engine.sendHistMu.Unlock()
			t.Fatalf("ordered ACK frontier %d absent", frontier)
		}
		proof := entry.proof
		fixture.engine.sendHistMu.Unlock()
		if valid, application := fixture.engine.acknowledgeSendFramesAt(
			frontier, proof, clock.Now(),
		); !valid || !application {
			t.Fatalf("ordered ACK %d valid/application=%t/%t", frontier, valid, application)
		}
	}
	if got, want := fixture.engine.sendAckNext.Load(), sequence+uint64(frames); got != want {
		t.Fatalf("ordered round ACK frontier=%d want=%d", got, want)
	}
	return orderedBondRound{
		counts: counts, holObserved: holObserved,
		maxCompletedAhead: maxCompletedAhead,
	}
}

func TestBondClosedLoopPreservesSchedulerOrderAndCumulativeACKHOL(t *testing.T) {
	base := time.Unix(92_000, 0)
	clock := newBondTestClock(base)
	installEngineNowForTest(t, clock.Now)
	slow := bondGraphNode(proto.GraphNodeKindPath, "slow")
	fast := bondGraphNode(proto.GraphNodeKindPath, "fast")
	slow.Weight = 100
	fast.Weight = 1
	root := bondGraphNode(proto.GraphNodeKindBond, "root", slow, fast)
	manifest, ids := bondGraphManifest(t, root, slow, fast)
	fixture := newBondPhysicalFixture(t, clock, manifest, ids, map[string]bondPhysicalPathSpec{
		"slow": {weight: 100, controlled: true},
		"fast": {weight: 1, controlled: true},
	})
	service := map[string]time.Duration{
		"slow": 40 * time.Millisecond,
		"fast": 5 * time.Millisecond,
	}
	var learned bool
	holObserved := false
	maxCompletedAhead := 0
	for round := 0; round < 12; round++ {
		observation := runOrderedControlledBondRound(
			t, fixture, clock, pathDispatchQueueSize, service,
		)
		holObserved = holObserved || observation.holObserved
		if observation.maxCompletedAhead > maxCompletedAhead {
			maxCompletedAhead = observation.maxCompletedAhead
		}
		evidence, valid := fixture.engine.targetCapacitySpeedsAtEpoch(
			clock.Now(), fixture.engine.currentPathTopologyEpoch(),
		)
		if !valid {
			t.Fatalf("round %d crossed topology epoch", round)
		}
		if evidence[ids["slow"]].observed() && evidence[ids["fast"]].observed() &&
			evidence[ids["fast"]].bytesPerSecond >= 4*evidence[ids["slow"]].bytesPerSecond {
			learned = true
			break
		}
	}
	if !learned {
		evidence, _ := fixture.engine.targetCapacitySpeedsAtEpoch(
			clock.Now(), fixture.engine.currentPathTopologyEpoch(),
		)
		fixture.engine.sendHistMu.Lock()
		states := make(map[proto.TargetID]targetDeliveryEvidence, len(fixture.engine.sendHist.targetDelivery))
		for id, state := range fixture.engine.sendHist.targetDelivery {
			states[id] = state
		}
		fixture.engine.sendHistMu.Unlock()
		t.Fatalf("ordered cumulative-ACK loop did not learn fast path: evidence=%+v states=%+v", evidence, states)
	}
	if !holObserved || maxCompletedAhead <= 0 || maxCompletedAhead >= pathDispatchQueueSize {
		t.Fatalf("ordered loop HOL observed=%t max-completed-ahead=%d", holObserved, maxCompletedAhead)
	}
	counts := map[proto.TargetID]int{}
	for index := 0; index < 500; index++ {
		ticket, _, err := fixture.engine.recursiveDispatchTicket(
			fixture.runtime, false, clock.Now(),
		)
		if err != nil || len(ticket.routes) != 1 {
			t.Fatalf("learned ticket %d routes=%+v err=%v", index, ticket.routes, err)
		}
		counts[ticket.routes[0].targetID]++
	}
	if counts[ids["fast"]] < 4*counts[ids["slow"]] {
		t.Fatalf("ordered closed-loop distribution=%v", counts)
	}
}

func TestBondCapacityUsesPhysicalServiceSpanAcrossCumulativeACKHOL(t *testing.T) {
	base := time.Unix(90_000, 0)
	clock := newBondTestClock(base)
	installEngineNowForTest(t, clock.Now)
	slow := bondGraphNode(proto.GraphNodeKindPath, "slow")
	fast := bondGraphNode(proto.GraphNodeKindPath, "fast")
	root := bondGraphNode(proto.GraphNodeKindBond, "root", slow, fast)
	manifest, ids := bondGraphManifest(t, root, slow, fast)
	fixture := newBondPhysicalFixture(t, clock, manifest, ids, map[string]bondPhysicalPathSpec{
		"slow": {weight: 1, controlled: true},
		"fast": {weight: 1, controlled: true},
	})
	slowResults := make(chan pathDispatchResult, 4)
	fastResults := make(chan pathDispatchResult, 4)
	for sequence := uint64(0); sequence < 8; sequence++ {
		pathName := "slow"
		results := slowResults
		if sequence%2 != 0 {
			pathName = "fast"
			results = fastResults
		}
		publishControlledBondFrame(t, fixture, sequence, pathName, false, false, false, results)
	}

	slowAttempt := awaitControlledBondWrite(t, fixture.paths["slow"], 0)
	fastAttempt := awaitControlledBondWrite(t, fixture.paths["fast"], 1)
	for index, sequence := range []uint64{1, 3, 5, 7} {
		clock.Set(base.Add(time.Duration(index+1) * 62500 * time.Microsecond))
		close(fastAttempt.release)
		awaitControlledBondResult(t, fastResults, "fast")
		if sequence != 7 {
			fastAttempt = awaitControlledBondWrite(t, fixture.paths["fast"], sequence+2)
		}
	}
	fastCompleted := clock.Now()
	for index, sequence := range []uint64{0, 2, 4, 6} {
		clock.Set(base.Add(time.Duration(index+1) * 260 * time.Millisecond))
		close(slowAttempt.release)
		awaitControlledBondResult(t, slowResults, "slow")
		if sequence != 6 {
			slowAttempt = awaitControlledBondWrite(t, fixture.paths["slow"], sequence+2)
		}
	}
	if !fastCompleted.Before(base.Add(260 * time.Millisecond)) {
		t.Fatalf("fast completion=%v did not precede first slow SEQ completion", fastCompleted.Sub(base))
	}
	if got := fixture.engine.sendAckNext.Load(); got != 0 {
		t.Fatalf("cumulative ACK advanced through held slow SEQ: %d", got)
	}
	fixture.engine.sendHistMu.Lock()
	last := fixture.engine.sendHistoryEntryLocked(7)
	if last == nil {
		fixture.engine.sendHistMu.Unlock()
		t.Fatal("last HOL frame absent from replay ledger")
	}
	proof := last.proof
	fixture.engine.sendHistMu.Unlock()
	if valid, application := fixture.engine.acknowledgeSendFramesAt(8, proof, clock.Now()); !valid || !application {
		t.Fatalf("HOL cumulative ACK valid/application=%t/%t", valid, application)
	}
	evidence, valid := fixture.engine.targetCapacitySpeedsAtEpoch(
		clock.Now(), fixture.engine.currentPathTopologyEpoch(),
	)
	if !valid || evidence[ids["slow"]].observed() || evidence[ids["fast"]].observed() {
		t.Fatalf("cross-leaf cumulative HOL produced capacity valid=%t evidence=%+v", valid, evidence)
	}
}

func TestBondBufferedWritesWithDelayedACKUseACKDrainRate(t *testing.T) {
	base := time.Unix(95_000, 0)
	targetID := proto.DeriveTargetID(proto.GraphNodeKindPath, "buffered")
	e := &Engine{}
	e.sendHist.targetDelivery = map[proto.TargetID]targetDeliveryEvidence{
		targetID: {topologyEpoch: 1, windowStart: base},
	}
	for index, ackDelay := range []time.Duration{time.Millisecond, 501 * time.Millisecond} {
		started := base.Add(time.Duration(index) * selectorGoodputMinimumWindow)
		observation := targetCapacityObservation{
			seen: true, attributable: true, bytes: MaxPayload,
			serviceNanos: uint64(selectorGoodputMinimumWindow / 4),
			started:      started, completed: started.Add(selectorGoodputMinimumWindow),
		}
		acknowledgedAt := base.Add(ackDelay)
		e.addTargetCapacityDeliveryLocked(targetID, 1, observation, acknowledgedAt)
		e.sampleTargetCapacityLocked(targetID, acknowledgedAt)
	}
	state := e.sendHist.targetDelivery[targetID]
	wantMaximum := bytesPerSecond(MaxPayload, 500*time.Millisecond)
	if !state.capacityEstimate.observed() ||
		state.capacityEstimate.bytesPerSecond > wantMaximum {
		t.Fatalf("buffered syscall occupancy inflated capacity above %d: %+v", wantMaximum, state.capacityEstimate)
	}
}

func seedBondCapacityEvidence(
	e *Engine,
	at time.Time,
	rates map[proto.TargetID]uint64,
) {
	e.sendHistMu.Lock()
	if e.sendHist.targetDelivery == nil {
		e.sendHist.targetDelivery = make(map[proto.TargetID]targetDeliveryEvidence)
	}
	epoch := e.currentPathTopologyEpoch()
	for targetID, rate := range rates {
		e.sendHist.targetDelivery[targetID] = targetDeliveryEvidence{
			topologyEpoch: epoch,
			capacityEstimate: speedEstimate{
				state: qualityStateFresh, bytesPerSecond: rate,
				confidence: evidenceConfidenceFull, source: speedSourceDelivered,
				sampleTime: at, sampleCount: 1,
			},
		}
	}
	e.bondEvidenceRevision.Add(1)
	e.bondCapacityRevision.Add(1)
	e.sendHistMu.Unlock()
}

func TestBondEvidenceCacheRevisionAvoidsPerWriteRebuild(t *testing.T) {
	clock := newBondTestClock(time.Unix(105_000, 0))
	installEngineNowForTest(t, clock.Now)
	const pathCount = 32
	children := make([]proto.GraphNode, 0, pathCount)
	nodes := make([]proto.GraphNode, 0, pathCount)
	specs := make(map[string]bondPhysicalPathSpec, pathCount)
	for index := 0; index < pathCount; index++ {
		name := fmt.Sprintf("path-%02d", index)
		path := bondGraphNode(proto.GraphNodeKindPath, name)
		children = append(children, path)
		nodes = append(nodes, path)
		specs[name] = bondPhysicalPathSpec{weight: 1}
	}
	root := bondGraphNode(proto.GraphNodeKindBond, "root", children...)
	manifest, ids := bondGraphManifest(t, root, nodes...)
	fixture := newBondPhysicalFixture(t, clock, manifest, ids, specs)
	payload := []byte{0x5a}
	if err := fixture.engine.SendPacket(payload); err != nil {
		t.Fatalf("warm physical write: %v", err)
	}
	warmRebuilds := fixture.runtime.bondEvidenceRebuilds.Load()
	if warmRebuilds != 1 {
		t.Fatalf("warm evidence rebuilds=%d want 1", warmRebuilds)
	}

	const steadyWrites = 2048
	for index := 0; index < steadyWrites; index++ {
		if err := fixture.engine.SendPacket(payload); err != nil {
			t.Fatalf("steady physical write %d: %v", index, err)
		}
	}
	if got := fixture.runtime.bondEvidenceRebuilds.Load(); got != warmRebuilds {
		t.Fatalf("%d no-ACK writes rebuilt %d path ledgers: before=%d after=%d", steadyWrites, got-warmRebuilds, warmRebuilds, got)
	}

	nextSeq := fixture.engine.sendPublishedNext.Load()
	fixture.engine.sendHistMu.Lock()
	entry := fixture.engine.sendHistoryEntryLocked(nextSeq - 1)
	if entry == nil {
		fixture.engine.sendHistMu.Unlock()
		t.Fatal("steady write ACK frontier is absent")
	}
	proof := entry.proof
	fixture.engine.sendHistMu.Unlock()
	if valid, application := fixture.engine.acknowledgeSendFramesAt(
		nextSeq, proof, clock.Now(),
	); !valid || !application {
		t.Fatalf("steady write ACK valid/application=%t/%t", valid, application)
	}
	if _, _, err := fixture.engine.recursiveDispatchTicket(
		fixture.runtime, false, clock.Now(),
	); err != nil {
		t.Fatalf("post-ACK ticket: %v", err)
	}
	postACKRebuilds := fixture.runtime.bondEvidenceRebuilds.Load()
	if postACKRebuilds != warmRebuilds {
		t.Fatalf("ACK-only revision rebuilt all path ledgers: before=%d after=%d", warmRebuilds, postACKRebuilds)
	}
	for index := 0; index < steadyWrites; index++ {
		if err := fixture.engine.SendPacket(payload); err != nil {
			t.Fatalf("post-ACK physical write %d: %v", index, err)
		}
	}
	if got := fixture.runtime.bondEvidenceRebuilds.Load(); got != postACKRebuilds {
		t.Fatalf("post-ACK steady writes rebuilt evidence: before=%d after=%d", postACKRebuilds, got)
	}
}

func TestBondQualificationUnrelatedPhysicalIncarnationChurnKeepsFiniteDuty(t *testing.T) {
	clock := newBondTestClock(time.Unix(106_000, 0))
	a := bondGraphNode(proto.GraphNodeKindPath, "a")
	b := bondGraphNode(proto.GraphNodeKindPath, "b")
	c := bondGraphNode(proto.GraphNodeKindPath, "c")
	choice := bondGraphNode(proto.GraphNodeKindSelector, "choice", a, b)
	root := bondGraphNode(proto.GraphNodeKindBond, "root", choice, c)
	manifest, ids := bondGraphManifest(t, root, choice, a, b, c)
	fixture := newBondPhysicalFixture(t, clock, manifest, ids, map[string]bondPhysicalPathSpec{
		"a": {weight: 1}, "b": {weight: 1}, "c": {weight: 1},
	})
	if err := fixture.runtime.commitSelectorChild(
		ids["choice"], ids["a"],
		map[proto.TargetID]bool{ids["a"]: true, ids["b"]: true, ids["c"]: true}, nil,
	); err != nil {
		t.Fatalf("select a: %v", err)
	}
	seedBondCapacityEvidence(fixture.engine, clock.Now(), map[proto.TargetID]uint64{ids["c"]: 100})

	for index := 0; index < int(bondQualificationMaximumTokens)*10; index++ {
		ticket, _, err := fixture.engine.recursiveDispatchTicket(fixture.runtime, false, clock.Now())
		if err != nil || len(ticket.routes) != 1 {
			t.Fatalf("exhaust duty ticket %d routes=%+v err=%v", index, ticket.routes, err)
		}
		if ticket.routes[0].capacityQualification {
			fixture.engine.sendHistMu.Lock()
			state := fixture.engine.sendHist.targetDelivery[ids["a"]]
			state.topologyEpoch = fixture.engine.currentPathTopologyEpoch()
			state.totalAcked++
			state.capacityEstimate = speedEstimate{}
			fixture.engine.sendHist.targetDelivery[ids["a"]] = state
			fixture.engine.bondEvidenceRevision.Add(1)
			fixture.engine.bondCapacityRevision.Add(1)
			fixture.engine.sendHistMu.Unlock()
		}
		fixture.runtime.mu.Lock()
		tokens := fixture.runtime.bonds[ids["root"]].qualificationTokensUsed
		fixture.runtime.mu.Unlock()
		if tokens == bondQualificationMaximumTokens {
			break
		}
	}
	fixture.runtime.mu.Lock()
	if got := fixture.runtime.bonds[ids["root"]].qualificationTokensUsed; got != bondQualificationMaximumTokens {
		fixture.runtime.mu.Unlock()
		t.Fatalf("qualification duty=%d want exhausted=%d", got, bondQualificationMaximumTokens)
	}
	fixture.runtime.mu.Unlock()

	previousEpoch := fixture.engine.currentPathTopologyEpoch()
	qualificationRoutes := 0
	const churnRounds = 48
	for index := 0; index < churnRounds; index++ {
		replacement := newBondPhysicalPath(fmt.Sprintf("b-replacement-%02d", index), clock, 0)
		replacement.engine = fixture.engine
		attachFixturePath(t, fixture.engine, replacement, transport.PathSpec{
			Transport: "bond-test", Address: replacement.name, Weight: 1,
		}, ids["b"])
		if epoch := fixture.engine.currentPathTopologyEpoch(); epoch <= previousEpoch {
			t.Fatalf("replacement %d topology epoch=%d did not advance from %d", index, epoch, previousEpoch)
		} else {
			previousEpoch = epoch
		}
		seedBondCapacityEvidence(fixture.engine, clock.Now(), map[proto.TargetID]uint64{ids["c"]: 100})
		ticket, _, err := fixture.engine.recursiveDispatchTicket(fixture.runtime, false, clock.Now())
		if err != nil || len(ticket.routes) != 1 {
			t.Fatalf("churn ticket %d routes=%+v err=%v", index, ticket.routes, err)
		}
		if ticket.routes[0].capacityQualification {
			qualificationRoutes++
		}
	}
	if qualificationRoutes > 1 {
		t.Fatalf("unrelated physical churn refreshed qualification duty: routes=%d rounds=%d", qualificationRoutes, churnRounds)
	}
	fixture.runtime.mu.Lock()
	gotTokens := fixture.runtime.bonds[ids["root"]].qualificationTokensUsed
	fixture.runtime.mu.Unlock()
	if gotTokens != bondQualificationMaximumTokens {
		t.Fatalf("unrelated physical churn changed finite duty=%d want %d", gotTokens, bondQualificationMaximumTokens)
	}
}

func TestBondDispatchReservationRollsBackBeforePhysicalAdmission(t *testing.T) {
	unknown := bondGraphNode(proto.GraphNodeKindPath, "unknown")
	known := bondGraphNode(proto.GraphNodeKindPath, "known")
	root := bondGraphNode(proto.GraphNodeKindBond, "root", unknown, known)
	manifest, ids := bondGraphManifest(t, root, unknown, known)
	attached := map[proto.TargetID]bool{ids["unknown"]: true, ids["known"]: true}
	scheduling := bondSchedulingContext{
		now: time.Unix(107_000, 0), topologyEpoch: 1,
		staticWeights:    map[proto.TargetID]uint64{ids["unknown"]: 1, ids["known"]: 1},
		effectiveWeights: map[proto.TargetID]uint64{ids["unknown"]: 1, ids["known"]: 100},
		observed:         map[proto.TargetID]bool{ids["known"]: true}, evidenceAware: true,
	}

	t.Run("full queue preserves first qualification probe", func(t *testing.T) {
		runtime := mustExecutionRuntime(t, manifest)
		slot := &pathSlot{dispatchQ: make(chan pathDispatchJob, pathDispatchQueueSize)}
		for index := 0; index < cap(slot.dispatchQ); index++ {
			slot.dispatchQ <- pathDispatchJob{}
		}
		ticket, err := runtime.reserveTicketScheduledPresence(attached, attached, nil, scheduling, true, 1, 0)
		if err != nil || len(ticket.routes) != 1 || ticket.routes[0].targetID != ids["unknown"] {
			t.Fatalf("full-queue reservation routes=%+v err=%v", ticket.routes, err)
		}
		_, admitted := slot.submitDispatchTracked(pathDispatchJob{})
		if admitted {
			t.Fatal("full queue admitted dispatch")
		}
		ticket.finalizeScheduling(false)
		runtime.mu.Lock()
		state := runtime.bonds[ids["root"]]
		if state.qualificationTokensUsed != 0 || len(state.qualification) != 0 || len(state.currentWeight) != 0 {
			runtime.mu.Unlock()
			t.Fatalf("failed admission consumed scheduler state: %+v", state)
		}
		runtime.mu.Unlock()

		<-slot.dispatchQ
		ticket, err = runtime.reserveTicketScheduledPresence(attached, attached, nil, scheduling, true, 1, 0)
		if err != nil || len(ticket.routes) != 1 || ticket.routes[0].targetID != ids["unknown"] ||
			!ticket.routes[0].capacityQualification {
			t.Fatalf("recovered first probe routes=%+v err=%v", ticket.routes, err)
		}
		_, admitted = slot.submitDispatchTracked(pathDispatchJob{})
		ticket.finalizeScheduling(admitted)
		if !admitted {
			t.Fatal("released queue did not admit first factual probe")
		}
		runtime.mu.Lock()
		state = runtime.bonds[ids["root"]]
		if state.qualificationTokensUsed != 1 || state.qualification[ids["unknown"]].totalSent != 1 {
			runtime.mu.Unlock()
			t.Fatalf("factual first probe state=%+v", state)
		}
		runtime.mu.Unlock()
	})

	t.Run("fenced slot preserves qualification and swrr debt", func(t *testing.T) {
		runtime := mustExecutionRuntime(t, manifest)
		slot := &pathSlot{dispatchQ: make(chan pathDispatchJob, 1), dispatchFenced: true}
		ticket, err := runtime.reserveTicketScheduledPresence(attached, attached, nil, scheduling, true, 1, 0)
		if err != nil || ticket.routes[0].targetID != ids["unknown"] {
			t.Fatalf("fenced reservation routes=%+v err=%v", ticket.routes, err)
		}
		_, admitted := slot.submitDispatchTracked(pathDispatchJob{})
		if admitted {
			t.Fatal("fenced slot admitted dispatch")
		}
		ticket.finalizeScheduling(false)
		slot.dispatchMu.Lock()
		slot.dispatchFenced = false
		slot.dispatchMu.Unlock()
		ticket, err = runtime.reserveTicketScheduledPresence(attached, attached, nil, scheduling, true, 1, 0)
		if err != nil || ticket.routes[0].targetID != ids["unknown"] || !ticket.routes[0].capacityQualification {
			t.Fatalf("unfenced first probe routes=%+v err=%v", ticket.routes, err)
		}
		_, admitted = slot.submitDispatchTracked(pathDispatchJob{})
		ticket.finalizeScheduling(admitted)
		if !admitted {
			t.Fatal("unfenced slot did not admit dispatch")
		}

		swrr := mustExecutionRuntime(t, manifest)
		static := scheduling
		static.observed = nil
		static.effectiveWeights = static.staticWeights
		static.evidenceAware = false
		full := &pathSlot{dispatchQ: make(chan pathDispatchJob, 1)}
		full.dispatchQ <- pathDispatchJob{}
		first, err := swrr.reserveTicketScheduledPresence(attached, attached, nil, static, true, 1, 0)
		if err != nil || first.routes[0].targetID != ids["unknown"] {
			t.Fatalf("first SWRR reservation routes=%+v err=%v", first.routes, err)
		}
		_, admitted = full.submitDispatchTracked(pathDispatchJob{})
		first.finalizeScheduling(admitted)
		if admitted {
			t.Fatal("full SWRR queue admitted dispatch")
		}
		<-full.dispatchQ
		second, err := swrr.reserveTicketScheduledPresence(attached, attached, nil, static, true, 1, 0)
		if err != nil || second.routes[0].targetID != ids["unknown"] {
			t.Fatalf("rollback changed next SWRR target routes=%+v err=%v", second.routes, err)
		}
		_, admitted = full.submitDispatchTracked(pathDispatchJob{})
		second.finalizeScheduling(admitted)
		if !admitted {
			t.Fatal("released SWRR queue did not admit dispatch")
		}
		third, err := swrr.reserveTicketScheduledPresence(attached, attached, nil, static, true, 1, 0)
		if err != nil || third.routes[0].targetID != ids["known"] {
			third.finalizeScheduling(false)
			t.Fatalf("committed SWRR debt did not advance routes=%+v err=%v", third.routes, err)
		}
		third.finalizeScheduling(false)
	})
}

func TestBondCachedRecursiveDispatchAllocationDoesNotScaleWithLeaves(t *testing.T) {
	results := make(map[int]float64)
	for _, pathCount := range []int{2, 32, 64} {
		t.Run(fmt.Sprintf("leaves-%d", pathCount), func(t *testing.T) {
			clock := newBondTestClock(time.Unix(108_000, 0))
			children := make([]proto.GraphNode, 0, pathCount)
			nodes := make([]proto.GraphNode, 0, pathCount)
			specs := make(map[string]bondPhysicalPathSpec, pathCount)
			for index := 0; index < pathCount; index++ {
				name := fmt.Sprintf("alloc-path-%02d", index)
				path := bondGraphNode(proto.GraphNodeKindPath, name)
				children = append(children, path)
				nodes = append(nodes, path)
				specs[name] = bondPhysicalPathSpec{weight: 1}
			}
			root := bondGraphNode(proto.GraphNodeKindBond, "alloc-root", children...)
			manifest, ids := bondGraphManifest(t, root, nodes...)
			fixture := newBondPhysicalFixture(t, clock, manifest, ids, specs)
			rates := make(map[proto.TargetID]uint64, pathCount)
			for name := range specs {
				rates[ids[name]] = 100
			}
			seedBondCapacityEvidence(fixture.engine, clock.Now(), rates)
			for index := 0; index < pathCount+8; index++ {
				ticket, _, err := fixture.engine.reserveRecursiveDispatchTicket(fixture.runtime, false, clock.Now())
				if err != nil {
					t.Fatalf("warm reservation %d: %v", index, err)
				}
				ticket.finalizeScheduling(false)
			}
			var runErr error
			allocations := testing.AllocsPerRun(512, func() {
				ticket, _, err := fixture.engine.reserveRecursiveDispatchTicket(fixture.runtime, false, clock.Now())
				if err != nil {
					runErr = err
					return
				}
				ticket.finalizeScheduling(false)
			})
			if runErr != nil {
				t.Fatalf("measured reservation: %v", runErr)
			}
			results[pathCount] = allocations
			t.Logf("cached recursive bond allocations/run: leaves=%d allocs=%.2f", pathCount, allocations)
		})
	}
	if results[64] > results[32]+1 || results[64] > results[2]+8 || results[64] > 12 {
		t.Fatalf("hot allocation count scales with leaves: 2=%.2f 32=%.2f 64=%.2f", results[2], results[32], results[64])
	}
}

func TestBondReservationCommitsPerLogicalRaceBranch(t *testing.T) {
	a := bondGraphNode(proto.GraphNodeKindPath, "a")
	b := bondGraphNode(proto.GraphNodeKindPath, "b")
	c := bondGraphNode(proto.GraphNodeKindPath, "c")
	d := bondGraphNode(proto.GraphNodeKindPath, "d")
	left := bondGraphNode(proto.GraphNodeKindBond, "left", a, b)
	right := bondGraphNode(proto.GraphNodeKindBond, "right", c, d)
	root := bondGraphNode(proto.GraphNodeKindRace, "root", left, right)
	manifest, ids := bondGraphManifest(t, root, left, right, a, b, c, d)
	attached := map[proto.TargetID]bool{
		ids["a"]: true, ids["b"]: true, ids["c"]: true, ids["d"]: true,
	}
	scheduling := bondSchedulingContext{
		now: time.Unix(108_500, 0), topologyEpoch: 1,
		staticWeights: map[proto.TargetID]uint64{
			ids["a"]: 1, ids["b"]: 1, ids["c"]: 1, ids["d"]: 1,
		},
		effectiveWeights: map[proto.TargetID]uint64{
			ids["a"]: 1, ids["b"]: 1, ids["c"]: 1, ids["d"]: 1,
		},
	}

	for _, failure := range []string{"full", "fenced", "removed", "closed"} {
		t.Run(failure, func(t *testing.T) {
			runtime := mustExecutionRuntime(t, manifest)
			ticket, err := runtime.reserveTicketScheduledPresence(
				attached, attached, nil, scheduling, true, 1, 0,
			)
			if err != nil || len(ticket.routes) != 2 ||
				ticket.routes[0].targetID != ids["a"] || ticket.routes[1].targetID != ids["c"] {
				ticket.finalizeScheduling(false)
				t.Fatalf("initial partial-race routes=%+v err=%v", ticket.routes, err)
			}

			leftSlot := &pathSlot{dispatchQ: make(chan pathDispatchJob, 1)}
			rightSlot := &pathSlot{dispatchQ: make(chan pathDispatchJob, 1)}
			switch failure {
			case "full":
				rightSlot.dispatchQ <- pathDispatchJob{}
			case "fenced":
				rightSlot.dispatchFenced = true
			case "removed":
				rightSlot.dispatchDead = true
				rightSlot.dispatchFenced = true
			case "closed":
				rightSlot.dispatchDead = true
				close(rightSlot.dispatchQ)
			}
			if _, admitted := leftSlot.submitDispatchTracked(pathDispatchJob{}); !admitted {
				ticket.finalizeScheduling(false)
				t.Fatal("left logical branch was not admitted")
			}
			ticket.markRouteAdmitted(0)
			// A completion/ACK racing the admission accounting may observe the
			// same route, but ancestry consumption remains idempotent.
			ticket.markRouteAdmitted(0)
			if _, admitted := rightSlot.submitDispatchTracked(pathDispatchJob{}); admitted {
				ticket.finalizeScheduling(false)
				t.Fatal("failed right logical branch was admitted")
			}
			ticket.finalizeSchedulingAdmitted()
			<-leftSlot.dispatchQ

			runtime.mu.Lock()
			leftPhase := runtime.bonds[ids["left"]].schedulePhase
			rightPhase := runtime.bonds[ids["right"]].schedulePhase
			runtime.mu.Unlock()
			if leftPhase == 0 || rightPhase != 0 {
				t.Fatalf("partial commit phases left=%d right=%d", leftPhase, rightPhase)
			}

			next, err := runtime.reserveTicketScheduledPresence(
				attached, attached, nil, scheduling, true, 1, 0,
			)
			if err != nil || len(next.routes) != 2 ||
				next.routes[0].targetID != ids["b"] || next.routes[1].targetID != ids["c"] {
				next.finalizeScheduling(false)
				t.Fatalf("post-partial routes=%+v err=%v", next.routes, err)
			}
			next.finalizeScheduling(false)
		})
	}
}

func TestBondAdmissionRevalidatesEveryProjectionAuthority(t *testing.T) {
	for _, barrier := range []string{"topology", "health", "ack-revision", "expiry", "clock-rollback"} {
		t.Run(barrier, func(t *testing.T) {
			clock := newBondTestClock(time.Unix(109_000, 0))
			installEngineNowForTest(t, clock.Now)
			a := bondGraphNode(proto.GraphNodeKindPath, "a")
			b := bondGraphNode(proto.GraphNodeKindPath, "b")
			root := bondGraphNode(proto.GraphNodeKindBond, "root", a, b)
			manifest, ids := bondGraphManifest(t, root, a, b)
			fixture := newBondPhysicalFixture(t, clock, manifest, ids, map[string]bondPhysicalPathSpec{
				"a": {weight: 1}, "b": {weight: 1},
			})
			seedBondCapacityEvidence(fixture.engine, clock.Now(), map[proto.TargetID]uint64{
				ids["a"]: 100, ids["b"]: 100,
			})

			calls := 0
			var mutate sync.Once
			fixture.engine.recursiveDispatchBeforeAdmission = func(projection *recursiveDispatchProjection) {
				calls++
				mutate.Do(func() {
					switch barrier {
					case "topology":
						fixture.engine.pathsMu.Lock()
						fixture.engine.advancePathTopologyEpochLocked()
						fixture.engine.pathsMu.Unlock()
					case "health":
						fixture.slots["b"].advanceHealthEvidenceRevision()
					case "ack-revision":
						fixture.engine.bondEvidenceRevision.Add(1)
					case "expiry":
						if projection == nil || projection.validUntil.IsZero() {
							t.Fatal("projection has no exact expiry boundary")
						}
						clock.Set(projection.validUntil)
					case "clock-rollback":
						if projection == nil {
							t.Fatal("projection is absent")
						}
						clock.mu.Lock()
						clock.now = projection.builtAt.Add(-time.Second)
						clock.mu.Unlock()
					}
				})
			}

			if err := fixture.engine.SendPacket([]byte("authority-barrier")); err != nil {
				t.Fatalf("send after %s invalidation: %v", barrier, err)
			}
			aSequences, _ := fixture.paths["a"].snapshot()
			bSequences, _ := fixture.paths["b"].snapshot()
			if calls < 2 {
				t.Fatalf("%s stale projection was not rebuilt; admission calls=%d", barrier, calls)
			}
			if len(aSequences) != 1 || len(bSequences) != 0 {
				t.Fatalf("%s stale ticket consumed scheduling debt: a=%v b=%v", barrier, aSequences, bSequences)
			}
		})
	}
}

func TestBondQualificationDescendantChurnPreservesStableSibling(t *testing.T) {
	a := bondGraphNode(proto.GraphNodeKindPath, "a")
	b1 := bondGraphNode(proto.GraphNodeKindPath, "b1")
	b2 := bondGraphNode(proto.GraphNodeKindPath, "b2")
	known := bondGraphNode(proto.GraphNodeKindPath, "known")
	choice := bondGraphNode(proto.GraphNodeKindSelector, "choice", b1, b2)
	root := bondGraphNode(proto.GraphNodeKindBond, "root", a, choice, known)
	manifest, ids := bondGraphManifest(t, root, choice, a, b1, b2, known)
	runtime := mustExecutionRuntime(t, manifest)
	attached := map[proto.TargetID]bool{
		ids["a"]: true, ids["b1"]: true, ids["b2"]: true, ids["known"]: true,
	}
	if err := runtime.commitSelectorChild(ids["choice"], ids["b1"], attached, nil); err != nil {
		t.Fatalf("select b1: %v", err)
	}
	scheduling := bondSchedulingContext{
		now: time.Unix(109_500, 0), topologyEpoch: 1,
		staticWeights: map[proto.TargetID]uint64{
			ids["a"]: 1, ids["b1"]: 1, ids["b2"]: 1, ids["known"]: 1,
		},
		effectiveWeights: map[proto.TargetID]uint64{
			ids["a"]: 1, ids["b1"]: 1, ids["b2"]: 1, ids["known"]: 100,
		},
		observed:     map[proto.TargetID]bool{ids["known"]: true},
		acknowledged: map[proto.TargetID]uint64{ids["a"]: 11, ids["b1"]: 7, ids["b2"]: 3},
		leafIdentity: map[proto.TargetID]bondLeafIdentity{
			ids["a"]:     {targetID: ids["a"], pathID: 1, owner: 1, generation: 1},
			ids["b1"]:    {targetID: ids["b1"], pathID: 2, owner: 2, generation: 1},
			ids["b2"]:    {targetID: ids["b2"], pathID: 3, owner: 3, generation: 1},
			ids["known"]: {targetID: ids["known"], pathID: 4, owner: 4, generation: 1},
		},
		evidenceAware: true,
	}
	warm, err := runtime.reserveTicketScheduledPresence(attached, attached, nil, scheduling, true, 1, 0)
	if err != nil {
		t.Fatalf("warm qualification cache: %v", err)
	}
	warm.finalizeScheduling(false)

	runtime.mu.Lock()
	state := runtime.bonds[ids["root"]]
	aIdentity := state.scratchUnknownObservations[ids["a"]].identity.clone()
	choiceIdentity := state.scratchUnknownObservations[ids["choice"]].identity.clone()
	state.qualification = map[proto.TargetID]*bondQualificationState{
		ids["a"]: {
			lastAcknowledged: 11, credit: 8, sentSinceACK: 3, totalSent: 19, identity: aIdentity,
		},
		ids["choice"]: {
			lastAcknowledged: 7, credit: 4, sentSinceACK: 2, totalSent: 9, identity: choiceIdentity,
		},
	}
	state.qualificationCursor = 1
	state.qualificationTokensUsed = 23
	stablePointer := state.qualification[ids["a"]]
	stableValue := *stablePointer
	stableValue.identity = stableValue.identity.clone()
	runtime.mu.Unlock()

	if err := runtime.commitSelectorChild(ids["choice"], ids["b2"], attached, nil); err != nil {
		t.Fatalf("select b2: %v", err)
	}
	ticket, err := runtime.buildTicketScheduledPresence(
		attached, attached, nil, scheduling, true, 1, 0,
	)
	if err != nil || len(ticket.routes) != 1 || ticket.routes[0].targetID != ids["b2"] ||
		!ticket.routes[0].capacityQualification {
		t.Fatalf("changed descendant qualification routes=%+v err=%v", ticket.routes, err)
	}

	runtime.mu.Lock()
	state = runtime.bonds[ids["root"]]
	stableAfter := state.qualification[ids["a"]]
	changedAfter := state.qualification[ids["choice"]]
	tokens := state.qualificationTokensUsed
	runtime.mu.Unlock()
	if stableAfter != stablePointer || stableAfter.lastAcknowledged != stableValue.lastAcknowledged ||
		stableAfter.credit != stableValue.credit || stableAfter.sentSinceACK != stableValue.sentSinceACK ||
		stableAfter.totalSent != stableValue.totalSent || !stableAfter.identity.equal(stableValue.identity) {
		t.Fatalf("stable sibling was reset: before=%+v after=%+v", stableValue, stableAfter)
	}
	if changedAfter == nil || changedAfter.lastAcknowledged != scheduling.acknowledged[ids["b2"]] ||
		changedAfter.credit != 1 || changedAfter.sentSinceACK != 1 || changedAfter.totalSent != 1 {
		t.Fatalf("changed child did not restart qualification: %+v", changedAfter)
	}
	if tokens != 24 {
		t.Fatalf("child churn reset or double-consumed bond duty: tokens=%d want=24", tokens)
	}
}

func TestBondQualificationMembershipChurnResetsOnlyReturningChild(t *testing.T) {
	a := bondGraphNode(proto.GraphNodeKindPath, "membership-a")
	b := bondGraphNode(proto.GraphNodeKindPath, "membership-b")
	known := bondGraphNode(proto.GraphNodeKindPath, "membership-known")
	root := bondGraphNode(proto.GraphNodeKindBond, "membership-root", a, b, known)
	manifest, ids := bondGraphManifest(t, root, a, b, known)
	runtime := mustExecutionRuntime(t, manifest)
	present := map[proto.TargetID]bool{ids["membership-a"]: true, ids["membership-b"]: true, ids["membership-known"]: true}
	scheduling := bondSchedulingContext{
		now: time.Unix(109_750, 0), topologyEpoch: 1,
		staticWeights: map[proto.TargetID]uint64{
			ids["membership-a"]: 1, ids["membership-b"]: 1, ids["membership-known"]: 1,
		},
		effectiveWeights: map[proto.TargetID]uint64{
			ids["membership-a"]: 1, ids["membership-b"]: 1, ids["membership-known"]: 100,
		},
		observed: map[proto.TargetID]bool{ids["membership-known"]: true},
		acknowledged: map[proto.TargetID]uint64{
			ids["membership-a"]: 12, ids["membership-b"]: 8,
		},
		evidenceAware: true,
	}
	warm, err := runtime.reserveTicketScheduledPresence(present, present, nil, scheduling, true, 1, 0)
	if err != nil {
		t.Fatalf("warm membership cache: %v", err)
	}
	warm.finalizeScheduling(false)
	runtime.mu.Lock()
	state := runtime.bonds[ids["membership-root"]]
	aIdentity := state.scratchUnknownObservations[ids["membership-a"]].identity.clone()
	bIdentity := state.scratchUnknownObservations[ids["membership-b"]].identity.clone()
	state.qualification = map[proto.TargetID]*bondQualificationState{
		ids["membership-a"]: {lastAcknowledged: 12, credit: 8, sentSinceACK: 4, totalSent: 20, identity: aIdentity},
		ids["membership-b"]: {lastAcknowledged: 8, credit: 4, sentSinceACK: 2, totalSent: 10, identity: bIdentity},
	}
	state.qualificationTokensUsed = 31
	stable := state.qualification[ids["membership-a"]]
	stableBefore := *stable
	stableBefore.identity = stableBefore.identity.clone()
	runtime.mu.Unlock()
	stableEqual := func(candidate *bondQualificationState) bool {
		return candidate != nil && candidate.lastAcknowledged == stableBefore.lastAcknowledged &&
			candidate.credit == stableBefore.credit && candidate.sentSinceACK == stableBefore.sentSinceACK &&
			candidate.totalSent == stableBefore.totalSent && candidate.identity.equal(stableBefore.identity)
	}

	withoutB := map[proto.TargetID]bool{ids["membership-a"]: true, ids["membership-known"]: true}
	absent, err := runtime.reserveTicketScheduledPresence(withoutB, withoutB, nil, scheduling, true, 1, 0)
	if err != nil {
		t.Fatalf("membership removal reservation: %v", err)
	}
	absent.finalizeScheduling(false)
	runtime.mu.Lock()
	state = runtime.bonds[ids["membership-root"]]
	if state.qualification[ids["membership-a"]] != stable ||
		!stableEqual(state.qualification[ids["membership-a"]]) ||
		state.qualification[ids["membership-b"]] != nil || state.qualificationTokensUsed != 31 {
		runtime.mu.Unlock()
		t.Fatalf("membership removal changed stable state or duty: %+v", state)
	}
	state.qualificationCursor = 1
	runtime.mu.Unlock()

	returning, err := runtime.buildTicketScheduledPresence(present, present, nil, scheduling, true, 1, 0)
	if err != nil || len(returning.routes) != 1 || returning.routes[0].targetID != ids["membership-b"] ||
		!returning.routes[0].capacityQualification {
		t.Fatalf("returning child routes=%+v err=%v", returning.routes, err)
	}
	runtime.mu.Lock()
	state = runtime.bonds[ids["membership-root"]]
	returningState := state.qualification[ids["membership-b"]]
	stableAfter := state.qualification[ids["membership-a"]]
	tokens := state.qualificationTokensUsed
	runtime.mu.Unlock()
	if stableAfter != stable || !stableEqual(stableAfter) {
		t.Fatalf("returning sibling reset stable child: before=%+v after=%+v", stableBefore, stableAfter)
	}
	if returningState == nil || returningState.credit != 1 || returningState.sentSinceACK != 1 ||
		returningState.totalSent != 1 || tokens != 32 {
		t.Fatalf("returning child did not restart locally: state=%+v tokens=%d", returningState, tokens)
	}
}

func TestBondCachedDispatchOperationCountDoesNotScaleWithLeaves(t *testing.T) {
	const reservations = 256
	for _, pathCount := range []int{2, 32, 64} {
		t.Run(fmt.Sprintf("leaves-%d", pathCount), func(t *testing.T) {
			clock := newBondTestClock(time.Unix(110_000+int64(pathCount), 0))
			installEngineNowForTest(t, clock.Now)
			children := make([]proto.GraphNode, 0, pathCount)
			nodes := make([]proto.GraphNode, 0, pathCount)
			specs := make(map[string]bondPhysicalPathSpec, pathCount)
			for index := 0; index < pathCount; index++ {
				name := fmt.Sprintf("cpu-path-%02d", index)
				path := bondGraphNode(proto.GraphNodeKindPath, name)
				children = append(children, path)
				nodes = append(nodes, path)
				specs[name] = bondPhysicalPathSpec{weight: 1, autoACK: true}
			}
			root := bondGraphNode(proto.GraphNodeKindBond, "cpu-root", children...)
			manifest, ids := bondGraphManifest(t, root, nodes...)
			fixture := newBondPhysicalFixture(t, clock, manifest, ids, specs)
			rates := make(map[proto.TargetID]uint64, pathCount)
			admission := make(map[proto.TargetID]*pathSlot, pathCount)
			for name := range specs {
				rates[ids[name]] = 100
				admission[ids[name]] = &pathSlot{dispatchQ: make(chan pathDispatchJob, 1)}
			}
			seedBondCapacityEvidence(fixture.engine, clock.Now(), rates)
			warm, snapshot, err := fixture.engine.reserveRecursiveDispatchTicket(
				fixture.runtime, false, clock.Now(),
			)
			if err != nil {
				t.Fatalf("warm production projection: %v", err)
			}
			warm.finalizeScheduling(false)

			// The same cached projection also drives stream-style pinning and
			// control fallback without rebuilding the topology projection.
			for _, variant := range []struct {
				name            string
				controlFallback bool
				packetized      bool
			}{
				{name: "stream", packetized: false},
				{name: "packet", packetized: true},
				{name: "control", controlFallback: true, packetized: true},
			} {
				ticket, err := fixture.runtime.reserveTicketFromProjection(
					snapshot.projection, variant.controlFallback, variant.packetized,
					1, 0,
				)
				if err != nil || len(ticket.routes) != 1 {
					ticket.finalizeScheduling(false)
					t.Fatalf("%s cached route=%+v err=%v", variant.name, ticket.routes, err)
				}
				slot := admission[ticket.routes[0].targetID]
				if _, ok := slot.submitDispatchTracked(pathDispatchJob{}); !ok {
					ticket.finalizeScheduling(false)
					t.Fatalf("%s route was not admitted", variant.name)
				}
				ticket.markRouteAdmitted(0)
				ticket.finalizeSchedulingAdmitted()
				<-slot.dispatchQ
			}

			fixture.runtime.mu.Lock()
			beforeOperations := fixture.runtime.bondHotOperations
			beforeRefresh := fixture.runtime.bondRefreshOperations
			fixture.runtime.mu.Unlock()
			for index := 0; index < reservations; index++ {
				ticket, _, err := fixture.engine.reserveRecursiveDispatchTicket(
					fixture.runtime, false, clock.Now(),
				)
				if err != nil || len(ticket.routes) != 1 {
					ticket.finalizeScheduling(false)
					t.Fatalf("reservation %d routes=%+v err=%v", index, ticket.routes, err)
				}
				slot := admission[ticket.routes[0].targetID]
				if _, ok := slot.submitDispatchTracked(pathDispatchJob{}); !ok {
					ticket.finalizeScheduling(false)
					t.Fatalf("reservation %d was not admitted", index)
				}
				ticket.markRouteAdmitted(0)
				ticket.finalizeSchedulingAdmitted()
				<-slot.dispatchQ
			}
			fixture.runtime.mu.Lock()
			operationDelta := fixture.runtime.bondHotOperations - beforeOperations
			refreshDelta := fixture.runtime.bondRefreshOperations - beforeRefresh
			fixture.runtime.mu.Unlock()
			if operationDelta != reservations || refreshDelta != 0 {
				t.Fatalf("cached reserve cost leaves=%d operations=%d want=%d refresh=%d",
					pathCount, operationDelta, reservations, refreshDelta)
			}

			fixture.runtime.mu.Lock()
			beforeOperations = fixture.runtime.bondHotOperations
			beforeRefresh = fixture.runtime.bondRefreshOperations
			fixture.runtime.mu.Unlock()
			beforeEvidenceRebuilds := fixture.runtime.bondEvidenceRebuilds.Load()
			const packets = 32
			for index := 0; index < packets; index++ {
				if err := fixture.engine.SendPacket([]byte{byte(index), 0xa5}); err != nil {
					t.Fatalf("SendPacket %d: %v", index, err)
				}
			}
			fixture.runtime.mu.Lock()
			operationDelta = fixture.runtime.bondHotOperations - beforeOperations
			refreshDelta = fixture.runtime.bondRefreshOperations - beforeRefresh
			fixture.runtime.mu.Unlock()
			if operationDelta != packets || refreshDelta != 0 {
				t.Fatalf("SendPacket cost leaves=%d operations=%d want=%d refresh=%d",
					pathCount, operationDelta, packets, refreshDelta)
			}
			if after := fixture.runtime.bondEvidenceRebuilds.Load(); after != beforeEvidenceRebuilds {
				t.Fatalf("SendPacket ACK path scanned ledgers at leaves=%d: before=%d after=%d",
					pathCount, beforeEvidenceRebuilds, after)
			}
		})
	}
}

func TestBondCachedDispatchOperationsFollowNestedLogicalBranches(t *testing.T) {
	clock := newBondTestClock(time.Unix(111_000, 0))
	installEngineNowForTest(t, clock.Now)
	const leavesPerBond = 32
	leftLeaves := make([]proto.GraphNode, 0, leavesPerBond)
	rightLeaves := make([]proto.GraphNode, 0, leavesPerBond)
	allLeaves := make([]proto.GraphNode, 0, 2*leavesPerBond)
	specs := make(map[string]bondPhysicalPathSpec, 2*leavesPerBond)
	for index := 0; index < leavesPerBond; index++ {
		leftName := fmt.Sprintf("nested-left-%02d", index)
		rightName := fmt.Sprintf("nested-right-%02d", index)
		left := bondGraphNode(proto.GraphNodeKindPath, leftName)
		right := bondGraphNode(proto.GraphNodeKindPath, rightName)
		leftLeaves = append(leftLeaves, left)
		rightLeaves = append(rightLeaves, right)
		allLeaves = append(allLeaves, left, right)
		specs[leftName] = bondPhysicalPathSpec{weight: 1}
		specs[rightName] = bondPhysicalPathSpec{weight: 1}
	}
	left := bondGraphNode(proto.GraphNodeKindBond, "nested-left", leftLeaves...)
	right := bondGraphNode(proto.GraphNodeKindBond, "nested-right", rightLeaves...)
	fanout := bondGraphNode(proto.GraphNodeKindRace, "nested-race", left, right)
	root := bondGraphNode(proto.GraphNodeKindSelector, "nested-selector", fanout)
	nodes := []proto.GraphNode{fanout, left, right}
	nodes = append(nodes, allLeaves...)
	manifest, ids := bondGraphManifest(t, root, nodes...)
	fixture := newBondPhysicalFixture(t, clock, manifest, ids, specs)
	rates := make(map[proto.TargetID]uint64, len(specs))
	for name := range specs {
		rates[ids[name]] = 100
	}
	seedBondCapacityEvidence(fixture.engine, clock.Now(), rates)
	warm, _, err := fixture.engine.reserveRecursiveDispatchTicket(fixture.runtime, false, clock.Now())
	if err != nil || len(warm.routes) != 2 {
		warm.finalizeScheduling(false)
		t.Fatalf("nested warm routes=%+v err=%v", warm.routes, err)
	}
	warm.finalizeScheduling(false)
	fixture.runtime.mu.Lock()
	beforeOperations := fixture.runtime.bondHotOperations
	beforeRefresh := fixture.runtime.bondRefreshOperations
	fixture.runtime.mu.Unlock()

	ticket, _, err := fixture.engine.reserveRecursiveDispatchTicket(fixture.runtime, false, clock.Now())
	if err != nil || len(ticket.routes) != 2 {
		ticket.finalizeScheduling(false)
		t.Fatalf("nested cached routes=%+v err=%v", ticket.routes, err)
	}
	for index := range ticket.routes {
		ticket.markRouteAdmitted(index)
	}
	ticket.finalizeSchedulingAdmitted()
	fixture.runtime.mu.Lock()
	operationDelta := fixture.runtime.bondHotOperations - beforeOperations
	refreshDelta := fixture.runtime.bondRefreshOperations - beforeRefresh
	fixture.runtime.mu.Unlock()
	if operationDelta != 2 || refreshDelta != 0 {
		t.Fatalf("nested cached cost operations=%d want=2 refresh=%d", operationDelta, refreshDelta)
	}
}

func TestNestedRaceCapacityFailsClosedToStaticBondWeights(t *testing.T) {
	t.Run("bond containing race cannot infer race child capacity", func(t *testing.T) {
		base := time.Unix(100_000, 0)
		clock := newBondTestClock(base)
		installEngineNowForTest(t, clock.Now)
		a := bondGraphNode(proto.GraphNodeKindPath, "a")
		b := bondGraphNode(proto.GraphNodeKindPath, "b")
		c := bondGraphNode(proto.GraphNodeKindPath, "c")
		redundant := bondGraphNode(proto.GraphNodeKindRace, "redundant", a, b)
		root := bondGraphNode(proto.GraphNodeKindBond, "root", redundant, c)
		manifest, ids := bondGraphManifest(t, root, redundant, a, b, c)
		fixture := newBondPhysicalFixture(t, clock, manifest, ids, map[string]bondPhysicalPathSpec{
			"a": {weight: 1, service: time.Millisecond, autoACK: true},
			"b": {weight: 1, service: time.Millisecond, autoACK: true},
			"c": {weight: 9, service: 10 * time.Millisecond, autoACK: true},
		})
		payload := make([]byte, MaxPayload)
		for index := 0; index < 120; index++ {
			if err := fixture.engine.SendPacket(payload); err != nil {
				t.Fatalf("packet %d: %v", index, err)
			}
		}
		deadline := time.Now().Add(2 * time.Second)
		var aSeq, bSeq, cSeq []uint64
		for {
			aSeq, _ = fixture.paths["a"].snapshot()
			bSeq, _ = fixture.paths["b"].snapshot()
			cSeq, _ = fixture.paths["c"].snapshot()
			if (len(aSeq) == 12 && len(bSeq) == 12 && len(cSeq) == 108) ||
				time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if len(aSeq) != 12 || len(bSeq) != 12 || len(cSeq) != 108 {
			t.Fatalf("bond(race(a,b),c) escaped static 1:9 weights: a=%d b=%d c=%d", len(aSeq), len(bSeq), len(cSeq))
		}
		evidence, valid := fixture.engine.targetCapacitySpeedsAtEpoch(
			clock.Now(), fixture.engine.currentPathTopologyEpoch(),
		)
		if !valid || evidence[ids["c"]].bytesPerSecond == 0 ||
			evidence[ids["a"]].bytesPerSecond != 0 || evidence[ids["b"]].bytesPerSecond != 0 {
			t.Fatalf("race fanout produced route-specific capacity valid=%t evidence=%+v", valid, evidence)
		}
	})

	t.Run("race containing bond ignores leaf capacity pollution", func(t *testing.T) {
		base := time.Unix(110_000, 0)
		clock := newBondTestClock(base)
		installEngineNowForTest(t, clock.Now)
		a := bondGraphNode(proto.GraphNodeKindPath, "a")
		b := bondGraphNode(proto.GraphNodeKindPath, "b")
		c := bondGraphNode(proto.GraphNodeKindPath, "c")
		aggregate := bondGraphNode(proto.GraphNodeKindBond, "aggregate", a, b)
		root := bondGraphNode(proto.GraphNodeKindRace, "root", aggregate, c)
		manifest, ids := bondGraphManifest(t, root, aggregate, a, b, c)
		fixture := newBondPhysicalFixture(t, clock, manifest, ids, map[string]bondPhysicalPathSpec{
			"a": {weight: 1}, "b": {weight: 9}, "c": {weight: 1},
		})
		seedBondCapacityEvidence(fixture.engine, clock.Now(), map[proto.TargetID]uint64{
			ids["a"]: 256, ids["b"]: 16,
		})
		counts := map[proto.TargetID]int{}
		for index := 0; index < 100; index++ {
			ticket, _, err := fixture.engine.reserveRecursiveDispatchTicket(
				fixture.runtime, false, clock.Now(),
			)
			if err != nil || len(ticket.routes) != 2 {
				ticket.finalizeScheduling(false)
				t.Fatalf("ticket %d routes=%+v err=%v", index, ticket.routes, err)
			}
			for routeIndex, route := range ticket.routes {
				counts[route.targetID]++
				ticket.markRouteAdmitted(routeIndex)
			}
			ticket.finalizeSchedulingAdmitted()
		}
		if counts[ids["a"]] != 10 || counts[ids["b"]] != 90 || counts[ids["c"]] != 100 {
			t.Fatalf(
				"race(bond(a,b),c) consumed ambiguous leaf capacity: a=%d b=%d c=%d",
				counts[ids["a"]], counts[ids["b"]], counts[ids["c"]],
			)
		}
	})
}

func TestBondSWRRResetsDebtWhenWeightVectorChanges(t *testing.T) {
	a := bondGraphNode(proto.GraphNodeKindPath, "a")
	b := bondGraphNode(proto.GraphNodeKindPath, "b")
	a.Weight = 7
	b.Weight = 1
	root := bondGraphNode(proto.GraphNodeKindBond, "root", a, b)
	manifest, ids := bondGraphManifest(t, root, a, b)
	attached := map[proto.TargetID]bool{ids["a"]: true, ids["b"]: true}

	t.Run("changing vectors retain bounded prefix discrepancy", func(t *testing.T) {
		runtime := mustExecutionRuntime(t, manifest)
		vectors := []map[proto.TargetID]uint64{
			{ids["a"]: 256, ids["b"]: 16},
			{ids["a"]: 255, ids["b"]: 17},
		}
		counts := map[proto.TargetID]int{}
		expectedA := 0.0
		for index := 0; index < 1024; index++ {
			weights := vectors[index%len(vectors)]
			ticket, err := runtime.buildTicketObserved(
				attached, nil, weights, true, 1, 0,
			)
			if err != nil || len(ticket.routes) != 1 {
				t.Fatalf("changing-vector ticket %d routes=%+v err=%v", index, ticket.routes, err)
			}
			counts[ticket.routes[0].targetID]++
			expectedA += float64(weights[ids["a"]]) /
				float64(weights[ids["a"]]+weights[ids["b"]])
			if discrepancy := math.Abs(float64(counts[ids["a"]]) - expectedA); discrepancy > 2 {
				t.Fatalf("prefix %d A discrepancy=%.3f counts=%v", index+1, discrepancy, counts)
			}
		}
		if counts[ids["b"]] < 55 || counts[ids["b"]] > 70 {
			t.Fatalf("changing vectors produced biased share: %v", counts)
		}
	})

	t.Run("pure proportional scaling preserves sequence", func(t *testing.T) {
		left := mustExecutionRuntime(t, manifest)
		right := mustExecutionRuntime(t, manifest)
		warm := map[proto.TargetID]uint64{ids["a"]: 3, ids["b"]: 1}
		for index := 0; index < 37; index++ {
			for _, runtime := range []*executionRuntime{left, right} {
				if _, err := runtime.buildTicketObserved(attached, nil, warm, true, 1, 0); err != nil {
					t.Fatalf("warm ticket %d: %v", index, err)
				}
			}
		}
		scaled := map[proto.TargetID]uint64{ids["a"]: 300, ids["b"]: 100}
		for index := 0; index < 128; index++ {
			leftTicket, leftErr := left.buildTicketObserved(attached, nil, warm, true, 1, 0)
			rightTicket, rightErr := right.buildTicketObserved(attached, nil, scaled, true, 1, 0)
			if leftErr != nil || rightErr != nil || len(leftTicket.routes) != 1 ||
				len(rightTicket.routes) != 1 ||
				leftTicket.routes[0].targetID != rightTicket.routes[0].targetID {
				t.Fatalf("scaled ticket %d left=%+v/%v right=%+v/%v", index, leftTicket.routes, leftErr, rightTicket.routes, rightErr)
			}
		}
	})

	t.Run("ratio reversal converges without inherited bias", func(t *testing.T) {
		runtime := mustExecutionRuntime(t, manifest)
		forward := map[proto.TargetID]uint64{ids["a"]: 9, ids["b"]: 1}
		reverse := map[proto.TargetID]uint64{ids["a"]: 1, ids["b"]: 9}
		for index := 0; index < 100; index++ {
			if _, err := runtime.buildTicketObserved(attached, nil, forward, true, 1, 0); err != nil {
				t.Fatalf("forward ticket %d: %v", index, err)
			}
		}
		counts := map[proto.TargetID]int{}
		for index := 0; index < 100; index++ {
			ticket, err := runtime.buildTicketObserved(attached, nil, reverse, true, 1, 0)
			if err != nil || len(ticket.routes) != 1 {
				t.Fatalf("reverse ticket %d routes=%+v err=%v", index, ticket.routes, err)
			}
			counts[ticket.routes[0].targetID]++
			expectedA := float64(index+1) / 10
			if discrepancy := math.Abs(float64(counts[ids["a"]]) - expectedA); discrepancy > 1 {
				t.Fatalf("reverse prefix %d discrepancy=%.3f counts=%v", index+1, discrepancy, counts)
			}
		}
		if counts[ids["a"]] != 10 || counts[ids["b"]] != 90 {
			t.Fatalf("reversed full-cycle share=%v", counts)
		}
	})

	t.Run("topology reset starts a complete unbiased cycle", func(t *testing.T) {
		runtime := mustExecutionRuntime(t, manifest)
		weights := map[proto.TargetID]uint64{ids["a"]: 7, ids["b"]: 3}
		context := bondSchedulingContext{
			now: time.Unix(120_000, 0), topologyEpoch: 1,
			staticWeights: weights, effectiveWeights: weights,
		}
		for index := 0; index < 17; index++ {
			if _, err := runtime.buildTicketScheduledPresence(
				attached, attached, nil, context, true, 1, 0,
			); err != nil {
				t.Fatalf("old-topology ticket %d: %v", index, err)
			}
		}
		context.topologyEpoch = 2
		counts := map[proto.TargetID]int{}
		for index := 0; index < 10; index++ {
			ticket, err := runtime.buildTicketScheduledPresence(
				attached, attached, nil, context, true, 1, 0,
			)
			if err != nil || len(ticket.routes) != 1 {
				t.Fatalf("new-topology ticket %d routes=%+v err=%v", index, ticket.routes, err)
			}
			counts[ticket.routes[0].targetID]++
		}
		if counts[ids["a"]] != 7 || counts[ids["b"]] != 3 {
			t.Fatalf("topology-reset full-cycle share=%v", counts)
		}
	})
}
