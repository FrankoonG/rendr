package rendr

import (
	"context"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

func TestRootTargetConstructorsCompileRecursiveGraphs(t *testing.T) {
	for _, tt := range []struct {
		name string
		kind TargetKind
	}{
		{name: "selector", kind: TargetKindSelector},
		{name: "race", kind: TargetKindRace},
		{name: "bond", kind: TargetKindBond},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := func(name string) Target {
				return Path(name, PathSpec{Transport: "tcp", Address: name})
			}
			var root Target
			switch tt.kind {
			case TargetKindSelector:
				root = Selector("root", []Target{
					Race("redundant", []Target{
						path("A"),
						Bond("bulk", []Target{path("B"), path("C")}),
					}),
					path("D"),
				})
			case TargetKindRace:
				root = Race("root", []Target{
					Selector("quality", []Target{path("A"), path("B")}),
					Bond("bulk", []Target{path("C"), path("D")}),
				})
			case TargetKindBond:
				root = Bond("root", []Target{
					Selector("quality", []Target{path("A"), path("B")}),
					Race("redundant", []Target{path("C"), path("D")}),
				})
			default:
				t.Fatalf("unsupported root kind %q", tt.kind)
			}
			ct, err := compileTargetForDial(root)
			if err != nil {
				t.Fatal(err)
			}
			if ct.graph.root.kind != tt.kind {
				t.Fatalf("root kind=%v want %v", ct.graph.root.kind, tt.kind)
			}
			if len(ct.paths) != 4 || ct.graph.maxDepth < 3 {
				t.Fatalf("paths/depth=%d/%d want 4/>=3", len(ct.paths), ct.graph.maxDepth)
			}
			seenKinds := map[TargetKind]bool{}
			for _, node := range ct.graph.nodesByName {
				seenKinds[node.kind] = true
			}
			for _, kind := range []TargetKind{TargetKindSelector, TargetKindRace, TargetKindBond, TargetKindPath} {
				if !seenKinds[kind] {
					t.Fatalf("recursive %s graph does not contain %s: %+v", tt.kind, kind, seenKinds)
				}
			}
		})
	}
	if _, err := compileTargetForDial(nil); err == nil {
		t.Fatal("nil root target was accepted")
	}

	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		connection, acceptErr := ln.Accept(ctx)
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		accepted <- connection
	}()
	runtimePath := func(name string) Target {
		return Path(name, PathSpec{Transport: "tcp", Address: ln.Addr().String()})
	}
	runtimeRoot := Selector("root", []Target{
		Race("redundant", []Target{
			runtimePath("A"),
			Bond("bulk", []Target{runtimePath("B"), runtimePath("C")}),
		}),
		runtimePath("D"),
	})
	client, err := (&sessionDialer{Root: runtimeRoot}).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server Conn
	select {
	case server = <-accepted:
	case err = <-errCh:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	waitForPathNames(t, client, []string{"A", "B", "C", "D"}, 2*time.Second)
	collector := newTier6IntegrityCollector(server)
	collector.write(t, client, tier6DeterministicPayload("recursive-graph-dial", 32<<10))
	tier6CloseWrite(t, client)
	facts := map[string]string{
		"graph_recursive":               "true",
		"graph_root_kinds":              "selector,race,bond",
		"graph_nested_group_kinds":      "selector,race,bond",
		"graph_leaf_count_each":         "4",
		"graph_minimum_depth":           "3",
		"graph_nil_root_rejected":       "true",
		"graph_single_root_compiled":    "true",
		"dial_smoke_path_count":         tier6Uint(uint64(len(client.Paths()))),
		"dial_smoke_single_root":        "true",
		"dial_smoke_application_errors": "0",
		"embedded_negative_control":     "nil-root-rejected",
		"topology_path_count":           tier6Uint(uint64(len(client.Paths()))),
	}
	mergeTier6Facts(t, facts, collector.finish(t, "dial_smoke_payload"))
	emitTier6Evidence(t, "T6.graph.compat-mode", facts)
}

func TestSelectorPeakTransferOrdersPeakTargetsLast(t *testing.T) {
	root := Selector("root",
		[]Target{
			Bond("bulk", []Target{
				Path("B", PathSpec{Transport: "tcp", Address: "b"}),
				Path("C", PathSpec{Transport: "tcp", Address: "c"}),
			}),
			Path("A", PathSpec{Transport: "tcp", Address: "a"}),
		},
		PeakTransfer{Targets: []string{"bulk"}},
	)

	ct, err := compileTargetForDial(root)
	if err != nil {
		t.Fatal(err)
	}
	if !ct.peakTransfer {
		t.Fatal("peakTransfer=false")
	}
	if bulk := ct.graph.nodesByName["bulk"]; bulk == nil || bulk.kind != TargetKindBond {
		t.Fatalf("compiled graph lost nested bond: %+v", bulk)
	}
	if got := ct.pathPeak; len(got) != 3 || got[0] || !got[1] || !got[2] {
		t.Fatalf("pathPeak=%v want [false true true]", got)
	}
	got := []string{ct.paths[0].Address, ct.paths[1].Address, ct.paths[2].Address}
	want := []string{"a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("path order=%v want %v", got, want)
		}
	}
}

func TestTargetConstructorsExposeGroupKinds(t *testing.T) {
	children := []Target{Path("A", PathSpec{Transport: "tcp", Address: "a"})}
	for _, tt := range []struct {
		name string
		t    Target
		kind TargetKind
	}{
		{name: "selector", t: Selector("s", children), kind: TargetKindSelector},
		{name: "race", t: Race("r", children), kind: TargetKindRace},
		{name: "bond", t: Bond("b", children), kind: TargetKindBond},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g, ok := tt.t.(GroupTarget)
			if !ok {
				t.Fatalf("target type %T is not GroupTarget", tt.t)
			}
			if g.Kind != tt.kind {
				t.Fatalf("kind=%v want %v", g.Kind, tt.kind)
			}
			if g.Name() == "" {
				t.Fatal("empty name")
			}
		})
	}
}

func TestDialerCompileDialPlanUsesSingleRoot(t *testing.T) {
	d := &sessionDialer{
		Root: Selector("root", []Target{
			Path("root-path", PathSpec{Transport: "tcp", Address: "root"}),
		}),
	}
	plan, err := d.compileDialPlan()
	if err != nil {
		t.Fatal(err)
	}
	if plan.graph.root.kind != TargetKindSelector {
		t.Fatalf("root kind=%v want selector", plan.graph.root.kind)
	}
	if plan.peakTransfer {
		t.Fatal("peak=true")
	}
	if len(plan.paths) != 1 || plan.paths[0].Address != "root" {
		t.Fatalf("paths=%+v; root should compile its only leaf", plan.paths)
	}
}

func TestDialerPrimaryExplicitPathReordersPlan(t *testing.T) {
	root := Selector("root", []Target{
		Path("A", PathSpec{Transport: "tcp", Address: "a"}),
		Path("B", PathSpec{Transport: "tcp", Address: "b"}),
	})
	plan, err := (&sessionDialer{Root: root, Primary: "B"}).compileDialPlan()
	if err != nil {
		t.Fatal(err)
	}
	if plan.primaryName != "B" {
		t.Fatalf("primary=%q want B", plan.primaryName)
	}
	if got := pathSpecName(plan.paths[0]); got != "B" {
		t.Fatalf("first path=%q want B", got)
	}
}

func TestDialerPrimaryExplicitGroupResolvesLeaf(t *testing.T) {
	bulk := Bond("bulk", []Target{
		Path("B", PathSpec{Transport: "tcp", Address: "b"}),
		Path("C", PathSpec{Transport: "tcp", Address: "c"}),
	})
	root := Selector("root", []Target{
		Path("A", PathSpec{Transport: "tcp", Address: "a"}),
		bulk,
	})
	plan, err := (&sessionDialer{Root: root, Primary: "bulk"}).compileDialPlan()
	if err != nil {
		t.Fatal(err)
	}
	if plan.primaryName != "B" {
		t.Fatalf("primary=%q want B", plan.primaryName)
	}
	if got := pathSpecName(plan.paths[0]); got != "B" {
		t.Fatalf("first path=%q want B", got)
	}
}

func TestDialerStatusPeerRendr(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan Conn, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err == nil {
			accepted <- c
		}
	}()

	client, err := (&sessionDialer{
		Root: Selector("root", []Target{
			Path("A", PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
		}),
	}).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	st := client.Status()
	if st.Peer.Kind != PeerRendr {
		t.Fatalf("peer kind=%q want %q", st.Peer.Kind, PeerRendr)
	}
	if st.Peer.InstanceID == (InstanceID{}) {
		t.Fatal("peer instance id is zero")
	}
	if len(st.Paths) != 1 || st.Paths[0].Name != "A" || st.Paths[0].State != PathAttached {
		t.Fatalf("paths=%+v want path A attached", st.Paths)
	}
}

func TestDialerPrimaryPreferFallbackStatus(t *testing.T) {
	good, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()

	bad, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	badAddr := bad.Addr().String()
	_ = bad.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan Conn, 1)
	go func() {
		c, err := good.Accept(ctx)
		if err == nil {
			accepted <- c
		}
	}()

	root := Selector("root", []Target{
		Path("A", PathSpec{Transport: "tcp", Address: badAddr}),
		Path("B", PathSpec{Transport: "tcp", Address: good.Addr().String()}),
	})
	client, err := (&sessionDialer{Root: root, Primary: "A"}).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	st := client.Status()
	if st.Peer.Kind != PeerRendr {
		t.Fatalf("peer kind=%q want %q", st.Peer.Kind, PeerRendr)
	}
	if len(st.Paths) != 2 {
		t.Fatalf("paths=%d want 2: %+v", len(st.Paths), st.Paths)
	}
	pathARecovering := st.Paths[0].State == PathPending ||
		st.Paths[0].State == PathDialing ||
		st.Paths[0].State == PathUnavailable
	if st.Paths[0].Name != "A" || !pathARecovering || st.Paths[0].Active {
		t.Fatalf("path A status=%+v want inactive pending/dialing/unavailable", st.Paths[0])
	}
	if st.Paths[1].Name != "B" || st.Paths[1].State != PathAttached || !st.Paths[1].Active {
		t.Fatalf("fallback status=%+v want active attached B", st.Paths[1])
	}
}

func TestDialerPrimaryRequireFails(t *testing.T) {
	good, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()

	bad, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	badAddr := bad.Addr().String()
	_ = bad.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	root := Selector("root", []Target{
		Path("A", PathSpec{Transport: "tcp", Address: badAddr}),
		Path("B", PathSpec{Transport: "tcp", Address: good.Addr().String()}),
	})
	client, err := (&sessionDialer{Root: root, Primary: "A", PrimaryPolicy: primaryRequire}).Dial(ctx)
	if err == nil {
		client.Close()
		t.Fatal("Dial succeeded with unavailable required primary")
	}
}

func TestDialerRootSelectorDialSmoke(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	accepted := make(chan Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	root := Selector("root", []Target{
		Path("A", PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
		Path("B", PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
	})
	client, err := (&sessionDialer{Root: root}).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	attachDeadline := time.Now().Add(3 * time.Second)
	for {
		status := client.Status()
		attached := 0
		for _, path := range status.Paths {
			if path.State == PathAttached && path.ID != 0 {
				attached++
			}
		}
		if attached == 2 && len(server.Paths()) == 2 {
			break
		}
		if time.Now().After(attachDeadline) {
			t.Fatalf("background paths did not converge: client_state=%q effective=%v status=%+v server_paths=%+v",
				status.State, status.EffectivePaths, status.Paths, server.Paths())
		}
		time.Sleep(10 * time.Millisecond)
	}
	collector := newTier6IntegrityCollector(server)
	payload := tier6DeterministicPayload("graph-dial-smoke", 32<<10)
	collector.write(t, client, payload)
	tier6CloseWrite(t, client)
	_ = collector.finish(t, "dial_smoke_payload")
}

func TestSelectorPeakTransferRuntimePromotesToBond(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	accepted := make(chan Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	controlled := newRuntimeControlledTCPTransport(t)
	for name, rate := range map[string]uint64{"A": 512 << 10, "B": 4 << 20, "C": 4 << 20} {
		if err := controlled.SetDataWriteRate(name, rate); err != nil {
			t.Fatal(err)
		}
	}
	spec := func(name string) PathSpec { return controlled.Spec(ln.Addr().String(), name) }
	root := Selector("root",
		[]Target{
			Path("A", spec("A")),
			Bond("bulk", []Target{
				Path("B", spec("B")),
				Path("C", spec("C")),
			}),
		},
		PeakTransfer{
			Targets:         []string{"bulk"},
			SaturationFor:   200 * time.Millisecond,
			ReturnFor:       200 * time.Millisecond,
			SaturationRatio: 0.8,
			ReturnRatio:     0.2,
		},
	)
	dialer := &sessionDialer{Root: root}
	controlled.Bind(t, dialer)
	client, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	waitForPathNames(t, client, []string{"A", "B", "C"}, 3*time.Second)
	waitForPathNames(t, server, []string{"A", "B", "C"}, 3*time.Second)
	collector := newTier6IntegrityCollector(server)
	recorder := newTier6MigrationRecorder(t, client)
	waitForEffectivePathNames(t, client, []string{"A"}, time.Second)

	controlPayload := tier6DeterministicPayload("A-to-bulk-control", 4<<10)
	collector.write(t, client, controlPayload)
	time.Sleep(100 * time.Millisecond)
	if got := effectivePathNames(client); !slices.Equal(got, []string{"A"}) {
		t.Fatalf("low-demand embedded control selected peak paths: %v", got)
	}
	for _, name := range []string{"B", "C"} {
		stats, statsErr := controlled.PathStats(name)
		if statsErr != nil {
			t.Fatal(statsErr)
		}
		if stats.PhysicalDataWriteBytes != 0 {
			t.Fatalf("low-demand embedded control wrote peak path %s: %+v", name, stats)
		}
	}

	chunk := tier6DeterministicPayload("A-to-bulk-data", 32<<10)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !slices.Equal(effectivePathNames(client), []string{"B", "C"}) {
		collector.write(t, client, chunk)
	}
	if got := effectivePathNames(client); !slices.Equal(got, []string{"B", "C"}) {
		t.Fatalf(
			"effective paths=%v want [B C]: diagnostic=%+v status=%+v paths=%+v",
			got, peakTransferDiagnostic(client, false), client.Status(), client.Paths(),
		)
	}
	assertPeakDemandEvidence(t, client, false)
	aStats, err := controlled.PathStats("A")
	if err != nil {
		t.Fatal(err)
	}
	if aStats.DelayedDataWrites == 0 || aStats.DataWriteBlocked == 0 || aStats.PhysicalDataWriteBytes == 0 {
		t.Fatalf("normal path did not experience physical DATA pressure: %+v", aStats)
	}

	before := writesByName(client.Paths())
	for i := 0; i < 24; i++ {
		collector.write(t, client, chunk)
	}
	after := writesByName(client.Paths())
	if after["B"] <= before["B"] || after["C"] <= before["C"] {
		t.Fatalf("peak bond did not dispatch on both peak paths: before=%v after=%v", before, after)
	}
	peakStats := make(map[string]runtimeControlledTCPPathStats, 2)
	for _, name := range []string{"B", "C"} {
		stats, statsErr := controlled.PathStats(name)
		if statsErr != nil {
			t.Fatal(statsErr)
		}
		peakStats[name] = stats
		if stats.PhysicalDataWriteBytes == 0 {
			t.Fatalf("peak bond child %s carried no physical DATA: %+v", name, stats)
		}
	}

	waitForEffectivePathNames(t, client, []string{"A"}, 3*time.Second)
	tier6CloseWrite(t, client)
	facts := map[string]string{
		"transition_history":             "A>B+C>A",
		"low_demand_stayed_normal":       "true",
		"low_demand_peak_physical_bytes": "0",
		"normal_saturation_observed":     tier6Bool(aStats.DelayedDataWrites > 0 && aStats.DataWriteBlocked > 0),
		"normal_physical_data_bytes":     tier6Uint(aStats.PhysicalDataWriteBytes),
		"bond_B_physical_data_bytes":     tier6Uint(peakStats["B"].PhysicalDataWriteBytes),
		"bond_C_physical_data_bytes":     tier6Uint(peakStats["C"].PhysicalDataWriteBytes),
		"bond_B_dispatch_increased":      tier6Bool(after["B"] > before["B"]),
		"bond_C_dispatch_increased":      tier6Bool(after["C"] > before["C"]),
		"embedded_negative_control":      "low-demand-stays-normal",
		"topology_path_count":            tier6Uint(uint64(len(client.Paths()))),
	}
	mergeTier6Facts(t, facts, collector.finish(t, "payload"))
	events := recorder.finish(t)
	if len(events) < 2 || !tier6MigrationContains(events, "A") ||
		(!tier6MigrationContains(events, "B") && !tier6MigrationContains(events, "C")) {
		t.Fatalf("committed migration history does not prove A -> bond -> A: %+v", events)
	}
	facts["committed_migrations"] = tier6Uint(uint64(len(events)))
	facts["migration_target_history"] = tier6MigrationTargets(events)
	emitTier6Evidence(t, "T6.peak.A-to-bulk-bond", facts)
}

func TestSelectorPeakTransferNormalSelectorUsesQuality(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	accepted := make(chan Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	controlled := newRuntimeControlledTCPTransport(t)
	for name, rate := range map[string]uint64{"A": 512 << 10, "B": 512 << 10, "C": 4 << 20} {
		if err := controlled.SetDataWriteRate(name, rate); err != nil {
			t.Fatal(err)
		}
	}
	spec := func(name string) PathSpec { return controlled.Spec(ln.Addr().String(), name) }
	root := Selector("root",
		[]Target{
			Selector("normal", []Target{
				Path("A", spec("A")),
				Path("B", spec("B")),
			}),
			Path("C", spec("C")),
		},
		PeakTransfer{
			Targets:         []string{"C"},
			SaturationFor:   200 * time.Millisecond,
			ReturnFor:       200 * time.Millisecond,
			SaturationRatio: 0.8,
			ReturnRatio:     0.2,
		},
	)
	dialer := &sessionDialer{
		Root:          root,
		Hysteresis:    0.05,
		Dwell:         100 * time.Millisecond,
		Cooldown:      100 * time.Millisecond,
		ProbeInterval: 100 * time.Millisecond,
		Retry:         retryPolicy{MinBackoff: 5 * time.Second, MaxBackoff: 5 * time.Second},
	}
	for name, delay := range map[string]time.Duration{
		"A": 250 * time.Millisecond,
		"B": 50 * time.Millisecond,
		"C": time.Millisecond,
	} {
		if err := controlled.SetProbeDelay(name, delay); err != nil {
			t.Fatal(err)
		}
	}
	controlled.Bind(t, dialer)
	client, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	waitForPathNames(t, client, []string{"A", "B", "C"}, 3*time.Second)
	waitForPathNames(t, server, []string{"A", "B", "C"}, 3*time.Second)
	collector := newTier6IntegrityCollector(server)

	ids := idsByName(client.Paths())
	if ids["A"] == 0 || ids["B"] == 0 || ids["C"] == 0 {
		t.Fatalf("idsByName=%v", ids)
	}
	recorder := newTier6MigrationRecorder(t, client)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if client.(testConnectionControl).ActivePath() == ids["B"] {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := client.(testConnectionControl).ActivePath(); got != ids["B"] {
		t.Fatalf("active path=%d want B=%d; peak C=%d must stay out of normal quality selector", got, ids["B"], ids["C"])
	}
	cBefore, err := controlled.PathStats("C")
	if err != nil {
		t.Fatal(err)
	}
	if cBefore.PhysicalDataWriteBytes != 0 {
		t.Fatalf("peak C carried DATA during normal quality selection: %+v", cBefore)
	}

	chunk := tier6DeterministicPayload("nested-normal-data", 32<<10)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && client.(testConnectionControl).ActivePath() != ids["C"] {
		collector.write(t, client, chunk)
	}
	if got := client.(testConnectionControl).ActivePath(); got != ids["C"] {
		t.Fatalf("normal selector did not peak-transfer B -> C: active=%d diagnostics=%+v", got, peakTransferDiagnostic(client, false))
	}
	assertPeakDemandEvidence(t, client, false)
	for i := 0; i < 24; i++ {
		collector.write(t, client, chunk)
	}
	waitForActivePath(t, client, ids["B"], 3*time.Second)
	bStats, err := controlled.PathStats("B")
	if err != nil {
		t.Fatal(err)
	}
	cStats, err := controlled.PathStats("C")
	if err != nil {
		t.Fatal(err)
	}
	if bStats.PhysicalDataWriteBytes == 0 || cStats.PhysicalDataWriteBytes == 0 {
		t.Fatalf("nested normal/peak physical DATA missing: B=%+v C=%+v", bStats, cStats)
	}
	tier6CloseWrite(t, client)
	facts := map[string]string{
		"transition_history":              "B>C>B",
		"normal_quality_selected":         "B",
		"peak_excluded_before_saturation": "true",
		"peak_pre_saturation_bytes":       tier6Uint(cBefore.PhysicalDataWriteBytes),
		"normal_B_physical_data_bytes":    tier6Uint(bStats.PhysicalDataWriteBytes),
		"peak_C_physical_data_bytes":      tier6Uint(cStats.PhysicalDataWriteBytes),
		"embedded_negative_control":       "peak-excluded-from-normal-quality",
		"topology_path_count":             tier6Uint(uint64(len(client.Paths()))),
	}
	mergeTier6Facts(t, facts, collector.finish(t, "payload"))
	events := recorder.finish(t)
	if !tier6MigrationContains(events, "C") || !tier6MigrationContains(events, "B") {
		t.Fatalf("committed migration history does not prove B -> C -> B: %+v", events)
	}
	facts["committed_migrations"] = tier6Uint(uint64(len(events)))
	facts["migration_target_history"] = tier6MigrationTargets(events)
	emitTier6Evidence(t, "T6.peak.nested-normal-to-C", facts)
}

func TestSelectorHotStandbyFailover(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accepted := make(chan Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	controlled := newRuntimeControlledTCPTransport(t)
	spec := func(name string) PathSpec { return controlled.Spec(ln.Addr().String(), name) }
	root := Selector("root", []Target{
		Path("A", spec("A")),
		Path("B", spec("B")),
	})
	dialer := &sessionDialer{
		Root:          root,
		Hysteresis:    0.05,
		Dwell:         100 * time.Millisecond,
		Cooldown:      100 * time.Millisecond,
		ProbeInterval: 30 * time.Second,
		Retry:         retryPolicy{MinBackoff: 5 * time.Second, MaxBackoff: 5 * time.Second},
	}
	controlled.Bind(t, dialer)
	client, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	waitForPathNames(t, client, []string{"A", "B"}, 3*time.Second)
	waitForPathNames(t, server, []string{"A", "B"}, 3*time.Second)
	collector := newTier6IntegrityCollector(server)

	ids := idsByName(client.Paths())
	if ids["A"] == 0 || ids["B"] == 0 {
		t.Fatalf("idsByName=%v", ids)
	}
	if err := controlled.SetQuality("A", PathQuality{RTT: 30 * time.Millisecond, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := controlled.SetQuality("B", PathQuality{RTT: 50 * time.Millisecond, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if got := client.(testConnectionControl).ActivePath(); got != ids["A"] {
		t.Fatalf("initial active=%d want A=%d", got, ids["A"])
	}
	recorder := newTier6MigrationRecorder(t, client)
	beforeFailure := tier6DeterministicPayload("hot-standby-before", 16<<10)
	collector.write(t, client, beforeFailure)
	aBefore, err := controlled.PathStats("A")
	if err != nil {
		t.Fatal(err)
	}
	bBefore, err := controlled.PathStats("B")
	if err != nil {
		t.Fatal(err)
	}
	if aBefore.PhysicalDataWriteBytes == 0 || bBefore.PhysicalDataWriteBytes != 0 {
		t.Fatalf("standby control before failure A/B=%+v/%+v", aBefore, bBefore)
	}
	failureAt := time.Now()
	if err := controlled.Fail("A"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if client.(testConnectionControl).ActivePath() == ids["B"] {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := client.(testConnectionControl).ActivePath(); got != ids["B"] {
		t.Fatalf("active after A death=%d want B=%d", got, ids["B"])
	}
	switchLatency := time.Since(failureAt)
	if switchLatency > time.Second {
		t.Fatalf("standby switch latency=%s, want <=1s", switchLatency)
	}
	afterFailure := tier6DeterministicPayload("hot-standby-after", 64<<10)
	collector.write(t, client, afterFailure)
	bAfter, err := controlled.PathStats("B")
	if err != nil {
		t.Fatal(err)
	}
	if bAfter.PhysicalDataWriteBytes == 0 {
		t.Fatalf("standby B carried no DATA after A carrier failure: %+v", bAfter)
	}
	tier6CloseWrite(t, client)
	facts := map[string]string{
		"transition_history":               "A>B",
		"carrier_A_failure_injected":       "true",
		"carrier_A_pre_failure_bytes":      tier6Uint(aBefore.PhysicalDataWriteBytes),
		"standby_B_pre_failure_bytes":      tier6Uint(bBefore.PhysicalDataWriteBytes),
		"standby_B_post_failure_bytes":     tier6Uint(bAfter.PhysicalDataWriteBytes),
		"standby_switch_latency_ns":        tier6Duration(switchLatency),
		"standby_switch_within_one_second": tier6Bool(switchLatency <= time.Second),
		"embedded_negative_control":        "healthy-primary-keeps-standby-idle",
		"topology_path_count":              tier6Uint(uint64(len(ids))),
	}
	mergeTier6Facts(t, facts, collector.finish(t, "payload"))
	events := recorder.finish(t)
	if !tier6MigrationContains(events, "B") || tier6MigrationContains(events, "A") {
		t.Fatalf("standby migration history=%+v, want A -> B only", events)
	}
	facts["committed_migrations"] = tier6Uint(uint64(len(events)))
	facts["migration_target_history"] = tier6MigrationTargets(events)
	emitTier6Evidence(t, "T6.failover.hot-standby", facts)
}

func TestSelectorPeakTransferCompositeNormalDeathStaysNormal(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accepted := make(chan Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	controlled := newRuntimeControlledTCPTransport(t)
	spec := func(name string) PathSpec { return controlled.Spec(ln.Addr().String(), name) }
	root := Selector("root",
		[]Target{
			Selector("normal", []Target{
				Selector("ab", []Target{
					Path("A", spec("A")),
					Path("B", spec("B")),
				}),
				Path("C", spec("C")),
			}),
			Path("D", spec("D")),
		},
		PeakTransfer{Targets: []string{"D"}, SaturationFor: 10 * time.Second},
	)
	dialer := &sessionDialer{
		Root:          root,
		Hysteresis:    0.05,
		Dwell:         100 * time.Millisecond,
		Cooldown:      100 * time.Millisecond,
		ProbeInterval: 100 * time.Millisecond,
		Retry:         retryPolicy{MinBackoff: 5 * time.Second, MaxBackoff: 5 * time.Second},
	}
	for name, delay := range map[string]time.Duration{
		"A": 30 * time.Millisecond,
		"B": 20 * time.Millisecond,
		"C": 10 * time.Millisecond,
		"D": time.Millisecond,
	} {
		if err := controlled.SetProbeDelay(name, delay); err != nil {
			t.Fatal(err)
		}
	}
	controlled.Bind(t, dialer)
	client, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	waitForPathNames(t, client, []string{"A", "B", "C", "D"}, 3*time.Second)
	waitForPathNames(t, server, []string{"A", "B", "C", "D"}, 3*time.Second)
	collector := newTier6IntegrityCollector(server)

	ids := idsByName(client.Paths())
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if client.(testConnectionControl).ActivePath() == ids["C"] {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := client.(testConnectionControl).ActivePath(); got != ids["C"] {
		t.Fatalf("active=%d want C=%d before death", got, ids["C"])
	}
	recorder := newTier6MigrationRecorder(t, client)
	beforeDeath := tier6DeterministicPayload("composite-before-death", 32<<10)
	collector.write(t, client, beforeDeath)
	cBefore, err := controlled.PathStats("C")
	if err != nil {
		t.Fatal(err)
	}
	dBefore, err := controlled.PathStats("D")
	if err != nil {
		t.Fatal(err)
	}
	if cBefore.PhysicalDataWriteBytes == 0 || dBefore.PhysicalDataWriteBytes != 0 {
		t.Fatalf("composite normal control C/D=%+v/%+v", cBefore, dBefore)
	}
	if err := controlled.Fail("C"); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(1 * time.Second)
	finalName := ""
	for time.Now().Before(deadline) {
		got := client.(testConnectionControl).ActivePath()
		if got == ids["A"] || got == ids["B"] {
			finalName = pathNameByID(client.Paths(), got)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if finalName != "A" && finalName != "B" {
		t.Fatalf("active after C death=%d; wanted A or B, not peak D=%d; stats=%+v paths=%+v",
			client.(testConnectionControl).ActivePath(), ids["D"],
			client.(ConnectionObserver).Stats(), client.Paths())
	}
	afterDeath := tier6DeterministicPayload("composite-after-death", 64<<10)
	collector.write(t, client, afterDeath)
	finalStats, err := controlled.PathStats(finalName)
	if err != nil {
		t.Fatal(err)
	}
	dAfter, err := controlled.PathStats("D")
	if err != nil {
		t.Fatal(err)
	}
	if finalStats.PhysicalDataWriteBytes == 0 || dAfter.PhysicalDataWriteBytes != 0 {
		t.Fatalf("normal failover/peak exclusion %s/D=%+v/%+v", finalName, finalStats, dAfter)
	}
	tier6CloseWrite(t, client)
	facts := map[string]string{
		"transition_history":              "C>" + finalName,
		"initial_normal_path":             "C",
		"final_normal_path":               finalName,
		"final_path_is_normal":            tier6Bool(finalName == "A" || finalName == "B"),
		"path_C_failure_injected":         "true",
		"peak_D_selected_during_failover": "false",
		"peak_D_physical_data_bytes":      tier6Uint(dAfter.PhysicalDataWriteBytes),
		"pre_failure_C_data_bytes":        tier6Uint(cBefore.PhysicalDataWriteBytes),
		"post_failure_normal_data_bytes":  tier6Uint(finalStats.PhysicalDataWriteBytes),
		"embedded_negative_control":       "peak-D-excluded-from-normal-failover",
		"topology_path_count":             tier6Uint(uint64(len(ids))),
	}
	mergeTier6Facts(t, facts, collector.finish(t, "payload"))
	events := recorder.finish(t)
	if len(events) == 0 {
		t.Fatalf("composite migration history missed failover: %+v", events)
	}
	if tier6MigrationContains(events, "D") {
		t.Fatalf("normal-path death transiently committed forbidden peak D: %+v", events)
	}
	facts["committed_migrations"] = tier6Uint(uint64(len(events)))
	facts["migration_target_history"] = tier6MigrationTargets(events)
	emitTier6Evidence(t, "T6.peak.composite-normal", facts)
}

func TestSelectorPeakTransferBadSpeedQualityGate(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accepted := make(chan Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	controlled := newRuntimeControlledTCPTransport(t)
	for name, rate := range map[string]uint64{"A": 512 << 10, "C": 2 << 20} {
		if err := controlled.SetDataWriteRate(name, rate); err != nil {
			t.Fatal(err)
		}
	}
	spec := func(name string) PathSpec { return controlled.Spec(ln.Addr().String(), name) }
	root := Selector("root",
		[]Target{
			Path("A", spec("A")),
			Path("C", spec("C")),
		},
		PeakTransfer{
			Targets:         []string{"C"},
			SaturationFor:   200 * time.Millisecond,
			SaturationRatio: 0.8,
		},
	)
	dialer := &sessionDialer{Root: root, ProbeInterval: time.Second}
	controlled.Bind(t, dialer)
	client, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	waitForPathNames(t, client, []string{"A", "C"}, 3*time.Second)
	waitForPathNames(t, server, []string{"A", "C"}, 3*time.Second)
	collector := newTier6IntegrityCollector(server)

	ids := idsByName(client.Paths())
	if got := client.(testConnectionControl).ActivePath(); got != ids["A"] {
		t.Fatalf("initial active=%d want A=%d", got, ids["A"])
	}
	recorder := newTier6MigrationRecorder(t, client)
	injectedBadQuality := PathQuality{
		RTT:    100 * time.Millisecond,
		Jitter: 250 * time.Millisecond,
		LossPP: 500,
		At:     time.Now(),
	}
	if err := controlled.SetQuality("C", injectedBadQuality); err != nil {
		t.Fatal(err)
	}
	backed, ok := client.(*engineBackedConn)
	if !ok || backed.peak == nil {
		t.Fatalf("client=%T has no peak-transfer controller", client)
	}
	if backed.peak.peakHealthy() {
		t.Fatalf("bad-quality stimulus was admitted before transfer: paths=%+v diagnostic=%+v",
			client.Paths(), peakTransferDiagnostic(client, false))
	}
	liveLossGuard := PathQuality{RTT: 10 * time.Millisecond, LossPP: 500, At: time.Now()}
	if err := controlled.SetQuality("C", liveLossGuard); err != nil {
		t.Fatal(err)
	}
	if backed.peak.peakHealthy() {
		t.Fatalf("loss-only live guard was admitted before demand: paths=%+v diagnostic=%+v",
			client.Paths(), peakTransferDiagnostic(client, false))
	}
	chunk := tier6DeterministicPayload("bad-speed-data", 32<<10)
	for i := 0; i < 48; i++ {
		collector.write(t, client, chunk)
	}
	time.Sleep(500 * time.Millisecond)
	assertPeakDemandEvidence(t, client, false)
	aStats, err := controlled.PathStats("A")
	if err != nil {
		t.Fatal(err)
	}
	if aStats.DelayedDataWrites == 0 || aStats.DataWriteBlocked == 0 {
		t.Fatalf("bad-candidate negative control did not saturate normal DATA: %+v", aStats)
	}
	badDecisionQuality := qualityByName(t, client.Paths(), "C")
	if badDecisionQuality.RTT <= 0 || badDecisionQuality.At.IsZero() ||
		badDecisionQuality.LossPP != liveLossGuard.LossPP || badDecisionQuality.Jitter > 200*time.Millisecond {
		t.Fatalf("loss-only decision quality=%+v want current timing, loss=%d, and admissible jitter",
			badDecisionQuality, liveLossGuard.LossPP)
	}
	if backed.peak.peakHealthy() {
		t.Fatalf("loss-only decision guard was admitted: quality=%+v diagnostic=%+v",
			badDecisionQuality, peakTransferDiagnostic(client, false))
	}
	if got := client.(testConnectionControl).ActivePath(); got == ids["C"] {
		t.Fatalf("active path promoted to bad peak C=%d", ids["C"])
	}
	cBadStats, err := controlled.PathStats("C")
	if err != nil {
		t.Fatal(err)
	}
	if cBadStats.PhysicalDataWriteBytes != 0 {
		t.Fatalf("bad peak candidate carried DATA before healthy control: %+v", cBadStats)
	}
	healthyDecisionQuality := badDecisionQuality
	healthyDecisionQuality.LossPP = 0
	if err := controlled.SetQuality("C", healthyDecisionQuality); err != nil {
		t.Fatal(err)
	}
	if !backed.peak.peakHealthy() {
		t.Fatalf("healthy-control stimulus was not visible before transfer: paths=%+v diagnostic=%+v",
			client.Paths(), peakTransferDiagnostic(client, false))
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && client.(testConnectionControl).ActivePath() != ids["C"] {
		collector.write(t, client, chunk)
	}
	if got := client.(testConnectionControl).ActivePath(); got != ids["C"] {
		t.Fatalf(
			"healthy-control candidate did not promote under the same demand: active=%d want=%d diagnostic=%+v",
			got, ids["C"], peakTransferDiagnostic(client, false),
		)
	}
	for i := 0; i < 8; i++ {
		collector.write(t, client, chunk)
	}
	cHealthyStats, err := controlled.PathStats("C")
	if err != nil {
		t.Fatal(err)
	}
	if cHealthyStats.PhysicalDataWriteBytes == 0 {
		t.Fatalf("healthy positive-control candidate carried no DATA: %+v", cHealthyStats)
	}
	tier6CloseWrite(t, client)
	facts := map[string]string{
		"transition_history":                    "A>C",
		"bad_quality_rejected":                  "true",
		"bad_quality_RTT_ns":                    tier6Duration(injectedBadQuality.RTT),
		"bad_quality_jitter_ns":                 tier6Duration(injectedBadQuality.Jitter),
		"bad_quality_loss_pp":                   tier6Uint(uint64(injectedBadQuality.LossPP)),
		"bad_quality_timing_fact_scope":         "initial-injection-not-live-decision",
		"bad_quality_live_rejection_basis":      "loss-only",
		"bad_quality_loss_pp_at_decision":       tier6Uint(uint64(badDecisionQuality.LossPP)),
		"bad_quality_decision_jitter_ns":        tier6Duration(badDecisionQuality.Jitter),
		"bad_candidate_physical_data_bytes":     tier6Uint(cBadStats.PhysicalDataWriteBytes),
		"healthy_quality_promoted":              "true",
		"healthy_candidate_physical_data_bytes": tier6Uint(cHealthyStats.PhysicalDataWriteBytes),
		"normal_saturation_observed":            tier6Bool(aStats.DelayedDataWrites > 0 && aStats.DataWriteBlocked > 0),
		"embedded_negative_control":             "bad-quality-blocks-promotion",
		"topology_path_count":                   tier6Uint(uint64(len(client.Paths()))),
	}
	mergeTier6Facts(t, facts, collector.finish(t, "payload"))
	events := recorder.finish(t)
	if !tier6MigrationContains(events, "C") {
		t.Fatalf("healthy control produced no committed migration to C: %+v", events)
	}
	facts["committed_migrations"] = tier6Uint(uint64(len(events)))
	facts["migration_target_history"] = tier6MigrationTargets(events)
	emitTier6Evidence(t, "T6.peak.bad-speed", facts)
}

func TestSelectorPeakTransferSkipsBadFirstPeakCandidate(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accepted := make(chan Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept(ctx)
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		accepted <- conn
	}()

	controlled := newRuntimeControlledTCPTransport(t)
	spec := func(name string) PathSpec { return controlled.Spec(ln.Addr().String(), name) }
	root := Selector("root", []Target{
		Path("A", spec("A")),
		Path("P1", spec("P1")),
		Path("P2", spec("P2")),
	}, PeakTransfer{Targets: []string{"P1", "P2"}, SaturationFor: 200 * time.Millisecond, SaturationRatio: 0.8})
	dialer := &sessionDialer{Root: root, ProbeInterval: 30 * time.Second}
	controlled.Bind(t, dialer)
	client, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server Conn
	select {
	case server = <-accepted:
	case err = <-errCh:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	waitForPathNames(t, client, []string{"A", "P1", "P2"}, 3*time.Second)
	waitForPathNames(t, server, []string{"A", "P1", "P2"}, 3*time.Second)
	go io.Copy(io.Discard, server)

	if err := controlled.SetQuality("P1", PathQuality{
		RTT: 100 * time.Millisecond, Jitter: 250 * time.Millisecond, LossPP: 500, At: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := controlled.SetQuality("P2", PathQuality{RTT: 120 * time.Millisecond, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	backed := client.(*engineBackedConn)
	targetID, ok := backed.peak.selectHealthyPeakTarget(false)
	if !ok {
		t.Fatal("no healthy peak target selected")
	}
	want := proto.DeriveTargetID(proto.GraphNodeKindPath, "P2")
	if targetID != want {
		t.Fatalf("selected peak target=%x want healthy P2=%x", targetID, want)
	}
	bad := proto.DeriveTargetID(proto.GraphNodeKindPath, "P1")
	selectorID := backed.peak.localTargets.selectorID
	if backed.e.LocalPeakTransferTargetHealthy(selectorID, bad) {
		t.Fatal("bad first peak candidate borrowed healthy sibling evidence")
	}
	if err := backed.peak.applyPolicy(false, peakTransferPeak, "healthy-second-candidate"); err != nil {
		t.Fatal(err)
	}
	ids := idsByName(client.Paths())
	if got := client.(testConnectionControl).ActivePath(); got != ids["P2"] {
		t.Fatalf("active path=%d want healthy P2=%d", got, ids["P2"])
	}
}

func TestSelectorPeakTransferStaleSpeedEvidence(t *testing.T) {
	admission := newPeakDirectionalFixture(t,
		Selector("stale-client-root", []Target{
			Path("stale-client-normal", PathSpec{}),
			Path("stale-client-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"stale-client-peak"}}),
		Selector("stale-server-root", []Target{
			Path("stale-server-normal", PathSpec{}),
			Path("stale-server-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"stale-server-peak"}}),
	)
	if admission.localPeak == admission.peerPeak {
		t.Fatal("stale admission fixture did not produce asymmetric endpoint target IDs")
	}
	staleAt := time.Now().Add(-10 * time.Second)
	admission.clientPaths[admission.localPeak].setQuality(PathQuality{RTT: 10 * time.Millisecond, At: staleAt})
	admission.serverPaths[admission.peerPeak].setQuality(PathQuality{RTT: 10 * time.Millisecond, At: time.Now()})
	if admission.client.LocalPeakTransferTargetHealthy(admission.controller.localTargets.selectorID, admission.localPeak) {
		t.Fatal("isolated engine admitted stale peak evidence")
	}
	if !admission.server.LocalPeakTransferTargetHealthy(admission.peerSelector, admission.peerPeak) {
		t.Fatal("server sender borrowed stale quality from the client endpoint")
	}
	admission.clientPaths[admission.localPeak].setQuality(PathQuality{RTT: 10 * time.Millisecond, At: time.Now()})
	admission.serverPaths[admission.peerPeak].setQuality(PathQuality{RTT: 10 * time.Millisecond, At: staleAt})
	if !admission.client.LocalPeakTransferTargetHealthy(admission.controller.localTargets.selectorID, admission.localPeak) {
		t.Fatal("isolated engine did not admit fresh peak evidence after stale rejection")
	}
	if admission.server.LocalPeakTransferTargetHealthy(admission.peerSelector, admission.peerPeak) {
		t.Fatal("server sender borrowed fresh quality from the client endpoint")
	}
	if err := admission.controller.applyPolicy(true, peakTransferPeak, "stale-peer-promotion"); err == nil {
		t.Fatal("real peer policy request bypassed stale owner evidence")
	}
	if got := admission.server.ActivePath(); got != admission.serverNormalPath {
		t.Fatalf("rejected stale peer request changed server path=%d want normal=%d", got, admission.serverNormalPath)
	}
	if got := admission.client.ActivePath(); got != admission.clientNormalPath {
		t.Fatalf("rejected stale peer request changed client path=%d want normal=%d", got, admission.clientNormalPath)
	}
	admission.serverPaths[admission.peerPeak].setQuality(PathQuality{RTT: 10 * time.Millisecond, At: time.Now()})
	if err := admission.controller.applyPolicy(true, peakTransferPeak, "fresh-peer-promotion"); err != nil {
		t.Fatalf("real peer policy request rejected fresh owner evidence: %v", err)
	}
	if got := admission.server.ActivePath(); got != admission.serverPeakPath {
		t.Fatalf("fresh peer request selected server path=%d want peak=%d", got, admission.serverPeakPath)
	}
	if got := admission.client.ActivePath(); got != admission.clientNormalPath {
		t.Fatalf("fresh peer request changed client path=%d want normal=%d", got, admission.clientNormalPath)
	}

	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	accepted := make(chan Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	controlled := newRuntimeControlledTCPTransport(t)
	for name, rate := range map[string]uint64{"A": 512 << 10, "C": 2 << 20} {
		if err := controlled.SetDataWriteRate(name, rate); err != nil {
			t.Fatal(err)
		}
	}
	spec := func(name string) PathSpec { return controlled.Spec(ln.Addr().String(), name) }
	root := Selector("root",
		[]Target{
			Path("A", spec("A")),
			Path("C", spec("C")),
		},
		PeakTransfer{
			Targets:         []string{"C"},
			SaturationFor:   200 * time.Millisecond,
			SaturationRatio: 0.8,
		},
	)
	dialer := &sessionDialer{Root: root, ProbeInterval: time.Second}
	controlled.Bind(t, dialer)
	client, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	waitForPathNames(t, client, []string{"A", "C"}, 3*time.Second)
	waitForPathNames(t, server, []string{"A", "C"}, 3*time.Second)
	collector := newTier6IntegrityCollector(server)
	backed, ok := client.(*engineBackedConn)
	if !ok || backed.peak == nil {
		t.Fatalf("client=%T has no peak-transfer controller", client)
	}

	ids := idsByName(client.Paths())
	if got := client.(testConnectionControl).ActivePath(); got != ids["A"] {
		t.Fatalf("initial active=%d want A=%d", got, ids["A"])
	}
	recorder := newTier6MigrationRecorder(t, client)
	liveLossGuard := PathQuality{
		RTT: 10 * time.Millisecond, LossPP: 500, At: time.Now(),
	}
	if err := controlled.SetQuality("C", liveLossGuard); err != nil {
		t.Fatal(err)
	}
	if backed.peak.peakHealthy() {
		t.Fatalf("live loss-only guard was admitted: paths=%+v", client.Paths())
	}
	chunk := tier6DeterministicPayload("stale-speed-data", 32<<10)
	// The loss-only live guard establishes a complete demand-backed capacity
	// window while the isolated fixture above owns timestamp staleness.
	for i := 0; i < 48; i++ {
		collector.write(t, client, chunk)
	}
	time.Sleep(500 * time.Millisecond)
	assertPeakDemandEvidence(t, client, false)
	aStats, err := controlled.PathStats("A")
	if err != nil {
		t.Fatal(err)
	}
	if aStats.DelayedDataWrites == 0 || aStats.DataWriteBlocked == 0 {
		t.Fatalf("stale-evidence negative control did not saturate normal DATA: %+v", aStats)
	}
	liveDecisionQuality := qualityByName(t, client.Paths(), "C")
	if liveDecisionQuality.RTT <= 0 || liveDecisionQuality.At.IsZero() ||
		liveDecisionQuality.LossPP != liveLossGuard.LossPP || liveDecisionQuality.Jitter > 200*time.Millisecond {
		t.Fatalf("live loss-only decision quality=%+v want current timing, loss=%d, and admissible jitter",
			liveDecisionQuality, liveLossGuard.LossPP)
	}
	if backed.peak.peakHealthy() {
		t.Fatalf("live loss-only decision guard was admitted: quality=%+v diagnostic=%+v",
			liveDecisionQuality, peakTransferDiagnostic(client, false))
	}
	if got := client.(testConnectionControl).ActivePath(); got == ids["C"] {
		t.Fatalf("active path promoted using stale peak evidence C=%d healthy=%t peak_ids=%v paths=%+v", ids["C"], backed.peak.peakHealthy(), backed.peak.peakIDs, client.Paths())
	}
	cStaleStats, err := controlled.PathStats("C")
	if err != nil {
		t.Fatal(err)
	}
	if cStaleStats.PhysicalDataWriteBytes != 0 {
		t.Fatalf("stale peak candidate carried DATA before fresh control: %+v", cStaleStats)
	}
	freshDecisionQuality := liveDecisionQuality
	freshDecisionQuality.LossPP = 0
	if err := controlled.SetQuality("C", freshDecisionQuality); err != nil {
		t.Fatal(err)
	}
	if !backed.peak.peakHealthy() {
		t.Fatalf("fresh peak evidence was not admitted before transfer: paths=%+v diagnostic=%+v",
			client.Paths(), peakTransferDiagnostic(client, false))
	}
	freshRefreshes := uint64(1)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && client.(testConnectionControl).ActivePath() != ids["C"] {
		if err := controlled.SetQuality("C", PathQuality{RTT: 10 * time.Millisecond, At: time.Now()}); err != nil {
			t.Fatal(err)
		}
		freshRefreshes++
		collector.write(t, client, chunk)
	}
	if got := client.(testConnectionControl).ActivePath(); got != ids["C"] {
		t.Fatalf(
			"fresh healthy-control candidate did not promote under the same demand: active=%d want=%d diagnostic=%+v",
			got, ids["C"], peakTransferDiagnostic(client, false),
		)
	}
	for i := 0; i < 8; i++ {
		collector.write(t, client, chunk)
	}
	cFreshStats, err := controlled.PathStats("C")
	if err != nil {
		t.Fatal(err)
	}
	if cFreshStats.PhysicalDataWriteBytes == 0 {
		t.Fatalf("fresh positive-control candidate carried no DATA: %+v", cFreshStats)
	}
	tier6CloseWrite(t, client)
	facts := map[string]string{
		"transition_history":                   "A>C",
		"stale_quality_rejected":               "true",
		"stale_admission_isolated":             "true",
		"stale_endpoint_roles_asymmetric":      "true",
		"live_bad_quality_rejected":            "true",
		"live_bad_quality_rejection_basis":     "loss-only",
		"live_bad_quality_loss_pp_at_decision": tier6Uint(uint64(liveDecisionQuality.LossPP)),
		"live_bad_quality_decision_jitter_ns":  tier6Duration(liveDecisionQuality.Jitter),
		"stale_quality_age_ns":                 tier6Duration(time.Since(staleAt)),
		"stale_peer_promotion_rejected":        "true",
		"stale_peer_fresh_control_accepted":    "true",
		"stale_candidate_physical_data_bytes":  tier6Uint(cStaleStats.PhysicalDataWriteBytes),
		"fresh_quality_promoted":               "true",
		"fresh_quality_refreshes":              tier6Uint(freshRefreshes),
		"fresh_candidate_physical_data_bytes":  tier6Uint(cFreshStats.PhysicalDataWriteBytes),
		"normal_saturation_observed":           tier6Bool(aStats.DelayedDataWrites > 0 && aStats.DataWriteBlocked > 0),
		"embedded_negative_control":            "stale-quality-blocks-local-and-peer-promotion",
		"topology_path_count":                  tier6Uint(uint64(len(client.Paths()))),
	}
	mergeTier6Facts(t, facts, collector.finish(t, "payload"))
	events := recorder.finish(t)
	if !tier6MigrationContains(events, "C") {
		t.Fatalf("fresh control produced no committed migration to C: %+v", events)
	}
	facts["committed_migrations"] = tier6Uint(uint64(len(events)))
	facts["migration_target_history"] = tier6MigrationTargets(events)
	emitTier6Evidence(t, "T6.peak.stale-speed", facts)
}

func TestSelectorPeakTransferProbeBudgetUsesSinglePeakCandidate(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accepted := make(chan Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	controlled := newRuntimeControlledTCPTransport(t)
	for name, rate := range map[string]uint64{"A": 512 << 10, "P1": 2 << 20, "P2": 2 << 20, "P3": 2 << 20} {
		if err := controlled.SetDataWriteRate(name, rate); err != nil {
			t.Fatal(err)
		}
	}
	spec := func(name string) PathSpec { return controlled.Spec(ln.Addr().String(), name) }
	root := Selector("root",
		[]Target{
			Path("A", spec("A")),
			Path("P1", spec("P1")),
			Path("P2", spec("P2")),
			Path("P3", spec("P3")),
		},
		PeakTransfer{
			Targets:         []string{"P1", "P2", "P3"},
			SaturationFor:   200 * time.Millisecond,
			SaturationRatio: 0.8,
		},
	)
	dialer := &sessionDialer{Root: root, ProbeInterval: 30 * time.Second}
	controlled.Bind(t, dialer)
	client, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	waitForPathNames(t, client, []string{"A", "P1", "P2", "P3"}, 3*time.Second)
	waitForPathNames(t, server, []string{"A", "P1", "P2", "P3"}, 3*time.Second)
	qualityAt := time.Now()
	for name, rtt := range map[string]time.Duration{
		"A": time.Millisecond, "P1": 2 * time.Millisecond,
		"P2": 20 * time.Millisecond, "P3": 30 * time.Millisecond,
	} {
		if err := controlled.SetQuality(name, PathQuality{RTT: rtt, At: qualityAt}); err != nil {
			t.Fatal(err)
		}
	}
	collector := newTier6IntegrityCollector(server)

	backed, ok := client.(*engineBackedConn)
	if !ok || backed.peak == nil {
		t.Fatalf("client=%T has no peak-transfer controller", client)
	}
	recorder := newTier6MigrationRecorder(t, client)
	before := firstDataDispatchesByName(client.Paths())
	chunk := tier6DeterministicPayload("passive-single-candidate-data", 32<<10)
	deadline := time.Now().Add(4 * time.Second)
	var observation peakCapacityObservation
	for time.Now().Before(deadline) {
		collector.write(t, client, chunk)
		observation = backed.peak.lastPeakObservation(false)
		if observation.conclusive {
			break
		}
	}
	if !observation.conclusive {
		t.Fatal("passive peak observation did not complete")
	}
	assertPeakDemandEvidence(t, client, false)
	aStats, err := controlled.PathStats("A")
	if err != nil {
		t.Fatal(err)
	}
	if aStats.DelayedDataWrites == 0 || aStats.DataWriteBlocked == 0 {
		t.Fatalf("single-candidate observation did not saturate normal DATA: %+v", aStats)
	}
	ids := idsByName(client.Paths())
	wantTarget := proto.DeriveTargetID(proto.GraphNodeKindPath, "P1")
	if observation.targetID != wantTarget {
		t.Fatalf("observed target=%x want P1=%x", observation.targetID, wantTarget)
	}
	if !observation.success || observation.bytes == 0 || observation.demand == 0 {
		t.Fatalf("P1 passive observation did not produce demand-backed delivery evidence: %+v", observation)
	}
	if observation.duration < defaultPeakWindow || observation.duration > defaultPeakMaximumWindow+defaultPeakWindow {
		t.Fatalf("passive observation duration=%s outside [%s,%s]", observation.duration,
			defaultPeakWindow, defaultPeakMaximumWindow+defaultPeakWindow)
	}
	after := firstDataDispatchesByName(client.Paths())
	if got := after["P1"] - before["P1"]; got == 0 {
		t.Fatalf("selected P1 carried no natural application DATA: before=%v after=%v", before, after)
	}
	p1Stats, err := controlled.PathStats("P1")
	if err != nil {
		t.Fatal(err)
	}
	if p1Stats.PhysicalDataWriteBytes == 0 {
		t.Fatalf("selected P1 carried no physical DATA: %+v", p1Stats)
	}
	if after["P2"] != before["P2"] || after["P3"] != before["P3"] {
		t.Fatalf("unselected peak candidates received application DATA: before=%v after=%v", before, after)
	}
	unselectedStats := make(map[string]runtimeControlledTCPPathStats, 2)
	for _, name := range []string{"P2", "P3"} {
		stats, statsErr := controlled.PathStats(name)
		if statsErr != nil {
			t.Fatal(statsErr)
		}
		unselectedStats[name] = stats
		if stats.PhysicalDataWriteBytes != 0 {
			t.Fatalf("unselected candidate %s carried physical DATA: %+v", name, stats)
		}
	}
	if got := client.(testConnectionControl).ActivePath(); got != ids["P1"] {
		t.Fatalf("active after successful bounded probe=%d want P1=%d", got, ids["P1"])
	}
	tier6CloseWrite(t, client)
	facts := map[string]string{
		"observation_kind":           "passive-application-data",
		"active_probe_used":          "false",
		"selected_candidate":         "P1",
		"observation_conclusive":     tier6Bool(observation.conclusive),
		"observation_success":        tier6Bool(observation.success),
		"observation_bytes":          tier6Uint(observation.bytes),
		"observation_demand_bytes":   tier6Uint(observation.demand),
		"observation_duration_ns":    tier6Duration(observation.duration),
		"P1_first_data_dispatches":   tier6Uint(after["P1"] - before["P1"]),
		"P1_physical_data_bytes":     tier6Uint(p1Stats.PhysicalDataWriteBytes),
		"P2_first_data_dispatches":   tier6Uint(after["P2"] - before["P2"]),
		"P3_first_data_dispatches":   tier6Uint(after["P3"] - before["P3"]),
		"P2_physical_data_bytes":     tier6Uint(unselectedStats["P2"].PhysicalDataWriteBytes),
		"P3_physical_data_bytes":     tier6Uint(unselectedStats["P3"].PhysicalDataWriteBytes),
		"normal_saturation_observed": tier6Bool(aStats.DelayedDataWrites > 0 && aStats.DataWriteBlocked > 0),
		"embedded_negative_control":  "unselected-candidates-carry-zero-application-data",
		"topology_path_count":        tier6Uint(uint64(len(client.Paths()))),
	}
	mergeTier6Facts(t, facts, collector.finish(t, "payload"))
	events := recorder.finish(t)
	if !tier6MigrationContains(events, "P1") || tier6MigrationContains(events, "P2") || tier6MigrationContains(events, "P3") {
		t.Fatalf("passive single-candidate migration history=%+v", events)
	}
	facts["committed_migrations"] = tier6Uint(uint64(len(events)))
	facts["migration_target_history"] = tier6MigrationTargets(events)
	emitTier6Evidence(t, "T6.peak.probe-budget", facts)
}

func TestSelectorPeakTransferSlowPeakRevertsAndSuppresses(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	accepted := make(chan Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	controlled := newRuntimeControlledTCPTransport(t)
	for name, rate := range map[string]uint64{"A": 1 << 20, "B": 256 << 10, "C": 2 << 20} {
		if err := controlled.SetDataWriteRate(name, rate); err != nil {
			t.Fatal(err)
		}
	}
	spec := func(name string) PathSpec { return controlled.Spec(ln.Addr().String(), name) }
	root := Selector("root",
		[]Target{
			Path("A", spec("A")),
			Path("B", spec("B")),
			Path("C", spec("C")),
		},
		PeakTransfer{
			Targets:         []string{"B", "C"},
			SaturationFor:   200 * time.Millisecond,
			ReturnFor:       3 * time.Second,
			SaturationRatio: 0.5,
			ReturnRatio:     0.2,
		},
	)
	d := &sessionDialer{Root: root, ProbeInterval: 30 * time.Second}
	controlled.Bind(t, d)
	client, err := d.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	waitForPathNames(t, client, []string{"A", "B", "C"}, 3*time.Second)
	waitForPathNames(t, server, []string{"A", "B", "C"}, 3*time.Second)
	collector := newTier6IntegrityCollector(server)

	ids := idsByName(client.Paths())
	if ids["A"] == 0 || ids["B"] == 0 || ids["C"] == 0 {
		t.Fatalf("idsByName=%v", ids)
	}
	qualityAt := time.Now()
	for index, name := range []string{"A", "B", "C"} {
		if err := controlled.SetQuality(name, PathQuality{RTT: time.Duration(index+1) * time.Millisecond, At: qualityAt}); err != nil {
			t.Fatal(err)
		}
	}
	recorder := newTier6MigrationRecorder(t, client)

	chunk := tier6DeterministicPayload("slow-peak-data", 32<<10)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !peakTransferMigrationObserved(recorder, "B") {
		collector.write(t, client, chunk)
	}
	if !peakTransferMigrationObserved(recorder, "B") {
		t.Fatalf("peak B was not selected: active=%d want B=%d diagnostics=%+v migrations=%+v",
			client.(testConnectionControl).ActivePath(), ids["B"], peakTransferDiagnostic(client, false),
			peakTransferMigrationSnapshot(recorder))
	}
	assertPeakDemandEvidence(t, client, false)
	aStats, err := controlled.PathStats("A")
	if err != nil {
		t.Fatal(err)
	}
	if aStats.DelayedDataWrites == 0 || aStats.PhysicalDataWriteBytes == 0 {
		t.Fatalf("normal path lacked DATA pressure before promotion: %+v", aStats)
	}

	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !peakTransferMigrationHasSequence(
		peakTransferMigrationSnapshot(recorder), "B", "A",
	) {
		collector.write(t, client, chunk)
	}
	if !peakTransferMigrationHasSequence(peakTransferMigrationSnapshot(recorder), "B", "A") {
		t.Fatalf("slow peak B did not return to A: diagnostics=%+v migrations=%+v",
			peakTransferDiagnostic(client, false), peakTransferMigrationSnapshot(recorder))
	}
	bStats, err := controlled.PathStats("B")
	if err != nil {
		t.Fatal(err)
	}
	observation := client.(*engineBackedConn).peak.lastPeakObservation(false)
	if bStats.DelayedDataWrites == 0 || bStats.PhysicalDataWriteBytes == 0 ||
		!observation.conclusive || observation.success || observation.demand == 0 {
		t.Fatalf("slow peak did not produce physical, demand-backed rejection: stats=%+v observation=%+v", bStats, observation)
	}

	bTarget := proto.DeriveTargetID(proto.GraphNodeKindPath, "B")
	backed := client.(*engineBackedConn)
	suppressionStarted, bSuppressed := waitPeakTargetSuppressed(backed.peak, false, bTarget, time.Second)
	if !bSuppressed {
		t.Fatal("slow peak B was not candidate-suppressed after capacity rejection")
	}
	deadline = suppressionStarted.Add(4 * time.Second)
	relayWrites := uint64(0)
	for time.Now().Before(deadline) && !peakTransferMigrationObserved(recorder, "C") {
		collector.write(t, client, chunk)
		relayWrites++
	}
	if !peakTransferMigrationObserved(recorder, "C") {
		t.Fatalf("healthy sibling C was not selected while B was suppressed: active=%d diagnostics=%+v migrations=%+v",
			client.(testConnectionControl).ActivePath(), peakTransferDiagnostic(client, false),
			peakTransferMigrationSnapshot(recorder))
	}
	if elapsed := time.Since(suppressionStarted); elapsed >= defaultPeakSuppressFor {
		t.Fatalf("C selection waited for B suppression expiry: elapsed=%s", elapsed)
	}
	for i := 0; i < 16; i++ {
		collector.write(t, client, chunk)
	}
	cStats, err := controlled.PathStats("C")
	if err != nil {
		t.Fatal(err)
	}
	if cStats.PhysicalDataWriteBytes == 0 {
		t.Fatalf("selected healthy sibling C carried no physical DATA: %+v", cStats)
	}
	tier6CloseWrite(t, client)
	facts := map[string]string{
		"transition_history":                   "A>B>A>C",
		"normal_A_physical_data_bytes":         tier6Uint(aStats.PhysicalDataWriteBytes),
		"slow_B_physical_data_bytes":           tier6Uint(bStats.PhysicalDataWriteBytes),
		"healthy_C_physical_data_bytes":        tier6Uint(cStats.PhysicalDataWriteBytes),
		"slow_peak_observation_conclusive":     tier6Bool(observation.conclusive),
		"slow_peak_observation_success":        tier6Bool(observation.success),
		"slow_peak_observation_demand_bytes":   tier6Uint(observation.demand),
		"reverted_to_normal":                   "true",
		"slow_B_suppressed":                    tier6Bool(bSuppressed),
		"relay_to_C_before_suppression_expiry": "true",
		"relay_writes":                         tier6Uint(relayWrites),
		"embedded_negative_control":            "rejected-B-does-not-block-healthy-C",
		"topology_path_count":                  tier6Uint(uint64(len(client.Paths()))),
	}
	mergeTier6Facts(t, facts, collector.finish(t, "payload"))
	events := recorder.finish(t)
	if !peakTransferMigrationHasSequence(events, "B", "A", "C") {
		t.Fatalf("slow peak migration history does not prove A -> B -> A -> C: %+v", events)
	}
	facts["committed_migrations"] = tier6Uint(uint64(len(events)))
	facts["migration_target_history"] = tier6MigrationTargets(events)
	emitTier6Evidence(t, "T6.peak.slow-peak-revert", facts)
}

func TestSelectorPeakTransferRxPromotesPeerSenderOnly(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	accepted := make(chan Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	controlled := newRuntimeControlledTCPTransport(t)
	for name, rate := range map[string]uint64{"A": 1 << 20, "B": 256 << 10, "C": 2 << 20} {
		if err := controlled.SetDataReadRate(name, rate); err != nil {
			t.Fatal(err)
		}
	}
	spec := func(name string) PathSpec { return controlled.Spec(ln.Addr().String(), name) }
	root := Selector("root",
		[]Target{
			Path("A", spec("A")),
			Path("B", spec("B")),
			Path("C", spec("C")),
		},
		PeakTransfer{
			Targets:         []string{"B", "C"},
			SaturationFor:   200 * time.Millisecond,
			ReturnFor:       3 * time.Second,
			SaturationRatio: 0.5,
			ReturnRatio:     0.2,
		},
	)
	dialer := &sessionDialer{Root: root, ProbeInterval: 30 * time.Second}
	controlled.Bind(t, dialer)
	client, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server Conn
	select {
	case server = <-accepted:
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	waitForPathNames(t, client, []string{"A", "B", "C"}, 3*time.Second)
	waitForPathNames(t, server, []string{"A", "B", "C"}, 3*time.Second)
	serverIDs := idsByName(server.Paths())
	clientIDs := idsByName(client.Paths())
	if serverIDs["A"] == 0 || serverIDs["B"] == 0 || serverIDs["C"] == 0 ||
		clientIDs["A"] == 0 || clientIDs["B"] == 0 || clientIDs["C"] == 0 {
		t.Fatalf("serverIDs=%v clientIDs=%v", serverIDs, clientIDs)
	}
	qualityAt := time.Now()
	for index, name := range []string{"A", "B", "C"} {
		if err := controlled.SetQuality(name, PathQuality{
			RTT: time.Duration(index+1) * time.Millisecond, At: qualityAt,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := server.(ConnectionObserver).ActivePath(); got != serverIDs["A"] {
		t.Fatalf("initial server sender path=%d want A=%d", got, serverIDs["A"])
	}
	if got := client.(ConnectionObserver).ActivePath(); got != clientIDs["A"] {
		t.Fatalf("initial client sender path=%d want A=%d", got, clientIDs["A"])
	}
	serverToClient := newTier6IntegrityCollector(client)
	clientToServer := newTier6IntegrityCollector(server)
	serverRecorder := newTier6MigrationRecorder(t, server)
	clientRecorder := newTier6MigrationRecorder(t, client)
	clientPayload := tier6DeterministicPayload("rx-peer-client-to-server", 16<<10)
	clientToServer.write(t, client, clientPayload)
	if got := client.(testConnectionControl).ActivePath(); got != clientIDs["A"] {
		t.Fatalf("client sender moved during baseline write: active=%d want A=%d", got, clientIDs["A"])
	}

	chunk := tier6DeterministicPayload("rx-peer-server-to-client", 64<<10)
	deadline := time.Now().Add(5 * time.Second)
	serverObserver := server.(ConnectionObserver)
	for time.Now().Before(deadline) && serverObserver.ActivePath() != serverIDs["B"] {
		serverToClient.write(t, server, chunk)
	}
	if got := serverObserver.ActivePath(); got != serverIDs["B"] {
		t.Fatalf(
			"server tx active path=%d want B=%d client-rx=%+v server-tx=%+v",
			got, serverIDs["B"], peakTransferDiagnostic(client, true),
			peakTransferDiagnostic(server, false),
		)
	}
	if got := client.(testConnectionControl).ActivePath(); got != clientIDs["A"] {
		t.Fatalf("client tx active path=%d want A=%d; rx policy must not move local tx", got, clientIDs["A"])
	}
	assertPeakDemandEvidence(t, client, true)
	aStats, err := controlled.PathStats("A")
	if err != nil {
		t.Fatal(err)
	}
	if aStats.DelayedDataReads == 0 || aStats.DataReadBlocked == 0 || aStats.PhysicalDataReadBytes == 0 {
		t.Fatalf("RX normal path did not exert physical DATA backpressure: %+v", aStats)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !peakTransferMigrationHasSequence(
		peakTransferMigrationSnapshot(serverRecorder), "B", "A",
	) {
		serverToClient.write(t, server, chunk)
	}
	if !peakTransferMigrationHasSequence(peakTransferMigrationSnapshot(serverRecorder), "B", "A") {
		t.Fatalf("slow peer peak B did not return to A: client-rx=%+v migrations=%+v",
			peakTransferDiagnostic(client, true), peakTransferMigrationSnapshot(serverRecorder))
	}
	bStats, err := controlled.PathStats("B")
	if err != nil {
		t.Fatal(err)
	}
	observation := client.(*engineBackedConn).peak.lastPeakObservation(true)
	eventsAfterReturn := peakTransferMigrationSnapshot(serverRecorder)
	factualCapacityDeparture := false
	for _, event := range eventsAfterReturn {
		if event.oldName == "B" && event.newName == "A" && event.cause == "probe-starved-data" {
			factualCapacityDeparture = true
			break
		}
	}
	passiveCapacityRejection := observation.conclusive && !observation.success && observation.demand != 0
	if bStats.DelayedDataReads == 0 || bStats.PhysicalDataReadBytes == 0 ||
		(!passiveCapacityRejection && !factualCapacityDeparture) {
		t.Fatalf("slow RX peak lacked physical demand-backed rejection: stats=%+v observation=%+v diagnostic=%+v migrations=%+v",
			bStats, observation, peakTransferDiagnostic(client, true),
			eventsAfterReturn)
	}
	suppressionStarted := time.Now()
	deadline = suppressionStarted.Add(4 * time.Second)
	relayWrites := uint64(0)
	for time.Now().Before(deadline) && !peakTransferMigrationHasSequence(
		peakTransferMigrationSnapshot(serverRecorder), "B", "A", "C",
	) {
		serverToClient.write(t, server, chunk)
		relayWrites++
	}
	if !peakTransferMigrationHasSequence(peakTransferMigrationSnapshot(serverRecorder), "B", "A", "C") {
		t.Fatalf("peer sender did not relay from suppressed B to C: client-rx=%+v migrations=%+v",
			peakTransferDiagnostic(client, true), peakTransferMigrationSnapshot(serverRecorder))
	}
	if elapsed := time.Since(suppressionStarted); elapsed >= defaultPeakSuppressFor {
		t.Fatalf("peer C selection waited for B suppression expiry: elapsed=%s", elapsed)
	}
	bSuppressed := true
	for i := 0; i < 16; i++ {
		serverToClient.write(t, server, chunk)
	}
	clientToServer.write(t, client, tier6DeterministicPayload("rx-peer-client-after", 64<<10))
	if got := client.(testConnectionControl).ActivePath(); got != clientIDs["A"] {
		t.Fatalf("client sender moved after peer promotion: active=%d want A=%d", got, clientIDs["A"])
	}
	cStats, err := controlled.PathStats("C")
	if err != nil {
		t.Fatal(err)
	}
	if cStats.PhysicalDataReadBytes == 0 || serverObserver.ActivePath() != serverIDs["C"] {
		t.Fatalf("healthy peer peak C did not carry DATA: stats=%+v active=%d want=%d",
			cStats, serverObserver.ActivePath(), serverIDs["C"])
	}
	tier6CloseWrite(t, server)
	tier6CloseWrite(t, client)
	facts := map[string]string{
		"server_sender_transition_history": "A>B>A>C",
		"client_sender_transition_history": "A",
		"server_sender_promoted_to_B":      "true",
		"server_sender_relayed_to_C":       "true",
		"client_sender_remained_on_A":      "true",
		"rx_saturation_observed":           tier6Bool(aStats.DelayedDataReads > 0 && aStats.DataReadBlocked > 0),
		"normal_A_physical_read_bytes":     tier6Uint(aStats.PhysicalDataReadBytes),
		"peak_B_physical_read_bytes":       tier6Uint(bStats.PhysicalDataReadBytes),
		"peak_C_physical_read_bytes":       tier6Uint(cStats.PhysicalDataReadBytes),
		"slow_B_suppressed":                tier6Bool(bSuppressed),
		"relay_writes":                     tier6Uint(relayWrites),
		"embedded_negative_control":        "peer-rx-suppressed-B-does-not-block-C-or-local-tx",
		"topology_path_count":              tier6Uint(uint64(len(client.Paths()))),
	}
	mergeTier6Facts(t, facts, serverToClient.finish(t, "server_to_client_payload"))
	mergeTier6Facts(t, facts, clientToServer.finish(t, "client_to_server_payload"))
	serverEvents := serverRecorder.finish(t)
	clientEvents := clientRecorder.finish(t)
	if !peakTransferMigrationHasSequence(serverEvents, "B", "A", "C") ||
		tier6MigrationContains(clientEvents, "B") || tier6MigrationContains(clientEvents, "C") {
		t.Fatalf("direction-specific migration histories server=%+v client=%+v", serverEvents, clientEvents)
	}
	facts["server_committed_migrations"] = tier6Uint(uint64(len(serverEvents)))
	facts["client_committed_migrations"] = tier6Uint(uint64(len(clientEvents)))
	facts["server_migration_target_history"] = tier6MigrationTargets(serverEvents)
	facts["client_migration_target_history"] = tier6MigrationTargets(clientEvents)
	emitTier6Evidence(t, "T6.peak.rx-peer-policy", facts)
}

func waitForEffectivePathNames(t *testing.T, c Conn, wantNames []string, within time.Duration) {
	t.Helper()
	want := append([]string(nil), wantNames...)
	slices.Sort(want)
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		observer, ok := c.(ConnectionObserver)
		if !ok {
			t.Fatalf("connection does not expose ConnectionObserver")
		}
		stats := observer.Stats()
		byID := make(map[uint32]string, len(stats.Paths))
		for _, path := range stats.Paths {
			byID[path.ID] = path.Spec.Opts["name"]
		}
		got := make([]string, 0, len(stats.EffectivePaths))
		for _, id := range stats.EffectivePaths {
			got = append(got, byID[id])
		}
		slices.Sort(got)
		if slices.Equal(got, want) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("effective paths=%v want %v", effectivePathNames(c), want)
}

func effectivePathNames(c Conn) []string {
	observer, ok := c.(ConnectionObserver)
	if !ok {
		return nil
	}
	stats := observer.Stats()
	byID := make(map[uint32]string, len(stats.Paths))
	for _, path := range stats.Paths {
		byID[path.ID] = path.Spec.Opts["name"]
	}
	out := make([]string, 0, len(stats.EffectivePaths))
	for _, id := range stats.EffectivePaths {
		out = append(out, byID[id])
	}
	slices.Sort(out)
	return out
}

func waitForActivePath(t *testing.T, c Conn, want uint32, within time.Duration) {
	t.Helper()
	admin, ok := c.(testConnectionControl)
	if !ok {
		t.Fatalf("connection does not expose testConnectionControl; want active path %d", want)
	}
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if admin.ActivePath() == want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("active path=%d want %d", admin.ActivePath(), want)
}

func peakTransferMigrationObserved(recorder *tier6MigrationRecorder, target string) bool {
	return tier6MigrationContains(peakTransferMigrationSnapshot(recorder), target)
}

func peakTransferMigrationSnapshot(recorder *tier6MigrationRecorder) []tier6MigrationEvent {
	if recorder == nil {
		return nil
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]tier6MigrationEvent(nil), recorder.events...)
}

func peakTransferMigrationHasSequence(events []tier6MigrationEvent, names ...string) bool {
	if len(names) == 0 {
		return true
	}
	next := 0
	for _, event := range events {
		if event.newName != names[next] {
			continue
		}
		next++
		if next == len(names) {
			return true
		}
	}
	return false
}

func waitPeakTargetSuppressed(
	controller *peakTransferController,
	rx bool,
	targetID proto.TargetID,
	within time.Duration,
) (time.Time, bool) {
	deadline := time.Now().Add(within)
	for {
		now := time.Now()
		controller.mu.Lock()
		state := &controller.tx
		if rx {
			state = &controller.rx
		}
		suppressed := state.peakTargetSuppressed(targetID, now)
		controller.mu.Unlock()
		if suppressed {
			return now, true
		}
		if now.After(deadline) {
			return now, false
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForPathNames(t *testing.T, c Conn, names []string, within time.Duration) {
	t.Helper()
	want := make(map[string]bool, len(names))
	for _, name := range names {
		want[name] = true
	}
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		got := idsByName(c.Paths())
		ok := true
		for name := range want {
			if got[name] == 0 {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("paths=%v; missing names %v; status=%+v", idsByName(c.Paths()), names, c.Status())
}

func writesByName(paths []PathInfo) map[string]uint64 {
	out := make(map[string]uint64, len(paths))
	for _, p := range paths {
		out[p.Spec.Opts["name"]] = p.Writes
	}
	return out
}

func qualityByName(t testing.TB, paths []PathInfo, name string) PathQuality {
	t.Helper()
	for _, path := range paths {
		if path.Spec.Opts["name"] == name {
			return path.Quality
		}
	}
	t.Fatalf("path quality for %q not found in %+v", name, paths)
	return PathQuality{}
}

func firstDataDispatchesByName(paths []PathInfo) map[string]uint64 {
	out := make(map[string]uint64, len(paths))
	for _, p := range paths {
		out[p.Spec.Opts["name"]] = p.FirstDataDispatches
	}
	return out
}

func idsByName(paths []PathInfo) map[string]uint32 {
	out := make(map[string]uint32, len(paths))
	for _, p := range paths {
		out[p.Spec.Opts["name"]] = p.ID
	}
	return out
}

func assertPeakDemandEvidence(t *testing.T, conn Conn, rx bool) {
	t.Helper()
	backed, ok := conn.(*engineBackedConn)
	if !ok || backed.peak == nil {
		t.Fatalf("connection %T has no peak-transfer controller", conn)
	}
	backed.peak.mu.Lock()
	state := backed.peak.tx
	if rx {
		state = backed.peak.rx
	}
	backed.peak.mu.Unlock()
	if state.normalBytes < defaultPeakMinBytes || state.normalPeakBps <= 0 {
		t.Fatalf("rx=%t lacks demand-backed normal capacity evidence: bytes=%d bps=%f state=%+v",
			rx, state.normalBytes, state.normalPeakBps, state)
	}
}

type peakTransferTestDiagnostic struct {
	DeliveryTarget       proto.TargetID
	DeliverySelector     proto.TargetID
	DeliveryGeneration   uint64
	DeliveryEpoch        uint64
	DeliveryAttributable bool
	DeliveryAcked        uint64
	DeliveryDemand       uint64
	HealthyPeak          bool
	OnPeak               bool
	ActivePeakTarget     proto.TargetID
	NormalPeakBPS        float64
	NormalBytes          uint64
	PolicyRetryAfter     time.Time
	LastPolicyError      string
	SaturatedSince       time.Time
	DemandSuppressUntil  time.Time
	PolicyUncertain      bool
	Cursor               peakDeliveryCursor
	LastObservation      peakCapacityObservation
}

func peakTransferDiagnostic(conn Conn, rx bool) peakTransferTestDiagnostic {
	backed, ok := conn.(*engineBackedConn)
	if !ok || backed.peak == nil {
		return peakTransferTestDiagnostic{}
	}
	diagnostic := peakTransferTestDiagnostic{}
	var delivery = backed.e.TargetApplicationDelivery(proto.TargetID{})
	if rx {
		delivery = backed.e.PeerTargetDelivery(proto.TargetID{})
	}
	diagnostic.DeliveryTarget = delivery.TargetID
	diagnostic.DeliverySelector = delivery.SelectorID
	diagnostic.DeliveryGeneration = delivery.SelectorGeneration
	diagnostic.DeliveryEpoch = delivery.EvidenceEpoch
	diagnostic.DeliveryAttributable = delivery.Attributable
	diagnostic.DeliveryAcked = delivery.AckedBytes
	diagnostic.DeliveryDemand = delivery.DemandBytes
	backed.peak.mu.Lock()
	state := &backed.peak.tx
	if rx {
		state = &backed.peak.rx
	}
	diagnostic.OnPeak = state.onPeak
	diagnostic.ActivePeakTarget = state.activePeakTarget
	diagnostic.NormalPeakBPS = state.normalPeakBps
	diagnostic.NormalBytes = state.normalBytes
	diagnostic.PolicyRetryAfter = state.policyRetryAfter
	diagnostic.LastPolicyError = state.lastPolicyError
	diagnostic.SaturatedSince = state.saturatedSince
	diagnostic.DemandSuppressUntil = state.demandSuppressUntil
	diagnostic.PolicyUncertain = state.policyOutcomeUncertain
	diagnostic.Cursor = state.cursor
	diagnostic.LastObservation = state.lastObservation
	backed.peak.mu.Unlock()
	_, diagnostic.HealthyPeak = backed.peak.selectHealthyPeakTarget(rx)
	return diagnostic
}
