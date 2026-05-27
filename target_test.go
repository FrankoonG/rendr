package rendr

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestLegacyRootTargetCompilesModes(t *testing.T) {
	paths := []PathSpec{
		{Transport: "tcp", Address: "a"},
		{Transport: "tcp", Address: "b"},
	}
	for _, tt := range []struct {
		name string
		mode Mode
		want Mode
	}{
		{name: "default", mode: 0, want: ModePrime},
		{name: "prime", mode: ModePrime, want: ModePrime},
		{name: "race", mode: ModeRace, want: ModeRace},
		{name: "bond", mode: ModeBond, want: ModeBond},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := compileTargetForDial(legacyRootTarget(tt.mode, paths))
			if err != nil {
				t.Fatal(err)
			}
			if ct.mode != tt.want {
				t.Fatalf("mode=%v want %v", ct.mode, tt.want)
			}
			if len(ct.paths) != len(paths) {
				t.Fatalf("paths=%d want %d", len(ct.paths), len(paths))
			}
		})
	}
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
	if ct.mode != ModePrime {
		t.Fatalf("mode=%v want %v", ct.mode, ModePrime)
	}
	if !ct.peakTransfer {
		t.Fatal("peakTransfer=false")
	}
	if !ct.runtimeNested {
		t.Fatal("runtimeNested=false for child bond")
	}
	if ct.peakMode != ModeBond {
		t.Fatalf("peakMode=%v want %v", ct.peakMode, ModeBond)
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

func TestDialerCompileDialPlanUsesRoot(t *testing.T) {
	d := &Dialer{
		Mode:  ModeBond,
		Paths: []PathSpec{{Transport: "tcp", Address: "legacy"}},
		Root: Selector("root", []Target{
			Path("root-path", PathSpec{Transport: "tcp", Address: "root"}),
		}),
	}
	plan, err := d.compileDialPlan()
	if err != nil {
		t.Fatal(err)
	}
	if plan.mode != ModePrime {
		t.Fatalf("mode=%v want %v", plan.mode, ModePrime)
	}
	if plan.peakTransfer {
		t.Fatal("peak=true")
	}
	if len(plan.paths) != 1 || plan.paths[0].Address != "root" {
		t.Fatalf("paths=%+v; root should take precedence over legacy Paths", plan.paths)
	}
}

func TestDialerRootSelectorDialSmoke(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
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
	client, err := (&Dialer{Root: root}).Dial(ctx)
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

	if len(client.Paths()) != 2 {
		t.Fatalf("client paths=%d want 2", len(client.Paths()))
	}
	if _, err := client.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := server.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ok" {
		t.Fatalf("payload=%q", string(buf))
	}
}

func TestSelectorPeakTransferRuntimePromotesToBond(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
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

	spec := func(name string) PathSpec {
		return PathSpec{Transport: "tcp", Address: ln.Addr().String(), Opts: map[string]string{"name": name}}
	}
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
	client, err := (&Dialer{Root: root}).Dial(ctx)
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
	drainDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, server)
		close(drainDone)
	}()

	chunk := make([]byte, 32<<10)
	for i := 0; i < 32; i++ {
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitForMode(t, client, ModeBond, 3*time.Second)

	before := writesByName(client.Paths())
	for i := 0; i < 24; i++ {
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	after := writesByName(client.Paths())
	if after["B"] <= before["B"] || after["C"] <= before["C"] {
		t.Fatalf("peak bond did not dispatch on both peak paths: before=%v after=%v", before, after)
	}

	waitForMode(t, client, ModePrime, 3*time.Second)
	_ = client.Close()
	select {
	case <-drainDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server drain did not finish")
	}
}

func TestSelectorPeakTransferNormalSelectorUsesQuality(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
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

	spec := func(name string) PathSpec {
		return PathSpec{Transport: "tcp", Address: ln.Addr().String(), Opts: map[string]string{"name": name}}
	}
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
			SaturationFor:   10 * time.Second,
			SaturationRatio: 0.99,
		},
	)
	client, err := (&Dialer{
		Root:       root,
		Hysteresis: 0.05,
		Dwell:      100 * time.Millisecond,
		Cooldown:   100 * time.Millisecond,
	}).Dial(ctx)
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

	ids := idsByName(client.Paths())
	if ids["A"] == 0 || ids["B"] == 0 || ids["C"] == 0 {
		t.Fatalf("idsByName=%v", ids)
	}
	ebc := client.(*engineBackedConn)
	ebc.Engine().SetPathQualityForTest(ids["A"], PathQuality{RTT: 250 * time.Millisecond, At: time.Now()})
	ebc.Engine().SetPathQualityForTest(ids["B"], PathQuality{RTT: 50 * time.Millisecond, At: time.Now()})
	ebc.Engine().SetPathQualityForTest(ids["C"], PathQuality{RTT: 1 * time.Millisecond, At: time.Now()})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if client.(AdminConn).ActivePath() == ids["B"] {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("active path=%d want B=%d; peak C=%d must stay out of normal quality selector",
		client.(AdminConn).ActivePath(), ids["B"], ids["C"])
}

func TestSelectorHotStandbyFailover(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
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

	spec := func(name string) PathSpec {
		return PathSpec{Transport: "tcp", Address: ln.Addr().String(), Opts: map[string]string{"name": name}}
	}
	root := Selector("root", []Target{
		Path("A", spec("A")),
		Path("B", spec("B")),
	})
	client, err := (&Dialer{
		Root:       root,
		Hysteresis: 0.05,
		Dwell:      100 * time.Millisecond,
		Cooldown:   100 * time.Millisecond,
	}).Dial(ctx)
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

	ids := idsByName(client.Paths())
	if ids["A"] == 0 || ids["B"] == 0 {
		t.Fatalf("idsByName=%v", ids)
	}
	ebc := client.(*engineBackedConn)
	ebc.Engine().SetPathQualityForTest(ids["A"], PathQuality{RTT: 30 * time.Millisecond, At: time.Now()})
	ebc.Engine().SetPathQualityForTest(ids["B"], PathQuality{RTT: 50 * time.Millisecond, At: time.Now()})
	if got := client.(AdminConn).ActivePath(); got != ids["A"] {
		t.Fatalf("initial active=%d want A=%d", got, ids["A"])
	}
	if err := ebc.ForceKillPathForTest(ids["A"]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if client.(AdminConn).ActivePath() == ids["B"] {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := client.(AdminConn).ActivePath(); got != ids["B"] {
		t.Fatalf("active after A death=%d want B=%d", got, ids["B"])
	}
	if _, err := client.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ok" {
		t.Fatalf("payload=%q", string(buf))
	}
}

func waitForMode(t *testing.T, c Conn, want Mode, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if m, ok := c.(interface{ Mode() Mode }); ok && m.Mode() == want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	if m, ok := c.(interface{ Mode() Mode }); ok {
		t.Fatalf("mode=%v want %v", m.Mode(), want)
	}
	t.Fatalf("connection does not expose Mode(); want %v", want)
}

func writesByName(paths []PathInfo) map[string]uint64 {
	out := make(map[string]uint64, len(paths))
	for _, p := range paths {
		out[p.Spec.Opts["name"]] = p.Writes
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
