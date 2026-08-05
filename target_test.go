package rendr

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestRootTargetConstructorsCompileModes(t *testing.T) {
	paths := []PathSpec{
		{Transport: "tcp", Address: "a"},
		{Transport: "tcp", Address: "b"},
	}
	for _, tt := range []struct {
		name string
		mode Mode
		want Mode
	}{
		{name: "selector", mode: ModeSelector, want: ModeSelector},
		{name: "race", mode: ModeRace, want: ModeRace},
		{name: "bond", mode: ModeBond, want: ModeBond},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := testRoot(map[Mode]TargetKind{ModeSelector: TargetKindSelector, ModeRace: TargetKindRace, ModeBond: TargetKindBond}[tt.mode], paths)
			ct, err := compileTargetForDial(root)
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
	if ct.mode != ModeSelector {
		t.Fatalf("mode=%v want %v", ct.mode, ModeSelector)
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
	if plan.mode != ModeSelector {
		t.Fatalf("mode=%v want %v", plan.mode, ModeSelector)
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

	waitForMode(t, client, ModeSelector, 3*time.Second)
	_ = client.Close()
	select {
	case <-drainDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server drain did not finish")
	}
}

func TestSelectorPeakTransferNormalSelectorUsesQuality(t *testing.T) {
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

	ids := idsByName(client.Paths())
	if ids["A"] == 0 || ids["B"] == 0 || ids["C"] == 0 {
		t.Fatalf("idsByName=%v", ids)
	}
	for name, quality := range map[string]PathQuality{
		"A": {RTT: 250 * time.Millisecond, At: time.Now()},
		"B": {RTT: 50 * time.Millisecond, At: time.Now()},
		"C": {RTT: 1 * time.Millisecond, At: time.Now()},
	} {
		if err := controlled.SetQuality(name, quality); err != nil {
			t.Fatal(err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if client.(testConnectionControl).ActivePath() == ids["B"] {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("active path=%d want B=%d; peak C=%d must stay out of normal quality selector",
		client.(testConnectionControl).ActivePath(), ids["B"], ids["C"])
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

	ids := idsByName(client.Paths())
	for name, quality := range map[string]PathQuality{
		"A": {RTT: 150 * time.Millisecond, At: time.Now()},
		"B": {RTT: 140 * time.Millisecond, At: time.Now()},
		"C": {RTT: 80 * time.Millisecond, At: time.Now()},
		"D": {RTT: 1 * time.Millisecond, At: time.Now()},
	} {
		if err := controlled.SetQuality(name, quality); err != nil {
			t.Fatal(err)
		}
	}

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
	if err := controlled.Fail("C"); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		got := client.(testConnectionControl).ActivePath()
		if got == ids["A"] || got == ids["B"] {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("active after C death=%d; wanted A or B, not peak D=%d",
		client.(testConnectionControl).ActivePath(), ids["D"])
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
	go io.Copy(io.Discard, server)

	ids := idsByName(client.Paths())
	if err := controlled.SetQuality("C", PathQuality{
		RTT:    100 * time.Millisecond,
		Jitter: 250 * time.Millisecond,
		LossPP: 500,
		At:     time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 32<<10)
	for i := 0; i < 48; i++ {
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	if got := client.(interface{ Mode() Mode }).Mode(); got != ModeSelector {
		t.Fatalf("mode=%v want selector; bad peak quality should block promotion", got)
	}
	if got := client.(testConnectionControl).ActivePath(); got == ids["C"] {
		t.Fatalf("active path promoted to bad peak C=%d", ids["C"])
	}
}

func TestSelectorPeakTransferStaleSpeedEvidence(t *testing.T) {
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
			Path("A", spec("A")),
			Path("C", spec("C")),
		},
		PeakTransfer{
			Targets:         []string{"C"},
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
	go io.Copy(io.Discard, server)

	ids := idsByName(client.Paths())
	if err := controlled.SetQuality("C", PathQuality{
		RTT: 10 * time.Millisecond,
		At:  time.Now().Add(-10 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 32<<10)
	for i := 0; i < 48; i++ {
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	if got := client.(interface{ Mode() Mode }).Mode(); got != ModeSelector {
		t.Fatalf("mode=%v want selector; stale peak evidence should block promotion", got)
	}
	if got := client.(testConnectionControl).ActivePath(); got == ids["C"] {
		t.Fatalf("active path promoted using stale peak evidence C=%d", ids["C"])
	}
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

	spec := func(name string) PathSpec {
		return PathSpec{Transport: "tcp", Address: ln.Addr().String(), Opts: map[string]string{"name": name}}
	}
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
			ProbeBudget:     64 << 10,
		},
	)
	client, err := (&sessionDialer{Root: root, ProbeInterval: 30 * time.Second}).Dial(ctx)
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
	go io.Copy(io.Discard, server)

	chunk := make([]byte, 32<<10)
	for i := 0; i < 32; i++ {
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	ids := idsByName(client.Paths())
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if client.(testConnectionControl).ActivePath() == ids["P1"] {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := client.(testConnectionControl).ActivePath(); got != ids["P1"] {
		t.Fatalf("active after peak promotion=%d want P1", got)
	}

	before := writesByName(client.Paths())
	for i := 0; i < 16; i++ {
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	after := writesByName(client.Paths())
	if after["P1"] <= before["P1"] {
		t.Fatalf("selected peak P1 did not receive writes: before=%v after=%v", before, after)
	}
	if after["P2"] != before["P2"] || after["P3"] != before["P3"] {
		t.Fatalf("unselected peak candidates received writes: before=%v after=%v", before, after)
	}
}

func TestSelectorPeakTransferSlowPeakRevertsAndSuppresses(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
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

	spec := func(name, transport string) PathSpec {
		return PathSpec{Transport: transport, Address: ln.Addr().String(), Opts: map[string]string{"name": name}}
	}
	root := Selector("root",
		[]Target{
			Path("A", spec("A", "tcp")),
			Path("B", spec("B", "slow-tcp")),
		},
		PeakTransfer{
			Targets:         []string{"B"},
			SaturationFor:   200 * time.Millisecond,
			ReturnFor:       200 * time.Millisecond,
			SaturationRatio: 0.5,
			ReturnRatio:     0.2,
		},
	)
	d := &sessionDialer{Root: root, ProbeInterval: 30 * time.Second}
	if err := d.AddStreamPathFactory("slow-tcp", func(ctx context.Context, addr string) (net.Conn, error) {
		var nd net.Dialer
		c, err := nd.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return &slowWriteConn{Conn: c, delay: 30 * time.Millisecond}, nil
	}); err != nil {
		t.Fatal(err)
	}
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
	go io.Copy(io.Discard, server)

	ids := idsByName(client.Paths())
	if ids["A"] == 0 || ids["B"] == 0 {
		t.Fatalf("idsByName=%v", ids)
	}

	chunk := make([]byte, 32<<10)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && client.(testConnectionControl).ActivePath() != ids["B"] {
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := client.(testConnectionControl).ActivePath(); got != ids["B"] {
		t.Fatalf("active path=%d want B=%d", got, ids["B"])
	}

	for i := 0; i < 48; i++ {
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	waitForActivePath(t, client, ids["A"], 3*time.Second)

	deadline = time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
		if got := client.(testConnectionControl).ActivePath(); got != ids["A"] {
			t.Fatalf("active path=%d want A=%d while slow peak is suppressed", got, ids["A"])
		}
	}
}

func TestSelectorPeakTransferRxPromotesPeerSenderOnly(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
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
			Path("B", spec("B")),
		},
		PeakTransfer{
			Targets:         []string{"B"},
			SaturationFor:   200 * time.Millisecond,
			ReturnFor:       200 * time.Millisecond,
			SaturationRatio: 0.5,
			ReturnRatio:     0.2,
		},
	)
	client, err := (&sessionDialer{Root: root, ProbeInterval: 30 * time.Second}).Dial(ctx)
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

	waitForPathNames(t, server, []string{"A", "B"}, 3*time.Second)
	serverIDs := idsByName(server.Paths())
	clientIDs := idsByName(client.Paths())
	if serverIDs["A"] == 0 || serverIDs["B"] == 0 || clientIDs["A"] == 0 || clientIDs["B"] == 0 {
		t.Fatalf("serverIDs=%v clientIDs=%v", serverIDs, clientIDs)
	}

	go func() {
		_, _ = io.Copy(io.Discard, client)
	}()

	chunk := make([]byte, 32<<10)
	deadline := time.Now().Add(5 * time.Second)
	serverObserver := server.(ConnectionObserver)
	for time.Now().Before(deadline) && serverObserver.ActivePath() != serverIDs["B"] {
		if _, err := server.Write(chunk); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := serverObserver.ActivePath(); got != serverIDs["B"] {
		t.Fatalf("server tx active path=%d want B=%d", got, serverIDs["B"])
	}
	if got := client.(testConnectionControl).ActivePath(); got != clientIDs["A"] {
		t.Fatalf("client tx active path=%d want A=%d; rx policy must not move local tx", got, clientIDs["A"])
	}
	for i := 0; i < 32; i++ {
		if _, err := server.Write(chunk); err != nil {
			t.Fatal(err)
		}
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
	t.Fatalf("paths=%v; missing names %v", idsByName(c.Paths()), names)
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

type slowWriteConn struct {
	net.Conn
	delay time.Duration
}

func (c *slowWriteConn) Write(p []byte) (int, error) {
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	return c.Conn.Write(p)
}
