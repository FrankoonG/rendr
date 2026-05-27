package rendr

import (
	"context"
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
	mode, paths, peak, err := d.compileDialPlan()
	if err != nil {
		t.Fatal(err)
	}
	if mode != ModePrime {
		t.Fatalf("mode=%v want %v", mode, ModePrime)
	}
	if peak {
		t.Fatal("peak=true")
	}
	if len(paths) != 1 || paths[0].Address != "root" {
		t.Fatalf("paths=%+v; root should take precedence over legacy Paths", paths)
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
