package rendr

import (
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type selectorControlPath struct {
	closed    chan struct{}
	closeOnce sync.Once
	data      atomic.Uint64
}

func newSelectorControlPath() *selectorControlPath {
	return &selectorControlPath{closed: make(chan struct{})}
}

func (p *selectorControlPath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}

func (p *selectorControlPath) Write(frame []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	header, err := proto.DecodeHeader(frame)
	if err != nil {
		return 0, err
	}
	if header.Type == proto.FrameData {
		p.data.Add(1)
	}
	return len(frame), nil
}

func (p *selectorControlPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (*selectorControlPath) Quality() transport.PathQuality            { return transport.PathQuality{} }
func (*selectorControlPath) OnDeath(func(transport.DeathCause, error)) {}
func (*selectorControlPath) LocalAddr() string                         { return "local" }
func (*selectorControlPath) RemoteAddr() string                        { return "remote" }

func TestMigrationControllerSelectsNestedBondForStreamAndPacket(t *testing.T) {
	plan, err := compileTargetForDial(Selector("root", []Target{
		Path("A", PathSpec{}),
		Bond("bulk", []Target{
			Path("B", PathSpec{}),
			Path("C", PathSpec{}),
		}),
	}))
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		wrap func(*engine.Engine) MigrationController
	}{
		{
			name: "stream",
			wrap: func(e *engine.Engine) MigrationController {
				return &engineBackedConn{e: e, graph: plan.graph}
			},
		},
		{
			name: "packet",
			wrap: func(e *engine.Engine) MigrationController {
				return &enginePacketConn{e: e, graph: plan.graph}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			if err := e.ConfigureLocalGraph(1, plan.graph.manifest); err != nil {
				t.Fatal(err)
			}
			if err := e.ConfigurePeerGraph(1, plan.graph.manifest); err != nil {
				t.Fatal(err)
			}
			paths := make(map[string]*selectorControlPath, 3)
			for _, name := range []string{"A", "B", "C"} {
				path := newSelectorControlPath()
				paths[name] = path
				targetID := plan.graph.nodesByName[name].id
				if _, err := e.AttachPathBound(
					path,
					transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": name}},
					engine.PathBinding{LocalTXTargetID: targetID, PeerTXTargetID: targetID},
				); err != nil {
					t.Fatalf("attach %s: %v", name, err)
				}
			}
			controller := test.wrap(e)
			observer, ok := controller.(ConnectionObserver)
			if !ok {
				t.Fatalf("controller %T does not expose ConnectionObserver", controller)
			}
			initial := observer.Stats()
			if len(initial.EffectivePaths) != 1 || initial.EffectivePaths[0] != pathIDByTargetName(t, e.Paths(), "A") {
				t.Fatalf("initial selector effective paths=%v, want A", initial.EffectivePaths)
			}
			if err := controller.SelectTarget("root", "bulk"); err != nil {
				t.Fatalf("select nested bond group: %v", err)
			}
			if err := controller.SelectTarget("root", "B"); err == nil {
				t.Fatal("nested leaf B was accepted as an immediate root child")
			}
			wantEffective := []uint32{
				pathIDByTargetName(t, e.Paths(), "B"),
				pathIDByTargetName(t, e.Paths(), "C"),
			}
			slices.Sort(wantEffective)
			if got := observer.Stats().EffectivePaths; !slices.Equal(got, wantEffective) {
				t.Fatalf("selected bond effective paths=%v want=%v", got, wantEffective)
			}
			if _, err := e.SendData([]byte("first")); err != nil {
				t.Fatal(err)
			}
			if _, err := e.SendData([]byte("second")); err != nil {
				t.Fatal(err)
			}
			if got := paths["A"].data.Load(); got != 0 {
				t.Fatalf("unselected path A received %d DATA frames", got)
			}
			if got := paths["B"].data.Load() + paths["C"].data.Load(); got != 2 {
				t.Fatalf("selected bond branch received %d DATA frames, want 2", got)
			}
		})
	}
}

func pathIDByTargetName(t *testing.T, paths []PathInfo, name string) uint32 {
	t.Helper()
	for _, path := range paths {
		if pathSpecName(path.Spec) == name {
			return path.ID
		}
	}
	t.Fatalf("path %q is not attached: %+v", name, paths)
	return 0
}
