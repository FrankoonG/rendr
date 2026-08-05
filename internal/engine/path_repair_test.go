package engine

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

type gatedRepairPath struct {
	*lifecycleHealthyPath
	replacement transport.PathConn
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
}

func TestPathAdmissionCannotEnterLeafDuringNativeRepair(t *testing.T) {
	e, binding := admissionTestEngine(t)
	t.Cleanup(func() { _ = e.Close() })
	replacement := newLifecycleHealthyPath()
	repairable := newGatedRepairPath(replacement, true)
	repairedID, err := e.AttachPathBound(repairable, transport.PathSpec{Transport: "repair-test", Address: "repair"}, binding)
	if err != nil {
		t.Fatal(err)
	}

	repairDone := make(chan error, 1)
	go func() { repairDone <- e.MigratePathLocalAddr(repairedID, "replacement-local") }()
	select {
	case <-repairable.started:
	case <-time.After(time.Second):
		t.Fatal("repair did not enter carrier rebuild")
	}

	candidate := newLifecycleHealthyPath()
	if _, err := e.PreparePathBound(candidate, transport.PathSpec{Transport: "repair-test", Address: "replacement"}, binding); !errors.Is(err, ErrPathAttachInProgress) {
		t.Fatalf("same-leaf admission during repair error=%v, want %v", err, ErrPathAttachInProgress)
	}
	close(repairable.release)
	select {
	case err := <-repairDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("repair did not complete after release")
	}
}

func TestNativeRepairCannotBypassLiveAdmissionBarrier(t *testing.T) {
	e, binding := admissionTestEngine(t)
	t.Cleanup(func() { _ = e.Close() })
	repairable := newGatedRepairPath(newLifecycleHealthyPath(), false)
	id, err := e.PreparePathBound(repairable, transport.PathSpec{Transport: "repair-test", Address: "repair"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.StagePathAttach(id); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivateStagedPath(id, true); err != nil {
		t.Fatal(err)
	}
	if err := e.MigratePathLocalAddr(id, "replacement-local"); !errors.Is(err, ErrPathAttachInProgress) {
		t.Fatalf("repair during live admission error=%v, want %v", err, ErrPathAttachInProgress)
	}
}

func newGatedRepairPath(replacement transport.PathConn, blocked bool) *gatedRepairPath {
	p := &gatedRepairPath{
		lifecycleHealthyPath: newLifecycleHealthyPath(),
		replacement:          replacement,
		started:              make(chan struct{}),
		release:              make(chan struct{}),
	}
	if !blocked {
		close(p.release)
	}
	return p
}

func (p *gatedRepairPath) MigratePathLocalAddr(string) (transport.PathConn, error) {
	p.startOnce.Do(func() { close(p.started) })
	<-p.release
	_ = p.lifecycleHealthyPath.Close()
	return p.replacement, nil
}

func TestRepairedPathIsAdmittedAndRemovable(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	replacement := newLifecycleHealthyPath()
	repairable := newGatedRepairPath(replacement, false)
	repairedID, err := e.AttachPath(repairable, transport.PathSpec{Transport: "repair-test", Address: "repair"})
	if err != nil {
		t.Fatal(err)
	}
	guard := newLifecycleHealthyPath()
	guardID, err := e.AttachPath(guard, transport.PathSpec{Transport: "repair-test", Address: "guard"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.MigratePathLocalAddr(repairedID, "replacement-local"); err != nil {
		t.Fatal(err)
	}
	if err := e.RemovePath(repairedID); err != nil {
		t.Fatalf("remove repaired path: %v", err)
	}
	paths := e.Paths()
	if len(paths) != 1 || paths[0].ID != guardID {
		t.Fatalf("paths after repaired-path removal=%v, want guard %d", paths, guardID)
	}
}

func TestRemovePathLinearizesAfterConcurrentRepair(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	replacement := newLifecycleHealthyPath()
	repairable := newGatedRepairPath(replacement, true)
	repairedID, err := e.AttachPath(repairable, transport.PathSpec{Transport: "repair-test", Address: "repair"})
	if err != nil {
		t.Fatal(err)
	}
	guard := newLifecycleHealthyPath()
	guardID, err := e.AttachPath(guard, transport.PathSpec{Transport: "repair-test", Address: "guard"})
	if err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	repairSlot := e.paths[repairedID]
	e.pathsMu.RUnlock()
	repairDone := make(chan error, 1)
	go func() { repairDone <- e.MigratePathLocalAddr(repairedID, "replacement-local") }()
	select {
	case <-repairable.started:
	case <-time.After(time.Second):
		t.Fatal("repair did not enter carrier rebuild")
	}
	removeDone := make(chan error, 1)
	go func() { removeDone <- e.RemovePath(repairedID) }()
	deadline := time.Now().Add(time.Second)
	for repairSlot.removeWaiters.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if repairSlot.removeWaiters.Load() == 0 {
		t.Fatal("RemovePath did not reach the repair serialization gate")
	}
	select {
	case err := <-removeDone:
		t.Fatalf("RemovePath crossed in-flight repair: %v", err)
	default:
	}
	close(repairable.release)
	select {
	case err := <-repairDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("repair did not complete after release")
	}
	select {
	case err := <-removeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("RemovePath did not revalidate repaired generation")
	}
	paths := e.Paths()
	if len(paths) != 1 || paths[0].ID != guardID {
		t.Fatalf("repair resurrected removed path %d: %v", repairedID, paths)
	}
}
