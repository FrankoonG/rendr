package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

type closeQualityPath struct {
	transport.PathConn
	engine *Engine

	started        chan struct{}
	cancelObserved chan struct{}
	lockAcquired   chan struct{}
	releaseCleanup chan struct{}
	cleanupDone    chan struct{}
	startOnce      sync.Once
	cancelOnce     sync.Once
	lockOnce       sync.Once
	doneOnce       sync.Once
}

func (p *closeQualityPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	p.startOnce.Do(func() { close(p.started) })
	<-ctx.Done()
	p.cancelOnce.Do(func() { close(p.cancelObserved) })
	p.engine.pathsMu.Lock()
	p.lockOnce.Do(func() { close(p.lockAcquired) })
	p.engine.pathsMu.Unlock()
	<-p.releaseCleanup
	p.doneOnce.Do(func() { close(p.cleanupDone) })
	return transport.PathQuality{}, ctx.Err()
}

func testCloseWaitsForQualityObserverCleanup(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	ids := configureLeafSelectorRuntime(t, e, "quality-close")
	base, peer := newMemoryPathPair()
	defer peer.Close()
	path := &closeQualityPath{
		PathConn: base,
		engine:   e,
		started:  make(chan struct{}), cancelObserved: make(chan struct{}),
		lockAcquired: make(chan struct{}), releaseCleanup: make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	id, err := e.AttachPathBound(path, transport.PathSpec{Transport: "quality-close"}, PathBinding{
		LocalTXTargetID: ids["quality-close"], PeerTXTargetID: ids["quality-close"],
	})
	if err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	slot := e.paths[id]
	e.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("missing quality-observed path")
	}
	slot.requestQualityObservation()
	select {
	case <-path.started:
	case <-time.After(time.Second):
		t.Fatal("quality observer did not enter QualityContext")
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- e.Close() }()
	select {
	case <-path.cancelObserved:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the quality observer")
	}
	select {
	case <-path.lockAcquired:
	case <-time.After(100 * time.Millisecond):
		close(path.releaseCleanup)
		t.Fatal("quality observer cleanup could not acquire pathsMu after cancellation")
	}
	select {
	case err := <-closeResult:
		close(path.releaseCleanup)
		t.Fatalf("Close returned before quality observer cleanup: %v", err)
	case <-e.Closed():
		close(path.releaseCleanup)
		t.Fatal("Closed was published before quality observer cleanup")
	case <-time.After(20 * time.Millisecond):
	}

	close(path.releaseCleanup)
	select {
	case <-path.cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("quality observer cleanup did not finish")
	}
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("Close after quality observer cleanup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not return after quality observer cleanup")
	}
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("Closed did not publish after quality observer cleanup")
	}
}
