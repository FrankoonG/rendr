package engine

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

type abnormalReadPath struct {
	transport.PathConn
	mode        string
	cause       error
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	once        sync.Once
}

func (path *abnormalReadPath) MaxFrameSize() int {
	return testPacketFrameSize(path.PathConn)
}

func (path *abnormalReadPath) Read(buffer []byte) (n int, err error) {
	triggered := false
	path.once.Do(func() { triggered = true })
	if !triggered {
		return path.PathConn.Read(buffer)
	}
	path.enteredOnce.Do(func() { close(path.entered) })
	<-path.release
	switch path.mode {
	case "panic":
		panic(path.cause)
	case "goexit":
		runtime.Goexit()
	}
	return 0, errors.New("unreachable abnormal read")
}

type abnormalOwnedReadPath struct {
	*abnormalReadPath
}

func (path *abnormalOwnedReadPath) ReadOwnedFrame() ([]byte, error) {
	buffer := make([]byte, MaxPayload)
	n, err := path.abnormalReadPath.Read(buffer)
	return buffer[:n], err
}

type invalidReadCountPath struct {
	transport.PathConn
	countFor    func(int) int
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	readCalls   atomic.Int32
	closeCalls  atomic.Int32
}

func (path *invalidReadCountPath) MaxFrameSize() int {
	return testPacketFrameSize(path.PathConn)
}

func (path *invalidReadCountPath) Read(buffer []byte) (int, error) {
	path.readCalls.Add(1)
	path.enteredOnce.Do(func() { close(path.entered) })
	<-path.release
	return path.countFor(len(buffer)), nil
}

func (path *invalidReadCountPath) Close() error {
	path.closeCalls.Add(1)
	return path.PathConn.Close()
}

type abnormalOnDeathPath struct {
	transport.PathConn
	mode  string
	cause error
	calls atomic.Int32
}

func (path *abnormalOnDeathPath) MaxFrameSize() int {
	return testPacketFrameSize(path.PathConn)
}

func (path *abnormalOnDeathPath) LeafMobilityClaim() *leafmobility.Claim {
	return testPathMobilityClaim(path.PathConn)
}

func (path *abnormalOnDeathPath) OnDeath(func(transport.DeathCause, error)) {
	path.calls.Add(1)
	switch path.mode {
	case "panic":
		panic(path.cause)
	case "goexit":
		runtime.Goexit()
	}
}

type abnormalClosePath struct {
	transport.PathConn
	mode        string
	cause       error
	entered     chan struct{}
	enteredOnce sync.Once
	closeOnce   sync.Once
}

func (path *abnormalClosePath) MaxFrameSize() int {
	return testPacketFrameSize(path.PathConn)
}

func (path *abnormalClosePath) Read(buffer []byte) (int, error) {
	path.enteredOnce.Do(func() { close(path.entered) })
	return path.PathConn.Read(buffer)
}

func (path *abnormalClosePath) Close() error {
	triggered := false
	path.closeOnce.Do(func() { triggered = true })
	if !triggered {
		return path.PathConn.Close()
	}
	switch path.mode {
	case "panic":
		panic(path.cause)
	case "goexit":
		runtime.Goexit()
	}
	return errors.New("unreachable abnormal close")
}

func TestPathReaderAbnormalExitRetiresGenerationAndFailsOver(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		owned     bool
		operation string
	}{
		{name: "PathConn panic", mode: "panic", operation: "PathConn.Read"},
		{name: "PathConn Goexit", mode: "goexit", operation: "PathConn.Read"},
		{name: "owned panic", mode: "panic", owned: true, operation: "OwnedFrameReader.ReadOwnedFrame"},
		{name: "owned Goexit", mode: "goexit", owned: true, operation: "OwnedFrameReader.ReadOwnedFrame"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
			e.SetPacketMode()
			t.Cleanup(func() { closeEngineWithin(t, e) })
			ids := configureLeafSelectorRuntime(t, e, "reader-a", "reader-b")

			aBase, aPeer := newMemoryPathPair()
			bBase, bPeer := newMemoryPathPair()
			t.Cleanup(func() {
				_ = aBase.Close()
				_ = aPeer.Close()
				_ = bBase.Close()
				_ = bPeer.Close()
			})
			cause := errors.New("abnormal path reader")
			abnormal := &abnormalReadPath{
				PathConn: aBase, mode: test.mode, cause: cause,
				entered: make(chan struct{}), release: make(chan struct{}),
			}
			var first transport.PathConn = abnormal
			if test.owned {
				first = &abnormalOwnedReadPath{abnormalReadPath: abnormal}
			}
			firstID := attachFixturePath(
				t, e, first,
				transport.PathSpec{Transport: "abnormal-reader", Address: test.name},
				ids["reader-a"],
			)
			secondID := attachFixturePath(
				t, e, bBase,
				transport.PathSpec{Transport: "memory", Address: "reader-survivor"},
				ids["reader-b"],
			)
			e.pathsMu.RLock()
			firstSlot := e.paths[firstID]
			e.pathsMu.RUnlock()
			if firstSlot == nil {
				t.Fatal("abnormal reader path is missing")
			}
			death := observeDispatchPathDeath(t, e, firstID)
			select {
			case <-abnormal.entered:
			case <-time.After(time.Second):
				t.Fatal("reader did not enter external callback")
			}
			close(abnormal.release)

			event := awaitControlPathDeath(t, death)
			if test.mode == "panic" {
				assertDispatchCallbackPanic(t, event.Err, cause, test.operation)
			} else {
				assertDispatchCallbackGoexit(t, event.Err, test.operation)
			}
			select {
			case <-firstSlot.doneR:
			case <-time.After(time.Second):
				t.Fatal("abnormal reader did not close doneR")
			}
			eventuallyEngine(t, time.Second, func() bool {
				return e.ActivePath() == secondID
			})
			e.pathsMu.RLock()
			_, firstAttached := e.paths[firstID]
			_, secondAttached := e.paths[secondID]
			e.pathsMu.RUnlock()
			if firstAttached || !secondAttached {
				t.Fatalf("post-reader topology first/second=%t/%t want false/true", firstAttached, secondAttached)
			}
			if err := e.CloseErr(); err != nil {
				t.Fatalf("reader failover closed application session: %v", err)
			}
		})
	}
}

func TestReadFirstFrameAbnormalExitPublishesTypedResult(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			local, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
			cause := errors.New("abnormal first-frame read")
			path := &abnormalReadPath{
				PathConn: local, mode: mode, cause: cause,
				entered: make(chan struct{}), release: make(chan struct{}),
			}
			result := make(chan error, 1)
			go func() {
				_, _, err := ReadFirstFrame(path)
				result <- err
			}()
			select {
			case <-path.entered:
			case <-time.After(time.Second):
				t.Fatal("first-frame read did not enter callback")
			}
			close(path.release)
			select {
			case err := <-result:
				if mode == "panic" {
					assertDispatchCallbackPanic(t, err, cause, "PathConn.Read")
				} else {
					assertDispatchCallbackGoexit(t, err, "PathConn.Read")
				}
			case <-time.After(time.Second):
				t.Fatal("first-frame abnormal read did not publish result")
			}
		})
	}
}

func TestReadFirstFrameRejectsInvalidPathReadCounts(t *testing.T) {
	for _, test := range []struct {
		name     string
		countFor func(int) int
	}{
		{name: "negative", countFor: func(int) int { return -1 }},
		{name: "larger than buffer", countFor: func(size int) int { return size + 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			local, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
			release := make(chan struct{})
			close(release)
			path := &invalidReadCountPath{
				PathConn: local,
				countFor: test.countFor,
				entered:  make(chan struct{}),
				release:  release,
			}

			_, _, err := ReadFirstFrame(path)
			var countErr *pathDispatchCallbackReadCountError
			if !errors.As(err, &countErr) || countErr.operation != externalPathReadOperation {
				t.Fatalf("ReadFirstFrame error=%v want typed PathConn.Read count failure", err)
			}
			if countErr.count >= 0 && countErr.count <= countErr.bufferSize {
				t.Fatalf("invalid count evidence=%d/%d unexpectedly in range", countErr.count, countErr.bufferSize)
			}
			if got := path.readCalls.Load(); got != 1 {
				t.Fatalf("PathConn.Read stimulus calls=%d want 1", got)
			}
		})
	}
}

func TestInvalidPathReadCountRetiresExactGenerationAndFailsOver(t *testing.T) {
	for _, test := range []struct {
		name     string
		countFor func(int) int
	}{
		{name: "negative", countFor: func(int) int { return -1 }},
		{name: "larger than buffer", countFor: func(size int) int { return size + 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
			e.SetPacketMode()
			t.Cleanup(func() { closeEngineWithin(t, e) })
			ids := configureLeafSelectorRuntime(t, e, "invalid-reader", "survivor")

			badBase, badPeer := newMemoryPathPair()
			goodBase, goodPeer := newMemoryPathPair()
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseRead := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(func() {
				releaseRead()
				_ = badPeer.Close()
				_ = goodBase.Close()
				_ = goodPeer.Close()
			})
			bad := &invalidReadCountPath{
				PathConn: badBase,
				countFor: test.countFor,
				entered:  make(chan struct{}),
				release:  release,
			}
			badID := attachFixturePath(
				t, e, bad,
				transport.PathSpec{Transport: "invalid-reader", Address: test.name},
				ids["invalid-reader"],
			)
			goodID := attachFixturePath(
				t, e, goodBase,
				transport.PathSpec{Transport: "memory", Address: "survivor"},
				ids["survivor"],
			)
			e.pathsMu.RLock()
			badSlot := e.paths[badID]
			e.pathsMu.RUnlock()
			if badSlot == nil {
				t.Fatal("invalid-read generation is missing before stimulus")
			}
			death := observeDispatchPathDeath(t, e, badID)
			select {
			case <-bad.entered:
			case <-time.After(time.Second):
				t.Fatal("PathConn.Read stimulus did not start")
			}
			releaseRead()

			event := awaitControlPathDeath(t, death)
			var countErr *pathDispatchCallbackReadCountError
			if !errors.As(event.Err, &countErr) || countErr.operation != externalPathReadOperation {
				t.Fatalf("path death error=%v want typed PathConn.Read count failure", event.Err)
			}
			if countErr.count >= 0 && countErr.count <= countErr.bufferSize {
				t.Fatalf("invalid count evidence=%d/%d unexpectedly in range", countErr.count, countErr.bufferSize)
			}
			select {
			case <-badSlot.doneR:
			case <-time.After(time.Second):
				t.Fatal("invalid-read generation reader did not terminate")
			}
			eventuallyEngine(t, time.Second, func() bool {
				e.pathsMu.RLock()
				defer e.pathsMu.RUnlock()
				return e.paths[badID] == nil && e.paths[goodID] != nil && e.activeID == goodID
			})
			eventuallyEngine(t, time.Second, func() bool { return bad.closeCalls.Load() == 1 })
			if got := bad.readCalls.Load(); got != 1 {
				t.Fatalf("PathConn.Read stimulus calls=%d want 1", got)
			}
			if err := e.CloseErr(); err != nil {
				t.Fatalf("invalid path callback closed the application session: %v", err)
			}
		})
	}
}

func TestOnDeathRegistrationAbnormalExitRollsBackStagedPath(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			e.SetPacketMode()
			t.Cleanup(func() { closeEngineWithin(t, e) })
			ids := configureLeafSelectorRuntime(t, e, "registration")
			local, peer, claim := newClaimedPacketFrameLimitPath(widePacketFrameLimit)
			t.Cleanup(func() { _ = peer.Close() })
			cause := errors.New("abnormal OnDeath registration")
			path := &abnormalOnDeathPath{PathConn: local, mode: mode, cause: cause}
			id, err := e.PreparePathBound(
				path,
				transport.PathSpec{Transport: "abnormal-registration", Address: mode},
				fixedPacketCapacityBinding(ids["registration"], widePacketFrameLimit),
			)
			if err != nil {
				t.Fatal(err)
			}
			e.pathsMu.RLock()
			slot := e.pendingPaths[id]
			e.pathsMu.RUnlock()
			if slot == nil {
				t.Fatal("prepared registration path is missing")
			}
			assertBoundTestClaim(t, claim)
			err = e.StagePathAttach(id)
			if mode == "panic" {
				assertDispatchCallbackPanic(t, err, cause, "PathConn.OnDeath")
			} else {
				assertDispatchCallbackGoexit(t, err, "PathConn.OnDeath")
			}
			if got := path.calls.Load(); got != 1 {
				t.Fatalf("OnDeath stimulus calls=%d want 1", got)
			}
			if slot.readerStarted.Load() {
				t.Fatal("failed OnDeath registration published readerStarted")
			}
			eventuallyEngine(t, time.Second, func() bool {
				e.pathsMu.RLock()
				defer e.pathsMu.RUnlock()
				return e.pendingPaths[id] == nil && e.stagedPaths[id] == nil && e.paths[id] == nil
			})
			assertRetiredTestClaim(t, claim)
		})
	}
}

func TestPathCloseAbnormalExitCannotForgeQuiescence(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			e.SetPacketMode()
			ids := configureLeafSelectorRuntime(t, e, "close")
			local, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = peer.Close() })
			cause := errors.New("abnormal PathConn.Close")
			path := &abnormalClosePath{
				PathConn: local, mode: mode, cause: cause, entered: make(chan struct{}),
			}
			_ = attachFixturePath(
				t, e, path,
				transport.PathSpec{Transport: "abnormal-close", Address: mode},
				ids["close"],
			)
			select {
			case <-path.entered:
			case <-time.After(time.Second):
				t.Fatal("reader did not acquire the carrier before Close")
			}

			started := time.Now()
			err := e.Close()
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("Engine.Close blocked for %s", elapsed)
			}
			if mode == "panic" {
				assertDispatchCallbackPanic(t, err, cause, "PathConn.Close")
			} else {
				assertDispatchCallbackGoexit(t, err, "PathConn.Close")
			}
			select {
			case <-e.Closed():
				t.Fatal("abnormal Close forged quiescence while reader still owned the carrier")
			default:
			}
			if err := local.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-e.Closed():
			case <-time.After(time.Second):
				t.Fatal("engine did not quiesce after underlying reader was released")
			}
		})
	}
}
