//go:build linux && amd64 && rendr_experimental_tcprepair

package tcp

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

type fakeRepairNamespaceOps struct {
	mu sync.Mutex

	targetFD   int
	originalFD int
	currentFD  int
	digests    map[int]leafmobility.ContextDigest
	setErrors  map[int]error
	sets       []int
	closed     []int
}

func newFakeRepairNamespaceOps() *fakeRepairNamespaceOps {
	expected := leafmobility.ContextDigest{1}
	return &fakeRepairNamespaceOps{
		targetFD: 20, originalFD: 10, currentFD: 10,
		digests:   map[int]leafmobility.ContextDigest{10: {2}, 20: expected},
		setErrors: make(map[int]error),
	}
}

func (ops *fakeRepairNamespaceOps) socketNamespaceFD(*net.TCPConn) (int, error) {
	return ops.targetFD, nil
}

func (ops *fakeRepairNamespaceOps) openCurrentNamespace() (int, error) {
	return ops.originalFD, nil
}

func (ops *fakeRepairNamespaceOps) sameNamespace(left, right int) (bool, error) {
	return left == right, nil
}

func (ops *fakeRepairNamespaceOps) setNamespace(fd int) error {
	ops.mu.Lock()
	defer ops.mu.Unlock()
	ops.sets = append(ops.sets, fd)
	if err := ops.setErrors[fd]; err != nil {
		return err
	}
	ops.currentFD = fd
	return nil
}

func (ops *fakeRepairNamespaceOps) currentContextDigest() (leafmobility.ContextDigest, error) {
	ops.mu.Lock()
	defer ops.mu.Unlock()
	return ops.digests[ops.currentFD], nil
}

func (ops *fakeRepairNamespaceOps) closeFD(fd int) error {
	ops.mu.Lock()
	ops.closed = append(ops.closed, fd)
	ops.mu.Unlock()
	return nil
}

func (ops *fakeRepairNamespaceOps) snapshot() (current int, sets, closed []int) {
	ops.mu.Lock()
	defer ops.mu.Unlock()
	return ops.currentFD, append([]int(nil), ops.sets...), append([]int(nil), ops.closed...)
}

func TestRepairNamespaceExecutorPinsTargetAndRestoresWorker(t *testing.T) {
	ops := newFakeRepairNamespaceOps()
	expected := ops.digests[ops.targetFD]
	executor, err := newRepairNamespaceExecutorWithOps(context.Background(), nil, expected, ops)
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}

	for call := 0; call < 3; call++ {
		if err := executor.Do(context.Background(), func(context.Context) error {
			current, _, _ := ops.snapshot()
			if current != ops.targetFD {
				return errors.New("operation ran outside target namespace")
			}
			return nil
		}); err != nil {
			t.Fatalf("Do(%d): %v", call, err)
		}
	}
	if err := executor.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := executor.Close(context.Background()); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
	current, sets, closed := ops.snapshot()
	if current != ops.originalFD || !reflect.DeepEqual(sets, []int{ops.targetFD, ops.originalFD}) {
		t.Fatalf("namespace state current=%d sets=%v", current, sets)
	}
	if !reflect.DeepEqual(closed, []int{ops.targetFD, ops.originalFD}) {
		t.Fatalf("closed fds=%v", closed)
	}
	if err := executor.Do(context.Background(), func(context.Context) error { return nil }); !errors.Is(err, errRepairExecutorClosed) {
		t.Fatalf("Do after Close = %v, want closed", err)
	}
}

func TestRepairSourceNamespaceMustMatchPreflightThread(t *testing.T) {
	t.Run("same", func(t *testing.T) {
		ops := newFakeRepairNamespaceOps()
		ops.targetFD = ops.originalFD
		if err := repairSourceMatchesCurrentNamespaceWithOps(nil, ops); err != nil {
			t.Fatalf("same namespace: %v", err)
		}
		_, _, closed := ops.snapshot()
		if !reflect.DeepEqual(closed, []int{ops.originalFD, ops.originalFD}) {
			t.Fatalf("closed fds=%v", closed)
		}
	})

	t.Run("different", func(t *testing.T) {
		ops := newFakeRepairNamespaceOps()
		if err := repairSourceMatchesCurrentNamespaceWithOps(nil, ops); !errors.Is(err, errRepairExecutorContext) {
			t.Fatalf("different namespace error=%v", err)
		}
	})
}

func TestRepairNamespaceExecutorRejectsContextMismatchBeforeWork(t *testing.T) {
	ops := newFakeRepairNamespaceOps()
	wrong := leafmobility.ContextDigest{99}
	executor, err := newRepairNamespaceExecutorWithOps(context.Background(), nil, wrong, ops)
	if executor != nil || !errors.Is(err, errRepairExecutorContext) {
		t.Fatalf("new executor = (%v, %v), want context failure", executor, err)
	}
	current, sets, closed := ops.snapshot()
	if current != ops.originalFD || !reflect.DeepEqual(sets, []int{ops.targetFD, ops.originalFD}) ||
		!reflect.DeepEqual(closed, []int{ops.targetFD, ops.originalFD}) {
		t.Fatalf("failed initialization cleanup current=%d sets=%v closed=%v", current, sets, closed)
	}
}

func TestRepairNamespaceExecutorContainsPanicAndRemainsUsable(t *testing.T) {
	ops := newFakeRepairNamespaceOps()
	executor, err := newRepairNamespaceExecutorWithOps(context.Background(), nil, ops.digests[ops.targetFD], ops)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close(context.Background())

	if err := executor.Do(context.Background(), func(context.Context) error { panic("injected") }); !errors.Is(err, errRepairExecutorPanic) {
		t.Fatalf("panic result = %v", err)
	}
	if err := executor.Do(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("executor unusable after panic: %v", err)
	}
}

func TestRepairNamespaceExecutorDoesNotStartCanceledWork(t *testing.T) {
	ops := newFakeRepairNamespaceOps()
	executor, err := newRepairNamespaceExecutorWithOps(context.Background(), nil, ops.digests[ops.targetFD], ops)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if err := executor.Do(ctx, func(context.Context) error {
		called = true
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Do = %v", err)
	}
	if called {
		t.Fatal("canceled operation was dispatched")
	}
}

func TestRepairNamespaceExecutorWaitsForAcceptedCanceledOperation(t *testing.T) {
	ops := newFakeRepairNamespaceOps()
	executor, err := newRepairNamespaceExecutorWithOps(context.Background(), nil, ops.digests[ops.targetFD], ops)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- executor.Do(ctx, func(context.Context) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		t.Fatalf("Do returned before accepted operation completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("accepted operation result: %v", err)
	}
}

func TestRepairNamespaceExecutorRestoreFailureTerminatesClosed(t *testing.T) {
	restoreFailure := errors.New("restore namespace failed")
	ops := newFakeRepairNamespaceOps()
	ops.setErrors[ops.originalFD] = restoreFailure
	executor, err := newRepairNamespaceExecutorWithOps(context.Background(), nil, ops.digests[ops.targetFD], ops)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Close(context.Background()); !errors.Is(err, restoreFailure) {
		t.Fatalf("Close = %v, want restore failure", err)
	}
	if !executor.Closed() {
		t.Fatal("executor did not prove worker termination after restore failure")
	}
	if err := executor.Do(context.Background(), func(context.Context) error { return nil }); !errors.Is(err, errRepairExecutorClosed) {
		t.Fatalf("Do after failed restore = %v, want closed", err)
	}
}
