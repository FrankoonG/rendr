//go:build linux && amd64

package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/internal/platform"
	"golang.org/x/sys/unix"
)

var (
	errRepairExecutorClosed  = errors.New("tcp: repair namespace executor is closed")
	errRepairExecutorContext = errors.New("tcp: repair namespace execution context changed")
	errRepairExecutorPanic   = errors.New("tcp: repair namespace operation panicked")
)

type repairNamespaceRequest struct {
	ctx    context.Context
	run    func(context.Context) error
	stop   bool
	result chan error
}

// repairNamespaceExecutor serializes all namespace-sensitive work for one
// attempt on one locked OS thread. callMu prevents a Close/Do send race from
// stranding a request after the worker has exited.
type repairNamespaceExecutor struct {
	requests chan repairNamespaceRequest
	done     chan struct{}

	callMu   sync.Mutex
	closed   bool
	closeErr error
}

type repairNamespaceOps interface {
	socketNamespaceFD(*net.TCPConn) (int, error)
	openCurrentNamespace() (int, error)
	sameNamespace(int, int) (bool, error)
	setNamespace(int) error
	currentContextDigest() (leafmobility.ContextDigest, error)
	closeFD(int) error
}

type systemRepairNamespaceOps struct{}

func (systemRepairNamespaceOps) socketNamespaceFD(conn *net.TCPConn) (int, error) {
	if conn == nil {
		return -1, errors.New("tcp: nil repair source")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("tcp: access repair source fd: %w", err)
	}
	namespaceFD := -1
	var ioctlErr error
	controlErr := raw.Control(func(fd uintptr) {
		result, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(unix.SIOCGSKNS), 0)
		if errno != 0 {
			ioctlErr = errno
			return
		}
		namespaceFD = int(result)
	})
	if err := errors.Join(controlErr, ioctlErr); err != nil {
		return -1, fmt.Errorf("tcp: get source network namespace: %w", err)
	}
	if namespaceFD < 0 {
		return -1, errors.New("tcp: source network namespace fd is invalid")
	}
	return namespaceFD, nil
}

func (systemRepairNamespaceOps) openCurrentNamespace() (int, error) {
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("tcp: open worker network namespace: %w", err)
	}
	return fd, nil
}

func (systemRepairNamespaceOps) sameNamespace(left, right int) (bool, error) {
	var leftState, rightState unix.Stat_t
	if err := unix.Fstat(left, &leftState); err != nil {
		return false, fmt.Errorf("tcp: stat source network namespace: %w", err)
	}
	if err := unix.Fstat(right, &rightState); err != nil {
		return false, fmt.Errorf("tcp: stat worker network namespace: %w", err)
	}
	return leftState.Dev == rightState.Dev && leftState.Ino == rightState.Ino, nil
}

func (systemRepairNamespaceOps) setNamespace(fd int) error {
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("tcp: enter repair network namespace: %w", err)
	}
	return nil
}

func (systemRepairNamespaceOps) currentContextDigest() (leafmobility.ContextDigest, error) {
	digest, err := platform.CurrentRuntimeContextDigest()
	return leafmobility.ContextDigest(digest), err
}

func (systemRepairNamespaceOps) closeFD(fd int) error {
	if fd < 0 {
		return nil
	}
	return unix.Close(fd)
}

func newRepairNamespaceExecutor(
	ctx context.Context,
	conn *net.TCPConn,
	expected leafmobility.ContextDigest,
) (*repairNamespaceExecutor, error) {
	return newRepairNamespaceExecutorWithOps(ctx, conn, expected, systemRepairNamespaceOps{})
}

func repairSourceMatchesCurrentNamespace(conn *net.TCPConn) error {
	return repairSourceMatchesCurrentNamespaceWithOps(conn, systemRepairNamespaceOps{})
}

func repairSourceMatchesCurrentNamespaceWithOps(conn *net.TCPConn, ops repairNamespaceOps) error {
	targetFD, err := ops.socketNamespaceFD(conn)
	if err != nil {
		return err
	}
	defer ops.closeFD(targetFD)
	currentFD, err := ops.openCurrentNamespace()
	if err != nil {
		return err
	}
	defer ops.closeFD(currentFD)
	same, err := ops.sameNamespace(targetFD, currentFD)
	if err != nil {
		return err
	}
	if !same {
		return fmt.Errorf("%w: source socket is outside the preflight network namespace", errRepairExecutorContext)
	}
	return nil
}

func newRepairNamespaceExecutorWithOps(
	ctx context.Context,
	conn *net.TCPConn,
	expected leafmobility.ContextDigest,
	ops repairNamespaceOps,
) (*repairNamespaceExecutor, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if expected == (leafmobility.ContextDigest{}) || ops == nil {
		return nil, errRepairExecutorContext
	}
	targetFD, err := ops.socketNamespaceFD(conn)
	if err != nil {
		return nil, err
	}
	executor := &repairNamespaceExecutor{
		requests: make(chan repairNamespaceRequest),
		done:     make(chan struct{}),
	}
	ready := make(chan error, 1)
	go executor.loop(targetFD, expected, ops, ready)
	select {
	case err := <-ready:
		if err != nil {
			<-executor.done
			return nil, err
		}
		return executor, nil
	case <-ctx.Done():
		// Initialization is finite and owns targetFD. Wait for it before
		// requesting shutdown so no namespace fd or locked thread is orphaned.
		err := <-ready
		if err == nil {
			_ = executor.Close(context.Background())
		} else {
			<-executor.done
		}
		return nil, context.Cause(ctx)
	}
}

func (executor *repairNamespaceExecutor) Do(ctx context.Context, run func(context.Context) error) error {
	if executor == nil || run == nil {
		return errRepairExecutorClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	executor.callMu.Lock()
	defer executor.callMu.Unlock()
	if executor.closed {
		return errRepairExecutorClosed
	}
	request := repairNamespaceRequest{ctx: ctx, run: run, result: make(chan error, 1)}
	select {
	case executor.requests <- request:
	case <-executor.done:
		executor.closed = true
		return errRepairExecutorClosed
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	// Once accepted, the caller waits for the operation to finish even if ctx
	// expires. Returning early would allow a destructive syscall to race a
	// subsequent rollback on the same attempt.
	return <-request.result
}

func (executor *repairNamespaceExecutor) Close(ctx context.Context) error {
	if executor == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	executor.callMu.Lock()
	defer executor.callMu.Unlock()
	if executor.closed {
		return executor.closeErr
	}
	request := repairNamespaceRequest{stop: true, result: make(chan error, 1)}
	select {
	case executor.requests <- request:
	case <-executor.done:
		executor.closed = true
		return executor.closeErr
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	executor.closeErr = <-request.result
	executor.closed = true
	<-executor.done
	return executor.closeErr
}

func (executor *repairNamespaceExecutor) loop(
	targetFD int,
	expected leafmobility.ContextDigest,
	ops repairNamespaceOps,
	ready chan<- error,
) {
	runtime.LockOSThread()
	restoreRequired := false
	restoreSucceeded := false
	originalFD := -1
	defer func() {
		_ = ops.closeFD(targetFD)
		_ = ops.closeFD(originalFD)
		close(executor.done)
		// A thread whose namespace could not be restored must die with this
		// goroutine. Unlocking would return contaminated process state to Go.
		if !restoreRequired || restoreSucceeded {
			runtime.UnlockOSThread()
		}
	}()

	var initErr error
	originalFD, initErr = ops.openCurrentNamespace()
	if initErr == nil {
		var same bool
		same, initErr = ops.sameNamespace(targetFD, originalFD)
		if initErr == nil && !same {
			if initErr = ops.setNamespace(targetFD); initErr == nil {
				restoreRequired = true
			}
		}
	}
	if initErr == nil {
		initErr = verifyRepairExecutionContext(expected, ops)
	}
	ready <- initErr
	if initErr != nil {
		if restoreRequired {
			restoreSucceeded = ops.setNamespace(originalFD) == nil
		}
		return
	}

	for request := range executor.requests {
		if request.stop {
			if restoreRequired {
				restoreErr := ops.setNamespace(originalFD)
				restoreSucceeded = restoreErr == nil
				request.result <- restoreErr
			} else {
				request.result <- nil
			}
			return
		}
		err := verifyRepairExecutionContext(expected, ops)
		if err == nil {
			err = invokeRepairNamespaceOperation(request.ctx, request.run)
		}
		if afterErr := verifyRepairExecutionContext(expected, ops); afterErr != nil {
			err = errors.Join(err, afterErr)
		}
		request.result <- err
	}
}

func verifyRepairExecutionContext(expected leafmobility.ContextDigest, ops repairNamespaceOps) error {
	current, err := ops.currentContextDigest()
	if err != nil || current != expected {
		return fmt.Errorf("%w: %v", errRepairExecutorContext, err)
	}
	return nil
}

func invokeRepairNamespaceOperation(ctx context.Context, run func(context.Context) error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w: %v", errRepairExecutorPanic, recovered)
		}
	}()
	return run(ctx)
}
