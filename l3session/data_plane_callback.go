package l3session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/l3ingress"
)

const (
	// Every admitted L3 flow may have one callback in each direction. Keep the
	// executor aligned with the flow-table admission bound so ordinary idle
	// connections are not mistaken for hostile detached callbacks.
	l3SessionDataPlaneCallbackLimit = 2 * l3ingress.DefaultFlowTableActiveCapacity
	dataPlaneControlTimeout         = 100 * time.Millisecond
	dataPlaneCloseTimeout           = time.Second
)

type dataPlaneCallbackClass uint8

const (
	dataPlaneReadCallback dataPlaneCallbackClass = iota
	dataPlaneWriteCallback
	dataPlaneControlCallback
	dataPlaneCloseCallback
	dataPlaneCallbackClassCount
)

type dataPlaneCallbackExecutor struct {
	slots [dataPlaneCallbackClassCount]chan struct{}

	cleanupAuthoritySlots chan struct{}
	cleanupMu             sync.Mutex
	cleanupQueue          []*dataPlaneCloseAuthority
	cleanupDispatching    bool
}

func newDataPlaneCallbackExecutor(limit int) *dataPlaneCallbackExecutor {
	if limit <= 0 {
		panic("l3session: data-plane callback limit must be positive")
	}
	executor := &dataPlaneCallbackExecutor{}
	for class := dataPlaneCallbackClass(0); class < dataPlaneCallbackClassCount; class++ {
		executor.slots[class] = make(chan struct{}, limit)
	}
	executor.cleanupAuthoritySlots = make(chan struct{}, limit)
	return executor
}

var dataPlaneProcessExecutor = newDataPlaneCallbackExecutor(l3SessionDataPlaneCallbackLimit)

func dataPlaneExecutorOrProcess(executor *dataPlaneCallbackExecutor) *dataPlaneCallbackExecutor {
	if executor != nil {
		return executor
	}
	return dataPlaneProcessExecutor
}

type dataPlaneCallbackResult[T any] struct {
	value T
	err   error
}

type dataPlaneCallbackTask[T any] struct {
	callback string
	done     chan struct{}
	result   dataPlaneCallbackResult[T]
}

func startDataPlaneCallback[T any](
	executor *dataPlaneCallbackExecutor,
	callback string,
	class dataPlaneCallbackClass,
	invoke func() (T, error),
) (*dataPlaneCallbackTask[T], error) {
	if executor == nil || class >= dataPlaneCallbackClassCount {
		return nil, &CallbackError{Callback: callback, Reason: CallbackFailureSaturated}
	}
	slots := executor.slots[class]
	select {
	case slots <- struct{}{}:
	default:
		return nil, &CallbackError{Callback: callback, Reason: CallbackFailureSaturated}
	}
	task := &dataPlaneCallbackTask[T]{callback: callback, done: make(chan struct{})}
	go func() {
		result := dataPlaneCallbackResult[T]{
			err: &CallbackError{Callback: callback, Reason: CallbackFailureGoexit},
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				result = dataPlaneCallbackResult[T]{err: dataPlanePanicError(callback, recovered)}
			}
			task.result = result
			<-slots
			close(task.done)
		}()
		result.value, result.err = invoke()
	}()
	return task, nil
}

func (task *dataPlaneCallbackTask[T]) wait(ctx context.Context) (zero T, err error) {
	if task == nil {
		return zero, errors.New("l3session: nil data-plane callback task")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-task.done:
		return task.result.value, task.result.err
	case <-ctx.Done():
		select {
		case <-task.done:
			return task.result.value, task.result.err
		default:
		}
		timer := time.NewTimer(dataPlaneControlTimeout)
		defer timer.Stop()
		select {
		case <-task.done:
			return task.result.value, task.result.err
		case <-timer.C:
			return zero, errors.Join(ctx.Err(), &CallbackError{
				Callback: task.callback,
				Reason:   CallbackFailureTimeout,
			})
		}
	}
}

func invokeDataPlaneCallback[T any](
	ctx context.Context,
	executor *dataPlaneCallbackExecutor,
	callback string,
	class dataPlaneCallbackClass,
	invoke func() (T, error),
) (zero T, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	task, err := startDataPlaneCallback(executor, callback, class, invoke)
	if err != nil {
		return zero, err
	}
	return task.wait(ctx)
}

func invokeBoundedDataPlaneError(
	executor *dataPlaneCallbackExecutor,
	callback string,
	class dataPlaneCallbackClass,
	invoke func() error,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), dataPlaneControlTimeout)
	defer cancel()
	_, err := invokeDataPlaneCallback(ctx, executor, callback, class, func() (struct{}, error) {
		return struct{}{}, invoke()
	})
	if errors.Is(err, context.DeadlineExceeded) {
		return &CallbackError{Callback: callback, Reason: CallbackFailureTimeout}
	}
	return err
}

func dataPlanePanicError(callback string, recovered any) *CallbackError {
	panicType := "<nil>"
	if typ := reflect.TypeOf(recovered); typ != nil {
		panicType = typ.String()
	}
	return &CallbackError{Callback: callback, Reason: CallbackFailurePanic, PanicType: panicType}
}

type dataPlaneCloseAuthority struct {
	executor *dataPlaneCallbackExecutor
	callback string
	close    func() error
	reserved *dataPlaneCleanupReservation

	mu           sync.Mutex
	task         *dataPlaneCallbackTask[struct{}]
	reservedRun  sync.Once
	reservedDone chan struct{}
	reservedErr  error
}

const (
	dataPlaneCleanupReserved uint32 = iota
	dataPlaneCleanupBound
	dataPlaneCleanupReleased
)

type dataPlaneCleanupReservation struct {
	executor *dataPlaneCallbackExecutor
	callback string
	state    atomic.Uint32
}

func reserveDataPlaneCleanupWithExecutor(
	executor *dataPlaneCallbackExecutor,
	callback string,
) (*dataPlaneCleanupReservation, error) {
	if executor == nil {
		return nil, &CallbackError{Callback: callback, Reason: CallbackFailureSaturated}
	}
	select {
	case executor.cleanupAuthoritySlots <- struct{}{}:
		return &dataPlaneCleanupReservation{executor: executor, callback: callback}, nil
	default:
		return nil, &CallbackError{Callback: callback, Reason: CallbackFailureSaturated}
	}
}

func (reservation *dataPlaneCleanupReservation) Bind(closeFn func() error) *dataPlaneCloseAuthority {
	if reservation == nil || reservation.executor == nil || closeFn == nil {
		panic("l3session: invalid data-plane cleanup reservation bind")
	}
	if !reservation.state.CompareAndSwap(dataPlaneCleanupReserved, dataPlaneCleanupBound) {
		panic("l3session: data-plane cleanup reservation already consumed")
	}
	return &dataPlaneCloseAuthority{
		executor:     reservation.executor,
		callback:     reservation.callback,
		close:        closeFn,
		reserved:     reservation,
		reservedDone: make(chan struct{}),
	}
}

func (reservation *dataPlaneCleanupReservation) Release() {
	if reservation == nil || reservation.executor == nil {
		return
	}
	if reservation.state.CompareAndSwap(dataPlaneCleanupReserved, dataPlaneCleanupReleased) {
		<-reservation.executor.cleanupAuthoritySlots
	}
}

func (reservation *dataPlaneCleanupReservation) releaseBound() {
	if reservation == nil || reservation.executor == nil {
		return
	}
	if reservation.state.CompareAndSwap(dataPlaneCleanupBound, dataPlaneCleanupReleased) {
		<-reservation.executor.cleanupAuthoritySlots
	}
}

func (executor *dataPlaneCallbackExecutor) enqueueReservedClose(authority *dataPlaneCloseAuthority) {
	executor.cleanupMu.Lock()
	// One reservation can enqueue once, so cleanupAuthoritySlots bounds this
	// queue. A single dispatcher may wait for execution capacity; callers never
	// create one waiting goroutine per rejected connection.
	executor.cleanupQueue = append(executor.cleanupQueue, authority)
	if !executor.cleanupDispatching {
		executor.cleanupDispatching = true
		go executor.dispatchReservedCloses()
	}
	executor.cleanupMu.Unlock()
}

func (executor *dataPlaneCallbackExecutor) dispatchReservedCloses() {
	for {
		executor.cleanupMu.Lock()
		if len(executor.cleanupQueue) == 0 {
			executor.cleanupDispatching = false
			executor.cleanupMu.Unlock()
			return
		}
		authority := executor.cleanupQueue[0]
		executor.cleanupQueue[0] = nil
		executor.cleanupQueue = executor.cleanupQueue[1:]
		executor.cleanupMu.Unlock()

		slots := executor.slots[dataPlaneCloseCallback]
		slots <- struct{}{}
		go authority.runReserved(func() { <-slots })
	}
}

func (authority *dataPlaneCloseAuthority) runReserved(releaseExecution func()) {
	result := error(&CallbackError{Callback: authority.callback, Reason: CallbackFailureGoexit})
	defer func() {
		if recovered := recover(); recovered != nil {
			result = dataPlanePanicError(authority.callback, recovered)
		}
		releaseExecution()
		authority.reserved.releaseBound()
		authority.reservedErr = result
		close(authority.reservedDone)
	}()
	result = authority.close()
}

func newDataPlaneCloseAuthorityWithExecutor(
	executor *dataPlaneCallbackExecutor,
	callback string,
	closeFn func() error,
) *dataPlaneCloseAuthority {
	return &dataPlaneCloseAuthority{executor: executor, callback: callback, close: closeFn}
}

func (authority *dataPlaneCloseAuthority) Close() error {
	if authority == nil || authority.close == nil {
		return nil
	}
	if authority.reserved != nil {
		authority.reservedRun.Do(func() {
			authority.executor.enqueueReservedClose(authority)
		})
		ctx, cancel := context.WithTimeout(context.Background(), dataPlaneCloseTimeout)
		defer cancel()
		select {
		case <-authority.reservedDone:
			return authority.reservedErr
		case <-ctx.Done():
			select {
			case <-authority.reservedDone:
				return authority.reservedErr
			default:
				return &CallbackError{Callback: authority.callback, Reason: CallbackFailureTimeout}
			}
		}
	}
	authority.mu.Lock()
	task := authority.task
	if task == nil {
		var err error
		task, err = startDataPlaneCallback(authority.executor, authority.callback, dataPlaneCloseCallback, func() (struct{}, error) {
			return struct{}{}, authority.close()
		})
		if err != nil {
			authority.mu.Unlock()
			return err
		}
		authority.task = task
	}
	authority.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), dataPlaneCloseTimeout)
	defer cancel()
	_, err := task.wait(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		return &CallbackError{Callback: authority.callback, Reason: CallbackFailureTimeout}
	}
	return err
}

type streamReadResult struct{ n int }
type streamWriteResult struct{ n int }

type dataPlaneStream struct {
	conn      net.Conn
	label     string
	executor  *dataPlaneCallbackExecutor
	closeAuth *dataPlaneCloseAuthority

	interruptOnce sync.Once
	interruptErr  error
}

func newDataPlaneStream(conn net.Conn, label string, closeFn func() error) *dataPlaneStream {
	return newDataPlaneStreamWithExecutor(dataPlaneProcessExecutor, conn, label, closeFn)
}

func newDataPlaneStreamWithExecutor(
	executor *dataPlaneCallbackExecutor,
	conn net.Conn,
	label string,
	closeFn func() error,
) *dataPlaneStream {
	return &dataPlaneStream{
		conn: conn, label: label, executor: executor,
		closeAuth: newDataPlaneCloseAuthorityWithExecutor(executor, label+" Close", closeFn),
	}
}

func newDataPlaneStreamWithCloseAuthority(
	conn net.Conn,
	label string,
	closeAuth *dataPlaneCloseAuthority,
) *dataPlaneStream {
	executor := dataPlaneProcessExecutor
	if closeAuth != nil && closeAuth.executor != nil {
		executor = closeAuth.executor
	}
	return &dataPlaneStream{
		conn: conn, label: label, executor: executor, closeAuth: closeAuth,
	}
}

func (stream *dataPlaneStream) read(ctx context.Context, payload []byte) (int, error) {
	if stream == nil || stream.conn == nil {
		return 0, net.ErrClosed
	}
	scratch := make([]byte, len(payload))
	result, err := invokeDataPlaneCallback(ctx, stream.executor, stream.label+" Read", dataPlaneReadCallback,
		func() (streamReadResult, error) {
			n, readErr := stream.conn.Read(scratch)
			return streamReadResult{n: n}, readErr
		})
	if result.n < 0 || result.n > len(scratch) {
		return 0, errors.Join(err,
			fmt.Errorf("l3session: %s Read returned invalid byte count %d", stream.label, result.n))
	}
	copy(payload, scratch[:result.n])
	return result.n, err
}

func (stream *dataPlaneStream) write(ctx context.Context, payload []byte) (int, error) {
	if stream == nil || stream.conn == nil {
		return 0, net.ErrClosed
	}
	owned := append([]byte(nil), payload...)
	result, err := invokeDataPlaneCallback(ctx, stream.executor, stream.label+" Write", dataPlaneWriteCallback,
		func() (streamWriteResult, error) {
			n, writeErr := stream.conn.Write(owned)
			return streamWriteResult{n: n}, writeErr
		})
	if result.n < 0 || result.n > len(owned) {
		return 0, errors.Join(err,
			fmt.Errorf("l3session: %s Write returned invalid byte count %d", stream.label, result.n))
	}
	return result.n, err
}

func (stream *dataPlaneStream) closeWrite() error {
	half, ok := stream.conn.(interface{ CloseWrite() error })
	if !ok {
		return fmt.Errorf("%w: %T", ErrTCPHalfCloseUnsupported, stream.conn)
	}
	return invokeBoundedDataPlaneError(stream.executor, stream.label+" CloseWrite", dataPlaneControlCallback, half.CloseWrite)
}

func (stream *dataPlaneStream) closeRead() error {
	half, ok := stream.conn.(interface{ CloseRead() error })
	if !ok {
		return nil
	}
	return invokeBoundedDataPlaneError(stream.executor, stream.label+" CloseRead", dataPlaneControlCallback, half.CloseRead)
}

func (stream *dataPlaneStream) setDeadline(deadline time.Time) error {
	return invokeBoundedDataPlaneError(stream.executor, stream.label+" SetDeadline", dataPlaneControlCallback,
		func() error { return stream.conn.SetDeadline(deadline) })
}

func (stream *dataPlaneStream) close() error { return stream.closeAuth.Close() }

func (stream *dataPlaneStream) interrupt() error {
	if stream == nil {
		return nil
	}
	stream.interruptOnce.Do(func() {
		stream.interruptErr = errors.Join(
			stream.setDeadline(time.Now()),
			stream.closeRead(),
			stream.close(),
		)
	})
	return stream.interruptErr
}

type packetReadResult struct {
	n    int
	addr net.Addr
}
type packetWriteResult struct{ n int }

type dataPlanePacket struct {
	conn      net.PacketConn
	label     string
	executor  *dataPlaneCallbackExecutor
	closeAuth *dataPlaneCloseAuthority

	interruptOnce sync.Once
	interruptErr  error
}

func newDataPlanePacket(conn net.PacketConn, label string, closeFn func() error) *dataPlanePacket {
	return newDataPlanePacketWithExecutor(dataPlaneProcessExecutor, conn, label, closeFn)
}

func newDataPlanePacketWithExecutor(
	executor *dataPlaneCallbackExecutor,
	conn net.PacketConn,
	label string,
	closeFn func() error,
) *dataPlanePacket {
	return &dataPlanePacket{
		conn: conn, label: label, executor: executor,
		closeAuth: newDataPlaneCloseAuthorityWithExecutor(executor, label+" Close", closeFn),
	}
}

func newDataPlanePacketWithCloseAuthority(
	conn net.PacketConn,
	label string,
	closeAuth *dataPlaneCloseAuthority,
) *dataPlanePacket {
	executor := dataPlaneProcessExecutor
	if closeAuth != nil && closeAuth.executor != nil {
		executor = closeAuth.executor
	}
	return &dataPlanePacket{
		conn: conn, label: label, executor: executor, closeAuth: closeAuth,
	}
}

func (packet *dataPlanePacket) readFrom(ctx context.Context, payload []byte) (int, net.Addr, error) {
	if packet == nil || packet.conn == nil {
		return 0, nil, net.ErrClosed
	}
	scratch := make([]byte, len(payload))
	result, err := invokeDataPlaneCallback(ctx, packet.executor, packet.label+" ReadFrom", dataPlaneReadCallback,
		func() (packetReadResult, error) {
			n, addr, readErr := packet.conn.ReadFrom(scratch)
			return packetReadResult{n: n, addr: cloneDataPlaneAddr(addr)}, readErr
		})
	if result.n < 0 || result.n > len(scratch) {
		return 0, nil, errors.Join(err,
			fmt.Errorf("l3session: %s ReadFrom returned invalid byte count %d", packet.label, result.n))
	}
	copy(payload, scratch[:result.n])
	return result.n, result.addr, err
}

func (packet *dataPlanePacket) writeTo(ctx context.Context, payload []byte, addr net.Addr) (int, error) {
	if packet == nil || packet.conn == nil {
		return 0, net.ErrClosed
	}
	owned := append([]byte(nil), payload...)
	ownedAddr := cloneDataPlaneAddr(addr)
	result, err := invokeDataPlaneCallback(ctx, packet.executor, packet.label+" WriteTo", dataPlaneWriteCallback,
		func() (packetWriteResult, error) {
			n, writeErr := packet.conn.WriteTo(owned, ownedAddr)
			return packetWriteResult{n: n}, writeErr
		})
	if result.n < 0 || result.n > len(owned) {
		return 0, errors.Join(err,
			fmt.Errorf("l3session: %s WriteTo returned invalid byte count %d", packet.label, result.n))
	}
	return result.n, err
}

func cloneDataPlaneAddr(addr net.Addr) net.Addr {
	switch value := addr.(type) {
	case *net.UDPAddr:
		if value == nil {
			return (*net.UDPAddr)(nil)
		}
		clone := *value
		clone.IP = append(net.IP(nil), value.IP...)
		return &clone
	case *net.TCPAddr:
		if value == nil {
			return (*net.TCPAddr)(nil)
		}
		clone := *value
		clone.IP = append(net.IP(nil), value.IP...)
		return &clone
	case *net.IPAddr:
		if value == nil {
			return (*net.IPAddr)(nil)
		}
		clone := *value
		clone.IP = append(net.IP(nil), value.IP...)
		return &clone
	case *net.UnixAddr:
		if value == nil {
			return (*net.UnixAddr)(nil)
		}
		clone := *value
		return &clone
	default:
		return addr
	}
}

func (packet *dataPlanePacket) setReadDeadline(deadline time.Time) error {
	return invokeBoundedDataPlaneError(packet.executor, packet.label+" SetReadDeadline", dataPlaneControlCallback,
		func() error { return packet.conn.SetReadDeadline(deadline) })
}

func (packet *dataPlanePacket) setWriteDeadline(deadline time.Time) error {
	return invokeBoundedDataPlaneError(packet.executor, packet.label+" SetWriteDeadline", dataPlaneControlCallback,
		func() error { return packet.conn.SetWriteDeadline(deadline) })
}

func (packet *dataPlanePacket) close() error { return packet.closeAuth.Close() }

func (packet *dataPlanePacket) interrupt() error {
	if packet == nil {
		return nil
	}
	packet.interruptOnce.Do(func() {
		now := time.Now()
		packet.interruptErr = errors.Join(
			packet.setReadDeadline(now),
			packet.setWriteDeadline(now),
			packet.close(),
		)
	})
	return packet.interruptErr
}
