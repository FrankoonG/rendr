package l3ingress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	l3IngressDataPlaneCallbackLimit = 2 * DefaultFlowTableActiveCapacity
	l3IngressDataPlaneCancelGrace   = 100 * time.Millisecond
)

type l3IngressDataPlaneClass uint8

const (
	l3IngressDataPlaneRead l3IngressDataPlaneClass = iota
	l3IngressDataPlaneWrite
	l3IngressDataPlaneControl
	l3IngressDataPlaneClassCount
)

type l3IngressDataPlaneExecutor struct {
	slots [l3IngressDataPlaneClassCount]chan struct{}
}

func newL3IngressDataPlaneExecutor(limit int) *l3IngressDataPlaneExecutor {
	if limit <= 0 {
		panic("l3ingress: data-plane callback limit must be positive")
	}
	executor := &l3IngressDataPlaneExecutor{}
	for class := l3IngressDataPlaneClass(0); class < l3IngressDataPlaneClassCount; class++ {
		executor.slots[class] = make(chan struct{}, limit)
	}
	return executor
}

var l3IngressDataPlaneProcessExecutor = newL3IngressDataPlaneExecutor(l3IngressDataPlaneCallbackLimit)

type l3IngressDataPlaneResult[T any] struct {
	value T
	err   error
}

type l3IngressDataPlaneTask[T any] struct {
	callback string
	done     chan struct{}
	result   l3IngressDataPlaneResult[T]
}

func startL3IngressDataPlaneCallback[T any](
	executor *l3IngressDataPlaneExecutor,
	callback string,
	class l3IngressDataPlaneClass,
	invoke func() (T, error),
) (*l3IngressDataPlaneTask[T], error) {
	if executor == nil || class >= l3IngressDataPlaneClassCount {
		return nil, &CallbackError{Callback: callback, Reason: CallbackFailureSaturated}
	}
	slots := executor.slots[class]
	select {
	case slots <- struct{}{}:
	default:
		return nil, &CallbackError{Callback: callback, Reason: CallbackFailureSaturated}
	}
	task := &l3IngressDataPlaneTask[T]{callback: callback, done: make(chan struct{})}
	go func() {
		result := l3IngressDataPlaneResult[T]{
			err: &CallbackError{Callback: callback, Reason: CallbackFailureGoexit},
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				result = l3IngressDataPlaneResult[T]{err: callbackPanicError(callback, recovered)}
			}
			task.result = result
			<-slots
			close(task.done)
		}()
		result.value, result.err = invoke()
	}()
	return task, nil
}

func (task *l3IngressDataPlaneTask[T]) wait(ctx context.Context) (zero T, err error) {
	if task == nil {
		return zero, errors.New("l3ingress: nil data-plane callback task")
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
		timer := time.NewTimer(l3IngressDataPlaneCancelGrace)
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

func invokeL3IngressDataPlaneCallback[T any](
	ctx context.Context,
	executor *l3IngressDataPlaneExecutor,
	callback string,
	class l3IngressDataPlaneClass,
	invoke func() (T, error),
) (zero T, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	task, err := startL3IngressDataPlaneCallback(executor, callback, class, invoke)
	if err != nil {
		return zero, err
	}
	return task.wait(ctx)
}

type l3IngressStreamResult struct{ n int }

type l3IngressDataPlaneTCP struct {
	conn     TCPConn
	label    string
	executor *l3IngressDataPlaneExecutor
}

func newL3IngressDataPlaneTCP(conn TCPConn, label string) *l3IngressDataPlaneTCP {
	return newL3IngressDataPlaneTCPWithExecutor(l3IngressDataPlaneProcessExecutor, conn, label)
}

func newL3IngressDataPlaneTCPWithExecutor(
	executor *l3IngressDataPlaneExecutor,
	conn TCPConn,
	label string,
) *l3IngressDataPlaneTCP {
	return &l3IngressDataPlaneTCP{conn: conn, label: label, executor: executor}
}

func (stream *l3IngressDataPlaneTCP) read(ctx context.Context, payload []byte) (int, error) {
	if stream == nil || stream.conn == nil {
		return 0, net.ErrClosed
	}
	scratch := make([]byte, len(payload))
	result, err := invokeL3IngressDataPlaneCallback(
		ctx, stream.executor, stream.label+".Read", l3IngressDataPlaneRead,
		func() (l3IngressStreamResult, error) {
			n, readErr := stream.conn.Read(scratch)
			return l3IngressStreamResult{n: n}, readErr
		},
	)
	if result.n < 0 || result.n > len(scratch) {
		return 0, errors.Join(err,
			fmt.Errorf("l3ingress: %s Read returned invalid byte count %d", stream.label, result.n))
	}
	copy(payload, scratch[:result.n])
	return result.n, err
}

func (stream *l3IngressDataPlaneTCP) write(ctx context.Context, payload []byte) (int, error) {
	if stream == nil || stream.conn == nil {
		return 0, net.ErrClosed
	}
	owned := append([]byte(nil), payload...)
	result, err := invokeL3IngressDataPlaneCallback(
		ctx, stream.executor, stream.label+".Write", l3IngressDataPlaneWrite,
		func() (l3IngressStreamResult, error) {
			n, writeErr := stream.conn.Write(owned)
			return l3IngressStreamResult{n: n}, writeErr
		},
	)
	if result.n < 0 || result.n > len(owned) {
		return 0, errors.Join(err,
			fmt.Errorf("l3ingress: %s Write returned invalid byte count %d", stream.label, result.n))
	}
	return result.n, err
}

func (stream *l3IngressDataPlaneTCP) closeWrite() error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultEgressCloseTimeout)
	defer cancel()
	_, err := invokeL3IngressDataPlaneCallback(
		ctx, stream.executor, stream.label+".CloseWrite", l3IngressDataPlaneControl,
		func() (struct{}, error) { return struct{}{}, stream.conn.CloseWrite() },
	)
	if errors.Is(err, context.DeadlineExceeded) {
		return &CallbackError{Callback: stream.label + ".CloseWrite", Reason: CallbackFailureTimeout}
	}
	return err
}

type l3IngressPacketResult struct {
	n    int
	addr net.Addr
}

type l3IngressDataPlanePacket struct {
	conn     net.PacketConn
	label    string
	executor *l3IngressDataPlaneExecutor
}

func newL3IngressDataPlanePacket(conn net.PacketConn, label string) *l3IngressDataPlanePacket {
	return newL3IngressDataPlanePacketWithExecutor(l3IngressDataPlaneProcessExecutor, conn, label)
}

func newL3IngressDataPlanePacketWithExecutor(
	executor *l3IngressDataPlaneExecutor,
	conn net.PacketConn,
	label string,
) *l3IngressDataPlanePacket {
	return &l3IngressDataPlanePacket{conn: conn, label: label, executor: executor}
}

func (packet *l3IngressDataPlanePacket) readFrom(
	ctx context.Context,
	payload []byte,
) (int, net.Addr, error) {
	if packet == nil || packet.conn == nil {
		return 0, nil, net.ErrClosed
	}
	scratch := make([]byte, len(payload))
	result, err := invokeL3IngressDataPlaneCallback(
		ctx, packet.executor, packet.label+".ReadFrom", l3IngressDataPlaneRead,
		func() (l3IngressPacketResult, error) {
			n, addr, readErr := packet.conn.ReadFrom(scratch)
			return l3IngressPacketResult{n: n, addr: cloneL3IngressDataPlaneAddr(addr)}, readErr
		},
	)
	if result.n < 0 || result.n > len(scratch) {
		return 0, nil, errors.Join(err,
			fmt.Errorf("l3ingress: %s ReadFrom returned invalid byte count %d", packet.label, result.n))
	}
	copy(payload, scratch[:result.n])
	return result.n, result.addr, err
}

func (packet *l3IngressDataPlanePacket) writeTo(
	ctx context.Context,
	payload []byte,
	addr net.Addr,
) (int, error) {
	if packet == nil || packet.conn == nil {
		return 0, net.ErrClosed
	}
	owned := append([]byte(nil), payload...)
	ownedAddr := cloneL3IngressDataPlaneAddr(addr)
	result, err := invokeL3IngressDataPlaneCallback(
		ctx, packet.executor, packet.label+".WriteTo", l3IngressDataPlaneWrite,
		func() (l3IngressStreamResult, error) {
			n, writeErr := packet.conn.WriteTo(owned, ownedAddr)
			return l3IngressStreamResult{n: n}, writeErr
		},
	)
	if result.n < 0 || result.n > len(owned) {
		return 0, errors.Join(err,
			fmt.Errorf("l3ingress: %s WriteTo returned invalid byte count %d", packet.label, result.n))
	}
	return result.n, err
}

func cloneL3IngressDataPlaneAddr(addr net.Addr) net.Addr {
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
