package rendr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"

	"github.com/FrankoonG/rendr/transport"
	"github.com/FrankoonG/rendr/transport/tcp"
	"github.com/FrankoonG/rendr/transport/udpflow"
)

type streamPathFactory func(context.Context, string) (net.Conn, error)
type packetPathFactory func(context.Context, string) (net.PacketConn, error)

// FactoryKind identifies the public factory contract that failed.
type FactoryKind string

const (
	FactoryKindStream FactoryKind = "stream"
	FactoryKindPacket FactoryKind = "packet"
	FactoryKindFramed FactoryKind = "framed"
)

// FactoryErrorReason is a machine-readable failure at the caller factory
// boundary.
type FactoryErrorReason string

const (
	FactoryReasonPanic     FactoryErrorReason = "panic"
	FactoryReasonAbnormal  FactoryErrorReason = "abnormal_exit"
	FactoryReasonNilResult FactoryErrorReason = "nil_result"
	FactoryReasonCleanup   FactoryErrorReason = "cleanup_abnormal_exit"
)

// FactoryError reports an invalid result or a recovered panic from a
// caller-provided carrier factory. PanicType is only the recovered value's Go
// type; the arbitrary value itself is never retained or formatted.
type FactoryError struct {
	FactoryID string
	Kind      FactoryKind
	Reason    FactoryErrorReason
	PanicType string
}

func (e *FactoryError) Error() string {
	if e == nil {
		return "rendr: path factory failed"
	}
	switch e.Reason {
	case FactoryReasonPanic:
		return fmt.Sprintf("rendr: %s path factory %q panicked", e.Kind, e.FactoryID)
	case FactoryReasonAbnormal:
		return fmt.Sprintf("rendr: %s path factory %q exited without returning", e.Kind, e.FactoryID)
	case FactoryReasonNilResult:
		return fmt.Sprintf("rendr: %s path factory %q returned a nil connection", e.Kind, e.FactoryID)
	case FactoryReasonCleanup:
		return fmt.Sprintf("rendr: %s path factory %q connection cleanup exited abnormally", e.Kind, e.FactoryID)
	default:
		return fmt.Sprintf("rendr: %s path factory %q failed", e.Kind, e.FactoryID)
	}
}

// pathFactoryResolver is the immutable, per-session snapshot of a Runtime's
// custom factories. A session must keep using the factories that established
// it even if the caller later registers factories for future sessions.
type pathFactoryResolver struct {
	stream  map[string]streamPathFactory
	packet  map[string]packetPathFactory
	framed  map[string]transport.PathFactory
	carrier map[string]CarrierFamily
}

func builtinPathFactories() map[string]transport.PathFactory {
	return map[string]transport.PathFactory{
		"tcp":     tcp.New(),
		"udpflow": udpflow.New(),
	}
}

func isBuiltinPathFactory(name string) bool {
	switch name {
	case "tcp", "udpflow":
		return true
	default:
		return false
	}
}

func (d *sessionDialer) snapshotFactoryResolver() *pathFactoryResolver {
	resolver := &pathFactoryResolver{
		stream:  make(map[string]streamPathFactory, len(d.streamFactories)),
		packet:  make(map[string]packetPathFactory, len(d.packetFactories)),
		framed:  builtinPathFactories(),
		carrier: map[string]CarrierFamily{"tcp": CarrierTCP, "udpflow": CarrierUDP},
	}
	for name, factory := range d.streamFactories {
		resolver.stream[name] = factory
	}
	for name, factory := range d.packetFactories {
		resolver.packet[name] = factory
	}
	for name, factory := range d.framedFactories {
		resolver.framed[name] = factory
	}
	for name, carrier := range d.factoryCarriers {
		resolver.carrier[name] = carrier
	}
	return resolver
}

func (r *pathFactoryResolver) carrierFamily(name string) CarrierFamily {
	if r == nil {
		return CarrierUnknown
	}
	return r.carrier[name]
}

func (r *pathFactoryResolver) hasFactory(name string) bool {
	if r == nil {
		return false
	}
	_, stream := r.stream[name]
	_, packet := r.packet[name]
	_, framed := r.framed[name]
	return stream || packet || framed
}

// dialPath resolves a path only against the immutable session snapshot. This
// preserves the same Runtime-local factory for initial dial, explicit AddPath,
// and recovery retries; unknown IDs fail closed.
func (r *pathFactoryResolver) dialPath(ctx context.Context, spec PathSpec) (transport.PathConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r != nil {
		if factory, ok := r.stream[spec.Transport]; ok {
			conn, err := invokePathFactory(ctx, spec.Transport, FactoryKindStream, func() (net.Conn, error) {
				return factory(ctx, spec.Address)
			})
			if err != nil {
				return nil, err
			}
			if nilFactoryResult(conn) {
				return nil, factoryErrorWithContext(ctx, &FactoryError{
					FactoryID: spec.Transport,
					Kind:      FactoryKindStream,
					Reason:    FactoryReasonNilResult,
				})
			}
			return tcp.Wrap(conn), nil
		}
		if factory, ok := r.packet[spec.Transport]; ok {
			conn, err := invokePathFactory(ctx, spec.Transport, FactoryKindPacket, func() (net.PacketConn, error) {
				return factory(ctx, spec.Address)
			})
			if err != nil {
				return nil, err
			}
			if nilFactoryResult(conn) {
				return nil, factoryErrorWithContext(ctx, &FactoryError{
					FactoryID: spec.Transport,
					Kind:      FactoryKindPacket,
					Reason:    FactoryReasonNilResult,
				})
			}
			return udpflow.WrapFromSpec(conn, spec)
		}
		if factory, ok := r.framed[spec.Transport]; ok {
			if isBuiltinPathFactory(spec.Transport) {
				// Built-in factories are rendr code. Never recover their panics as
				// caller failures; doing so would hide an internal invariant bug.
				conn, err := factory.DialPath(ctx, spec)
				if err != nil {
					return nil, err
				}
				if nilFactoryResult(conn) {
					return nil, fmt.Errorf("rendr: built-in path factory %q returned a nil connection", spec.Transport)
				}
				return conn, nil
			}
			conn, err := invokePathFactory(ctx, spec.Transport, FactoryKindFramed, func() (transport.PathConn, error) {
				return factory.DialPath(ctx, spec)
			})
			if err != nil {
				return nil, err
			}
			if nilFactoryResult(conn) {
				return nil, factoryErrorWithContext(ctx, &FactoryError{
					FactoryID: spec.Transport,
					Kind:      FactoryKindFramed,
					Reason:    FactoryReasonNilResult,
				})
			}
			return conn, nil
		}
	}
	return nil, fmt.Errorf("rendr: path factory %q is not registered on this Runtime", spec.Transport)
}

// invokePathFactory isolates only caller code. Wrapping, framing, and all
// rendr-owned code run outside this boundary so their panics remain visible.
func invokePathFactory[T any](ctx context.Context, factoryID string, kind FactoryKind, invoke func() (T, error)) (result T, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return result, ctxErr
	}

	call := runCallerFactory(invoke)
	if call.failure != nil {
		var zero T
		call.failure.FactoryID = factoryID
		call.failure.Kind = kind
		return zero, factoryErrorWithContext(ctx, call.failure)
	}
	result, err = call.value, call.err

	ctxErr := ctx.Err()
	if err == nil && ctxErr == nil {
		return result, nil
	}
	if err == nil && nilFactoryResult(result) {
		// Let the caller classify the invalid nil result and join the context
		// cause, preserving both machine-readable facts.
		return result, nil
	}
	cleanupErr := cleanupFactoryResult(result, factoryID, kind)
	var zero T
	return zero, joinFactoryErrors(ctxErr, err, cleanupErr)
}

type callerFactoryResult[T any] struct {
	value   T
	err     error
	failure *FactoryError
}

// runCallerFactory isolates runtime.Goexit as well as recoverable panics. Path
// creation is not a data-plane operation, so the one short-lived goroutine is
// preferable to allowing caller code to terminate an engine recovery worker.
// A factory that never returns still violates its context contract and leaves
// this call fail-stopped; rendr does not launch additional retries behind it.
func runCallerFactory[T any](invoke func() (T, error)) callerFactoryResult[T] {
	result := make(chan callerFactoryResult[T], 1)
	go func() {
		completed := false
		defer func() {
			if completed {
				return
			}
			recovered := recover()
			reason := FactoryReasonAbnormal
			panicType := ""
			if recovered != nil {
				reason = FactoryReasonPanic
				panicType = reflect.TypeOf(recovered).String()
			}
			result <- callerFactoryResult[T]{failure: &FactoryError{
				Reason:    reason,
				PanicType: panicType,
			}}
		}()
		value, err := invoke()
		completed = true
		result <- callerFactoryResult[T]{value: value, err: err}
	}()
	return <-result
}

func cleanupFactoryResult(value any, factoryID string, kind FactoryKind) (err error) {
	if nilFactoryResult(value) {
		return nil
	}
	closer, ok := value.(io.Closer)
	if !ok {
		return nil
	}
	call := runCallerFactory(func() (struct{}, error) {
		return struct{}{}, closer.Close()
	})
	if call.failure != nil {
		return &FactoryError{
			FactoryID: factoryID,
			Kind:      kind,
			Reason:    FactoryReasonCleanup,
			PanicType: call.failure.PanicType,
		}
	}
	return call.err
}

func factoryErrorWithContext(ctx context.Context, err *FactoryError) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return joinFactoryErrors(ctxErr, err)
	}
	return err
}

func joinFactoryErrors(errs ...error) error {
	joined := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			joined = append(joined, err)
		}
	}
	switch len(joined) {
	case 0:
		return nil
	case 1:
		return joined[0]
	default:
		return errors.Join(joined...)
	}
}

func nilFactoryResult(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
