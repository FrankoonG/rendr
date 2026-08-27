package rendr

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	"github.com/FrankoonG/rendr/transport/tcp"
	"github.com/FrankoonG/rendr/transport/udpflow"
)

type streamPathFactory func(context.Context, string) (net.Conn, error)
type packetPathFactory func(context.Context, string) (PacketEndpoint, error)

type validatedPacketEndpoint struct {
	conn            net.PacketConn
	peer            udpflow.PeerSnapshot
	maxDatagramSize int
}

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
	FactoryReasonPanic                 FactoryErrorReason = "panic"
	FactoryReasonAbnormal              FactoryErrorReason = "abnormal_exit"
	FactoryReasonNilResult             FactoryErrorReason = "nil_result"
	FactoryReasonCleanup               FactoryErrorReason = "cleanup_abnormal_exit"
	FactoryReasonCleanupTimeout        FactoryErrorReason = "cleanup_timeout"
	FactoryReasonBusy                  FactoryErrorReason = "busy"
	FactoryReasonCapacity              FactoryErrorReason = "capacity"
	FactoryReasonInvalidPacketConn     FactoryErrorReason = "invalid_packet_conn"
	FactoryReasonInvalidPacketPeer     FactoryErrorReason = "invalid_packet_peer"
	FactoryReasonInvalidPacketCapacity FactoryErrorReason = "invalid_packet_capacity"
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
	case FactoryReasonCleanupTimeout:
		return fmt.Sprintf("rendr: %s path factory %q connection cleanup exceeded its bounded wait", e.Kind, e.FactoryID)
	case FactoryReasonBusy:
		return fmt.Sprintf("rendr: %s path factory %q has an invocation or connection cleanup still in progress", e.Kind, e.FactoryID)
	case FactoryReasonCapacity:
		return fmt.Sprintf("rendr: %s path factory %q reached its outstanding callback capacity", e.Kind, e.FactoryID)
	case FactoryReasonInvalidPacketConn:
		return fmt.Sprintf("rendr: %s path factory %q returned an endpoint with a nil connection", e.Kind, e.FactoryID)
	case FactoryReasonInvalidPacketPeer:
		return fmt.Sprintf("rendr: %s path factory %q returned an endpoint with an invalid packet peer identity", e.Kind, e.FactoryID)
	case FactoryReasonInvalidPacketCapacity:
		return fmt.Sprintf("rendr: %s path factory %q returned an endpoint with an invalid datagram capacity", e.Kind, e.FactoryID)
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

	callGateMu    sync.Mutex
	callGates     map[factoryCallKey]*factoryCallGate
	runtimeBudget *factoryCallbackBudget
}

type factoryCallKey struct {
	id   string
	kind FactoryKind
}

const (
	maxOutstandingFactoryCallbacks = 256
	maxRuntimeFactoryCallbacks     = 256
	maxProcessFactoryCallbacks     = 512
)

type factoryCallbackBudget struct {
	permits chan struct{}
}

func newFactoryCallbackBudget(limit int) *factoryCallbackBudget {
	return &factoryCallbackBudget{permits: make(chan struct{}, limit)}
}

func (b *factoryCallbackBudget) tryAcquire() bool {
	if b == nil {
		return true
	}
	select {
	case b.permits <- struct{}{}:
		return true
	default:
		return false
	}
}

func (b *factoryCallbackBudget) release() {
	if b != nil {
		<-b.permits
	}
}

var processFactoryCallbackBudget = newFactoryCallbackBudget(maxProcessFactoryCallbacks)

type factoryCallbackPermit struct {
	runtime *factoryCallbackBudget
	process *factoryCallbackBudget
}

func acquireFactoryCallbackPermit(runtimeBudget *factoryCallbackBudget, factoryID string, kind FactoryKind) (*factoryCallbackPermit, error) {
	if !runtimeBudget.tryAcquire() {
		return nil, &FactoryError{FactoryID: factoryID, Kind: kind, Reason: FactoryReasonCapacity}
	}
	if !processFactoryCallbackBudget.tryAcquire() {
		runtimeBudget.release()
		return nil, &FactoryError{FactoryID: factoryID, Kind: kind, Reason: FactoryReasonCapacity}
	}
	return &factoryCallbackPermit{runtime: runtimeBudget, process: processFactoryCallbackBudget}, nil
}

func (p *factoryCallbackPermit) release() {
	if p == nil {
		return
	}
	p.process.release()
	p.runtime.release()
}

// factoryCallGate permits healthy callbacks to overlap while imposing a hard
// bound. Once any callback outlives cancellation or a cleanup exceeds its
// bounded wait, new calls fail immediately until that exact owner exits.
type factoryCallGate struct {
	mu            sync.Mutex
	active        int
	unresolved    int
	lateErr       error
	runtimeBudget *factoryCallbackBudget
}

func newFactoryCallGate(runtimeBudget *factoryCallbackBudget) *factoryCallGate {
	return &factoryCallGate{runtimeBudget: runtimeBudget}
}

type factoryCallLease struct {
	gate       *factoryCallGate
	permit     *factoryCallbackPermit
	unresolved bool
	completed  bool
}

func (g *factoryCallGate) acquire(factoryID string, kind FactoryKind, reserved *factoryCallbackPermit) (*factoryCallLease, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.unresolved != 0 {
		reserved.release()
		return nil, &FactoryError{
			FactoryID: factoryID,
			Kind:      kind,
			Reason:    FactoryReasonBusy,
		}
	}
	if g.lateErr != nil {
		err := g.lateErr
		g.lateErr = nil
		reserved.release()
		return nil, err
	}
	if g.active >= maxOutstandingFactoryCallbacks {
		reserved.release()
		return nil, &FactoryError{
			FactoryID: factoryID,
			Kind:      kind,
			Reason:    FactoryReasonCapacity,
		}
	}
	permit := reserved
	if permit == nil {
		var err error
		permit, err = acquireFactoryCallbackPermit(g.runtimeBudget, factoryID, kind)
		if err != nil {
			return nil, err
		}
	}
	g.active++
	return &factoryCallLease{gate: g, permit: permit}, nil
}

func (l *factoryCallLease) markUnresolved() {
	g := l.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	if l.completed || l.unresolved {
		panic("rendr: factory call lease has invalid unresolved transition")
	}
	l.unresolved = true
	g.unresolved++
}

func (l *factoryCallLease) complete(lateErr error) {
	g := l.gate
	g.mu.Lock()
	if l.completed || g.active <= 0 {
		g.mu.Unlock()
		panic("rendr: factory call lease completed without an owner")
	}
	l.completed = true
	g.active--
	if l.unresolved {
		g.unresolved--
	}
	if lateErr != nil {
		g.lateErr = joinFactoryErrors(g.lateErr, lateErr)
	}
	permit := l.permit
	l.permit = nil
	permit.release()
	g.mu.Unlock()
}

func (l *factoryCallLease) transferPermit() *factoryCallbackPermit {
	g := l.gate
	g.mu.Lock()
	if l.completed || l.unresolved || g.active <= 0 {
		g.mu.Unlock()
		panic("rendr: factory call lease transferred without a live owner")
	}
	l.completed = true
	g.active--
	permit := l.permit
	l.permit = nil
	g.mu.Unlock()
	return permit
}

func (r *pathFactoryResolver) factoryCallGate(factoryID string, kind FactoryKind) *factoryCallGate {
	key := factoryCallKey{id: factoryID, kind: kind}
	r.callGateMu.Lock()
	defer r.callGateMu.Unlock()
	if r.callGates == nil {
		r.callGates = make(map[factoryCallKey]*factoryCallGate)
	}
	gate := r.callGates[key]
	if gate == nil {
		gate = newFactoryCallGate(r.runtimeBudget)
		r.callGates[key] = gate
	}
	return gate
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
		stream:        make(map[string]streamPathFactory, len(d.streamFactories)),
		packet:        make(map[string]packetPathFactory, len(d.packetFactories)),
		framed:        builtinPathFactories(),
		carrier:       map[string]CarrierFamily{"tcp": CarrierTCP, "udpflow": CarrierUDP},
		runtimeBudget: d.factoryCallbackBudget,
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
	path, _, err := r.dialPathOwned(ctx, spec, nil, false)
	return path, err
}

func (r *pathFactoryResolver) dialPathOwned(
	ctx context.Context,
	spec PathSpec,
	reserved *factoryCallbackPermit,
	retainSuccess bool,
) (transport.PathConn, *factoryCallbackPermit, error) {
	if err := ctx.Err(); err != nil {
		reserved.release()
		return nil, nil, err
	}
	if r != nil {
		if factory, ok := r.stream[spec.Transport]; ok {
			conn, retained, err := invokePathFactoryOwned(ctx, r.factoryCallGate(spec.Transport, FactoryKindStream), reserved, retainSuccess, spec.Transport, FactoryKindStream, func() (net.Conn, error) {
				return factory(ctx, spec.Address)
			})
			if err != nil {
				return nil, nil, err
			}
			if nilFactoryResult(conn) {
				return nil, nil, factoryErrorWithContext(ctx, &FactoryError{
					FactoryID: spec.Transport,
					Kind:      FactoryKindStream,
					Reason:    FactoryReasonNilResult,
				})
			}
			return tcp.Wrap(conn), retained, nil
		}
		if factory, ok := r.packet[spec.Transport]; ok {
			flowID, err := preparePacketFactoryFlowID(spec)
			if err != nil {
				reserved.release()
				return nil, nil, err
			}
			var acquiredPacketConn net.PacketConn
			path, retained, err := invokePathFactoryOwnedWithCloser(ctx, r.factoryCallGate(spec.Transport, FactoryKindPacket), reserved, retainSuccess, spec.Transport, FactoryKindPacket, func(path transport.PathConn) io.Closer {
				if !nilFactoryResult(path) {
					return path
				}
				if nilFactoryResult(acquiredPacketConn) {
					return nil
				}
				return acquiredPacketConn
			}, func() io.Closer {
				if nilFactoryResult(acquiredPacketConn) {
					return nil
				}
				return acquiredPacketConn
			}, func() (transport.PathConn, error) {
				endpoint, err := factory(ctx, spec.Address)
				acquiredPacketConn = endpoint.Conn
				if err != nil {
					return nil, err
				}
				if nilFactoryResult(endpoint.Conn) {
					return nil, &FactoryError{
						FactoryID: spec.Transport,
						Kind:      FactoryKindPacket,
						Reason:    FactoryReasonInvalidPacketConn,
					}
				}
				if err := udpflow.ValidateDatagramSize(endpoint.MaxDatagramSize); err != nil {
					return nil, &FactoryError{
						FactoryID: spec.Transport,
						Kind:      FactoryKindPacket,
						Reason:    FactoryReasonInvalidPacketCapacity,
					}
				}
				peer, peerErr := udpflow.SnapshotPeer(endpoint.Peer)
				if peerErr != nil {
					return nil, &FactoryError{
						FactoryID: spec.Transport,
						Kind:      FactoryKindPacket,
						Reason:    FactoryReasonInvalidPacketPeer,
					}
				}
				if peerErr := acceptCustomPacketPeerSnapshot(endpoint.Conn, peer); peerErr != nil {
					return nil, &FactoryError{
						FactoryID: spec.Transport,
						Kind:      FactoryKindPacket,
						Reason:    FactoryReasonInvalidPacketPeer,
					}
				}
				return udpflow.Wrap(endpoint.Conn, peer, flowID, endpoint.MaxDatagramSize)
			})
			if err != nil {
				return nil, nil, err
			}
			return path, retained, nil
		}
		if factory, ok := r.framed[spec.Transport]; ok {
			if isBuiltinPathFactory(spec.Transport) {
				if reserved != nil {
					reserved.release()
					return nil, nil, fmt.Errorf("rendr: built-in path factory %q cannot consume external cleanup authority", spec.Transport)
				}
				// Built-in factories are rendr code. Never recover their panics as
				// caller failures; doing so would hide an internal invariant bug.
				conn, err := factory.DialPath(ctx, spec)
				if err != nil {
					return nil, nil, err
				}
				if nilFactoryResult(conn) {
					return nil, nil, fmt.Errorf("rendr: built-in path factory %q returned a nil connection", spec.Transport)
				}
				return conn, nil, nil
			}
			conn, retained, err := invokePathFactoryOwned(ctx, r.factoryCallGate(spec.Transport, FactoryKindFramed), reserved, retainSuccess, spec.Transport, FactoryKindFramed, func() (transport.PathConn, error) {
				return factory.DialPath(ctx, spec)
			})
			if err != nil {
				return nil, nil, err
			}
			if nilFactoryResult(conn) {
				return nil, nil, factoryErrorWithContext(ctx, &FactoryError{
					FactoryID: spec.Transport,
					Kind:      FactoryKindFramed,
					Reason:    FactoryReasonNilResult,
				})
			}
			return conn, retained, nil
		}
	}
	reserved.release()
	return nil, nil, fmt.Errorf("rendr: path factory %q is not registered on this Runtime", spec.Transport)
}

func preparePacketFactoryFlowID(spec PathSpec) ([proto.UDPFlowIDSize]byte, error) {
	var flowID [proto.UDPFlowIDSize]byte
	if encoded := spec.Opts["flow_id_hex"]; encoded != "" {
		if len(encoded) != 2*proto.UDPFlowIDSize {
			return flowID, fmt.Errorf("udpflow: flow_id_hex must be %d hex chars", 2*proto.UDPFlowIDSize)
		}
		if _, err := hex.Decode(flowID[:], []byte(encoded)); err != nil {
			return flowID, fmt.Errorf("udpflow: invalid flow_id_hex: %w", err)
		}
		return flowID, nil
	}
	if _, err := rand.Read(flowID[:]); err != nil {
		return flowID, err
	}
	return flowID, nil
}

type preAdoptionPathState uint8

const (
	preAdoptionPathOwned preAdoptionPathState = iota
	preAdoptionPathClosing
	preAdoptionPathClosed
	preAdoptionPathTransferred
)

// preAdoptionPathLease owns a custom-factory path until an engine explicitly
// accepts it. Callers inspect Path, then call ReleaseToEngine only when the
// engine reports ownership; every other branch calls Close. Close invokes the
// external callback at most once and returns within callerFactoryCleanupWait.
type preAdoptionPathLease struct {
	path      transport.PathConn
	factoryID string
	kind      FactoryKind
	external  bool
	permit    *factoryCallbackPermit

	mu       sync.Mutex
	state    preAdoptionPathState
	closeErr error
	closed   chan struct{}
}

// dialPathForAdoption is the ownership-explicit counterpart to dialPath. Root
// admission call sites should use it whenever a successful path may still need
// cleanup before engine adoption.
func (r *pathFactoryResolver) dialPathForAdoption(ctx context.Context, spec PathSpec) (*preAdoptionPathLease, error) {
	kind, external := r.customFactoryKind(spec.Transport)
	var (
		path   transport.PathConn
		permit *factoryCallbackPermit
		err    error
	)
	if external {
		permit, err = acquireFactoryCallbackPermit(r.runtimeBudget, spec.Transport, kind)
		if err != nil {
			return nil, err
		}
		path, permit, err = r.dialPathOwned(ctx, spec, permit, true)
	} else {
		path, err = r.dialPath(ctx, spec)
	}
	if err != nil {
		return nil, err
	}
	if external && permit == nil {
		panic("rendr: successful external path lost pre-adoption cleanup authority")
	}
	return &preAdoptionPathLease{
		path:      path,
		factoryID: spec.Transport,
		kind:      kind,
		external:  external,
		permit:    permit,
		closed:    make(chan struct{}),
	}, nil
}

func (r *pathFactoryResolver) customFactoryKind(factoryID string) (FactoryKind, bool) {
	if r == nil {
		return "", false
	}
	if _, ok := r.stream[factoryID]; ok {
		return FactoryKindStream, true
	}
	if _, ok := r.packet[factoryID]; ok {
		return FactoryKindPacket, true
	}
	if _, ok := r.framed[factoryID]; ok && !isBuiltinPathFactory(factoryID) {
		return FactoryKindFramed, true
	}
	return "", false
}

func (l *preAdoptionPathLease) Path() transport.PathConn {
	if l == nil {
		return nil
	}
	return l.path
}

func (l *preAdoptionPathLease) ReleaseToEngine() error {
	if l == nil {
		return errors.New("rendr: nil pre-adoption path lease")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch l.state {
	case preAdoptionPathOwned:
		l.state = preAdoptionPathTransferred
		permit := l.permit
		l.permit = nil
		permit.release()
		return nil
	case preAdoptionPathTransferred:
		return nil
	default:
		return fmt.Errorf("rendr: path factory %q cannot transfer a path after cleanup started", l.factoryID)
	}
}

func (l *preAdoptionPathLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	switch l.state {
	case preAdoptionPathTransferred:
		l.mu.Unlock()
		return nil
	case preAdoptionPathClosed:
		err := l.closeErr
		l.mu.Unlock()
		return err
	case preAdoptionPathOwned:
		if !l.external {
			l.state = preAdoptionPathClosing
			l.mu.Unlock()
			err := l.path.Close()
			l.finishClose(err)
			return err
		}
		l.state = preAdoptionPathClosing
		go l.closeExternal()
	}
	closed := l.closed
	l.mu.Unlock()

	timer := time.NewTimer(callerFactoryCleanupWait)
	defer timer.Stop()
	select {
	case <-closed:
		l.mu.Lock()
		err := l.closeErr
		l.mu.Unlock()
		return err
	case <-timer.C:
		return &FactoryError{
			FactoryID: l.factoryID,
			Kind:      l.kind,
			Reason:    FactoryReasonCleanupTimeout,
		}
	}
}

func (l *preAdoptionPathLease) closeExternal() {
	var terminalErr error
	completed := false
	defer func() {
		if !completed {
			recovered := recover()
			panicType := ""
			if recovered != nil {
				panicType = reflect.TypeOf(recovered).String()
			}
			terminalErr = &FactoryError{
				FactoryID: l.factoryID,
				Kind:      l.kind,
				Reason:    FactoryReasonCleanup,
				PanicType: panicType,
			}
		}
		l.finishClose(terminalErr)
	}()
	terminalErr = l.path.Close()
	completed = true
}

func (l *preAdoptionPathLease) finishClose(err error) {
	l.mu.Lock()
	l.closeErr = err
	l.state = preAdoptionPathClosed
	permit := l.permit
	l.permit = nil
	permit.release()
	close(l.closed)
	l.mu.Unlock()
}

// invokePathFactory isolates only caller code. Wrapping, framing, and all
// rendr-owned code run outside this boundary so their panics remain visible.
func invokePathFactory[T any](ctx context.Context, gate *factoryCallGate, factoryID string, kind FactoryKind, invoke func() (T, error)) (result T, err error) {
	result, _, err = invokePathFactoryOwned(ctx, gate, nil, false, factoryID, kind, invoke)
	return result, err
}

func invokePathFactoryOwned[T any](
	ctx context.Context,
	gate *factoryCallGate,
	reserved *factoryCallbackPermit,
	retainSuccess bool,
	factoryID string,
	kind FactoryKind,
	invoke func() (T, error),
) (result T, retained *factoryCallbackPermit, err error) {
	return invokePathFactoryOwnedWithCloser(ctx, gate, reserved, retainSuccess, factoryID, kind, factoryResultCloser[T], nil, invoke)
}

func invokePathFactoryOwnedWithCloser[T any](
	ctx context.Context,
	gate *factoryCallGate,
	reserved *factoryCallbackPermit,
	retainSuccess bool,
	factoryID string,
	kind FactoryKind,
	resultCloser func(T) io.Closer,
	abnormalResultCloser func() io.Closer,
	invoke func() (T, error),
) (result T, retained *factoryCallbackPermit, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		reserved.release()
		return result, nil, ctxErr
	}
	owner, err := gate.acquire(factoryID, kind, reserved)
	if err != nil {
		return result, nil, err
	}

	call := waitCallerFactory(ctx, startCallerFactory(owner, factoryID, kind, resultCloser, abnormalResultCloser, invoke))
	if call == nil {
		return result, nil, ctx.Err()
	}
	if call.failure != nil {
		var zero T
		call.failure.FactoryID = factoryID
		call.failure.Kind = kind
		failureErr := factoryErrorWithContext(ctx, call.failure)
		if call.abnormalCloser == nil {
			owner.complete(nil)
			return zero, nil, failureErr
		}
		cleanup := startFactoryResultCleanup(owner, factoryID, kind, call.abnormalCloser, false, nil)
		cleanupErr := waitFactoryResultCleanup(cleanup, factoryID, kind)
		return zero, nil, joinFactoryErrors(failureErr, cleanupErr)
	}
	result, err = call.value, call.err
	closer := resultCloser(result)

	ctxErr := ctx.Err()
	if err == nil && ctxErr == nil {
		if retainSuccess && closer != nil {
			return result, owner.transferPermit(), nil
		}
		owner.complete(nil)
		return result, nil, nil
	}
	if err == nil && closer == nil {
		// Let the caller classify the invalid nil result and join the context
		// cause, preserving both machine-readable facts.
		owner.complete(nil)
		return result, nil, nil
	}
	if closer == nil {
		owner.complete(nil)
		var zero T
		return zero, nil, joinFactoryErrors(ctxErr, err)
	}
	cleanup := startFactoryResultCleanup(owner, factoryID, kind, closer, false, nil)
	cleanupErr := waitFactoryResultCleanup(cleanup, factoryID, kind)
	var zero T
	return zero, nil, joinFactoryErrors(ctxErr, err, cleanupErr)
}

type callerFactoryResult[T any] struct {
	value          T
	err            error
	failure        *FactoryError
	abnormalCloser io.Closer
}

const (
	callerFactoryWaiting uint32 = iota
	callerFactoryDelivered
	callerFactoryAbandoned
)

const callerFactoryCancellationHandoff = 5 * time.Millisecond

type callerFactoryInvocation[T any] struct {
	state          atomic.Uint32
	result         chan callerFactoryResult[T]
	owner          *factoryCallLease
	abandonedReady chan struct{}
}

func startCallerFactory[T any](
	owner *factoryCallLease,
	factoryID string,
	kind FactoryKind,
	resultCloser func(T) io.Closer,
	abnormalResultCloser func() io.Closer,
	invoke func() (T, error),
) *callerFactoryInvocation[T] {
	call := &callerFactoryInvocation[T]{
		result:         make(chan callerFactoryResult[T], 1),
		owner:          owner,
		abandonedReady: make(chan struct{}),
	}
	go func() {
		var terminal callerFactoryResult[T]
		completed := false
		defer func() {
			if !completed {
				recovered := recover()
				reason := FactoryReasonAbnormal
				panicType := ""
				if recovered != nil {
					reason = FactoryReasonPanic
					panicType = reflect.TypeOf(recovered).String()
				}
				terminal.failure = &FactoryError{Reason: reason, PanicType: panicType}
				if abnormalResultCloser != nil {
					terminal.abnormalCloser = abnormalResultCloser()
				}
			}
			if call.state.CompareAndSwap(callerFactoryWaiting, callerFactoryDelivered) {
				call.result <- terminal
			} else {
				<-call.abandonedReady
				// Cancellation transferred ownership to this worker. Reap any
				// late connection before allowing another invocation through.
				lateErr := callerFactoryTerminalError(terminal, factoryID, kind)
				closer := terminal.abnormalCloser
				if closer == nil {
					closer = resultCloser(terminal.value)
				}
				if closer == nil {
					owner.complete(lateErr)
				} else {
					startFactoryResultCleanup(owner, factoryID, kind, closer, true, lateErr)
				}
			}
		}()
		terminal.value, terminal.err = invoke()
		completed = true
	}()
	return call
}

func waitCallerFactory[T any](ctx context.Context, call *callerFactoryInvocation[T]) *callerFactoryResult[T] {
	select {
	case result := <-call.result:
		return &result
	case <-ctx.Done():
		// Preserve a result that caused cancellation immediately before returning
		// (for example cancel followed by panic or a nil result). This handoff is
		// strictly bounded; a callback that ignores context cannot extend it.
		timer := time.NewTimer(callerFactoryCancellationHandoff)
		defer timer.Stop()
		select {
		case result := <-call.result:
			return &result
		case <-timer.C:
		}
		if call.state.CompareAndSwap(callerFactoryWaiting, callerFactoryAbandoned) {
			call.owner.markUnresolved()
			close(call.abandonedReady)
			return nil
		}
		// The callback has already completed and owns result publication.
		// The buffered send below cannot depend on caller code or I/O.
		result := <-call.result
		return &result
	}
}

func callerFactoryTerminalError[T any](call callerFactoryResult[T], factoryID string, kind FactoryKind) error {
	if call.failure != nil {
		call.failure.FactoryID = factoryID
		call.failure.Kind = kind
		return joinFactoryErrors(call.err, call.failure)
	}
	return call.err
}

const callerFactoryCleanupWait = 50 * time.Millisecond

const (
	callerCleanupWaiting uint32 = iota
	callerCleanupDelivered
	callerCleanupAbandoned
)

type callerFactoryCleanup struct {
	state          atomic.Uint32
	result         chan error
	owner          *factoryCallLease
	abandonedReady chan struct{}
}

func startFactoryResultCleanup(
	owner *factoryCallLease,
	factoryID string,
	kind FactoryKind,
	closer io.Closer,
	detached bool,
	priorErr error,
) *callerFactoryCleanup {
	cleanup := &callerFactoryCleanup{
		result:         make(chan error, 1),
		owner:          owner,
		abandonedReady: make(chan struct{}),
	}
	if detached {
		cleanup.state.Store(callerCleanupAbandoned)
		close(cleanup.abandonedReady)
	}
	go func() {
		var terminalErr error
		completed := false
		defer func() {
			if !completed {
				recovered := recover()
				panicType := ""
				if recovered != nil {
					panicType = reflect.TypeOf(recovered).String()
				}
				terminalErr = &FactoryError{
					FactoryID: factoryID,
					Kind:      kind,
					Reason:    FactoryReasonCleanup,
					PanicType: panicType,
				}
			}
			if cleanup.state.CompareAndSwap(callerCleanupWaiting, callerCleanupDelivered) {
				cleanup.result <- terminalErr
			} else {
				<-cleanup.abandonedReady
				owner.complete(joinFactoryErrors(priorErr, terminalErr))
			}
		}()
		terminalErr = closer.Close()
		completed = true
	}()
	return cleanup
}

func factoryResultCloser[T any](value T) io.Closer {
	if nilFactoryResult(value) {
		return nil
	}
	closer, ok := any(value).(io.Closer)
	if !ok {
		panic("rendr: internal factory result does not implement io.Closer")
	}
	return closer
}

func validatedPacketEndpointCloser(endpoint validatedPacketEndpoint) io.Closer {
	if nilFactoryResult(endpoint.conn) {
		return nil
	}
	return endpoint.conn
}

func acceptCustomPacketPeerSnapshot(conn net.PacketConn, peer udpflow.PeerSnapshot) (err error) {
	if peer.IsStandard() {
		return nil
	}
	acceptor, ok := conn.(PacketPeerSnapshotAcceptor)
	if !ok {
		return udpflow.ErrInvalidPeerIdentity
	}
	defer func() {
		if recover() != nil {
			err = udpflow.ErrInvalidPeerIdentity
		}
	}()
	if acceptor.AcceptPacketPeerSnapshot(peer.OutboundAddr()) != nil {
		return udpflow.ErrInvalidPeerIdentity
	}
	return nil
}

func waitFactoryResultCleanup(cleanup *callerFactoryCleanup, factoryID string, kind FactoryKind) error {
	timer := time.NewTimer(callerFactoryCleanupWait)
	defer timer.Stop()
	select {
	case err := <-cleanup.result:
		cleanup.owner.complete(nil)
		return err
	case <-timer.C:
		if cleanup.state.CompareAndSwap(callerCleanupWaiting, callerCleanupAbandoned) {
			cleanup.owner.markUnresolved()
			close(cleanup.abandonedReady)
			return &FactoryError{
				FactoryID: factoryID,
				Kind:      kind,
				Reason:    FactoryReasonCleanupTimeout,
			}
		}
		// Completion won the handoff. Publication is buffered and contains no
		// caller code, so waiting here cannot exceed the cleanup callback.
		err := <-cleanup.result
		cleanup.owner.complete(nil)
		return err
	}
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
