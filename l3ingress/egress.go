package l3ingress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"time"
)

// Direction identifies where a classified flow entered rendr.
type Direction uint8

const (
	DirectionIngress Direction = iota + 1
	DirectionEgress
)

// TCPConn is the peer-side stream contract required by TUN-originated TCP
// flows. A plain net.Conn is insufficient because request EOF must propagate
// without closing the reverse response direction.
type TCPConn interface {
	net.Conn
	CloseWrite() error
}

// Egress is implemented by embedding programs that own the final
// peer-side landing choice for a TUN-originated flow.
type Egress interface {
	DialTCP(ctx context.Context, id L3Identity) (TCPConn, error)
	DialUDP(ctx context.Context, id L3Identity) (net.PacketConn, netip.AddrPort, error)
}

// EgressErrorReason is a machine-readable peer egress dispatch failure.
type EgressErrorReason string

const (
	ReasonInvalidEgressName   EgressErrorReason = "invalid_egress_name"
	ReasonEgressNotFound      EgressErrorReason = "egress_not_found"
	ReasonProtocolMismatch    EgressErrorReason = "protocol_mismatch"
	ReasonInvalidEgressConn   EgressErrorReason = "invalid_egress_connection"
	ReasonInvalidEgressResult EgressErrorReason = "invalid_egress_result"
)

// DefaultEgressCloseTimeout bounds embedding-provided connection cleanup.
// A callback that outlives the bound keeps its sole cleanup authority and may
// finish later; rendr never starts a second Close call for the same connection.
const DefaultEgressCloseTimeout = 100 * time.Millisecond

// DefaultEgressDialTimeout bounds embedding-provided egress selection when the
// caller has no earlier deadline.
const DefaultEgressDialTimeout = 5 * time.Second

const l3IngressRelayCloseWorkerLimit = l3IngressProcessCallbackLimit

// Kept for package-local tests that assert the single-relay subset of the
// process-wide bound.
const l3IngressRelayCloseFanoutLimit = l3IngressRelayCloseWorkerLimit

// One TCP flow owns an ingress endpoint and an egress connection. Reserving
// twice the flow-table capacity lets every admitted flow retain durable cleanup
// authority without allowing an unbounded queue of external objects.
const l3IngressCleanupAuthorityLimit = 2 * DefaultFlowTableActiveCapacity

var (
	l3IngressCleanupAuthoritySlots = make(chan struct{}, l3IngressCleanupAuthorityLimit)
	l3IngressCleanupQueue          = make(chan *egressCloseAuthority, l3IngressCleanupAuthorityLimit)
	l3IngressCleanupDispatcherOnce sync.Once
	l3IngressRelayCloseSlots       = make(chan struct{}, l3IngressRelayCloseWorkerLimit)
	l3IngressRelayCloseQueue       = make(chan *relayCloseJob, l3IngressCleanupAuthorityLimit)
	l3IngressRelayCloseOnce        sync.Once
)

// EgressError keeps peer-side dispatch failures inspectable.
type EgressError struct {
	Reason EgressErrorReason
	Name   string
	Proto  Protocol
}

func (e *EgressError) Error() string {
	switch e.Reason {
	case ReasonInvalidEgressName:
		return "l3ingress: invalid egress name"
	case ReasonEgressNotFound:
		return fmt.Sprintf("l3ingress: egress %q not found", e.Name)
	case ReasonProtocolMismatch:
		return fmt.Sprintf("l3ingress: egress %q cannot handle %s identity", e.Name, e.Proto)
	case ReasonInvalidEgressConn:
		return fmt.Sprintf("l3ingress: egress %q returned a nil connection", e.Name)
	case ReasonInvalidEgressResult:
		return fmt.Sprintf("l3ingress: egress %q returned both a connection and an error", e.Name)
	default:
		return "l3ingress: egress error"
	}
}

// EgressRegistry dispatches peer-side flows to embedding-provided
// egress hooks. It does not implement any final network egress itself.
type EgressRegistry struct {
	mu     sync.RWMutex
	egress map[string]Egress
}

// NewEgressRegistry creates an empty peer egress registry.
func NewEgressRegistry() *EgressRegistry {
	return &EgressRegistry{egress: make(map[string]Egress)}
}

// Register adds or replaces a named embedding-provided egress hook.
func (r *EgressRegistry) Register(name string, e Egress) error {
	if name == "" || nilInterface(e) {
		return &EgressError{Reason: ReasonInvalidEgressName, Name: name}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.egress[name] = e
	return nil
}

// Unregister removes a named egress hook.
func (r *EgressRegistry) Unregister(name string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.egress, name)
}

// Lookup returns a registered egress hook.
func (r *EgressRegistry) Lookup(name string) (Egress, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.egress[name]
	return e, ok
}

// DialTCP dispatches a TCP identity to the named peer-side egress hook.
func (r *EgressRegistry) DialTCP(ctx context.Context, name string, id L3Identity) (TCPConn, error) {
	return r.dialTCPObserved(ctx, name, id, nil, nil)
}

func (r *EgressRegistry) dialTCPObserved(
	ctx context.Context,
	name string,
	id L3Identity,
	onSettled func(),
	observer func(error),
) (TCPConn, error) {
	if id.Proto != ProtocolTCP {
		settleEgressDial(onSettled)
		return nil, &EgressError{Reason: ReasonProtocolMismatch, Name: name, Proto: id.Proto}
	}
	e, err := r.require(name)
	if err != nil {
		settleEgressDial(onSettled)
		return nil, err
	}
	reservation, err := reserveEgressCleanupAuthority("Egress.DialTCP cleanup authority")
	if err != nil {
		settleEgressDial(onSettled)
		return nil, err
	}
	bound := false
	defer func() {
		if !bound {
			reservation.Release()
		}
	}()
	result, invokeErr, transferred := invokeEgressCallback(
		ctx,
		"Egress.DialTCP",
		func(callbackCtx context.Context) tcpEgressDialResult {
			conn, callbackErr := e.DialTCP(callbackCtx, id)
			return tcpEgressDialResult{conn: conn, err: callbackErr}
		},
		func(result tcpEgressDialResult, invocationErr error) {
			cleanupLateTCPEgressResult(reservation, result, invocationErr, onSettled, observer)
		},
	)
	if transferred {
		bound = true
	}
	if invokeErr != nil {
		if !transferred {
			settleEgressDial(onSettled)
		}
		return nil, invokeErr
	}
	conn, err := result.conn, result.err
	if nilInterface(conn) {
		if err != nil {
			settleEgressDial(onSettled)
			return nil, err
		}
		settleEgressDial(onSettled)
		return nil, &EgressError{Reason: ReasonInvalidEgressConn, Name: name, Proto: id.Proto}
	}
	authority := reservation.BindWithSettlement(
		conn,
		"Egress.DialTCP connection Close",
		onSettled,
	)
	authority.observeLateTerminal(observer)
	bound = true
	if err != nil {
		cleanupErr := authority.Close()
		return nil, errors.Join(
			&EgressError{Reason: ReasonInvalidEgressResult, Name: name, Proto: id.Proto},
			err,
			cleanupErr,
		)
	}
	return &authoritativeTCPConn{TCPConn: conn, authority: authority}, nil
}

// DialUDP dispatches a UDP identity to the named peer-side egress hook.
func (r *EgressRegistry) DialUDP(ctx context.Context, name string, id L3Identity) (net.PacketConn, netip.AddrPort, error) {
	return r.dialUDPWithSettlement(ctx, name, id, nil, nil)
}

func (r *EgressRegistry) dialUDPWithSettlement(
	ctx context.Context,
	name string,
	id L3Identity,
	onLateSettlement func(),
	observer func(error),
) (net.PacketConn, netip.AddrPort, error) {
	if id.Proto != ProtocolUDP {
		settleEgressDial(onLateSettlement)
		return nil, netip.AddrPort{}, &EgressError{Reason: ReasonProtocolMismatch, Name: name, Proto: id.Proto}
	}
	e, err := r.require(name)
	if err != nil {
		settleEgressDial(onLateSettlement)
		return nil, netip.AddrPort{}, err
	}
	reservation, err := reserveEgressCleanupAuthority("Egress.DialUDP cleanup authority")
	if err != nil {
		settleEgressDial(onLateSettlement)
		return nil, netip.AddrPort{}, err
	}
	bound := false
	defer func() {
		if !bound {
			reservation.Release()
		}
	}()
	result, invokeErr, transferred := invokeEgressCallback(
		ctx,
		"Egress.DialUDP",
		func(callbackCtx context.Context) udpEgressDialResult {
			conn, remote, callbackErr := e.DialUDP(callbackCtx, id)
			return udpEgressDialResult{conn: conn, remote: remote, err: callbackErr}
		},
		func(result udpEgressDialResult, invocationErr error) {
			cleanupLateUDPEgressResult(reservation, result, invocationErr, onLateSettlement, observer)
		},
	)
	if transferred {
		bound = true
	}
	if invokeErr != nil {
		if !transferred {
			settleEgressDial(onLateSettlement)
		}
		return nil, netip.AddrPort{}, invokeErr
	}
	conn, remote, err := result.conn, result.remote, result.err
	if nilInterface(conn) {
		if err != nil {
			settleEgressDial(onLateSettlement)
			return nil, netip.AddrPort{}, err
		}
		settleEgressDial(onLateSettlement)
		return nil, netip.AddrPort{}, &EgressError{Reason: ReasonInvalidEgressConn, Name: name, Proto: id.Proto}
	}
	authority := reservation.BindWithSettlement(
		conn,
		"Egress.DialUDP connection Close",
		onLateSettlement,
	)
	authority.observeLateTerminal(observer)
	bound = true
	if err != nil {
		cleanupErr := authority.Close()
		return nil, netip.AddrPort{}, errors.Join(
			&EgressError{Reason: ReasonInvalidEgressResult, Name: name, Proto: id.Proto},
			err,
			cleanupErr,
		)
	}
	return &authoritativePacketConn{PacketConn: conn, authority: authority}, remote, nil
}

type egressCloser interface {
	Close() error
}

type tcpEgressDialResult struct {
	conn TCPConn
	err  error
}

type udpEgressDialResult struct {
	conn   net.PacketConn
	remote netip.AddrPort
	err    error
}

type egressInvocationResult[T any] struct {
	value T
	err   error
}

func invokeEgressCallback[T any](
	ctx context.Context,
	callback string,
	invoke func(context.Context) T,
	cleanupLate func(T, error),
) (zero T, err error, reservationTransferred bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return zero, err, false
	}
	releaseProcess, ok := tryAcquireL3IngressCallback(l3IngressCallbackEgressInvoke)
	if !ok {
		return zero, &CallbackError{Callback: callback, Reason: CallbackFailureSaturated}, false
	}
	callbackCtx, cancel := context.WithTimeout(ctx, DefaultEgressDialTimeout)
	resultCh := make(chan egressInvocationResult[T])
	accepted := make(chan struct{})
	abandoned := make(chan struct{})
	go func() {
		result := egressInvocationResult[T]{
			err: &CallbackError{Callback: callback, Reason: CallbackFailureGoexit},
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				result = egressInvocationResult[T]{err: callbackPanicError(callback, recovered)}
			}
			releaseProcess()
			select {
			case resultCh <- result:
				select {
				case <-accepted:
				case <-abandoned:
					cleanupLate(result.value, result.err)
				}
			case <-abandoned:
				cleanupLate(result.value, result.err)
			}
		}()
		result = egressInvocationResult[T]{value: invoke(callbackCtx)}
	}()
	select {
	case result := <-resultCh:
		close(accepted)
		cancel()
		return result.value, result.err, false
	case <-callbackCtx.Done():
		close(abandoned)
		callbackErr := callbackCtx.Err()
		cancel()
		if errors.Is(callbackErr, context.DeadlineExceeded) {
			return zero, &CallbackError{Callback: callback, Reason: CallbackFailureTimeout}, true
		}
		return zero, callbackErr, true
	}
}

func cleanupLateTCPEgressResult(
	reservation *egressCleanupReservation,
	result tcpEgressDialResult,
	invocationErr error,
	onSettled func(),
	observer func(error),
) {
	reportEgressDiagnostic(observer, invocationErr)
	reportEgressDiagnostic(observer, result.err)
	if nilInterface(result.conn) {
		reservation.Release()
		settleEgressDial(onSettled)
		return
	}
	authority := reservation.BindWithSettlement(
		result.conn,
		"late Egress.DialTCP result Close",
		onSettled,
	)
	authority.observeLateTerminal(observer)
	reportEgressDiagnostic(observer, authority.Close())
}

func cleanupLateUDPEgressResult(
	reservation *egressCleanupReservation,
	result udpEgressDialResult,
	invocationErr error,
	onSettled func(),
	observer func(error),
) {
	reportEgressDiagnostic(observer, invocationErr)
	reportEgressDiagnostic(observer, result.err)
	if nilInterface(result.conn) {
		reservation.Release()
		settleEgressDial(onSettled)
		return
	}
	authority := reservation.BindWithSettlement(
		result.conn,
		"late Egress.DialUDP result Close",
		onSettled,
	)
	authority.observeLateTerminal(observer)
	reportEgressDiagnostic(observer, authority.Close())
}

func settleEgressDial(onSettled func()) {
	if onSettled != nil {
		onSettled()
	}
}

func reportEgressDiagnostic(observer func(error), err error) {
	if observer != nil && err != nil {
		observer(err)
	}
}

type egressCleanupReservation struct {
	releaseOnce sync.Once
}

func reserveEgressCleanupAuthority(callback string) (*egressCleanupReservation, error) {
	select {
	case l3IngressCleanupAuthoritySlots <- struct{}{}:
		return &egressCleanupReservation{}, nil
	default:
		return nil, &CallbackError{Callback: callback, Reason: CallbackFailureSaturated}
	}
}

func (r *egressCleanupReservation) Bind(closer egressCloser, callback string) *egressCloseAuthority {
	return r.BindWithSettlement(closer, callback, nil)
}

func (r *egressCleanupReservation) BindWithSettlement(
	closer egressCloser,
	callback string,
	onSettled func(),
) *egressCloseAuthority {
	return &egressCloseAuthority{
		closer:      closer,
		callback:    callback,
		reservation: r,
		done:        make(chan struct{}),
		onSettled:   onSettled,
	}
}

func (r *egressCleanupReservation) Release() {
	if r == nil {
		return
	}
	r.releaseOnce.Do(func() { <-l3IngressCleanupAuthoritySlots })
}

type authoritativeCloser interface {
	egressAuthority() *egressCloseAuthority
}

type authoritativeTCPConn struct {
	TCPConn
	authority *egressCloseAuthority
}

func (c *authoritativeTCPConn) Close() error { return c.authority.Close() }
func (c *authoritativeTCPConn) egressAuthority() *egressCloseAuthority {
	return c.authority
}

type authoritativePacketConn struct {
	net.PacketConn
	authority *egressCloseAuthority
}

func (c *authoritativePacketConn) Close() error { return c.authority.Close() }
func (c *authoritativePacketConn) egressAuthority() *egressCloseAuthority {
	return c.authority
}

func closeAuthorityOf(closer egressCloser) (*egressCloseAuthority, bool) {
	owned, ok := closer.(authoritativeCloser)
	if !ok || owned.egressAuthority() == nil {
		return nil, false
	}
	return owned.egressAuthority(), true
}

// egressCloseAuthority is the only code path allowed to invoke one external
// connection's Close method. The process callback slot remains held until the
// callback actually exits, including after the caller observes a timeout.
type egressCloseAuthority struct {
	closer      egressCloser
	callback    string
	reservation *egressCleanupReservation

	once      sync.Once
	done      chan struct{}
	mu        sync.Mutex
	err       error
	completed bool
	timedOut  bool

	onSettled            func()
	lateTerminal         func(error)
	lateTerminalReported bool
}

func newEgressCloseAuthority(closer egressCloser, callback string) (*egressCloseAuthority, error) {
	reservation, err := reserveEgressCleanupAuthority(callback + " authority")
	if err != nil {
		return nil, err
	}
	return reservation.Bind(closer, callback), nil
}

func (a *egressCloseAuthority) Close() error {
	if a == nil || a.closer == nil {
		return nil
	}
	a.once.Do(a.start)
	timer := time.NewTimer(DefaultEgressCloseTimeout)
	defer stopFlowCallbackTimer(timer)
	select {
	case <-a.done:
		a.mu.Lock()
		err := a.err
		a.mu.Unlock()
		return err
	case <-timer.C:
		a.mu.Lock()
		if a.completed {
			err := a.err
			a.mu.Unlock()
			return err
		}
		a.timedOut = true
		a.mu.Unlock()
		return &CallbackError{Callback: a.callback, Reason: CallbackFailureTimeout}
	}
}

func (a *egressCloseAuthority) start() {
	l3IngressCleanupDispatcherOnce.Do(func() { go dispatchEgressCleanup() })
	// Queue capacity equals the number of durable reservations. Because one
	// authority enqueues at most once and releases only after execution, an
	// admitted authority always has queue capacity here.
	l3IngressCleanupQueue <- a
}

func (a *egressCloseAuthority) run(releaseProcess func()) {
	result := error(&CallbackError{Callback: a.callback, Reason: CallbackFailureGoexit})
	defer func() {
		if recovered := recover(); recovered != nil {
			result = callbackPanicError(a.callback, recovered)
		}
		releaseProcess()
		a.reservation.Release()
		a.complete(result)
	}()
	result = a.closer.Close()
}

func dispatchEgressCleanup() {
	slots := l3IngressProcessCallbackSlots[l3IngressCallbackEgressCleanup]
	for authority := range l3IngressCleanupQueue {
		// This is the sole capacity waiter. A full executor blocks one fixed
		// dispatcher rather than creating one waiter goroutine per connection.
		slots <- struct{}{}
		var releaseOnce sync.Once
		releaseProcess := func() { releaseOnce.Do(func() { <-slots }) }
		go authority.run(releaseProcess)
	}
}

func (a *egressCloseAuthority) complete(err error) {
	a.mu.Lock()
	a.err = err
	a.completed = true
	lateTerminal, terminalErr := a.takeLateTerminalLocked()
	a.mu.Unlock()
	if a.onSettled != nil {
		a.onSettled()
	}
	if lateTerminal != nil {
		lateTerminal(terminalErr)
	}
	close(a.done)
}

func (a *egressCloseAuthority) observeLateTerminal(observer func(error)) {
	if a == nil || observer == nil {
		return
	}
	a.mu.Lock()
	if a.lateTerminal == nil {
		a.lateTerminal = observer
	}
	lateTerminal, terminalErr := a.takeLateTerminalLocked()
	a.mu.Unlock()
	if lateTerminal != nil {
		lateTerminal(terminalErr)
	}
}

func (a *egressCloseAuthority) takeLateTerminalLocked() (func(error), error) {
	if !a.completed || !a.timedOut || a.lateTerminalReported || a.lateTerminal == nil {
		return nil, nil
	}
	a.lateTerminalReported = true
	return a.lateTerminal, a.err
}

// egressSessionCleanup binds all connection cleanup for one relay session to
// one sync.Once. Individual connections also retain their own once authority.
type egressSessionCleanup struct {
	once        sync.Once
	authorities []*egressCloseAuthority
	err         error
}

func newEgressSessionCleanup(authorities ...*egressCloseAuthority) *egressSessionCleanup {
	return &egressSessionCleanup{authorities: authorities}
}

func (c *egressSessionCleanup) observeLateTerminal(observer func(error)) {
	if c == nil || observer == nil {
		return
	}
	for _, authority := range c.authorities {
		authority.observeLateTerminal(observer)
	}
}

func (c *egressSessionCleanup) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		for _, authority := range c.authorities {
			c.err = errors.Join(c.err, authority.Close())
		}
	})
	return c.err
}

type relayCloseJob struct {
	run  func()
	done *sync.WaitGroup
}

func (j *relayCloseJob) execute() {
	defer func() {
		_ = recover()
		j.done.Done()
	}()
	j.run()
}

func dispatchRelayCloseJobs() {
	for job := range l3IngressRelayCloseQueue {
		l3IngressRelayCloseSlots <- struct{}{}
		go func(job *relayCloseJob) {
			defer func() { <-l3IngressRelayCloseSlots }()
			job.execute()
		}(job)
	}
}

func closeRelaySessionsBounded[K comparable, S any](sessions map[K]S, closeSession func(S)) {
	if len(sessions) == 0 {
		return
	}
	l3IngressRelayCloseOnce.Do(func() { go dispatchRelayCloseJobs() })
	var completed sync.WaitGroup
	completed.Add(len(sessions))
	for _, session := range sessions {
		session := session
		l3IngressRelayCloseQueue <- &relayCloseJob{
			run:  func() { closeSession(session) },
			done: &completed,
		}
	}
	completed.Wait()
}

func waitEgressWorker(done <-chan struct{}, callback string) error {
	if done == nil {
		return nil
	}
	timer := time.NewTimer(DefaultEgressCloseTimeout)
	defer stopFlowCallbackTimer(timer)
	select {
	case <-done:
		return nil
	case <-timer.C:
		select {
		case <-done:
			return nil
		default:
		}
		return &CallbackError{Callback: callback, Reason: CallbackFailureTimeout}
	}
}

func (r *EgressRegistry) require(name string) (Egress, error) {
	if name == "" {
		return nil, &EgressError{Reason: ReasonInvalidEgressName, Name: name}
	}
	if r == nil {
		return nil, &EgressError{Reason: ReasonEgressNotFound, Name: name}
	}
	r.mu.RLock()
	e, ok := r.egress[name]
	r.mu.RUnlock()
	if !ok {
		return nil, &EgressError{Reason: ReasonEgressNotFound, Name: name}
	}
	return e, nil
}

// EgressErrorReasonOf extracts a machine-readable reason from an egress error.
func EgressErrorReasonOf(err error) (EgressErrorReason, bool) {
	var e *EgressError
	if !errors.As(err, &e) {
		return "", false
	}
	return e.Reason, true
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface ||
		kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

// FlowMeta is passed to an external router before rendr starts a
// per-flow session.
type FlowMeta struct {
	L3Identity L3Identity
	Direction  Direction
	CreatedAt  time.Time
	Labels     map[string]string
}

// FlowDecision is the router's decision outcome. Root is intentionally
// opaque in this package so l3ingress stays below the root target graph
// and avoids importing the top-level rendr package.
type FlowDecision struct {
	Peer       string
	Root       any
	Egress     string
	Labels     map[string]string
	Deny       bool
	DenyReason string
}

// FlowDecisionFunc lets embedders reuse TUN/l3ingress while keeping
// domain, CIDR, user, or profile routing outside rendr core.
type FlowDecisionFunc func(context.Context, FlowMeta) (FlowDecision, error)
