// Package l3session bridges l3ingress flow decisions to concrete rendr
// stream or packet sessions.
package l3session

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

const (
	// defaultConfigureSessionConcurrency bounds callbacks that ignore their
	// caller's cancellation and remain in flight.
	defaultConfigureSessionConcurrency = 64
	// DefaultConfigureSessionTimeout bounds the legacy context-free callback.
	DefaultConfigureSessionTimeout = 5 * time.Second
	configureSessionProcessLimit   = 128
)

var configureSessionProcessSlots = make(chan struct{}, configureSessionProcessLimit)

func acquireSessionCallbackPermits(local, process chan struct{}) bool {
	select {
	case local <- struct{}{}:
	default:
		return false
	}
	select {
	case process <- struct{}{}:
		return true
	default:
		<-local
		return false
	}
}

func releaseSessionCallbackPermits(local, process chan struct{}) {
	<-process
	<-local
}

// ErrorReason is a machine-readable session start failure.
type ErrorReason string

const (
	ReasonUnsupportedKind ErrorReason = "unsupported_session_kind"
	ReasonUnsupportedRoot ErrorReason = "unsupported_root_target"
)

// CallbackFailureReason classifies a ConfigureSession boundary failure.
type CallbackFailureReason string

const (
	CallbackFailurePanic     CallbackFailureReason = "panic"
	CallbackFailureGoexit    CallbackFailureReason = "goexit"
	CallbackFailureTimeout   CallbackFailureReason = "timeout"
	CallbackFailureSaturated CallbackFailureReason = "saturated"
)

// CallbackError never retains or formats the recovered panic payload.
type CallbackError struct {
	Callback  string
	Reason    CallbackFailureReason
	PanicType string
}

func (e *CallbackError) Error() string {
	if e == nil {
		return "l3session: external callback failed"
	}
	message := "l3session: " + e.Callback + " callback " + string(e.Reason)
	if e.PanicType != "" {
		message += " (panic type " + e.PanicType + ")"
	}
	return message
}

func (e *CallbackError) Unwrap() error {
	if e != nil && e.Reason == CallbackFailureTimeout {
		return context.DeadlineExceeded
	}
	return nil
}

// Error keeps l3ingress-to-rendr bridge failures inspectable.
type Error struct {
	Reason ErrorReason
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "l3session: " + string(e.Reason)
	}
	return "l3session: " + string(e.Reason) + ": " + e.Detail
}

// Session is one concrete rendr session created for a classified L3 flow.
// Exactly one of Conn or PacketConn is non-nil.
type Session struct {
	request    l3ingress.SessionRequest
	conn       rendr.Conn
	packetConn rendr.PacketConn

	onCloseMu sync.Mutex
	onClose   []func()
	closeOnce sync.Once
	closed    atomic.Bool
	closeErr  error
}

// Request returns a defensive snapshot of the flow request that created the
// session. Mutable labels and target graph state are never shared with callers.
func (s *Session) Request() l3ingress.SessionRequest {
	if s == nil {
		return l3ingress.SessionRequest{}
	}
	return cloneSessionRequest(s.request)
}

// Conn returns the stable stream connection, or nil for packet sessions.
func (s *Session) Conn() rendr.Conn {
	if s == nil {
		return nil
	}
	return s.conn
}

// PacketConn returns the stable packet connection, or nil for stream
// sessions.
func (s *Session) PacketConn() rendr.PacketConn {
	if s == nil {
		return nil
	}
	return s.packetConn
}

// Close closes the underlying rendr session.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.closed.Store(true)
	// This is an owned rendr lifecycle, whose graceful close may legitimately
	// outlive the shorter timeout reserved for untrusted external callbacks.
	return s.closePhysical()
}

func (s *Session) closePhysical() error {
	s.closeOnce.Do(func() {
		s.onCloseMu.Lock()
		onClose := s.onClose
		s.onClose = nil
		s.onCloseMu.Unlock()
		for _, fn := range onClose {
			if fn != nil {
				fn()
			}
		}
		if s.conn != nil {
			s.closeErr = s.conn.Close()
			return
		}
		if s.packetConn != nil {
			s.closeErr = s.packetConn.Close()
		}
	})
	return s.closeErr
}

func (s *Session) addOnClose(fn func()) {
	if s == nil || fn == nil {
		return
	}
	s.onCloseMu.Lock()
	if s.closed.Load() {
		s.onCloseMu.Unlock()
		fn()
		return
	}
	s.onClose = append(s.onClose, fn)
	s.onCloseMu.Unlock()
}

func (s *Session) isClosed() bool {
	return s == nil || s.closed.Load()
}

// Starter starts rendr sessions for l3ingress SessionRequests.
type Starter struct {
	// Runtime owns factories, tuning, capabilities, and the rendr instance
	// identity shared by sessions. When nil, Starter creates one default
	// Runtime on first use and reuses it for its lifetime.
	Runtime *rendr.Runtime

	// ConfigureSession is the narrow per-session customization point. The L3
	// identity requirement is copied from the request after this hook returns,
	// so a hook cannot accidentally weaken fail-closed identity preservation.
	ConfigureSession func(l3ingress.SessionRequest, *rendr.SessionConfig) error
	// ConfigureSessionTimeout bounds callback initialization. Zero selects the
	// package default. Concurrency is an internal resource budget.
	ConfigureSessionTimeout time.Duration

	runtimeMu         sync.Mutex
	resolvedRuntime   *rendr.Runtime
	configureOnce     sync.Once
	configureSlots    chan struct{}
	configureTimeout  time.Duration
	configureErr      error
	configureActiveMu sync.Mutex
	configureActive   map[l3ingress.L3Identity]struct{}

	// configureSessionConcurrency is a package-test fault-injection override.
	configureSessionConcurrency int
	dataPlaneExecutor           *dataPlaneCallbackExecutor
}

// Start creates either a rendr Conn or PacketConn for req. req.Root must be a
// rendr.Target; lower l3ingress packages keep it opaque to avoid an import
// cycle.
func (s *Starter) Start(ctx context.Context, req l3ingress.SessionRequest) (*Session, error) {
	if s == nil {
		return nil, errors.New("l3session: nil Starter")
	}
	root, ok := req.Root.(rendr.Target)
	if !ok || root == nil {
		return nil, &Error{
			Reason: ReasonUnsupportedRoot,
			Detail: fmt.Sprintf("%T", req.Root),
		}
	}
	if err := requireCanonicalSessionRequest(req); err != nil {
		return nil, err
	}
	config := rendr.SessionConfig{
		Root:               root,
		PreserveL3Identity: req.PreserveL3Identity,
	}
	if s.ConfigureSession != nil {
		configured, err := s.invokeConfigureSession(ctx, req, config)
		if err != nil {
			return nil, err
		}
		config = configured
	}
	config.PreserveL3Identity = req.PreserveL3Identity
	runtime, err := s.sessionRuntime()
	if err != nil {
		return nil, err
	}
	switch req.Kind {
	case l3ingress.SessionKindStream:
		var cleanup *dataPlaneCleanupReservation
		if req.PreserveL3Identity {
			cleanup, err = reserveDataPlaneCleanupWithExecutor(
				dataPlaneExecutorOrProcess(s.dataPlaneExecutor),
				"Starter rejected stream Close",
			)
			if err != nil {
				return nil, err
			}
		}
		c, err := runtime.Dial(ctx, config)
		if err != nil {
			cleanup.Release()
			return nil, err
		}
		if req.PreserveL3Identity {
			if err := requirePeerL3Identity(c); err != nil {
				return nil, errors.Join(err, cleanup.Bind(c.Close).Close())
			}
			cleanup.Release()
		}
		return &Session{request: cloneSessionRequest(req), conn: c}, nil
	case l3ingress.SessionKindPacket:
		var cleanup *dataPlaneCleanupReservation
		if req.PreserveL3Identity {
			cleanup, err = reserveDataPlaneCleanupWithExecutor(
				dataPlaneExecutorOrProcess(s.dataPlaneExecutor),
				"Starter rejected packet Close",
			)
			if err != nil {
				return nil, err
			}
		}
		pc, err := runtime.DialPacket(ctx, config)
		if err != nil {
			cleanup.Release()
			return nil, err
		}
		if req.PreserveL3Identity {
			if err := requirePeerL3Identity(pc); err != nil {
				return nil, errors.Join(err, cleanup.Bind(pc.Close).Close())
			}
			cleanup.Release()
		}
		return &Session{request: cloneSessionRequest(req), packetConn: pc}, nil
	default:
		return nil, &Error{
			Reason: ReasonUnsupportedKind,
			Detail: string(req.Kind),
		}
	}
}

type configureSessionResult struct {
	config rendr.SessionConfig
	err    error
}

func (s *Starter) invokeConfigureSession(
	ctx context.Context,
	req l3ingress.SessionRequest,
	config rendr.SessionConfig,
) (rendr.SessionConfig, error) {
	if err := ctx.Err(); err != nil {
		return rendr.SessionConfig{}, err
	}
	s.configureOnce.Do(func() {
		concurrency := s.configureSessionConcurrency
		if concurrency < 0 {
			s.configureErr = errors.New("l3session: configure session concurrency must not be negative")
			return
		}
		if concurrency == 0 {
			concurrency = defaultConfigureSessionConcurrency
		}
		if concurrency > defaultConfigureSessionConcurrency {
			s.configureErr = fmt.Errorf(
				"l3session: configure session concurrency %d exceeds hard limit %d",
				concurrency, defaultConfigureSessionConcurrency,
			)
			return
		}
		timeout := s.ConfigureSessionTimeout
		if timeout < 0 {
			s.configureErr = errors.New("l3session: configure session timeout must not be negative")
			return
		}
		if timeout == 0 {
			timeout = DefaultConfigureSessionTimeout
		}
		s.configureSlots = make(chan struct{}, concurrency)
		s.configureTimeout = timeout
	})
	if s.configureErr != nil {
		return rendr.SessionConfig{}, s.configureErr
	}
	if !s.reserveConfigureSession(req.Identity) {
		return rendr.SessionConfig{}, &CallbackError{
			Callback: "ConfigureSession",
			Reason:   CallbackFailureSaturated,
		}
	}
	if !acquireSessionCallbackPermits(s.configureSlots, configureSessionProcessSlots) {
		s.releaseConfigureSession(req.Identity)
		return rendr.SessionConfig{}, &CallbackError{
			Callback: "ConfigureSession",
			Reason:   CallbackFailureSaturated,
		}
	}
	callbackCtx, cancel := context.WithTimeout(ctx, s.configureTimeout)
	defer cancel()
	results := make(chan configureSessionResult, 1)
	callback := s.ConfigureSession
	callbackReq := cloneSessionRequest(req)
	go func() {
		result := configureSessionResult{
			config: config,
			err: &CallbackError{
				Callback: "ConfigureSession",
				Reason:   CallbackFailureGoexit,
			},
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				result.err = configureSessionPanicError(recovered)
			}
			releaseSessionCallbackPermits(s.configureSlots, configureSessionProcessSlots)
			s.releaseConfigureSession(req.Identity)
			results <- result
		}()
		result.err = callback(callbackReq, &result.config)
	}()
	select {
	case result := <-results:
		return result.config, result.err
	case <-callbackCtx.Done():
		select {
		case result := <-results:
			return result.config, result.err
		default:
		}
		if err := ctx.Err(); err != nil {
			return rendr.SessionConfig{}, err
		}
		return rendr.SessionConfig{}, &CallbackError{
			Callback: "ConfigureSession",
			Reason:   CallbackFailureTimeout,
		}
	}
}

func (s *Starter) reserveConfigureSession(id l3ingress.L3Identity) bool {
	s.configureActiveMu.Lock()
	defer s.configureActiveMu.Unlock()
	if s.configureActive == nil {
		s.configureActive = make(map[l3ingress.L3Identity]struct{})
	}
	if _, active := s.configureActive[id]; active {
		return false
	}
	s.configureActive[id] = struct{}{}
	return true
}

func (s *Starter) releaseConfigureSession(id l3ingress.L3Identity) {
	s.configureActiveMu.Lock()
	delete(s.configureActive, id)
	s.configureActiveMu.Unlock()
}

func cloneSessionRequest(req l3ingress.SessionRequest) l3ingress.SessionRequest {
	req.Root = cloneSessionRequestRoot(req.Root)
	if len(req.Labels) == 0 {
		req.Labels = nil
	} else {
		labels := req.Labels
		req.Labels = make(map[string]string, len(labels))
		for key, value := range labels {
			req.Labels[key] = value
		}
	}
	return req
}

func cloneSessionRequestRoot(root any) any {
	switch target := root.(type) {
	case rendr.PathTarget:
		target.Spec = target.Spec.Clone()
		return target
	case *rendr.PathTarget:
		if target == nil {
			return (*rendr.PathTarget)(nil)
		}
		clone := *target
		clone.Spec = target.Spec.Clone()
		return &clone
	case rendr.GroupTarget:
		return cloneSessionRequestGroup(target)
	case *rendr.GroupTarget:
		if target == nil {
			return (*rendr.GroupTarget)(nil)
		}
		clone := cloneSessionRequestGroup(*target)
		return &clone
	default:
		return root
	}
}

func cloneSessionRequestGroup(group rendr.GroupTarget) rendr.GroupTarget {
	if len(group.Children) == 0 {
		group.Children = nil
	} else {
		children := make([]rendr.Target, len(group.Children))
		for index, child := range group.Children {
			children[index], _ = cloneSessionRequestRoot(child).(rendr.Target)
		}
		group.Children = children
	}
	if group.Peak != nil {
		peak := *group.Peak
		peak.Targets = append([]string(nil), group.Peak.Targets...)
		group.Peak = &peak
	}
	return group
}

func configureSessionPanicError(recovered any) *CallbackError {
	panicType := "<nil>"
	if typ := reflect.TypeOf(recovered); typ != nil {
		panicType = typ.String()
	}
	return &CallbackError{
		Callback:  "ConfigureSession",
		Reason:    CallbackFailurePanic,
		PanicType: panicType,
	}
}

func (s *Starter) sessionRuntime() (*rendr.Runtime, error) {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	if s.resolvedRuntime != nil {
		return s.resolvedRuntime, nil
	}
	if s.Runtime != nil {
		s.resolvedRuntime = s.Runtime
		return s.resolvedRuntime, nil
	}
	runtime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		return nil, err
	}
	s.resolvedRuntime = runtime
	return runtime, nil
}

type statusCloser interface {
	Status() rendr.Status
	Close() error
}

func requirePeerL3Identity(conn statusCloser) error {
	if conn != nil && conn.Status().Peer.Caps.Has(rendr.CapL3Identity) {
		return nil
	}
	return l3ingress.RequirePeerL3Identity(0)
}

// AsError returns the typed l3session error when err contains one.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
