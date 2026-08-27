package l3session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

var ErrSessionGenerationConflict = errors.New("l3session: flow generation conflicts with active session")

// ErrSessionClosedDuringStart means OnStart returned success after the
// candidate session had already begun closing. Such a candidate is never
// published.
var ErrSessionClosedDuringStart = errors.New("l3session: session closed during OnStart")

const (
	// defaultOnStartConcurrency bounds OnStart callbacks that ignore their
	// context and remain in flight after the caller returns.
	defaultOnStartConcurrency = 64
	// DefaultOnStartTimeout bounds initialization before a Session can be
	// published for packet handling.
	DefaultOnStartTimeout = 5 * time.Second
	onStartProcessLimit   = 128
)

var onStartProcessSlots = make(chan struct{}, onStartProcessLimit)

// OnStartFunc observes a newly-created, not-yet-published session through an
// immutable view. The callback never receives the manager-owned *Session.
type OnStartFunc func(context.Context, PendingSessionView) error

// Manager turns packet events into one rendr session per L3 flow. It
// intentionally owns only session lifecycle; payload relay stays in
// protocol-specific adapters.
type Manager struct {
	Starter *Starter
	OnStart OnStartFunc
	// OnStartTimeout bounds callback initialization. Zero selects the package
	// default. Concurrency is an internal resource budget, not a policy knob.
	OnStartTimeout time.Duration
	// FlowTable receives selected-path and migration observations for
	// sessions started by this manager. A nil FlowTable is valid.
	FlowTable *l3ingress.FlowTable

	mu              sync.Mutex
	sessions        map[l3ingress.L3Identity]*Session
	pending         map[l3ingress.L3Identity]*pendingSessionStart
	ownedStarter    *Starter
	onStartOnce     sync.Once
	onStartSlots    chan struct{}
	onStartLimit    time.Duration
	onStartErr      error
	onStartActiveMu sync.Mutex
	onStartActive   map[l3ingress.L3Identity]struct{}

	// onStartConcurrency is a package-test fault-injection override. Production
	// callers always use defaultOnStartConcurrency.
	onStartConcurrency int
}

type pendingSessionStart struct {
	ref            l3ingress.FlowRef
	done           chan struct{}
	physicalDone   chan struct{}
	retired        chan struct{}
	cancel         context.CancelFunc
	waiters        int
	completed      bool
	physicalExit   bool
	abandoned      bool
	fenced         bool
	published      bool
	doneClosed     bool
	physicalClosed bool
	retiredClosed  bool
	sess           *Session
	err            error
}

type onStartResult struct {
	err error
}

// HandlePacket implements l3ingress.PacketHandler. The first packet for a
// decided flow starts a rendr session; later packets for the same flow reuse
// the cached session and return nil.
func (m *Manager) HandlePacket(ctx context.Context, ev l3ingress.PacketEvent) error {
	_, err := m.EnsureSession(ctx, ev)
	return err
}

// EnsureSession starts or reuses the session for ev and returns the exact
// generation-bound object. Callers must retain this pointer instead of looking
// the session up again by tuple after asynchronous work.
func (m *Manager) EnsureSession(ctx context.Context, ev l3ingress.PacketEvent) (*Session, error) {
	req, err := l3ingress.BuildSessionRequest(ev)
	if err != nil {
		return nil, err
	}
	if err := requireCanonicalSessionRequest(req); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for {
		m.mu.Lock()
		if existing := m.sessions[req.Identity]; existing != nil {
			m.mu.Unlock()
			if sessionRefsConflict(existing.request.Ref, req.Ref) {
				return nil, fmt.Errorf("%w: active=%+v requested=%+v", ErrSessionGenerationConflict,
					existing.request.Ref, req.Ref)
			}
			return existing, nil
		}
		if pending := m.pending[req.Identity]; pending != nil {
			if sessionRefsConflict(pending.ref, req.Ref) {
				m.mu.Unlock()
				return nil, fmt.Errorf("%w: active=%+v requested=%+v", ErrSessionGenerationConflict,
					pending.ref, req.Ref)
			}
			if pending.completed && pending.err != nil {
				retired := pending.retired
				m.mu.Unlock()
				select {
				case <-retired:
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			if pending.abandoned || pending.fenced {
				retired := pending.retired
				m.mu.Unlock()
				select {
				case <-retired:
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			pending.waiters++
			m.mu.Unlock()
			return m.waitPendingSession(ctx, req.Identity, req.Ref, pending)
		}
		if m.pending == nil {
			m.pending = make(map[l3ingress.L3Identity]*pendingSessionStart)
		}
		if m.sessions == nil {
			m.sessions = make(map[l3ingress.L3Identity]*Session)
		}
		startCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		pending := &pendingSessionStart{
			ref: req.Ref, done: make(chan struct{}), physicalDone: make(chan struct{}), retired: make(chan struct{}),
			cancel: cancel, waiters: 1,
		}
		m.pending[req.Identity] = pending
		m.mu.Unlock()
		go m.runPendingSessionStart(startCtx, req, pending)
		return m.waitPendingSession(ctx, req.Identity, req.Ref, pending)
	}
}

func (m *Manager) waitPendingSession(
	ctx context.Context,
	id l3ingress.L3Identity,
	ref l3ingress.FlowRef,
	pending *pendingSessionStart,
) (*Session, error) {
	select {
	case <-pending.done:
	case <-ctx.Done():
	}

	m.mu.Lock()
	pending.waiters--
	if pending.completed {
		if pending.err != nil {
			err := pending.err
			m.mu.Unlock()
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			var cleanup *Session
			retire := false
			if pending.waiters == 0 && !pending.published && m.pending[id] == pending {
				pending.abandoned = true
				cleanup = pending.sess
				retire = true
			}
			m.mu.Unlock()
			if cleanup != nil {
				_ = cleanup.Close()
			}
			if retire {
				m.mu.Lock()
				if m.pending[id] == pending {
					delete(m.pending, id)
					closePendingRetiredLocked(pending)
				}
				m.mu.Unlock()
			}
			return nil, err
		}
		if pending.fenced || pending.sess == nil {
			m.mu.Unlock()
			return nil, net.ErrClosed
		}
		if !pending.published {
			if m.pending[id] != pending {
				m.mu.Unlock()
				return nil, net.ErrClosed
			}
			if existing := m.sessions[id]; existing != nil {
				delete(m.pending, id)
				closePendingRetiredLocked(pending)
				pending.published = true
				pending.sess = existing
				m.mu.Unlock()
				if sessionRefsConflict(existing.request.Ref, ref) {
					return nil, fmt.Errorf("%w: active=%+v requested=%+v", ErrSessionGenerationConflict,
						existing.request.Ref, ref)
				}
				return existing, nil
			}
			m.sessions[id] = pending.sess
			pending.published = true
			delete(m.pending, id)
			closePendingRetiredLocked(pending)
			sess := pending.sess
			m.mu.Unlock()
			m.observeSessionPaths(id, ref, sess)
			return sess, nil
		}
		sess := pending.sess
		m.mu.Unlock()
		return sess, nil
	}

	err := ctx.Err()
	if err == nil {
		err = net.ErrClosed
	}
	if pending.waiters == 0 && m.pending[id] == pending {
		pending.abandoned = true
		pending.cancel()
	}
	m.mu.Unlock()
	return nil, err
}

func (m *Manager) runPendingSessionStart(
	ctx context.Context,
	req l3ingress.SessionRequest,
	pending *pendingSessionStart,
) {
	defer pending.cancel()
	if m.OnStart != nil && m.onStartIdentityActive(req.Identity) {
		m.finishPendingSessionStart(req.Identity, pending, nil, &CallbackError{
			Callback: "Manager.OnStart", Reason: CallbackFailureSaturated,
		})
		return
	}
	sess, err := m.sessionStarter().Start(ctx, req)
	if err == nil && m.OnStart != nil {
		err = m.invokeOnStart(ctx, sess)
	}
	if err == nil && (sess.isClosed() || sessionTransportClosing(sess)) {
		err = ErrSessionClosedDuringStart
	}
	m.finishPendingSessionStart(req.Identity, pending, sess, err)
}

func (m *Manager) finishPendingSessionStart(
	id l3ingress.L3Identity,
	pending *pendingSessionStart,
	sess *Session,
	err error,
) {
	var cleanup *Session
	retire := false
	m.mu.Lock()
	pending.physicalExit = true
	if sess != nil {
		pending.sess = sess
	}
	owned := m.pending[id] == pending
	if !owned || pending.abandoned || pending.fenced {
		retire = owned
		pending.completed = true
		if pending.err == nil {
			pending.err = net.ErrClosed
		}
		cleanup = sess
	} else if err != nil {
		retire = true
		pending.completed = true
		pending.err = err
		cleanup = sess
	} else if existing := m.sessions[id]; existing != nil {
		retire = true
		pending.completed = true
		if sessionRefsConflict(existing.request.Ref, pending.ref) {
			pending.err = fmt.Errorf("%w: active=%+v requested=%+v", ErrSessionGenerationConflict,
				existing.request.Ref, pending.ref)
		} else {
			pending.sess = existing
			pending.published = true
		}
		cleanup = sess
	} else {
		pending.completed = true
		pending.sess = sess
	}
	closePendingOutcomeLocked(pending)
	m.mu.Unlock()
	if cleanup != nil {
		_ = cleanup.Close()
	}
	m.mu.Lock()
	if retire && m.pending[id] == pending {
		delete(m.pending, id)
		closePendingRetiredLocked(pending)
	}
	closePendingPhysicalLocked(pending)
	m.mu.Unlock()
}

func closePendingOutcomeLocked(pending *pendingSessionStart) {
	if !pending.doneClosed {
		pending.doneClosed = true
		close(pending.done)
	}
}

func closePendingPhysicalLocked(pending *pendingSessionStart) {
	if !pending.physicalClosed {
		pending.physicalClosed = true
		close(pending.physicalDone)
	}
}

func closePendingRetiredLocked(pending *pendingSessionStart) {
	if !pending.retiredClosed {
		pending.retiredClosed = true
		close(pending.retired)
	}
}

func (m *Manager) invokeOnStart(ctx context.Context, sess *Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.onStartOnce.Do(func() {
		concurrency := m.onStartConcurrency
		if concurrency < 0 {
			m.onStartErr = errors.New("l3session: OnStart concurrency must not be negative")
			return
		}
		if concurrency == 0 {
			concurrency = defaultOnStartConcurrency
		}
		if concurrency > defaultOnStartConcurrency {
			m.onStartErr = fmt.Errorf(
				"l3session: OnStart concurrency %d exceeds hard limit %d",
				concurrency, defaultOnStartConcurrency,
			)
			return
		}
		timeout := m.OnStartTimeout
		if timeout < 0 {
			m.onStartErr = errors.New("l3session: OnStart timeout must not be negative")
			return
		}
		if timeout == 0 {
			timeout = DefaultOnStartTimeout
		}
		m.onStartSlots = make(chan struct{}, concurrency)
		m.onStartLimit = timeout
	})
	if m.onStartErr != nil {
		return m.onStartErr
	}
	id := sess.request.Identity
	if !m.reserveOnStartIdentity(id) {
		return &CallbackError{Callback: "Manager.OnStart", Reason: CallbackFailureSaturated}
	}
	if !acquireSessionCallbackPermits(m.onStartSlots, onStartProcessSlots) {
		m.releaseOnStartIdentity(id)
		return &CallbackError{Callback: "Manager.OnStart", Reason: CallbackFailureSaturated}
	}
	callbackCtx, cancel := context.WithTimeout(ctx, m.onStartLimit)
	defer cancel()
	results := make(chan onStartResult, 1)
	callback := m.OnStart
	view, access := newPendingSessionView(sess)
	go func() {
		result := onStartResult{err: &CallbackError{
			Callback: "Manager.OnStart",
			Reason:   CallbackFailureGoexit,
		}}
		defer func() {
			if recovered := recover(); recovered != nil {
				result.err = managerOnStartPanicError(recovered)
			}
			releaseSessionCallbackPermits(m.onStartSlots, onStartProcessSlots)
			m.releaseOnStartIdentity(id)
			results <- result
		}()
		result.err = callback(callbackCtx, view)
	}()
	select {
	case result := <-results:
		access.revoke()
		if result.err == nil && (access.closed.Load() || sess.isClosed() || sessionTransportClosing(sess)) {
			return ErrSessionClosedDuringStart
		}
		return result.err
	case <-callbackCtx.Done():
		select {
		case result := <-results:
			access.revoke()
			return result.err
		default:
		}
		access.revoke()
		if err := ctx.Err(); err != nil {
			return err
		}
		return &CallbackError{Callback: "Manager.OnStart", Reason: CallbackFailureTimeout}
	}
}

func (m *Manager) reserveOnStartIdentity(id l3ingress.L3Identity) bool {
	m.onStartActiveMu.Lock()
	defer m.onStartActiveMu.Unlock()
	if m.onStartActive == nil {
		m.onStartActive = make(map[l3ingress.L3Identity]struct{})
	}
	if _, active := m.onStartActive[id]; active {
		return false
	}
	m.onStartActive[id] = struct{}{}
	return true
}

func (m *Manager) releaseOnStartIdentity(id l3ingress.L3Identity) {
	m.onStartActiveMu.Lock()
	delete(m.onStartActive, id)
	m.onStartActiveMu.Unlock()
}

func (m *Manager) onStartIdentityActive(id l3ingress.L3Identity) bool {
	m.onStartActiveMu.Lock()
	_, active := m.onStartActive[id]
	m.onStartActiveMu.Unlock()
	return active
}

type sessionStateObserver interface {
	State() string
}

func sessionTransportClosing(sess *Session) bool {
	if sess == nil {
		return true
	}
	var observer sessionStateObserver
	if sess.conn != nil {
		observer, _ = sess.conn.(sessionStateObserver)
	} else if sess.packetConn != nil {
		observer, _ = sess.packetConn.(sessionStateObserver)
	}
	if observer == nil {
		return false
	}
	switch observer.State() {
	case "closing", "dead":
		return true
	default:
		return false
	}
}

func managerOnStartPanicError(recovered any) *CallbackError {
	panicType := "<nil>"
	if typ := reflect.TypeOf(recovered); typ != nil {
		panicType = typ.String()
	}
	return &CallbackError{
		Callback:  "Manager.OnStart",
		Reason:    CallbackFailurePanic,
		PanicType: panicType,
	}
}

func (m *Manager) sessionStarter() *Starter {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Starter != nil {
		return m.Starter
	}
	if m.ownedStarter == nil {
		m.ownedStarter = &Starter{}
	}
	return m.ownedStarter
}

// ObserveFlow implements l3ingress.FlowObserver. Closed flow snapshots close
// and forget the matching rendr session so TCP FIN/RST and explicit FlowTable
// closes do not leave orphan sessions behind.
func (m *Manager) ObserveFlow(snapshot l3ingress.FlowSnapshot) {
	if !snapshot.Closed {
		return
	}
	if snapshot.Ref != (l3ingress.FlowRef{}) {
		_, _ = m.CloseRef(snapshot.Ref)
		return
	}
	_ = m.Close(snapshot.Flow.L3Identity)
}

// Session returns the cached session for id, if present.
func (m *Manager) Session(id l3ingress.L3Identity) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions == nil {
		return nil, false
	}
	sess, ok := m.sessions[id]
	return sess, ok
}

// SessionRef returns the session only when ref names its exact activation.
func (m *Manager) SessionRef(ref l3ingress.FlowRef) (*Session, bool) {
	if ref == (l3ingress.FlowRef{}) {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sess := m.sessions[ref.Identity]
	if sess == nil || sess.request.Ref != ref {
		return nil, false
	}
	return sess, true
}

// Close closes and forgets one active session.
func (m *Manager) Close(id l3ingress.L3Identity) error {
	m.mu.Lock()
	sess := m.sessions[id]
	delete(m.sessions, id)
	var candidate *Session
	var cancel context.CancelFunc
	var pendingStart *pendingSessionStart
	if pending := m.pending[id]; pending != nil {
		pendingStart = pending
		candidate, cancel = m.fencePendingLocked(id, pending)
	}
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var err error
	if sess != nil {
		err = errors.Join(err, sess.Close())
	}
	if candidate != nil && candidate != sess {
		err = errors.Join(err, candidate.Close())
	}
	m.retireFencedPending(id, pendingStart)
	return err
}

// CloseSession closes expected and removes it only if it is still the current
// session for its identity. A stale relay can therefore finish without
// deleting a replacement session that reused the same tuple.
func (m *Manager) CloseSession(expected *Session) error {
	if expected == nil {
		return nil
	}
	m.mu.Lock()
	if m.sessions[expected.request.Identity] == expected {
		delete(m.sessions, expected.request.Identity)
	}
	m.mu.Unlock()
	return expected.Close()
}

// CloseRef closes the current session only when ref still names its flow
// activation. It returns false for stale refs without affecting a replacement.
func (m *Manager) CloseRef(ref l3ingress.FlowRef) (bool, error) {
	if ref == (l3ingress.FlowRef{}) {
		return false, nil
	}
	m.mu.Lock()
	sess := m.sessions[ref.Identity]
	pending := m.pending[ref.Identity]
	matchedSession := sess != nil && sess.request.Ref == ref
	matchedPending := pending != nil && pending.ref == ref
	if !matchedSession && !matchedPending {
		m.mu.Unlock()
		return false, nil
	}
	if matchedSession {
		delete(m.sessions, ref.Identity)
	}
	var candidate *Session
	var cancel context.CancelFunc
	var pendingStart *pendingSessionStart
	if matchedPending {
		pendingStart = pending
		candidate, cancel = m.fencePendingLocked(ref.Identity, pending)
	}
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var err error
	if matchedSession {
		err = errors.Join(err, sess.Close())
	}
	if candidate != nil && candidate != sess {
		err = errors.Join(err, candidate.Close())
	}
	m.retireFencedPending(ref.Identity, pendingStart)
	return true, err
}

// CloseAll closes and forgets every active session.
func (m *Manager) CloseAll() error {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for id, sess := range m.sessions {
		sessions = append(sessions, sess)
		delete(m.sessions, id)
	}
	candidates := make([]*Session, 0, len(m.pending))
	cancels := make([]context.CancelFunc, 0, len(m.pending))
	type fencedPending struct {
		id      l3ingress.L3Identity
		pending *pendingSessionStart
	}
	fenced := make([]fencedPending, 0, len(m.pending))
	for id, pending := range m.pending {
		fenced = append(fenced, fencedPending{id: id, pending: pending})
		candidate, cancel := m.fencePendingLocked(id, pending)
		if candidate != nil {
			candidates = append(candidates, candidate)
		}
		if cancel != nil {
			cancels = append(cancels, cancel)
		}
	}
	m.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	var err error
	for _, sess := range sessions {
		err = errors.Join(err, sess.Close())
	}
	for _, sess := range candidates {
		err = errors.Join(err, sess.Close())
	}
	for _, entry := range fenced {
		m.retireFencedPending(entry.id, entry.pending)
	}
	return err
}

func (m *Manager) fencePendingLocked(
	id l3ingress.L3Identity,
	pending *pendingSessionStart,
) (*Session, context.CancelFunc) {
	pending.fenced = true
	if !pending.completed {
		pending.completed = true
		pending.err = net.ErrClosed
		closePendingOutcomeLocked(pending)
	} else if pending.err == nil && !pending.published {
		pending.err = net.ErrClosed
	}
	var candidate *Session
	if pending.physicalExit && m.pending[id] == pending {
		candidate = pending.sess
	}
	return candidate, pending.cancel
}

func (m *Manager) retireFencedPending(id l3ingress.L3Identity, pending *pendingSessionStart) {
	if pending == nil {
		return
	}
	m.mu.Lock()
	if pending.physicalExit && m.pending[id] == pending {
		delete(m.pending, id)
		closePendingRetiredLocked(pending)
	}
	m.mu.Unlock()
}

func (m *Manager) add(id l3ingress.L3Identity, sess *Session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions == nil {
		m.sessions = make(map[l3ingress.L3Identity]*Session)
	}
	if m.sessions[id] != nil {
		return false
	}
	m.sessions[id] = sess
	return true
}

func (m *Manager) observeSessionPaths(id l3ingress.L3Identity, ref l3ingress.FlowRef, sess *Session) {
	if m.FlowTable == nil || sess == nil {
		return
	}
	recordPathSelection(m.FlowTable, id, ref, sessionPathNames(sess))
	if h := sessionMigrateHook(sess); h != nil {
		cancel := h.OnMigrate(func(_, _ uint32, _ string) {
			recordMigration(m.FlowTable, id, ref, sessionPathNames(sess))
		})
		sess.addOnClose(cancel)
	}
}

func sessionRefsConflict(active, requested l3ingress.FlowRef) bool {
	return requested != (l3ingress.FlowRef{}) && active != requested
}

func recordPathSelection(table *l3ingress.FlowTable, id l3ingress.L3Identity, ref l3ingress.FlowRef, paths []string) {
	if ref != (l3ingress.FlowRef{}) {
		table.RecordPathSelectionRef(ref, paths)
		return
	}
	table.RecordPathSelection(id, paths)
}

func recordMigration(table *l3ingress.FlowTable, id l3ingress.L3Identity, ref l3ingress.FlowRef, paths []string) {
	if ref != (l3ingress.FlowRef{}) {
		table.RecordMigrationRef(ref, paths)
		return
	}
	table.RecordMigration(id, paths)
}

type migrateHook interface {
	OnMigrate(func(oldID, newID uint32, cause string)) (cancel func())
}

func sessionMigrateHook(sess *Session) migrateHook {
	if sess.conn != nil {
		if h, ok := sess.conn.(migrateHook); ok {
			return h
		}
	}
	if sess.packetConn != nil {
		if h, ok := sess.packetConn.(migrateHook); ok {
			return h
		}
	}
	return nil
}

func sessionPathNames(sess *Session) []string {
	if sess == nil {
		return nil
	}
	if sess.conn != nil {
		if c, ok := sess.conn.(rendr.ConnectionObserver); ok {
			return selectedPathNames(c.Stats())
		}
		return pathNames(sess.conn.Paths())
	}
	if sess.packetConn != nil {
		if c, ok := sess.packetConn.(rendr.ConnectionObserver); ok {
			return selectedPathNames(c.Stats())
		}
		return pathNames(sess.packetConn.Paths())
	}
	return nil
}

func selectedPathNames(stats rendr.ConnStats) []string {
	effective := make(map[uint32]bool, len(stats.EffectivePaths))
	for _, id := range stats.EffectivePaths {
		effective[id] = true
	}
	active := make([]rendr.PathInfo, 0, len(effective))
	for _, p := range stats.Paths {
		if effective[p.ID] {
			active = append(active, p)
		}
	}
	if len(active) == 0 {
		return nil
	}
	return pathNames(active)
}

func pathNames(paths []rendr.PathInfo) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		name := ""
		if p.Spec.Opts != nil {
			name = p.Spec.Opts["name"]
		}
		if name == "" {
			name = p.Spec.Transport + ":" + p.Spec.Address
		}
		out = append(out, name)
	}
	return out
}
