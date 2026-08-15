package l3session

import (
	"context"
	"errors"
	"fmt"
	"sync"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

var ErrSessionGenerationConflict = errors.New("l3session: flow generation conflicts with active session")

// OnStartFunc observes newly-created sessions. Future TCP/UDP flow
// adapters attach payload relays here after the rendr session exists.
type OnStartFunc func(context.Context, *Session) error

// Manager turns packet events into one rendr session per L3 flow. It
// intentionally owns only session lifecycle; payload relay stays in
// protocol-specific adapters.
type Manager struct {
	Starter *Starter
	OnStart OnStartFunc
	// FlowTable receives selected-path and migration observations for
	// sessions started by this manager. A nil FlowTable is valid.
	FlowTable *l3ingress.FlowTable

	mu           sync.Mutex
	sessions     map[l3ingress.L3Identity]*Session
	ownedStarter *Starter
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
	for {
		if existing, ok := m.Session(req.Identity); ok {
			if sessionRefsConflict(existing.Request.Ref, req.Ref) {
				return nil, fmt.Errorf("%w: active=%+v requested=%+v", ErrSessionGenerationConflict,
					existing.Request.Ref, req.Ref)
			}
			return existing, nil
		}
		sess, err := m.sessionStarter().Start(ctx, req)
		if err != nil {
			return nil, err
		}
		if !m.add(req.Identity, sess) {
			existing, _ := m.Session(req.Identity)
			_ = sess.Close()
			if existing == nil {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				continue
			}
			if sessionRefsConflict(existing.Request.Ref, req.Ref) {
				return nil, fmt.Errorf("%w: active=%+v requested=%+v", ErrSessionGenerationConflict,
					existing.Request.Ref, req.Ref)
			}
			return existing, nil
		}
		m.observeSessionPaths(req.Identity, req.Ref, sess)
		if m.OnStart != nil {
			if err := m.OnStart(ctx, sess); err != nil {
				_ = m.CloseSession(sess)
				return nil, err
			}
		}
		return sess, nil
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
	if sess == nil || sess.Request.Ref != ref {
		return nil, false
	}
	return sess, true
}

// Close closes and forgets one active session.
func (m *Manager) Close(id l3ingress.L3Identity) error {
	m.mu.Lock()
	sess := m.sessions[id]
	delete(m.sessions, id)
	m.mu.Unlock()
	if sess == nil {
		return nil
	}
	return sess.Close()
}

// CloseSession closes expected and removes it only if it is still the current
// session for its identity. A stale relay can therefore finish without
// deleting a replacement session that reused the same tuple.
func (m *Manager) CloseSession(expected *Session) error {
	if expected == nil {
		return nil
	}
	m.mu.Lock()
	if m.sessions[expected.Request.Identity] == expected {
		delete(m.sessions, expected.Request.Identity)
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
	if sess == nil || sess.Request.Ref != ref {
		m.mu.Unlock()
		return false, nil
	}
	delete(m.sessions, ref.Identity)
	m.mu.Unlock()
	return true, sess.Close()
}

// CloseAll closes and forgets every active session.
func (m *Manager) CloseAll() error {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for id, sess := range m.sessions {
		sessions = append(sessions, sess)
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	var err error
	for _, sess := range sessions {
		err = errors.Join(err, sess.Close())
	}
	return err
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
		sess.onClose = append(sess.onClose, cancel)
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
	if sess.Conn != nil {
		if h, ok := sess.Conn.(migrateHook); ok {
			return h
		}
	}
	if sess.PacketConn != nil {
		if h, ok := sess.PacketConn.(migrateHook); ok {
			return h
		}
	}
	return nil
}

func sessionPathNames(sess *Session) []string {
	if sess == nil {
		return nil
	}
	if sess.Conn != nil {
		if c, ok := sess.Conn.(rendr.ConnectionObserver); ok {
			return selectedPathNames(c.Stats())
		}
		return pathNames(sess.Conn.Paths())
	}
	if sess.PacketConn != nil {
		if c, ok := sess.PacketConn.(rendr.ConnectionObserver); ok {
			return selectedPathNames(c.Stats())
		}
		return pathNames(sess.PacketConn.Paths())
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
