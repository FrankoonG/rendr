package l3session

import (
	"context"
	"errors"
	"sync"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

// OnStartFunc observes newly-created sessions. Future TCP/UDP flow
// adapters attach payload relays here after the rendr session exists.
type OnStartFunc func(context.Context, *Session) error

// Manager turns packet events into one rendr session per L3 flow. It
// intentionally owns only session lifecycle; payload relay stays in
// protocol-specific adapters.
type Manager struct {
	Starter Starter
	OnStart OnStartFunc
	// FlowTable receives selected-path and migration observations for
	// sessions started by this manager. A nil FlowTable is valid.
	FlowTable *l3ingress.FlowTable

	mu       sync.Mutex
	sessions map[l3ingress.L3Identity]*Session
}

// HandlePacket implements l3ingress.PacketHandler. The first packet for a
// decided flow starts a rendr session; later packets for the same flow reuse
// the cached session and return nil.
func (m *Manager) HandlePacket(ctx context.Context, ev l3ingress.PacketEvent) error {
	req, err := l3ingress.BuildSessionRequest(ev)
	if err != nil {
		return err
	}
	if _, ok := m.Session(req.Identity); ok {
		return nil
	}
	sess, err := m.Starter.Start(ctx, req)
	if err != nil {
		return err
	}
	if !m.add(req.Identity, sess) {
		_ = sess.Close()
		return nil
	}
	m.observeSessionPaths(req.Identity, sess)
	if m.OnStart != nil {
		if err := m.OnStart(ctx, sess); err != nil {
			_ = m.Close(req.Identity)
			return err
		}
	}
	return nil
}

// ObserveFlow implements l3ingress.FlowObserver. Closed flow snapshots close
// and forget the matching rendr session so TCP FIN/RST and explicit FlowTable
// closes do not leave orphan sessions behind.
func (m *Manager) ObserveFlow(snapshot l3ingress.FlowSnapshot) {
	if !snapshot.Closed {
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

func (m *Manager) observeSessionPaths(id l3ingress.L3Identity, sess *Session) {
	if m.FlowTable == nil || sess == nil {
		return
	}
	m.FlowTable.RecordPathSelection(id, sessionPathNames(sess))
	if h := sessionMigrateHook(sess); h != nil {
		cancel := h.OnMigrate(func(_, _ uint32, _ string) {
			m.FlowTable.RecordMigration(id, sessionPathNames(sess))
		})
		sess.onClose = append(sess.onClose, cancel)
	}
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
		if c, ok := sess.Conn.(rendr.AdminConn); ok {
			return selectedPathNames(c.Stats())
		}
		return pathNames(sess.Conn.Paths())
	}
	if sess.PacketConn != nil {
		if c, ok := sess.PacketConn.(rendr.AdminPacketConn); ok {
			return selectedPathNames(c.Stats())
		}
		return pathNames(sess.PacketConn.Paths())
	}
	return nil
}

func selectedPathNames(stats rendr.ConnStats) []string {
	if stats.Mode == rendr.ModeBond || stats.Mode == rendr.ModeRace {
		return pathNames(stats.Paths)
	}
	active := make([]rendr.PathInfo, 0, 1)
	for _, p := range stats.Paths {
		if p.Active || p.ID == stats.ActivePath {
			active = append(active, p)
		}
	}
	if len(active) == 0 {
		return pathNames(stats.Paths)
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
