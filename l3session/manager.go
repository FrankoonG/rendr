package l3session

import (
	"context"
	"errors"
	"sync"

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
	if m.OnStart != nil {
		if err := m.OnStart(ctx, sess); err != nil {
			_ = m.Close(req.Identity)
			return err
		}
	}
	return nil
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
