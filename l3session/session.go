// Package l3session bridges l3ingress flow decisions to concrete rendr
// stream or packet sessions.
package l3session

import (
	"context"
	"errors"
	"fmt"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

// ErrorReason is a machine-readable session start failure.
type ErrorReason string

const (
	ReasonUnsupportedKind ErrorReason = "unsupported_session_kind"
	ReasonUnsupportedRoot ErrorReason = "unsupported_root_target"
)

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
	Request    l3ingress.SessionRequest
	Conn       rendr.Conn
	PacketConn rendr.PacketConn

	onClose []func()
}

// Close closes the underlying rendr session.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	for _, fn := range s.onClose {
		if fn != nil {
			fn()
		}
	}
	if s.Conn != nil {
		return s.Conn.Close()
	}
	if s.PacketConn != nil {
		return s.PacketConn.Close()
	}
	return nil
}

// DialerOption lets embedders inject per-session Dialer knobs such as
// factories, prime timing, or migration budget without making l3ingress
// depend on top-level rendr types.
type DialerOption func(req l3ingress.SessionRequest, d *rendr.Dialer) error

// Starter starts rendr sessions for l3ingress SessionRequests.
type Starter struct {
	Options []DialerOption
}

// Start creates either a rendr Conn or PacketConn for req. req.Root must be a
// rendr.Target; lower l3ingress packages keep it opaque to avoid an import
// cycle.
func (s Starter) Start(ctx context.Context, req l3ingress.SessionRequest) (*Session, error) {
	root, ok := req.Root.(rendr.Target)
	if !ok || root == nil {
		return nil, &Error{
			Reason: ReasonUnsupportedRoot,
			Detail: fmt.Sprintf("%T", req.Root),
		}
	}
	d := &rendr.Dialer{
		Root:               root,
		PreserveL3Identity: req.PreserveL3Identity,
	}
	for _, opt := range s.Options {
		if opt == nil {
			continue
		}
		if err := opt(req, d); err != nil {
			return nil, err
		}
	}
	switch req.Kind {
	case l3ingress.SessionKindStream:
		c, err := d.Dial(ctx)
		if err != nil {
			return nil, err
		}
		if req.PreserveL3Identity {
			admin, ok := c.(rendr.AdminConn)
			if !ok {
				_ = c.Close()
				return nil, l3ingress.RequirePeerL3Identity(0)
			}
			if err := l3ingress.RequirePeerL3Identity(admin.Stats().PeerCaps); err != nil {
				_ = c.Close()
				return nil, err
			}
		}
		return &Session{Request: req, Conn: c}, nil
	case l3ingress.SessionKindPacket:
		pc, err := d.DialPacket(ctx)
		if err != nil {
			return nil, err
		}
		if req.PreserveL3Identity {
			admin, ok := pc.(rendr.AdminPacketConn)
			if !ok {
				_ = pc.Close()
				return nil, l3ingress.RequirePeerL3Identity(0)
			}
			if err := l3ingress.RequirePeerL3Identity(admin.Stats().PeerCaps); err != nil {
				_ = pc.Close()
				return nil, err
			}
		}
		return &Session{Request: req, PacketConn: pc}, nil
	default:
		return nil, &Error{
			Reason: ReasonUnsupportedKind,
			Detail: string(req.Kind),
		}
	}
}

// AsError returns the typed l3session error when err contains one.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
