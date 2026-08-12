// Package l3session bridges l3ingress flow decisions to concrete rendr
// stream or packet sessions.
package l3session

import (
	"context"
	"errors"
	"fmt"
	"sync"

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

	onClose   []func()
	closeOnce sync.Once
	closeErr  error
}

// Close closes the underlying rendr session.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		for _, fn := range s.onClose {
			if fn != nil {
				fn()
			}
		}
		if s.Conn != nil {
			s.closeErr = s.Conn.Close()
			return
		}
		if s.PacketConn != nil {
			s.closeErr = s.PacketConn.Close()
		}
	})
	return s.closeErr
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

	runtimeMu       sync.Mutex
	resolvedRuntime *rendr.Runtime
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
	config := rendr.SessionConfig{
		Root:               root,
		PreserveL3Identity: req.PreserveL3Identity,
	}
	if s.ConfigureSession != nil {
		if err := s.ConfigureSession(req, &config); err != nil {
			return nil, err
		}
	}
	config.PreserveL3Identity = req.PreserveL3Identity
	runtime, err := s.sessionRuntime()
	if err != nil {
		return nil, err
	}
	switch req.Kind {
	case l3ingress.SessionKindStream:
		c, err := runtime.Dial(ctx, config)
		if err != nil {
			return nil, err
		}
		if req.PreserveL3Identity {
			if err := requirePeerL3Identity(c); err != nil {
				_ = c.Close()
				return nil, err
			}
		}
		return &Session{Request: req, Conn: c}, nil
	case l3ingress.SessionKindPacket:
		pc, err := runtime.DialPacket(ctx, config)
		if err != nil {
			return nil, err
		}
		if req.PreserveL3Identity {
			if err := requirePeerL3Identity(pc); err != nil {
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
