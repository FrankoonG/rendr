package l3ingress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Direction identifies where a classified flow entered rendr.
type Direction uint8

const (
	DirectionIngress Direction = iota + 1
	DirectionEgress
)

// Egress is implemented by embedding programs that own the final
// peer-side landing choice for a TUN-originated flow.
type Egress interface {
	DialTCP(ctx context.Context, id L3Identity) (net.Conn, error)
	DialUDP(ctx context.Context, id L3Identity) (net.PacketConn, netip.AddrPort, error)
}

// EgressErrorReason is a machine-readable peer egress dispatch failure.
type EgressErrorReason string

const (
	ReasonInvalidEgressName EgressErrorReason = "invalid_egress_name"
	ReasonEgressNotFound    EgressErrorReason = "egress_not_found"
	ReasonProtocolMismatch  EgressErrorReason = "protocol_mismatch"
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
	if name == "" || e == nil {
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
func (r *EgressRegistry) DialTCP(ctx context.Context, name string, id L3Identity) (net.Conn, error) {
	if id.Proto != ProtocolTCP {
		return nil, &EgressError{Reason: ReasonProtocolMismatch, Name: name, Proto: id.Proto}
	}
	e, err := r.require(name)
	if err != nil {
		return nil, err
	}
	return e.DialTCP(ctx, id)
}

// DialUDP dispatches a UDP identity to the named peer-side egress hook.
func (r *EgressRegistry) DialUDP(ctx context.Context, name string, id L3Identity) (net.PacketConn, netip.AddrPort, error) {
	if id.Proto != ProtocolUDP {
		return nil, netip.AddrPort{}, &EgressError{Reason: ReasonProtocolMismatch, Name: name, Proto: id.Proto}
	}
	e, err := r.require(name)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	return e.DialUDP(ctx, id)
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
	Peer   string
	Root   any
	Egress string
	Labels map[string]string
}

// FlowDecisionFunc lets embedders reuse TUN/l3ingress while keeping
// domain, CIDR, user, or profile routing outside rendr core.
type FlowDecisionFunc func(context.Context, FlowMeta) (FlowDecision, error)
