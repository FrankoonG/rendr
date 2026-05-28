package l3ingress

import (
	"context"
	"net"
	"net/netip"
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
