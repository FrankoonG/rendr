package xray

import (
	"context"
	"net"

	"github.com/FrankoonG/rendr"
)

// PacketListener wraps a rendr.PacketListener so xray-side adapters
// for datagram-oriented protocols can plug rendr in as the underlying
// migration-capable transport. It is the packet-mode analogue of
// xray.Listener.
type PacketListener struct {
	inner rendr.PacketListener
}

// ListenUDPFlow starts an opaque-UDP rendr listener at addr in
// packet-boundary mode. Returned PacketConns preserve message
// boundaries 1-to-1 with application WriteTo/ReadFrom calls.
//
// Stream-mode peers connecting to this listener are routed to the
// underlying stream Accept channel and not seen here; AcceptPacket
// only yields packet-mode HELLOs.
func ListenUDPFlow(addr string) (*PacketListener, error) {
	ln, err := rendr.ListenUDPFlowPacket(addr)
	if err != nil {
		return nil, err
	}
	return &PacketListener{inner: ln}, nil
}

// AcceptPacket blocks until a packet-mode rendr Conn is available.
// The returned value implements net.PacketConn; callers that also
// want migration / FlowID introspection can type-assert to
// rendr.PacketConn or rendr.AdminPacketConn.
func (l *PacketListener) AcceptPacket() (net.PacketConn, error) {
	return l.inner.AcceptPacket(context.Background())
}

// AcceptPacketContext is the cancellable variant.
func (l *PacketListener) AcceptPacketContext(ctx context.Context) (net.PacketConn, error) {
	return l.inner.AcceptPacket(ctx)
}

// Close shuts the listener.
func (l *PacketListener) Close() error { return l.inner.Close() }

// Addr reports the local network address.
func (l *PacketListener) Addr() net.Addr { return l.inner.Addr() }

// FlowIDs returns the set of live flow_ids the packet listener is
// serving. Symmetric with xray.Listener.FlowIDs.
func (l *PacketListener) FlowIDs() [][16]byte { return l.inner.FlowIDs() }
