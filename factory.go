package rendr

import (
	"context"
	"fmt"
	"net"
)

// StreamPathFactory constructs the underlying byte-stream net.Conn for
// one rendr stream-mode path. The factory's contract:
//
//   - The returned net.Conn MUST preserve byte order (Read sees Write's
//     bytes in order, unbroken). rendr layers 2-byte length-prefix
//     framing on top; a torn or reordered byte stream will fail HELLO
//     and the path is rejected.
//   - The returned connection MUST terminate at the same rendr peer as
//     every other path in the Dialer (docs/plan.md §"项目定位" C1).
//     rendr verifies this in HELLO via the shared flow_id; a mismatch
//     causes the path to be dropped at handshake.
//
// Typical uses:
//   - Wrap an xray-core outbound chain (vless / trojan / ss / nested /
//     reverse) so rendr migrates across xray-protected paths.
//   - Plug in a custom transport (e.g. a private overlay socket) that
//     isn't worth a full transport.Transport adapter.
//
// addr is passed straight from PathSpec.Address. ctx is honored for
// dial cancellation.
type StreamPathFactory func(ctx context.Context, addr string) (net.Conn, error)

// PacketPathFactory will play the same role for packet-mode paths
// (rendr's flow-id-framed datagrams). Reserved for M9 X5 stage 2;
// adding a factory raises ErrPacketFactoryStage2.
type PacketPathFactory func(ctx context.Context, addr string) (net.PacketConn, error)

// AddStreamPathFactory registers a stream factory under name. Any
// PathSpec in d.Paths whose Transport equals name is dialed via this
// factory instead of transport.Default. Names must be unique per
// Dialer; a duplicate (or shadowing of a packet factory name) returns
// an error.
//
// Factories are consulted before transport.Default, so they can also
// override a registered transport (e.g. a custom "tcp" implementation
// for one Dialer only). To reach the global registry name, just leave
// it unregistered on the Dialer.
func (d *Dialer) AddStreamPathFactory(name string, f StreamPathFactory) error {
	if name == "" {
		return fmt.Errorf("rendr: empty StreamPathFactory name")
	}
	if f == nil {
		return fmt.Errorf("rendr: nil StreamPathFactory %q", name)
	}
	if d.streamFactories == nil {
		d.streamFactories = map[string]StreamPathFactory{}
	}
	if _, dup := d.streamFactories[name]; dup {
		return fmt.Errorf("rendr: stream factory %q already registered on this Dialer", name)
	}
	if _, dup := d.packetFactories[name]; dup {
		return fmt.Errorf("rendr: %q already registered as PacketPathFactory on this Dialer", name)
	}
	d.streamFactories[name] = f
	return nil
}

// AddPacketPathFactory mirrors AddStreamPathFactory for packet-mode
// paths. Currently returns ErrPacketFactoryStage2 — packet factory
// support lands in M9 X5 stage 2 after the udpflow PathConn refactor.
func (d *Dialer) AddPacketPathFactory(name string, f PacketPathFactory) error {
	return ErrPacketFactoryStage2
}
