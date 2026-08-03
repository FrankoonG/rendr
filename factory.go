package rendr

import (
	"context"
	"fmt"
	"net"

	"github.com/FrankoonG/rendr/transport"
	"github.com/FrankoonG/rendr/transport/tcp"
	"github.com/FrankoonG/rendr/transport/udpflow"
)

// pathFactoryResolver is the immutable, per-session snapshot of a Dialer's
// custom factories. A session must keep using the factories that established
// it even if the caller later reuses or mutates the original Dialer.
type pathFactoryResolver struct {
	stream map[string]StreamPathFactory
	packet map[string]PacketPathFactory
}

func (d *Dialer) snapshotFactoryResolver() *pathFactoryResolver {
	resolver := &pathFactoryResolver{
		stream: make(map[string]StreamPathFactory, len(d.streamFactories)),
		packet: make(map[string]PacketPathFactory, len(d.packetFactories)),
	}
	for name, factory := range d.streamFactories {
		resolver.stream[name] = factory
	}
	for name, factory := range d.packetFactories {
		resolver.packet[name] = factory
	}
	return resolver
}

// dialPath resolves a path against the session snapshot before consulting the
// process-wide transport registry. The nil receiver is intentional: inbound
// listener sessions have no caller-provided factories and retain the existing
// registry-only AddPath behavior.
func (r *pathFactoryResolver) dialPath(ctx context.Context, spec PathSpec) (transport.PathConn, error) {
	if r != nil {
		if factory, ok := r.stream[spec.Transport]; ok {
			conn, err := factory(ctx, spec.Address)
			if err != nil {
				return nil, err
			}
			return tcp.Wrap(conn), nil
		}
		if factory, ok := r.packet[spec.Transport]; ok {
			conn, err := factory(ctx, spec.Address)
			if err != nil {
				return nil, err
			}
			return udpflow.WrapFromSpec(conn, spec)
		}
	}
	return dialPath(ctx, spec)
}

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

// PacketPathFactory mirrors StreamPathFactory for packet-mode paths.
// The returned net.PacketConn MUST preserve datagram boundaries
// (single WriteTo == single peer ReadFrom) and have MTU sufficient
// for the rendr 8-byte flow-id header plus expected payload.
//
// rendr-side wraps the returned net.PacketConn with
// transport/udpflow.WrapFromSpec — the same flow-id framing layer
// that backs the built-in udpflow transport. The factory does NOT
// have to produce a "connected" socket: udpflow's WrapFromSpec
// resolves PathSpec.Address as the WriteTo peer and validates
// incoming flow_ids regardless of source-addr.
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
//
// Dial and DialPacket snapshot the registered factories. Registrations or
// other Dialer mutations after a connection is created do not affect that
// connection's retries or dynamic AddPath calls.
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

// AddPacketPathFactory registers a packet factory under name. Any
// PathSpec in d.Paths whose Transport equals name is dialed via this
// factory instead of transport.Default, used only by DialPacket()
// (packet-mode sessions). The contract:
//
//   - The returned net.PacketConn MUST preserve datagram boundaries
//     (one WriteTo == one peer ReadFrom).
//   - MTU MUST be sufficient for the rendr 8B flow-id header plus
//     expected payload.
//   - PathSpec.Address (or PathSpec.Opts["peer_addr"] if you need to
//     decouple "dial target" from "datagram peer") is resolved as
//     net.ResolveUDPAddr and used as the WriteTo destination on every
//     outgoing datagram.
//   - PathSpec.Opts["flow_id_hex"] (14 hex digits = 7 bytes) overrides
//     the random flow_id; otherwise crypto/rand picks one.
//
// Names are unique per Dialer across both stream and packet maps.
// Existing sessions retain the factory snapshot captured when they dialed;
// registering another factory later affects only future sessions.
func (d *Dialer) AddPacketPathFactory(name string, f PacketPathFactory) error {
	if name == "" {
		return fmt.Errorf("rendr: empty PacketPathFactory name")
	}
	if f == nil {
		return fmt.Errorf("rendr: nil PacketPathFactory %q", name)
	}
	if d.packetFactories == nil {
		d.packetFactories = map[string]PacketPathFactory{}
	}
	if _, dup := d.packetFactories[name]; dup {
		return fmt.Errorf("rendr: packet factory %q already registered on this Dialer", name)
	}
	if _, dup := d.streamFactories[name]; dup {
		return fmt.Errorf("rendr: %q already registered as StreamPathFactory on this Dialer", name)
	}
	d.packetFactories[name] = f
	return nil
}
