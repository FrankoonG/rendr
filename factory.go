package rendr

import (
	"context"
	"net"

	"github.com/FrankoonG/rendr/transport"
	"github.com/FrankoonG/rendr/transport/tcp"
	"github.com/FrankoonG/rendr/transport/udpflow"
)

type streamPathFactory func(context.Context, string) (net.Conn, error)
type packetPathFactory func(context.Context, string) (net.PacketConn, error)

// pathFactoryResolver is the immutable, per-session snapshot of a Runtime's
// custom factories. A session must keep using the factories that established
// it even if the caller later registers factories for future sessions.
type pathFactoryResolver struct {
	stream  map[string]streamPathFactory
	packet  map[string]packetPathFactory
	carrier map[string]CarrierFamily
}

func (d *sessionDialer) snapshotFactoryResolver() *pathFactoryResolver {
	resolver := &pathFactoryResolver{
		stream:  make(map[string]streamPathFactory, len(d.streamFactories)),
		packet:  make(map[string]packetPathFactory, len(d.packetFactories)),
		carrier: make(map[string]CarrierFamily, len(d.factoryCarriers)),
	}
	for name, factory := range d.streamFactories {
		resolver.stream[name] = factory
	}
	for name, factory := range d.packetFactories {
		resolver.packet[name] = factory
	}
	for name, carrier := range d.factoryCarriers {
		resolver.carrier[name] = carrier
	}
	return resolver
}

func (r *pathFactoryResolver) carrierFamily(name string) CarrierFamily {
	if r == nil {
		return CarrierUnknown
	}
	return r.carrier[name]
}

func (r *pathFactoryResolver) hasFactory(name string) bool {
	if r == nil {
		return false
	}
	_, stream := r.stream[name]
	_, packet := r.packet[name]
	return stream || packet
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
