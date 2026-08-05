package rendr

import (
	"context"
	"fmt"
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
	framed  map[string]transport.PathFactory
	carrier map[string]CarrierFamily
}

func builtinPathFactories() map[string]transport.PathFactory {
	return map[string]transport.PathFactory{
		"tcp":     tcp.New(),
		"udpflow": udpflow.New(),
	}
}

func isBuiltinPathFactory(name string) bool {
	switch name {
	case "tcp", "udpflow":
		return true
	default:
		return false
	}
}

func (d *sessionDialer) snapshotFactoryResolver() *pathFactoryResolver {
	resolver := &pathFactoryResolver{
		stream:  make(map[string]streamPathFactory, len(d.streamFactories)),
		packet:  make(map[string]packetPathFactory, len(d.packetFactories)),
		framed:  builtinPathFactories(),
		carrier: map[string]CarrierFamily{"tcp": CarrierTCP, "udpflow": CarrierUDP},
	}
	for name, factory := range d.streamFactories {
		resolver.stream[name] = factory
	}
	for name, factory := range d.packetFactories {
		resolver.packet[name] = factory
	}
	for name, factory := range d.framedFactories {
		resolver.framed[name] = factory
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
	_, framed := r.framed[name]
	return stream || packet || framed
}

// dialPath resolves a path only against the immutable session snapshot. This
// preserves the same Runtime-local factory for initial dial, explicit AddPath,
// and recovery retries; unknown IDs fail closed.
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
		if factory, ok := r.framed[spec.Transport]; ok {
			return factory.DialPath(ctx, spec)
		}
	}
	return nil, fmt.Errorf("rendr: path factory %q is not registered on this Runtime", spec.Transport)
}
