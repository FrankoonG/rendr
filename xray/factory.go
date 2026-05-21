package xray

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/FrankoonG/rendr"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

// XrayInstanceAsStreamFactory returns a rendr StreamPathFactory that
// dials through a started xray-core Instance. The Instance's routing
// and outbound configuration decides which xray protocol chain carries
// the bytes; rendr sees only the resulting net.Conn.
func XrayInstanceAsStreamFactory(inst *core.Instance) rendr.StreamPathFactory {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		dest, err := parseTCPDestination(addr)
		if err != nil {
			return nil, err
		}
		return core.Dial(ctx, inst, dest)
	}
}

// XrayInstanceAsPacketFactory returns the UDP-side equivalent of
// XrayInstanceAsStreamFactory. xray-core's UDP dispatcher derives the
// per-packet target from the xray Instance configuration; rendr's
// packet path wrapper still receives PathSpec.Address and uses it as
// its own WriteTo peer.
func XrayInstanceAsPacketFactory(inst *core.Instance) rendr.PacketPathFactory {
	return func(ctx context.Context, addr string) (net.PacketConn, error) {
		_ = addr
		return core.DialUDP(ctx, inst)
	}
}

// XrayOutboundAsStreamFactory is the roadmap-named glue-B helper. The
// stable xray-core public API dispatches through a started Instance,
// so the outbound chain should already be installed in inst; chain is
// retained in the signature for embedders that keep the chosen config
// object next to the factory.
func XrayOutboundAsStreamFactory(inst *core.Instance, chain *core.OutboundHandlerConfig) rendr.StreamPathFactory {
	_ = chain
	return XrayInstanceAsStreamFactory(inst)
}

// XrayOutboundAsPacketFactory is the packet-mode companion to
// XrayOutboundAsStreamFactory.
func XrayOutboundAsPacketFactory(inst *core.Instance, chain *core.OutboundHandlerConfig) rendr.PacketPathFactory {
	_ = chain
	return XrayInstanceAsPacketFactory(inst)
}

func parseTCPDestination(addr string) (xnet.Destination, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("rendr/xray: bad addr %q: %w", addr, err)
	}
	p, err := strconv.ParseUint(strings.TrimSpace(port), 10, 16)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("rendr/xray: bad port in %q: %w", addr, err)
	}
	return xnet.Destination{
		Network: xnet.Network_TCP,
		Address: xnet.ParseAddress(host),
		Port:    xnet.Port(p),
	}, nil
}
