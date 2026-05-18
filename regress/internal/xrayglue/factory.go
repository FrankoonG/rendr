package xrayglue

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/FrankoonG/rendr"
	"github.com/xtls/xray-core/core"
	xnet "github.com/xtls/xray-core/common/net"
)

// XrayInstanceAsStreamFactory returns a rendr.StreamPathFactory that
// routes every Dial through the supplied xray Instance via
// core.Dial. The xray Config baked into inst decides which outbound
// chain carries the bytes — direct VLESS, Trojan, Shadowsocks-2022,
// nested chains, reverse, etc.
//
// The factory parses PathSpec.Address as "host:port" (the only form
// rendr's existing PathSpec syntax uses) and dispatches via the TCP
// destination kind. UDP-bearing protocols belong to
// XrayInstanceAsPacketFactory, not here.
//
// The supplied inst must have already been started (inst.Start());
// shutdown is the caller's responsibility — the factory does not
// retain ownership.
//
// Used by docs/regression-suite.md §7 T3 to back path-profiles like
// PYS-D-1 (VLESS+Vision+TLS direct) with real xray protocol code.
func XrayInstanceAsStreamFactory(inst *core.Instance) rendr.StreamPathFactory {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		dest, err := parseTCPDestination(addr)
		if err != nil {
			return nil, err
		}
		return core.Dial(ctx, inst, dest)
	}
}

// XrayInstanceAsPacketFactory is the UDP-side equivalent. core.DialUDP
// returns a net.PacketConn dispatched through the same xray Instance.
// The packet factory then becomes a rendr.PacketPathFactory; rendr's
// dialer wraps it via udpflow.WrapFromSpec, applying the 8-byte
// flow-id header per outgoing datagram.
//
// Note: core.DialUDP does NOT take a destination — xray's UDP
// dispatcher resolves the per-packet target from inside the UDP
// outbound's configuration. For rendr's purposes the PathSpec.Address
// supplied to the factory is forwarded straight to udpflow.WrapFromSpec
// (which treats it as the WriteTo peer); ensure your xray Config's
// UDP outbound is wired to forward there.
func XrayInstanceAsPacketFactory(inst *core.Instance) rendr.PacketPathFactory {
	return func(ctx context.Context, addr string) (net.PacketConn, error) {
		// addr is unused at the xray-dial level (UDP dispatcher
		// has its own internal addressing); rendr's udpflow wrap
		// uses it to pin the WriteTo peer.
		_ = addr
		return core.DialUDP(ctx, inst)
	}
}

// parseTCPDestination converts "host:port" into xray's
// net.Destination shape with Network=TCP. Mirrors xray-core's own
// internal address parsing without importing private packages.
func parseTCPDestination(addr string) (xnet.Destination, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("xrayglue: bad addr %q: %w", addr, err)
	}
	p, err := strconv.ParseUint(strings.TrimSpace(port), 10, 16)
	if err != nil {
		return xnet.Destination{}, fmt.Errorf("xrayglue: bad port in %q: %w", addr, err)
	}
	return xnet.Destination{
		Network: xnet.Network_TCP,
		Address: xnet.ParseAddress(host),
		Port:    xnet.Port(p),
	}, nil
}
