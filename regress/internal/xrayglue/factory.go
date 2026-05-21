package xrayglue

import (
	"github.com/FrankoonG/rendr"
	rendrxray "github.com/FrankoonG/rendr/xray"
	"github.com/xtls/xray-core/core"
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
	return rendrxray.XrayInstanceAsStreamFactory(inst)
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
	return rendrxray.XrayInstanceAsPacketFactory(inst)
}
