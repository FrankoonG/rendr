package xray

import (
	"context"
	"fmt"
	"net"

	"github.com/FrankoonG/rendr"
	xrouter "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
)

// BalancerStreamFactory is one outbound selected from an xray
// BalancingRule, exposed as a rendr StreamPathFactory registration.
type BalancerStreamFactory struct {
	// Name is stable for this process and suitable for
	// rendr.Dialer.AddStreamPathFactory plus PathSpec.Transport.
	Name string

	// OutboundTag is the xray outbound tag forced for this path.
	OutboundTag string

	Factory rendr.StreamPathFactory
}

// BalancerPacketFactory is the packet-mode companion to
// BalancerStreamFactory.
type BalancerPacketFactory struct {
	Name        string
	OutboundTag string
	Factory     rendr.PacketPathFactory
}

// XrayTaggedOutboundAsStreamFactory returns a StreamPathFactory that
// dispatches through a specific xray outbound tag. This is the small
// building block behind BalancerObject adapter mode: xray owns the
// protocol chain, rendr owns path migration.
func XrayTaggedOutboundAsStreamFactory(inst *core.Instance, outboundTag string) rendr.StreamPathFactory {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		dest, err := parseTCPDestination(addr)
		if err != nil {
			return nil, err
		}
		if outboundTag != "" {
			ctx = session.SetForcedOutboundTagToContext(ctx, outboundTag)
		}
		return core.Dial(ctx, inst, dest)
	}
}

// XrayTaggedOutboundAsPacketFactory returns a PacketPathFactory forced
// through a specific xray outbound tag.
func XrayTaggedOutboundAsPacketFactory(inst *core.Instance, outboundTag string) rendr.PacketPathFactory {
	return func(ctx context.Context, addr string) (net.PacketConn, error) {
		_ = addr
		if outboundTag != "" {
			ctx = session.SetForcedOutboundTagToContext(ctx, outboundTag)
		}
		return core.DialUDP(ctx, inst)
	}
}

// XrayBalancerAsStreamFactories adapts an xray BalancingRule into
// per-outbound rendr stream factories. The returned factories use the
// selected outbound tags as forced xray detours; embedders put the
// matching Name into rendr PathSpec.Transport and the rendr server
// address into PathSpec.Address.
func XrayBalancerAsStreamFactories(inst *core.Instance, rule *xrouter.BalancingRule) ([]BalancerStreamFactory, error) {
	tags, err := xrayBalancerOutboundTags(inst, rule)
	if err != nil {
		return nil, err
	}
	out := make([]BalancerStreamFactory, len(tags))
	for i, tag := range tags {
		name := "xray:" + tag
		out[i] = BalancerStreamFactory{
			Name:        name,
			OutboundTag: tag,
			Factory:     XrayTaggedOutboundAsStreamFactory(inst, tag),
		}
	}
	return out, nil
}

// XrayBalancerAsPacketFactories adapts an xray BalancingRule into
// packet-mode rendr factories.
func XrayBalancerAsPacketFactories(inst *core.Instance, rule *xrouter.BalancingRule) ([]BalancerPacketFactory, error) {
	tags, err := xrayBalancerOutboundTags(inst, rule)
	if err != nil {
		return nil, err
	}
	out := make([]BalancerPacketFactory, len(tags))
	for i, tag := range tags {
		name := "xray:" + tag
		out[i] = BalancerPacketFactory{
			Name:        name,
			OutboundTag: tag,
			Factory:     XrayTaggedOutboundAsPacketFactory(inst, tag),
		}
	}
	return out, nil
}

func xrayBalancerOutboundTags(inst *core.Instance, rule *xrouter.BalancingRule) ([]string, error) {
	if inst == nil {
		return nil, fmt.Errorf("rendr/xray: nil xray Instance")
	}
	if rule == nil {
		return nil, fmt.Errorf("rendr/xray: nil BalancingRule")
	}
	feat := inst.GetFeature(outbound.ManagerType())
	ohm, ok := feat.(outbound.Manager)
	if !ok || ohm == nil {
		return nil, fmt.Errorf("rendr/xray: outbound manager unavailable")
	}
	balancer, err := rule.Build(ohm, nil)
	if err != nil {
		return nil, fmt.Errorf("rendr/xray: build BalancingRule: %w", err)
	}
	tags, err := balancer.SelectOutbounds()
	if err != nil {
		return nil, fmt.Errorf("rendr/xray: select BalancingRule outbounds: %w", err)
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("rendr/xray: BalancingRule selected no outbounds")
	}
	return tags, nil
}
