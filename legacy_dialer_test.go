package rendr

import "fmt"

// These aliases keep historical package-local tests useful while ensuring the
// v1 production package exports only Runtime. External packages never compile
// this file.
type Dialer = sessionDialer
type StreamPathFactory = streamPathFactory
type PacketPathFactory = packetPathFactory
type PrimaryPolicy = primaryPolicy
type RetryPolicy = retryPolicy

const (
	PrimaryPrefer  = primaryPrefer
	PrimaryRequire = primaryRequire
)

func (d *sessionDialer) AddStreamPathFactory(name string, f streamPathFactory) error {
	if name == "" {
		return fmt.Errorf("rendr: empty StreamPathFactory name")
	}
	if f == nil {
		return fmt.Errorf("rendr: nil StreamPathFactory %q", name)
	}
	if d.streamFactories == nil {
		d.streamFactories = map[string]streamPathFactory{}
	}
	if _, dup := d.streamFactories[name]; dup {
		return fmt.Errorf("rendr: stream factory %q already registered on this Dialer", name)
	}
	if _, dup := d.packetFactories[name]; dup {
		return fmt.Errorf("rendr: %q already registered as PacketPathFactory on this Dialer", name)
	}
	d.streamFactories[name] = f
	if d.factoryCarriers == nil {
		d.factoryCarriers = map[string]CarrierFamily{}
	}
	d.factoryCarriers[name] = CarrierUnknown
	return nil
}

func (d *sessionDialer) AddPacketPathFactory(name string, f packetPathFactory) error {
	if name == "" {
		return fmt.Errorf("rendr: empty PacketPathFactory name")
	}
	if f == nil {
		return fmt.Errorf("rendr: nil PacketPathFactory %q", name)
	}
	if d.packetFactories == nil {
		d.packetFactories = map[string]packetPathFactory{}
	}
	if _, dup := d.packetFactories[name]; dup {
		return fmt.Errorf("rendr: packet factory %q already registered on this Dialer", name)
	}
	if _, dup := d.streamFactories[name]; dup {
		return fmt.Errorf("rendr: %q already registered as StreamPathFactory on this Dialer", name)
	}
	d.packetFactories[name] = f
	if d.factoryCarriers == nil {
		d.factoryCarriers = map[string]CarrierFamily{}
	}
	d.factoryCarriers[name] = CarrierUnknown
	return nil
}
