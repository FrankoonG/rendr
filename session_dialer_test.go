package rendr

import "fmt"

// These test-only helpers exercise the internal session factory maps.
// External packages never compile this file.
func (d *sessionDialer) AddStreamPathFactory(name string, f streamPathFactory) error {
	if name == "" {
		return fmt.Errorf("rendr: empty stream factory name")
	}
	if f == nil {
		return fmt.Errorf("rendr: nil stream factory %q", name)
	}
	if d.streamFactories == nil {
		d.streamFactories = map[string]streamPathFactory{}
	}
	if _, dup := d.streamFactories[name]; dup {
		return fmt.Errorf("rendr: stream factory %q already registered on this session dialer", name)
	}
	if _, dup := d.packetFactories[name]; dup {
		return fmt.Errorf("rendr: %q already registered as packet factory on this session dialer", name)
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
		return fmt.Errorf("rendr: empty packet factory name")
	}
	if f == nil {
		return fmt.Errorf("rendr: nil packet factory %q", name)
	}
	if d.packetFactories == nil {
		d.packetFactories = map[string]packetPathFactory{}
	}
	if _, dup := d.packetFactories[name]; dup {
		return fmt.Errorf("rendr: packet factory %q already registered on this session dialer", name)
	}
	if _, dup := d.streamFactories[name]; dup {
		return fmt.Errorf("rendr: %q already registered as stream factory on this session dialer", name)
	}
	d.packetFactories[name] = f
	if d.factoryCarriers == nil {
		d.factoryCarriers = map[string]CarrierFamily{}
	}
	d.factoryCarriers[name] = CarrierUnknown
	return nil
}
