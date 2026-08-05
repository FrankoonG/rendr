package rendr

import (
	"fmt"

	"github.com/FrankoonG/rendr/transport"
)

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

func (d *sessionDialer) AddFramedPathFactory(name string, carrier CarrierFamily, f transport.PathFactory) error {
	if name == "" {
		return fmt.Errorf("rendr: empty framed factory name")
	}
	if f == nil {
		return fmt.Errorf("rendr: nil framed factory %q", name)
	}
	if d.framedFactories == nil {
		d.framedFactories = map[string]transport.PathFactory{}
	}
	if _, dup := d.framedFactories[name]; dup {
		return fmt.Errorf("rendr: framed factory %q already registered on this session dialer", name)
	}
	if _, dup := d.streamFactories[name]; dup {
		return fmt.Errorf("rendr: %q already registered as stream factory on this session dialer", name)
	}
	if _, dup := d.packetFactories[name]; dup {
		return fmt.Errorf("rendr: %q already registered as packet factory on this session dialer", name)
	}
	d.framedFactories[name] = f
	if d.factoryCarriers == nil {
		d.factoryCarriers = map[string]CarrierFamily{}
	}
	d.factoryCarriers[name] = carrier
	return nil
}
