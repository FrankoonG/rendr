// Package tun provides the TUN frontend surface. The first milestone
// exposes capability probing and config validation; packet-to-flow
// adaptation lives in l3ingress.
package tun

import (
	"fmt"
	"net/netip"

	"github.com/FrankoonG/rendr/virtualif"
)

// Config describes a TUN ingress requested by an embedding program.
type Config struct {
	Enabled   bool
	Name      string
	MTU       int
	Addresses []netip.Prefix
}

const (
	DefaultMTU = 1500
	MinMTU     = 576
)

// Normalize fills defaults for optional fields.
func (c Config) Normalize() Config {
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	return c
}

// Validate checks fields that can be validated without touching the OS.
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	c = c.Normalize()
	if c.MTU < MinMTU {
		return &virtualif.Error{
			Op:     "tun config",
			Reason: virtualif.ReasonInvalidMTU,
			Err:    fmt.Errorf("mtu %d < %d", c.MTU, MinMTU),
		}
	}
	for i, p := range c.Addresses {
		if !p.IsValid() {
			return &virtualif.Error{
				Op:     "tun config",
				Reason: virtualif.ReasonTUNUnavailable,
				Err:    fmt.Errorf("address %d is invalid", i),
			}
		}
	}
	return nil
}
