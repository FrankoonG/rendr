// Package tun provides the TUN frontend surface. The first milestone
// exposes capability probing and config validation; packet-to-flow
// adaptation lives in l3ingress.
package tun

import (
	"fmt"

	"github.com/FrankoonG/rendr/virtualif"
)

// Config describes a TUN ingress requested by an embedding program.
type Config struct {
	Enabled bool
	Name    string
	MTU     int
	Queues  int
}

const (
	DefaultMTU = 1500
	// MinMTU keeps the dual-stack frontend valid for IPv6 without a hidden
	// adaptation layer below the virtual interface.
	MinMTU        = 1280
	MaxMTU        = 65535
	DefaultQueues = 1
	MaxQueues     = 64
)

// Normalize fills defaults for optional fields.
func (c Config) Normalize() Config {
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.Queues == 0 {
		c.Queues = DefaultQueues
	}
	return c
}

// Validate checks fields that can be validated without touching the OS.
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	c = c.Normalize()
	if c.MTU < MinMTU || c.MTU > MaxMTU {
		return &virtualif.Error{
			Op:     "tun config",
			Reason: virtualif.ReasonInvalidMTU,
			Err:    fmt.Errorf("mtu %d outside [%d,%d]", c.MTU, MinMTU, MaxMTU),
		}
	}
	if c.Queues < 1 || c.Queues > MaxQueues {
		return &virtualif.Error{
			Op:     "tun config",
			Reason: virtualif.ReasonInvalidQueueCount,
			Err:    fmt.Errorf("queues %d outside [1,%d]", c.Queues, MaxQueues),
		}
	}
	return nil
}
