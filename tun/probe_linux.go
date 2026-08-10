//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net"

	"github.com/FrankoonG/rendr/virtualif"
)

const devNetTun = "/dev/net/tun"

type probeDevice interface {
	Close() error
	Name() string
	MTU() int
	QueueCount() int
}

type probeOpenFunc func(Config) (probeDevice, error)
type probeGoneFunc func(string) (bool, error)

// Probe reports whether this process can open the default Linux TUN
// configuration. The temporary interface disappears before Probe returns.
// Config-specific callers must still treat Open as the final authority.
func Probe() virtualif.Capability {
	return probeConfig(
		Config{Enabled: true, Name: "rendrp%d"},
		func(cfg Config) (probeDevice, error) { return Open(cfg) },
	)
}

func probeConfig(cfg Config, open probeOpenFunc) virtualif.Capability {
	return probeConfigWithVerifier(cfg, open, probeInterfaceGone)
}

func probeConfigWithVerifier(cfg Config, open probeOpenFunc, gone probeGoneFunc) virtualif.Capability {
	if open == nil {
		return failedProbe(errors.New("nil TUN opener"))
	}
	if gone == nil {
		return failedProbe(errors.New("nil TUN cleanup verifier"))
	}
	if !cfg.Enabled {
		return failedProbe(&virtualif.Error{
			Op:     "tun probe",
			Reason: virtualif.ReasonTUNUnavailable,
			Err:    errors.New("disabled"),
		})
	}
	if err := cfg.Validate(); err != nil {
		return failedProbe(err)
	}
	normalized := cfg.Normalize()
	device, err := open(cfg)
	if err != nil {
		if device != nil {
			err = errors.Join(err, closeProbeDevice(device))
		}
		return failedProbe(err)
	}
	if device == nil {
		return failedProbe(errors.New("TUN opener returned a nil device"))
	}

	var semanticErr error
	if device.Name() == "" {
		semanticErr = errors.Join(semanticErr, errors.New("kernel returned an empty TUN name"))
	}
	if actual := device.MTU(); actual != normalized.MTU {
		semanticErr = errors.Join(semanticErr, fmt.Errorf("TUN MTU=%d want %d", actual, normalized.MTU))
	}
	if actual := device.QueueCount(); actual != normalized.Queues {
		semanticErr = errors.Join(semanticErr, fmt.Errorf("TUN queues=%d want %d", actual, normalized.Queues))
	}
	name := device.Name()
	semanticErr = errors.Join(semanticErr, closeProbeDevice(device))
	if name != "" {
		removed, verifyErr := gone(name)
		if verifyErr != nil {
			semanticErr = errors.Join(semanticErr, fmt.Errorf("verify temporary TUN removal: %w", verifyErr))
		} else if !removed {
			semanticErr = errors.Join(semanticErr, fmt.Errorf("temporary TUN %q remains after close", name))
		}
	}
	if semanticErr != nil {
		return failedProbe(semanticErr)
	}
	return virtualif.Capability{Available: true}
}

func closeProbeDevice(device probeDevice) error {
	if device == nil {
		return nil
	}
	if err := device.Close(); err != nil {
		return fmt.Errorf("close temporary TUN: %w", err)
	}
	return nil
}

func probeInterfaceGone(name string) (bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}
	for _, iface := range interfaces {
		if iface.Name == name {
			return false, nil
		}
	}
	return true, nil
}

func failedProbe(err error) virtualif.Capability {
	reason := virtualif.ReasonTUNUnavailable
	var verr *virtualif.Error
	if errors.As(err, &verr) && verr.Reason != "" {
		reason = verr.Reason
	} else {
		err = &virtualif.Error{Op: "tun probe", Reason: reason, Err: err}
	}
	return virtualif.Capability{Reason: reason, Err: err}
}
