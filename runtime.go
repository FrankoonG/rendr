package rendr

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/FrankoonG/rendr/internal/engine"
)

// Runtime owns process-wide rendr policy defaults, factory registrations,
// capability state, and runtime identity. Configuration is copied and frozen
// by NewRuntime; individual sessions supply only SessionConfig.
type Runtime struct {
	config     RuntimeConfig
	instanceID InstanceID

	mu              sync.RWMutex
	streamFactories map[string]StreamFactory
	packetFactories map[string]PacketFactory
}

// SessionConfig describes one stream or packet session. Root is mandatory.
// No field selects a mobility implementation; leaf planning remains owned by
// rendr and negotiated with the peer.
type SessionConfig struct {
	Root Target

	PreserveL3Identity bool
}

// CarrierFamily states the factual network family beneath a generic factory.
// It neither selects nor grants a mobility implementation.
type CarrierFamily uint8

const (
	CarrierUnknown CarrierFamily = iota
	CarrierTCP
	CarrierUDP
)

func (f CarrierFamily) valid() bool { return f <= CarrierUDP }

type StreamFactory struct {
	Carrier CarrierFamily
	Dial    func(context.Context, string) (net.Conn, error)
}

type PacketFactory struct {
	Carrier CarrierFamily
	Dial    func(context.Context, string) (net.PacketConn, error)
}

func NewRuntime(config RuntimeConfig) (*Runtime, error) {
	normalized, err := normalizeRuntimeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		config:          normalized,
		instanceID:      engine.NewInstanceID(),
		streamFactories: make(map[string]StreamFactory),
		packetFactories: make(map[string]PacketFactory),
	}, nil
}

// Config returns the immutable normalized runtime configuration by value.
func (r *Runtime) Config() RuntimeConfig {
	if r == nil {
		return RuntimeConfig{}
	}
	return r.config
}

func (r *Runtime) Dial(ctx context.Context, config SessionConfig) (Conn, error) {
	dialer, err := r.sessionDialer(config)
	if err != nil {
		return nil, err
	}
	return dialer.Dial(ctx)
}

func (r *Runtime) DialPacket(ctx context.Context, config SessionConfig) (PacketConn, error) {
	dialer, err := r.sessionDialer(config)
	if err != nil {
		return nil, err
	}
	return dialer.DialPacket(ctx)
}

// RegisterStreamFactory registers a process-local generic stream carrier.
// Sessions snapshot the registry at dial time, so later registrations cannot
// change recovery behavior of an existing connection.
func (r *Runtime) RegisterStreamFactory(name string, factory StreamFactory) error {
	if r == nil {
		return fmt.Errorf("rendr: nil Runtime")
	}
	if name == "" {
		return fmt.Errorf("rendr: empty StreamFactory name")
	}
	if factory.Dial == nil {
		return fmt.Errorf("rendr: nil StreamFactory.Dial %q", name)
	}
	if !factory.Carrier.valid() {
		return fmt.Errorf("rendr: invalid StreamFactory carrier %d", factory.Carrier)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.streamFactories[name]; exists {
		return fmt.Errorf("rendr: stream factory %q already registered", name)
	}
	if _, exists := r.packetFactories[name]; exists {
		return fmt.Errorf("rendr: %q already registered as PacketFactory", name)
	}
	r.streamFactories[name] = factory
	return nil
}

func (r *Runtime) RegisterPacketFactory(name string, factory PacketFactory) error {
	if r == nil {
		return fmt.Errorf("rendr: nil Runtime")
	}
	if name == "" {
		return fmt.Errorf("rendr: empty PacketFactory name")
	}
	if factory.Dial == nil {
		return fmt.Errorf("rendr: nil PacketFactory.Dial %q", name)
	}
	if !factory.Carrier.valid() {
		return fmt.Errorf("rendr: invalid PacketFactory carrier %d", factory.Carrier)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.packetFactories[name]; exists {
		return fmt.Errorf("rendr: packet factory %q already registered", name)
	}
	if _, exists := r.streamFactories[name]; exists {
		return fmt.Errorf("rendr: %q already registered as StreamFactory", name)
	}
	r.packetFactories[name] = factory
	return nil
}

func (r *Runtime) sessionDialer(config SessionConfig) (*Dialer, error) {
	if r == nil {
		return nil, fmt.Errorf("rendr: nil Runtime")
	}
	if config.Root == nil || isTypedNilTarget(config.Root) {
		return nil, errRootRequired
	}
	r.mu.RLock()
	streams := make(map[string]StreamPathFactory, len(r.streamFactories))
	carriers := make(map[string]CarrierFamily, len(r.streamFactories)+len(r.packetFactories))
	for name, factory := range r.streamFactories {
		streams[name] = factory.Dial
		carriers[name] = factory.Carrier
	}
	packets := make(map[string]PacketPathFactory, len(r.packetFactories))
	for name, factory := range r.packetFactories {
		packets[name] = factory.Dial
		carriers[name] = factory.Carrier
	}
	r.mu.RUnlock()
	return &Dialer{
		Root:               config.Root,
		Runtime:            r.config,
		PreserveL3Identity: config.PreserveL3Identity,
		InstanceID:         r.instanceID,
		streamFactories:    streams,
		packetFactories:    packets,
		factoryCarriers:    carriers,
	}, nil
}
