package rendr

import (
	"context"
	"fmt"
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
	streamFactories map[string]StreamPathFactory
	packetFactories map[string]PacketPathFactory
}

// SessionConfig describes one stream or packet session. Root is mandatory.
// No field selects a mobility implementation; leaf planning remains owned by
// rendr and negotiated with the peer.
type SessionConfig struct {
	Root Target

	Primary       string
	PrimaryPolicy PrimaryPolicy

	PreserveL3Identity bool
}

func NewRuntime(config RuntimeConfig) (*Runtime, error) {
	normalized, err := normalizeRuntimeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		config:          normalized,
		instanceID:      engine.NewInstanceID(),
		streamFactories: make(map[string]StreamPathFactory),
		packetFactories: make(map[string]PacketPathFactory),
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

// AddStreamPathFactory registers a process-local generic stream carrier.
// Sessions snapshot the registry at dial time, so later registrations cannot
// change recovery behavior of an existing connection.
func (r *Runtime) AddStreamPathFactory(name string, factory StreamPathFactory) error {
	if r == nil {
		return fmt.Errorf("rendr: nil Runtime")
	}
	if name == "" {
		return fmt.Errorf("rendr: empty StreamPathFactory name")
	}
	if factory == nil {
		return fmt.Errorf("rendr: nil StreamPathFactory %q", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.streamFactories[name]; exists {
		return fmt.Errorf("rendr: stream factory %q already registered", name)
	}
	if _, exists := r.packetFactories[name]; exists {
		return fmt.Errorf("rendr: %q already registered as PacketPathFactory", name)
	}
	r.streamFactories[name] = factory
	return nil
}

func (r *Runtime) AddPacketPathFactory(name string, factory PacketPathFactory) error {
	if r == nil {
		return fmt.Errorf("rendr: nil Runtime")
	}
	if name == "" {
		return fmt.Errorf("rendr: empty PacketPathFactory name")
	}
	if factory == nil {
		return fmt.Errorf("rendr: nil PacketPathFactory %q", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.packetFactories[name]; exists {
		return fmt.Errorf("rendr: packet factory %q already registered", name)
	}
	if _, exists := r.streamFactories[name]; exists {
		return fmt.Errorf("rendr: %q already registered as StreamPathFactory", name)
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
	for name, factory := range r.streamFactories {
		streams[name] = factory
	}
	packets := make(map[string]PacketPathFactory, len(r.packetFactories))
	for name, factory := range r.packetFactories {
		packets[name] = factory
	}
	r.mu.RUnlock()
	return &Dialer{
		Root:               config.Root,
		Runtime:            r.config,
		PreserveL3Identity: config.PreserveL3Identity,
		InstanceID:         r.instanceID,
		Primary:            config.Primary,
		PrimaryPolicy:      config.PrimaryPolicy,
		streamFactories:    streams,
		packetFactories:    packets,
	}, nil
}
