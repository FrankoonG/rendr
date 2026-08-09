package rendr

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/transport"
)

// Runtime owns one isolated set of rendr policy defaults, factory registrations,
// capability state, and runtime identity. Configuration is copied and frozen
// by NewRuntime; individual sessions supply only SessionConfig.
type Runtime struct {
	config         RuntimeConfig
	instanceID     InstanceID
	bridges        *engine.BridgeTable
	mobilityLedger *engine.LeafMobilityPeerLedger

	mu              sync.RWMutex
	streamFactories map[string]StreamFactory
	packetFactories map[string]PacketFactory
	framedFactories map[string]FramedFactory

	listenMu sync.Mutex
	listener *SessionListener
}

func (r *Runtime) claimListener(listener *SessionListener) error {
	r.listenMu.Lock()
	defer r.listenMu.Unlock()
	if r.listener != nil {
		return fmt.Errorf("rendr: Runtime already has an active SessionListener")
	}
	r.listener = listener
	return nil
}

func (r *Runtime) releaseListener(listener *SessionListener) {
	r.listenMu.Lock()
	if r.listener == listener {
		r.listener = nil
	}
	r.listenMu.Unlock()
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
	// Carrier reports the factual network family beneath Dial. It does not
	// request a mobility backend or assert ownership of the returned socket.
	Carrier CarrierFamily
	// Dial receives PathSpec.Address and must honor context cancellation. The
	// returned connection must be an ordered byte stream terminating at the
	// same rendr peer as every other leaf in the session.
	Dial func(context.Context, string) (net.Conn, error)
}

type PacketFactory struct {
	// Carrier reports the factual network family beneath Dial. It does not
	// request a mobility backend or assert ownership of the returned socket.
	Carrier CarrierFamily
	// Dial receives PathSpec.Address and must honor context cancellation. The
	// returned connection must preserve datagram boundaries and provide an MTU
	// sufficient for rendr flow framing plus the application's payload.
	Dial func(context.Context, string) (net.PacketConn, error)
}

// FramedFactory registers an advanced carrier whose Factory already
// returns a transport.PathConn with rendr frame boundaries. It is intended for
// optional adapters such as QUIC and gVisor. Like the generic factories, it
// states only carrier facts and never grants owned mobility.
type FramedFactory struct {
	Carrier CarrierFamily
	Factory transport.PathFactory
}

func NewRuntime(config RuntimeConfig) (*Runtime, error) {
	normalized, err := normalizeRuntimeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		config:          normalized,
		instanceID:      engine.NewInstanceID(),
		bridges:         engine.NewBridgeTable(),
		mobilityLedger:  engine.NewLeafMobilityPeerLedger(),
		streamFactories: make(map[string]StreamFactory),
		packetFactories: make(map[string]PacketFactory),
		framedFactories: make(map[string]FramedFactory),
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
	if isBuiltinPathFactory(name) {
		return fmt.Errorf("rendr: stream factory %q conflicts with a built-in carrier", name)
	}
	if _, exists := r.streamFactories[name]; exists {
		return fmt.Errorf("rendr: stream factory %q already registered", name)
	}
	if _, exists := r.packetFactories[name]; exists {
		return fmt.Errorf("rendr: %q already registered as PacketFactory", name)
	}
	if _, exists := r.framedFactories[name]; exists {
		return fmt.Errorf("rendr: %q already registered as FramedFactory", name)
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
	if isBuiltinPathFactory(name) {
		return fmt.Errorf("rendr: packet factory %q conflicts with a built-in carrier", name)
	}
	if _, exists := r.packetFactories[name]; exists {
		return fmt.Errorf("rendr: packet factory %q already registered", name)
	}
	if _, exists := r.streamFactories[name]; exists {
		return fmt.Errorf("rendr: %q already registered as StreamFactory", name)
	}
	if _, exists := r.framedFactories[name]; exists {
		return fmt.Errorf("rendr: %q already registered as FramedFactory", name)
	}
	r.packetFactories[name] = factory
	return nil
}

// RegisterFramedFactory registers an optional already-framed carrier. Sessions
// snapshot the descriptor at dial time. The registration ID is an opaque
// lookup key and is never passed to the mobility planner.
func (r *Runtime) RegisterFramedFactory(name string, factory FramedFactory) error {
	if r == nil {
		return fmt.Errorf("rendr: nil Runtime")
	}
	if name == "" {
		return fmt.Errorf("rendr: empty FramedFactory name")
	}
	if nilPathFactory(factory.Factory) {
		return fmt.Errorf("rendr: nil FramedFactory.Factory %q", name)
	}
	if !factory.Carrier.valid() {
		return fmt.Errorf("rendr: invalid FramedFactory carrier %d", factory.Carrier)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if isBuiltinPathFactory(name) {
		return fmt.Errorf("rendr: framed factory %q conflicts with a built-in carrier", name)
	}
	if _, exists := r.streamFactories[name]; exists {
		return fmt.Errorf("rendr: %q already registered as StreamFactory", name)
	}
	if _, exists := r.packetFactories[name]; exists {
		return fmt.Errorf("rendr: %q already registered as PacketFactory", name)
	}
	if _, exists := r.framedFactories[name]; exists {
		return fmt.Errorf("rendr: framed factory %q already registered", name)
	}
	r.framedFactories[name] = factory
	return nil
}

func (r *Runtime) sessionDialer(config SessionConfig) (*sessionDialer, error) {
	if r == nil {
		return nil, fmt.Errorf("rendr: nil Runtime")
	}
	if config.Root == nil || isTypedNilTarget(config.Root) {
		return nil, errRootRequired
	}
	r.mu.RLock()
	streams := make(map[string]streamPathFactory, len(r.streamFactories))
	carriers := make(map[string]CarrierFamily, len(r.streamFactories)+len(r.packetFactories)+len(r.framedFactories))
	for name, factory := range r.streamFactories {
		streams[name] = factory.Dial
		carriers[name] = factory.Carrier
	}
	packets := make(map[string]packetPathFactory, len(r.packetFactories))
	for name, factory := range r.packetFactories {
		packets[name] = factory.Dial
		carriers[name] = factory.Carrier
	}
	framed := make(map[string]transport.PathFactory, len(r.framedFactories))
	for name, factory := range r.framedFactories {
		framed[name] = factory.Factory
		carriers[name] = factory.Carrier
	}
	r.mu.RUnlock()
	return &sessionDialer{
		Root:               config.Root,
		Runtime:            r.config,
		PreserveL3Identity: config.PreserveL3Identity,
		InstanceID:         r.instanceID,
		streamFactories:    streams,
		packetFactories:    packets,
		framedFactories:    framed,
		factoryCarriers:    carriers,
		mobilityLedger:     r.mobilityLedger,
	}, nil
}

func nilPathFactory(factory transport.PathFactory) bool {
	if factory == nil {
		return true
	}
	value := reflect.ValueOf(factory)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (r *Runtime) engineLimits() engine.Limits {
	if r == nil {
		return engine.Limits{}
	}
	return engine.Limits{
		MigrationBudget:      r.config.Recovery.MigrationBudget,
		SelectorHysteresis:   r.config.Selector.LatencyBandRatio,
		SelectorLatencyFloor: r.config.Selector.LatencyBandFloor,
		SelectorDwell:        r.config.Selector.QualityDwell,
		SelectorCooldown:     r.config.Selector.QualityCooldown,
	}
}
