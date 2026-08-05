package rendr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	"github.com/FrankoonG/rendr/transport/tcp"
	uflow "github.com/FrankoonG/rendr/transport/udpflow"
)

const (
	runtimeAcceptQueueSize    = 16
	runtimeHandshakeLimit     = 64
	runtimeHandshakeTimeout   = 10 * time.Second
	runtimeBridgeAwaitTimeout = 10 * time.Second
)

// StreamSource contributes one embedder-owned stream listener to a Runtime
// ingress domain. SessionListener.Close closes Listener; already accepted
// rendr sessions own independent connections and remain usable.
type StreamSource struct {
	Name     string
	Carrier  CarrierFamily
	Listener net.Listener
}

// PacketSource contributes one embedder-owned packet socket to a Runtime
// ingress domain. The socket is demultiplexed by rendr flow ID. Closing the
// SessionListener stops new flows but keeps the shared socket alive until all
// accepted sessions release their virtual paths.
type PacketSource struct {
	Name    string
	Carrier CarrierFamily
	Conn    net.PacketConn
}

// ListenConfig describes the inbound carrier sources that share one Runtime
// identity and bridge namespace.
type ListenConfig struct {
	Streams []StreamSource
	Packets []PacketSource
}

// SessionListener accepts application sessions assembled from all sources in
// one ListenConfig. It implements net.Listener for stream sessions and also
// provides a context-aware, strongly typed AcceptStream method.
type SessionListener struct {
	runtime *Runtime

	streamAccept chan *engineBackedConn
	packetAccept chan *enginePacketConn
	streamSlots  chan struct{}
	packetSlots  chan struct{}
	handshakes   chan struct{}

	addrs    []net.Addr
	closers  []func() error
	carriers map[string]CarrierFamily

	sourceMu     sync.Mutex
	activeSource int
	sourceErr    error
	acceptErr    error

	inflightMu   sync.Mutex
	inflight     map[uint64]transport.PathConn
	nextInflight atomic.Uint64
	closing      bool
	workers      sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
	closed    chan struct{}
}

// Listen starts one Runtime-owned ingress domain. All sources use the
// Runtime's stable instance ID and bridge table, so an initial path accepted
// on one source can be joined by a BRIDGE path accepted on another.
func (r *Runtime) Listen(config ListenConfig) (*SessionListener, error) {
	if r == nil {
		return nil, fmt.Errorf("rendr: nil Runtime")
	}
	if len(config.Streams)+len(config.Packets) == 0 {
		return nil, fmt.Errorf("rendr: ListenConfig requires at least one source")
	}
	seen := make(map[string]struct{}, len(config.Streams)+len(config.Packets))
	seenObjects := make(map[uintptr]string, len(config.Streams)+len(config.Packets))
	for index, source := range config.Streams {
		if source.Name == "" {
			return nil, fmt.Errorf("rendr: StreamSource[%d] has an empty name", index)
		}
		if _, duplicate := seen[source.Name]; duplicate {
			return nil, fmt.Errorf("rendr: duplicate inbound source %q", source.Name)
		}
		seen[source.Name] = struct{}{}
		if !source.Carrier.valid() {
			return nil, fmt.Errorf("rendr: StreamSource %q has invalid carrier %d", source.Name, source.Carrier)
		}
		if isNilNetworkSource(source.Listener) {
			return nil, fmt.Errorf("rendr: StreamSource %q has a nil Listener", source.Name)
		}
		if pointer := networkSourcePointer(source.Listener); pointer != 0 {
			if previous := seenObjects[pointer]; previous != "" {
				return nil, fmt.Errorf("rendr: inbound sources %q and %q share one network object", previous, source.Name)
			}
			seenObjects[pointer] = source.Name
		}
	}
	for index, source := range config.Packets {
		if source.Name == "" {
			return nil, fmt.Errorf("rendr: PacketSource[%d] has an empty name", index)
		}
		if _, duplicate := seen[source.Name]; duplicate {
			return nil, fmt.Errorf("rendr: duplicate inbound source %q", source.Name)
		}
		seen[source.Name] = struct{}{}
		if !source.Carrier.valid() {
			return nil, fmt.Errorf("rendr: PacketSource %q has invalid carrier %d", source.Name, source.Carrier)
		}
		if isNilNetworkSource(source.Conn) {
			return nil, fmt.Errorf("rendr: PacketSource %q has a nil Conn", source.Name)
		}
		if pointer := networkSourcePointer(source.Conn); pointer != 0 {
			if previous := seenObjects[pointer]; previous != "" {
				return nil, fmt.Errorf("rendr: inbound sources %q and %q share one network object", previous, source.Name)
			}
			seenObjects[pointer] = source.Name
		}
	}

	l := &SessionListener{
		runtime:      r,
		streamAccept: make(chan *engineBackedConn, runtimeAcceptQueueSize),
		packetAccept: make(chan *enginePacketConn, runtimeAcceptQueueSize),
		streamSlots:  make(chan struct{}, runtimeAcceptQueueSize),
		packetSlots:  make(chan struct{}, runtimeAcceptQueueSize),
		handshakes:   make(chan struct{}, runtimeHandshakeLimit),
		activeSource: len(config.Streams) + len(config.Packets),
		inflight:     make(map[uint64]transport.PathConn),
		closed:       make(chan struct{}),
		carriers:     make(map[string]CarrierFamily, len(config.Streams)+len(config.Packets)),
	}
	if err := r.claimListener(l); err != nil {
		return nil, err
	}
	for _, source := range config.Streams {
		l.carriers[source.Name] = source.Carrier
		l.addrs = append(l.addrs, source.Listener.Addr())
		l.closers = append(l.closers, source.Listener.Close)
		l.workers.Add(1)
		go func(source StreamSource) {
			defer l.workers.Done()
			l.acceptStreamSource(source)
		}(source)
	}
	for _, source := range config.Packets {
		l.carriers[source.Name] = source.Carrier
		packetListener, err := uflow.NewListenerFromPacketConn(source.Conn)
		if err != nil {
			l.shutdown(err)
			return nil, err
		}
		l.addrs = append(l.addrs, packetListener.Addr())
		l.closers = append(l.closers, packetListener.Close)
		l.workers.Add(1)
		go func(source PacketSource, packetListener *uflow.Listener) {
			defer l.workers.Done()
			l.acceptPacketSource(source, packetListener)
		}(source, packetListener)
	}
	return l, nil
}

// Accept implements net.Listener. Packet-mode sessions are delivered only by
// AcceptPacket and never appear here.
func (l *SessionListener) Accept() (net.Conn, error) {
	conn, err := l.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (l *SessionListener) AcceptStream(ctx context.Context) (Conn, error) {
	if l == nil {
		return nil, net.ErrClosed
	}
	select {
	case <-l.closed:
		return nil, l.listenerError()
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, l.listenerError()
	case conn := <-l.streamAccept:
		l.inflightMu.Lock()
		closing := l.closing
		l.inflightMu.Unlock()
		l.releaseAcceptSlot(false)
		if closing {
			_ = conn.Close()
			return nil, l.listenerError()
		}
		return conn, nil
	}
}

func (l *SessionListener) AcceptPacket(ctx context.Context) (PacketConn, error) {
	if l == nil {
		return nil, net.ErrClosed
	}
	select {
	case <-l.closed:
		return nil, l.listenerError()
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, l.listenerError()
	case conn := <-l.packetAccept:
		l.inflightMu.Lock()
		closing := l.closing
		l.inflightMu.Unlock()
		l.releaseAcceptSlot(true)
		if closing {
			_ = conn.Close()
			return nil, l.listenerError()
		}
		return conn, nil
	}
}

func (l *SessionListener) Close() error {
	if l == nil {
		return nil
	}
	l.shutdown(net.ErrClosed)
	return l.closeErr
}

func (l *SessionListener) Addr() net.Addr {
	if l == nil || len(l.addrs) == 0 {
		return nil
	}
	return l.addrs[0]
}

func (l *SessionListener) Addrs() []net.Addr {
	if l == nil {
		return nil
	}
	return append([]net.Addr(nil), l.addrs...)
}

// FlowIDs returns the active flow set for the whole Runtime ingress domain,
// including sessions accepted by another SessionListener on the same Runtime.
func (l *SessionListener) FlowIDs() [][16]byte {
	if l == nil || l.runtime == nil || l.runtime.bridges == nil {
		return nil
	}
	return l.runtime.bridges.Snapshot()
}

func (l *SessionListener) acceptStreamSource(source StreamSource) {
	for {
		raw, err := source.Listener.Accept()
		if err != nil {
			l.sourceEnded(err)
			return
		}
		if !l.acquireHandshake() {
			_ = raw.Close()
			return
		}
		_ = raw.SetDeadline(time.Now().Add(runtimeHandshakeTimeout))
		pc := tcp.Wrap(raw)
		inflightID, ok := l.trackInflight(pc)
		if !ok {
			<-l.handshakes
			_ = pc.Close()
			return
		}
		l.workers.Add(1)
		go func() {
			defer l.workers.Done()
			l.serveIncoming(inflightID, source.Name, source.Carrier, pc, func() {
				_ = raw.SetDeadline(time.Time{})
			})
		}()
	}
}

func (l *SessionListener) acceptPacketSource(source PacketSource, listener *uflow.Listener) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-l.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	for {
		pc, err := listener.Accept(ctx)
		if err != nil {
			l.sourceEnded(err)
			return
		}
		if !l.acquireHandshake() {
			_ = pc.Close()
			return
		}
		inflightID, ok := l.trackInflight(pc)
		if !ok {
			<-l.handshakes
			_ = pc.Close()
			return
		}
		l.workers.Add(1)
		go func() {
			defer l.workers.Done()
			l.serveIncoming(inflightID, source.Name, source.Carrier, pc, func() {})
		}()
	}
}

func (l *SessionListener) acquireHandshake() bool {
	select {
	case <-l.closed:
		return false
	case l.handshakes <- struct{}{}:
		return true
	}
}

func (l *SessionListener) serveIncoming(inflightID uint64, sourceName string, _ CarrierFamily, pc transport.PathConn, clearDeadline func()) {
	owned := false
	var clearDeadlineOnce sync.Once
	clearHandshakeDeadline := func() { clearDeadlineOnce.Do(clearDeadline) }
	defer func() {
		clearHandshakeDeadline()
		l.untrackInflight(inflightID)
		<-l.handshakes
		if !owned {
			_ = pc.Close()
		}
	}()

	hdr, payload, err := engine.ReadFirstFrame(pc)
	if err != nil {
		return
	}
	code, ok := canonicalFirstControlCode(hdr)
	if !ok {
		return
	}
	// The first-frame deadline has done its job. Admission owns separate 10s
	// pre-COMMIT and migration-budget post-COMMIT contexts; retaining the
	// socket deadline would truncate reconciliation.
	clearHandshakeDeadline()
	switch code {
	case proto.CtrlHello:
		owned = l.handleRuntimeHello(inflightID, sourceName, pc, payload)
	case proto.CtrlBridgeTag:
		owned = l.handleRuntimeBridge(sourceName, pc, payload)
	}
}

func (l *SessionListener) handleRuntimeHello(inflightID uint64, sourceName string, pc transport.PathConn, payload []byte) bool {
	hello, err := decodeHelloForAdmission(pc, payload)
	if err != nil {
		return false
	}
	if hello.FlowID == ([16]byte{}) || hello.InstanceID == (proto.InstanceID{}) {
		return false
	}
	packetMode := hello.Caps&proto.CapsPacketMode != 0
	var reservation engine.BridgeReservation
	for {
		reservation, err = l.runtime.bridges.Reserve(hello.FlowID)
		if err == nil {
			break
		}
		if !errors.Is(err, engine.ErrBridgeDuplicate) {
			return false
		}
		e, state, waitErr := l.awaitRuntimeEngine(hello.FlowID)
		if waitErr != nil {
			return false
		}
		if state == engine.BridgeEntryAbsent {
			continue
		}
		if state != engine.BridgeEntryActive || e == nil {
			return false
		}
		return l.handleDuplicateRuntimeHello(sourceName, pc, hello, payload, e)
	}
	if !l.acquireAcceptSlot(packetMode) {
		l.runtime.bridges.Abort(reservation)
		return false
	}
	slotHeld := true
	defer func() {
		if slotHeld {
			l.releaseAcceptSlot(packetMode)
		}
	}()

	activated := false
	defer func() {
		if !activated {
			l.runtime.bridges.Abort(reservation)
		}
	}()

	e := engine.New(engine.SideServer, hello.FlowID, l.runtime.engineLimits())
	engineOwnsPath := false
	defer func() {
		if !activated {
			_ = e.Close()
		}
	}()
	if err := e.AcceptPeerNegotiation(hello.Negotiation, hello.LocalTXManifest); err != nil {
		return false
	}
	if err := e.MirrorPeerGraphForLocal(); err != nil {
		return false
	}
	e.SetLocalInstanceID(l.runtime.instanceID)
	e.SetPeerKind(engine.PeerRendr)
	e.SetPeerInstanceID(hello.InstanceID)
	e.SetPeerCaps(hello.Caps)
	if packetMode {
		e.SetPacketMode()
	}

	spec := specWithTargetName(PathSpec{Transport: sourceName, Address: pc.RemoteAddr()}, helloPathName(hello))
	pathID, localTargetID, err := attachServerPath(e, pc, spec, hello.InitialTargetID)
	if err != nil {
		return false
	}
	if err := acknowledgeInitialServerPath(context.Background(), e, pathID, pc, l.runtime.instanceID, eLocalCaps(e), localTargetID, hello, payload); err != nil {
		return false
	}
	engineOwnsPath = true
	if err := l.runtime.bridges.Activate(reservation, e); err != nil {
		_ = e.Close()
		return engineOwnsPath
	}
	activated = true
	go func() {
		<-e.Closed()
		l.runtime.bridges.RemoveActive(reservation, e)
	}()

	mode := modeFromManifest(hello.LocalTXManifest)
	laddr := addrFromString(pc.LocalAddr())
	raddr := addrFromString(pc.RemoteAddr())
	if packetMode {
		conn := newEnginePacketConn(e, mode, laddr, raddr)
		conn.carriers = l.carriers
		if l.publishPacket(inflightID, conn) {
			slotHeld = false
		} else {
			// The application never acquired this session, so there is no
			// graceful-close obligation. A graceful BYE can wait the full
			// migration budget after listener shutdown has already removed every
			// route, pinning the worker that shutdown is joining.
			_ = e.Close()
		}
		return true
	}
	conn := newEngineBackedConn(e, &engine.Conn{E: e, LAddr: laddr, RAddr: raddr}, mode)
	conn.carriers = l.carriers
	if l.publishStream(inflightID, conn) {
		slotHeld = false
	} else {
		_ = e.Close()
	}
	return true
}

func (l *SessionListener) handleDuplicateRuntimeHello(sourceName string, pc transport.PathConn, hello proto.HelloPayload, proposalWire []byte, e *engine.Engine) bool {
	if e.PeerKind() != engine.PeerRendr || e.PeerInstanceID() != hello.InstanceID || e.PeerCaps() != hello.Caps {
		return false
	}
	if e.Packetized() != (hello.Caps&proto.CapsPacketMode != 0) {
		return false
	}
	if err := e.ValidatePeerNegotiation(hello.Negotiation, hello.LocalTXManifest); err != nil {
		return false
	}
	name, err := e.PeerPathName(hello.InitialTargetID)
	if err != nil || name != helloPathName(hello) {
		return false
	}
	spec := specWithTargetName(PathSpec{Transport: sourceName, Address: pc.RemoteAddr()}, name)
	pathID, localTargetID, err := attachServerPath(e, pc, spec, hello.InitialTargetID)
	if err != nil {
		return false
	}
	if err := acknowledgeInitialServerPath(context.Background(), e, pathID, pc, l.runtime.instanceID, eLocalCaps(e), localTargetID, hello, proposalWire); err != nil {
		return false
	}
	return true
}

func (l *SessionListener) handleRuntimeBridge(sourceName string, pc transport.PathConn, payload []byte) bool {
	tag, err := proto.DecodeBridgeTag(payload)
	if err != nil {
		return false
	}
	if tag.ExpectedPeerInstanceID != l.runtime.instanceID {
		_ = engine.PerformBridgeAck(pc, tag, l.runtime.instanceID, proto.AckRejectInstance, "peer instance mismatch")
		return false
	}
	e, state, err := l.awaitRuntimeEngine(tag.BridgeID)
	if err != nil || state != engine.BridgeEntryActive || e == nil {
		_ = engine.PerformBridgeAck(pc, tag, l.runtime.instanceID, proto.AckRejectUnknown, "unknown flow")
		return false
	}
	select {
	case <-l.closed:
		return false
	default:
	}
	if err := e.ValidateBridgeBinding(tag); err != nil {
		_ = engine.PerformBridgeAck(pc, tag, l.runtime.instanceID, bridgeValidationAckCode(err), err.Error())
		return false
	}
	spec := specWithTargetName(PathSpec{Transport: sourceName, Address: pc.RemoteAddr()}, bridgePathName(e, tag))
	pathID, localTargetID, err := attachServerPath(e, pc, spec, tag.TargetID)
	if err != nil {
		_ = engine.PerformBridgeAck(pc, tag, l.runtime.instanceID, proto.AckRejectAttach, err.Error())
		return false
	}
	if err := acknowledgeServerPath(context.Background(), e, pathID, pc, tag, payload, l.runtime.instanceID, localTargetID); err != nil {
		return false
	}
	return true
}

func (l *SessionListener) awaitRuntimeEngine(flowID [16]byte) (*engine.Engine, engine.BridgeEntryState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runtimeBridgeAwaitTimeout)
	stopCloseWatch := make(chan struct{})
	go func() {
		select {
		case <-l.closed:
			cancel()
		case <-ctx.Done():
		case <-stopCloseWatch:
		}
	}()
	defer close(stopCloseWatch)
	defer cancel()
	return l.runtime.bridges.WaitActive(ctx, flowID)
}

func modeFromManifest(manifest proto.GraphManifest) Mode {
	root, ok := manifest.Node(manifest.RootID)
	if !ok {
		return ModeSelector
	}
	switch root.Kind {
	case proto.GraphNodeKindBond:
		return ModeBond
	case proto.GraphNodeKindRace:
		return ModeRace
	default:
		return ModeSelector
	}
}

func (l *SessionListener) acquireAcceptSlot(packet bool) bool {
	slots := l.streamSlots
	if packet {
		slots = l.packetSlots
	}
	timer := time.NewTimer(runtimeHandshakeTimeout)
	defer timer.Stop()
	select {
	case slots <- struct{}{}:
		return true
	case <-l.closed:
		return false
	case <-timer.C:
		return false
	}
}

func (l *SessionListener) releaseAcceptSlot(packet bool) {
	slots := l.streamSlots
	if packet {
		slots = l.packetSlots
	}
	select {
	case <-slots:
	default:
	}
}

func (l *SessionListener) sourceEnded(err error) {
	select {
	case <-l.closed:
		return
	default:
	}
	l.sourceMu.Lock()
	if l.sourceErr == nil {
		l.sourceErr = err
	}
	l.activeSource--
	last := l.activeSource == 0
	cause := l.sourceErr
	l.sourceMu.Unlock()
	if last {
		// sourceEnded runs inside a counted source worker. Shutdown joins all
		// workers, so transfer ownership to another goroutine before returning.
		go l.shutdown(cause)
	}
}

func (l *SessionListener) shutdown(cause error) {
	l.closeOnce.Do(func() {
		l.sourceMu.Lock()
		if l.acceptErr == nil {
			l.acceptErr = cause
		}
		l.sourceMu.Unlock()
		close(l.closed)
		for _, closeSource := range l.closers {
			if err := closeSource(); err != nil && l.closeErr == nil && err != net.ErrClosed {
				l.closeErr = err
			}
		}
		l.closeInflight()
		l.workers.Wait()
		l.drainQueuedSessions()
		l.runtime.releaseListener(l)
	})
}

func (l *SessionListener) listenerError() error {
	l.sourceMu.Lock()
	defer l.sourceMu.Unlock()
	if l.acceptErr != nil {
		return l.acceptErr
	}
	return net.ErrClosed
}

func (l *SessionListener) trackInflight(pc transport.PathConn) (uint64, bool) {
	l.inflightMu.Lock()
	defer l.inflightMu.Unlock()
	if l.closing {
		return 0, false
	}
	id := l.nextInflight.Add(1)
	l.inflight[id] = pc
	return id, true
}

func (l *SessionListener) untrackInflight(id uint64) {
	l.inflightMu.Lock()
	delete(l.inflight, id)
	l.inflightMu.Unlock()
}

func (l *SessionListener) closeInflight() {
	l.inflightMu.Lock()
	l.closing = true
	paths := make([]transport.PathConn, 0, len(l.inflight))
	for _, pc := range l.inflight {
		paths = append(paths, pc)
	}
	l.inflightMu.Unlock()
	for _, pc := range paths {
		_ = pc.Close()
	}
}

func (l *SessionListener) publishStream(inflightID uint64, conn *engineBackedConn) bool {
	l.inflightMu.Lock()
	defer l.inflightMu.Unlock()
	if l.closing {
		return false
	}
	select {
	case l.streamAccept <- conn:
		delete(l.inflight, inflightID)
		return true
	default:
		return false
	}
}

func (l *SessionListener) publishPacket(inflightID uint64, conn *enginePacketConn) bool {
	l.inflightMu.Lock()
	defer l.inflightMu.Unlock()
	if l.closing {
		return false
	}
	select {
	case l.packetAccept <- conn:
		delete(l.inflight, inflightID)
		return true
	default:
		return false
	}
}

func isNilNetworkSource(source any) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func networkSourcePointer(source any) uintptr {
	if isNilNetworkSource(source) {
		return 0
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return value.Pointer()
	default:
		return 0
	}
}

func (l *SessionListener) drainQueuedSessions() {
	for {
		select {
		case conn := <-l.streamAccept:
			l.releaseAcceptSlot(false)
			_ = conn.e.Close()
		default:
			goto packets
		}
	}

packets:
	for {
		select {
		case conn := <-l.packetAccept:
			l.releaseAcceptSlot(true)
			_ = conn.e.Close()
		default:
			return
		}
	}
}
