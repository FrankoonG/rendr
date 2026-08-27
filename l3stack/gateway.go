// Package l3stack terminates raw IP flows from a virtual interface and hands
// their payload to l3session. It is an optional adapter: the rendr root module
// and target graph do not depend on a userspace IP stack.
package l3stack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/l3session"
	"github.com/FrankoonG/rendr/virtualif"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	defaultLinkQueue      = 1024
	defaultTCPMaxInFlight = 4096
	tcpFlowLockShards     = 64
	stackNICID            = tcpip.NICID(1)
)

// FlowErrorHandler observes a flow-local failure. One rejected or failed flow
// does not terminate unrelated sessions or the virtual interface pump.
type FlowErrorHandler func(l3ingress.L3Identity, error)

// CallbackStatus is bounded evidence for optional Gateway callback failures.
type CallbackStatus struct {
	Drops       uint64
	Panics      uint64
	Goexits     uint64
	Timeouts    uint64
	LastFailure l3ingress.CallbackError
	HasFailure  bool
}

// Config assembles one virtual-interface ingress gateway.
type Config struct {
	Device  virtualif.FullDuplexCancellableDevice
	Router  l3ingress.FlowDecisionFunc
	Starter *l3session.Starter

	// FlowTable is optional. When nil, Gateway creates one around Router.
	FlowTable    *l3ingress.FlowTable
	OnParseError l3ingress.ParseErrorHandler
	OnFlowError  FlowErrorHandler
	// ObserverTimeout bounds OnParseError and OnFlowError. Zero selects the
	// l3ingress observer default.
	ObserverTimeout time.Duration

	TCPMaxInFlight int
	LinkQueue      int
	// TCPPeerReadyTimeout bounds each SYN's wait for the remote egress. Zero
	// uses l3session.DefaultTCPPeerReadyTimeout.
	TCPPeerReadyTimeout time.Duration

	// FlowLifetime controls automatic active-flow and closed-history reaping.
	// New normalizes and retains an immutable value copy.
	FlowLifetime FlowLifetimeTuning
}

// Gateway owns one gVisor TCP endpoint domain plus the rendr per-flow relays.
// It does not own Device; the embedding application controls interface policy
// and lifetime.
type Gateway struct {
	device          virtualif.FullDuplexCancellableDevice
	table           *l3ingress.FlowTable
	router          l3ingress.FlowDecisionFunc
	onParseError    l3ingress.ParseErrorHandler
	onFlowError     FlowErrorHandler
	observerTimeout time.Duration
	flowErrorBusy   atomic.Bool
	callbackMu      sync.Mutex
	callbackStatus  CallbackStatus

	link  *channel.Endpoint
	stack *stack.Stack

	manager *l3session.Manager
	tcp     *l3session.TCPRelay
	udp     *l3session.UDPRelay

	flowLifetime FlowLifetimeTuning
	reapCadence  time.Duration
	flowState    gatewayFlowState

	pendingMu  sync.Mutex
	pending    map[l3ingress.FlowRef]l3ingress.PacketEvent
	admissions map[l3ingress.FlowRef]*tcpAdmission
	flowLocks  [tcpFlowLockShards]sync.Mutex

	runMu        sync.Mutex
	runCtx       context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	runErr       error
	started      atomic.Bool
	closed       atomic.Bool
	flowsMu      sync.Mutex
	flowsStopped bool
	flows        sync.WaitGroup
	stackUseMu   sync.Mutex
	stackClosing bool
	stackClose   sync.Once
	stackWait    sync.Once
	teardownOnce sync.Once
	teardownErr  error
	teardownOps  gatewayTeardownOps
}

type tcpAdmission struct {
	cancel context.CancelFunc
}

type gatewayTeardownOps struct {
	closeLink    func()
	closeUDP     func() error
	closeManager func() error
	closeStack   func()
	waitStack    func()
}

// New creates an idle gateway. Run performs packet I/O.
func New(config Config) (*Gateway, error) {
	if config.Device == nil {
		return nil, errors.New("l3stack: nil device")
	}
	if config.Device.MTU() < 1280 {
		return nil, fmt.Errorf("l3stack: device MTU %d is below IPv6 minimum", config.Device.MTU())
	}
	if config.TCPPeerReadyTimeout < 0 {
		return nil, errors.New("l3stack: negative TCP peer readiness timeout")
	}
	if config.ObserverTimeout < 0 {
		return nil, errors.New("l3stack: negative observer timeout")
	}
	flowLifetime, err := normalizeFlowLifetimeTuning(config.FlowLifetime)
	if err != nil {
		return nil, err
	}
	table := config.FlowTable
	if table == nil {
		if config.Router == nil {
			return nil, errors.New("l3stack: nil flow router")
		}
		table = l3ingress.NewFlowTable(config.Router, l3ingress.FlowTableOptions{})
	}
	queue := config.LinkQueue
	if queue <= 0 {
		queue = defaultLinkQueue
	}
	maxInFlight := config.TCPMaxInFlight
	if maxInFlight <= 0 {
		maxInFlight = defaultTCPMaxInFlight
	}
	observerTimeout := config.ObserverTimeout
	if observerTimeout == 0 {
		observerTimeout = l3ingress.DefaultFlowObserverTimeout
	}
	link := channel.New(queue, uint32(config.Device.MTU()), "")
	netstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{gtcp.NewProtocol},
	})
	if err := netstack.CreateNIC(stackNICID, link); err != nil {
		netstack.Close()
		link.Close()
		return nil, fmt.Errorf("l3stack: create NIC: %s", err)
	}
	if err := netstack.SetSpoofing(stackNICID, true); err != nil {
		netstack.Close()
		link.Close()
		return nil, fmt.Errorf("l3stack: enable spoofing: %s", err)
	}
	if err := netstack.SetPromiscuousMode(stackNICID, true); err != nil {
		netstack.Close()
		link.Close()
		return nil, fmt.Errorf("l3stack: enable promiscuous mode: %s", err)
	}
	netstack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: stackNICID},
		{Destination: header.IPv6EmptySubnet, NIC: stackNICID},
	})

	manager := &l3session.Manager{Starter: config.Starter, FlowTable: table}
	g := &Gateway{
		device: config.Device, table: table, router: config.Router,
		onParseError: config.OnParseError, onFlowError: config.OnFlowError,
		observerTimeout: observerTimeout,
		link:            link, stack: netstack, manager: manager,
		flowLifetime: flowLifetime,
		reapCadence:  flowReapCadence(flowLifetime),
		pending:      make(map[l3ingress.FlowRef]l3ingress.PacketEvent),
		admissions:   make(map[l3ingress.FlowRef]*tcpAdmission),
		done:         make(chan struct{}),
	}
	g.tcp = &l3session.TCPRelay{Manager: manager, PeerReadyTimeout: config.TCPPeerReadyTimeout}
	g.udp = &l3session.UDPRelay{
		Device: config.Device, Manager: manager,
		ReplyActivity: gatewayUDPReplyActivity{gateway: g},
	}
	g.teardownOps = gatewayTeardownOps{
		closeLink:    g.link.Close,
		closeUDP:     g.udp.Close,
		closeManager: g.manager.CloseAll,
		closeStack:   g.closeTCPStack,
		waitStack:    g.waitTCPStack,
	}
	forwarder := gtcp.NewForwarder(netstack, 0, maxInFlight, g.acceptTCP)
	netstack.SetTransportProtocolHandler(gtcp.ProtocolNumber, forwarder.HandlePacket)
	return g, nil
}

// Run pumps packets until ctx is canceled, Device closes, or a device-level
// error occurs. Flow-local failures are reported through OnFlowError.
func (g *Gateway) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("l3stack: nil run context")
	}
	if !g.started.CompareAndSwap(false, true) {
		return errors.New("l3stack: Run may be called only once")
	}
	runCtx, cancel := context.WithCancel(ctx)
	g.runMu.Lock()
	g.runCtx = runCtx
	g.cancel = cancel
	if g.closed.Load() {
		g.runMu.Unlock()
		cancel()
		err := errors.Join(net.ErrClosed, g.teardown(nil))
		g.finishRun(err)
		return err
	}
	g.runMu.Unlock()

	outboundDone := make(chan error, 1)
	go func() { outboundDone <- g.pumpOutbound(runCtx) }()
	pump := l3ingress.Pump{
		Device: g.device, Handler: g, Direction: l3ingress.DirectionIngress,
		OnParseError: g.onParseError, ObserverTimeout: g.observerTimeout,
	}
	pumpDone := make(chan error, 1)
	go func() { pumpDone <- pump.Run(runCtx) }()
	reapTimer := time.NewTimer(g.reapCadence)
	defer stopAndDrainTimer(reapTimer)
	var pumpErr, outboundErr error
	pumpReturned := false
	outboundReturned := false

runLoop:
	for {
		select {
		case pumpErr = <-pumpDone:
			pumpReturned = true
			break runLoop
		case outboundErr = <-outboundDone:
			outboundReturned = true
			break runLoop
		case now := <-reapTimer.C:
			g.reapFlowLifetimes(now)
			reapTimer.Reset(g.reapCadence)
		case <-runCtx.Done():
			break runLoop
		}
	}
	cancel()
	teardownErr := g.teardown(func() {
		if !pumpReturned {
			pumpErr = <-pumpDone
		}
		if !outboundReturned {
			outboundErr = <-outboundDone
		}
	})
	err := errors.Join(normalizeRunError(runCtx, pumpErr), normalizeRunError(runCtx, outboundErr), teardownErr)
	g.finishRun(err)
	return err
}

// Close cancels Run and waits for all flow relays. It does not close Device.
func (g *Gateway) Close() error {
	if g == nil {
		return nil
	}
	if !g.closed.CompareAndSwap(false, true) {
		if g.started.Load() {
			<-g.done
			return g.result()
		}
		return g.teardown(nil)
	}
	g.runMu.Lock()
	cancel := g.cancel
	g.runMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if g.started.Load() {
		<-g.done
		return g.result()
	}
	return g.teardown(nil)
}

// teardown releases every gateway-owned resource once. Only Run supplies an
// I/O join: Close invokes teardown directly only when it observed no Run.
func (g *Gateway) teardown(waitForRunIO func()) error {
	g.teardownOnce.Do(func() {
		g.stopTCPFlows()
		g.teardownOps.closeLink()
		udpErr := g.teardownOps.closeUDP()
		managerErr := g.teardownOps.closeManager()
		g.teardownOps.closeStack()
		if waitForRunIO != nil {
			waitForRunIO()
		}
		g.flows.Wait()
		g.teardownOps.waitStack()
		g.closeTrackedFlows(l3ingress.FlowCloseDeviceClosed)
		g.teardownErr = errors.Join(udpErr, managerErr)
	})
	return g.teardownErr
}

func (g *Gateway) finishRun(err error) {
	g.runMu.Lock()
	g.runErr = err
	close(g.done)
	g.runMu.Unlock()
}

func (g *Gateway) result() error {
	g.runMu.Lock()
	defer g.runMu.Unlock()
	return g.runErr
}

// CallbackStatus returns bounded OnFlowError failure evidence. OnParseError
// evidence belongs to the l3ingress Pump that executes that callback.
func (g *Gateway) CallbackStatus() CallbackStatus {
	if g == nil {
		return CallbackStatus{}
	}
	g.callbackMu.Lock()
	defer g.callbackMu.Unlock()
	return g.callbackStatus
}

// HandlePacket implements l3ingress.PacketHandler.
func (g *Gateway) HandlePacket(ctx context.Context, event l3ingress.PacketEvent) error {
	// This gateway terminates only TCP and UDP flows. Kernel-generated ICMP and
	// ICMPv6 control traffic must not allocate a session or surface as an
	// application-flow failure.
	switch event.Meta.Identity.Proto {
	case l3ingress.ProtocolTCP, l3ingress.ProtocolUDP:
	default:
		return nil
	}
	isInitialTCPSYN := event.Meta.Identity.Proto == l3ingress.ProtocolTCP &&
		event.Meta.TCPFlags&l3ingress.TCPFlagSYN != 0 && event.Meta.TCPFlags&l3ingress.TCPFlagACK == 0
	originalFlow := event.Flow
	if isInitialTCPSYN {
		flowLock := g.tcpFlowLock(event.Meta.Identity)
		flowLock.Lock()
		for wait := g.reapWaitLocked(event.Meta.Identity); wait != nil; wait = g.reapWaitLocked(event.Meta.Identity) {
			flowLock.Unlock()
			select {
			case <-wait:
			case <-ctx.Done():
				return ctx.Err()
			}
			flowLock.Lock()
		}
		decision, _, snapshot, err := g.table.Resolve(ctx, originalFlow, len(event.Packet))
		if err != nil {
			flowLock.Unlock()
			return g.handleFlowError(ctx, event.Meta.Identity, l3ingress.FlowRef{}, err)
		}
		event.Decision = decision
		event.Decided = snapshot.Decided
		event.Flow = snapshot.Flow
		event.Ref = snapshot.Ref
		if decision.Deny {
			flowLock.Unlock()
			return nil
		}
		g.pendingMu.Lock()
		g.pending[event.Ref] = event
		g.pendingMu.Unlock()
		if !g.beginFlowOperationLocked(event.Ref) {
			flowLock.Unlock()
			g.forgetPending(event.Ref)
			return g.handleFlowError(ctx, event.Meta.Identity, event.Ref, errors.New("l3stack: flow entered idle reap during SYN admission"))
		}
		flowLock.Unlock()
	} else {
		for {
			decision, _, snapshot, err := g.table.Resolve(ctx, originalFlow, len(event.Packet))
			if err != nil {
				return g.handleFlowError(ctx, event.Meta.Identity, l3ingress.FlowRef{}, err)
			}
			event.Decision = decision
			event.Decided = snapshot.Decided
			event.Flow = snapshot.Flow
			event.Ref = snapshot.Ref
			if decision.Deny {
				return nil
			}
			started, err := g.beginFlowOperation(ctx, event.Ref)
			if err != nil {
				return err
			}
			if started {
				break
			}
		}
	}
	var flowErr error
	switch event.Meta.Identity.Proto {
	case l3ingress.ProtocolUDP:
		flowErr = g.udp.HandlePacket(ctx, event)
	case l3ingress.ProtocolTCP:
		flowErr = g.injectTCP(event.Packet)
	}
	g.endFlowOperation(event.Ref, false)
	return g.handleFlowError(ctx, event.Meta.Identity, event.Ref, flowErr)
}

func (g *Gateway) handleFlowError(
	ctx context.Context,
	id l3ingress.L3Identity,
	ref l3ingress.FlowRef,
	err error,
) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if ref != (l3ingress.FlowRef{}) {
		flowLock := g.tcpFlowLock(ref.Identity)
		flowLock.Lock()
		closed, ok := g.table.CloseRef(ref, l3ingress.FlowCloseManual)
		flowLock.Unlock()
		if ok {
			g.closeReapedSession(closed)
		}
	}
	g.reportFlowError(id, err)
	return nil
}

func (g *Gateway) injectTCP(packet []byte) error {
	var protocol tcpip.NetworkProtocolNumber
	switch {
	case len(packet) != 0 && packet[0]>>4 == 4:
		protocol = header.IPv4ProtocolNumber
	case len(packet) != 0 && packet[0]>>4 == 6:
		protocol = header.IPv6ProtocolNumber
	default:
		return errors.New("l3stack: invalid IP packet")
	}
	g.stackUseMu.Lock()
	defer g.stackUseMu.Unlock()
	if g.stackClosing {
		return net.ErrClosed
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	g.link.InjectInbound(protocol, pkt)
	pkt.DecRef()
	return nil
}

func (g *Gateway) acceptTCP(request *gtcp.ForwarderRequest) {
	if !g.beginTCPFlow() {
		return
	}
	flowOwned := true
	defer func() {
		if flowOwned {
			g.flows.Done()
		}
	}()
	id, err := identityFromEndpoint(request.ID())
	if err != nil {
		g.completeTCPRequest(request, true)
		g.reportFlowError(l3ingress.L3Identity{}, err)
		return
	}
	event, ok := g.takePending(id)
	if !ok {
		g.completeTCPRequest(request, true)
		g.reportFlowError(id, errors.New("l3stack: TCP SYN has no routed flow decision"))
		return
	}
	g.runMu.Lock()
	runCtx := g.runCtx
	g.runMu.Unlock()
	if runCtx == nil || runCtx.Err() != nil || g.closed.Load() {
		g.rejectTCP(request, event, id, net.ErrClosed)
		return
	}
	admissionCtx, admission := g.beginTCPAdmission(runCtx, event.Ref)
	admissionOwned := true
	defer func() {
		if admissionOwned {
			g.endTCPAdmission(event.Ref, admission)
		}
	}()
	if !g.currentTCPFlow(event.Ref) {
		g.rejectTCP(request, event, id, errors.New("l3stack: TCP flow decision expired before accept"))
		return
	}
	// The peer must validate identity and connect its final egress before
	// CreateEndpoint performs the local TCP handshake. Otherwise Dial could
	// succeed and only then reset when the remote egress rejects the flow.
	prepared, err := g.tcp.Prepare(admissionCtx, event)
	if err != nil {
		g.rejectTCP(request, event, id, err)
		return
	}
	if prepared.FlowRef() != event.Ref {
		_ = prepared.Close()
		g.rejectTCP(request, event, id, fmt.Errorf("l3stack: prepared TCP generation %+v does not match pending %+v",
			prepared.FlowRef(), event.Ref))
		return
	}
	flowLock := g.tcpFlowLock(id)
	flowLock.Lock()
	if admissionCtx.Err() != nil || runCtx.Err() != nil || g.closed.Load() || !g.currentTCPFlowLocked(event.Ref) {
		flowLock.Unlock()
		_ = prepared.Close()
		g.rejectTCP(request, event, id, net.ErrClosed)
		return
	}
	flowLock.Unlock()
	var queue waiter.Queue
	endpoint, tcpErr := request.CreateEndpoint(&queue)
	if tcpErr != nil {
		_ = prepared.Close()
		g.rejectTCP(request, event, id, fmt.Errorf("l3stack: create TCP endpoint: %s", tcpErr))
		return
	}
	flowLock.Lock()
	if admissionCtx.Err() != nil || runCtx.Err() != nil || g.closed.Load() || !g.currentTCPFlowLocked(event.Ref) {
		endpoint.Close()
		flowLock.Unlock()
		_ = prepared.Close()
		g.rejectTCP(request, event, id, net.ErrClosed)
		return
	}
	if !g.markTCPEstablishedLocked(event.Ref) {
		endpoint.Close()
		flowLock.Unlock()
		_ = prepared.Close()
		g.rejectTCP(request, event, id, errors.New("l3stack: TCP flow expired during admission"))
		return
	}
	if !g.completeTCPRequest(request, false) {
		endpoint.Close()
		g.retireFlowState(event.Ref)
		flowLock.Unlock()
		_ = prepared.Close()
		return
	}
	flowLock.Unlock()
	conn := gonet.NewTCPConn(&queue, endpoint)
	g.endTCPAdmission(event.Ref, admission)
	admissionOwned = false
	flowOwned = false
	go func() {
		defer g.flows.Done()
		err := g.tcp.ServePrepared(runCtx, prepared, conn)
		g.finishTCPFlow(runCtx, event, err)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			g.reportFlowError(id, err)
		}
	}()
}

func (g *Gateway) rejectTCP(
	request *gtcp.ForwarderRequest,
	event l3ingress.PacketEvent,
	id l3ingress.L3Identity,
	err error,
) {
	g.completeTCPRequest(request, true)
	flowLock := g.tcpFlowLock(id)
	flowLock.Lock()
	if event.Ref != (l3ingress.FlowRef{}) {
		closed, ok := g.table.CloseRef(event.Ref, l3ingress.FlowCloseManual)
		flowLock.Unlock()
		if ok {
			g.closeReapedSession(closed)
		}
	} else {
		closed, ok := g.table.Close(id, l3ingress.FlowCloseManual)
		flowLock.Unlock()
		if ok {
			g.closeReapedSession(closed)
		}
	}
	if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		g.reportFlowError(id, err)
	}
}

func (g *Gateway) closeTrackedFlows(reason l3ingress.FlowCloseReason) {
	if g == nil || g.table == nil {
		return
	}
	for _, snapshot := range g.table.Snapshots() {
		flowLock := g.tcpFlowLock(snapshot.Ref.Identity)
		flowLock.Lock()
		closed, ok := g.table.CloseRef(snapshot.Ref, reason)
		flowLock.Unlock()
		if ok {
			g.closeReapedSession(closed)
		}
	}
}

func (g *Gateway) closeReapedSession(snapshot l3ingress.FlowSnapshot) {
	if snapshot.Ref == (l3ingress.FlowRef{}) {
		return
	}
	defer g.retireFlowState(snapshot.Ref)
	g.forgetPending(snapshot.Ref)
	if snapshot.Flow.L3Identity.Proto == l3ingress.ProtocolUDP {
		g.udp.CloseFlowRef(snapshot.Ref)
		return
	}
	_, _ = g.manager.CloseRef(snapshot.Ref)
}

func (g *Gateway) forgetPending(ref l3ingress.FlowRef) {
	if ref == (l3ingress.FlowRef{}) {
		return
	}
	g.pendingMu.Lock()
	delete(g.pending, ref)
	admission := g.admissions[ref]
	if admission != nil {
		delete(g.admissions, ref)
	}
	g.pendingMu.Unlock()
	if admission != nil {
		admission.cancel()
	}
}

func (g *Gateway) takePending(id l3ingress.L3Identity) (l3ingress.PacketEvent, bool) {
	g.pendingMu.Lock()
	defer g.pendingMu.Unlock()
	var selected l3ingress.FlowRef
	for ref := range g.pending {
		if ref.Identity != id || selected != (l3ingress.FlowRef{}) && ref.Generation >= selected.Generation {
			continue
		}
		selected = ref
	}
	if selected == (l3ingress.FlowRef{}) {
		return l3ingress.PacketEvent{}, false
	}
	event := g.pending[selected]
	delete(g.pending, selected)
	return event, true
}

func (g *Gateway) beginTCPAdmission(parent context.Context, ref l3ingress.FlowRef) (context.Context, *tcpAdmission) {
	ctx, cancel := context.WithCancel(parent)
	admission := &tcpAdmission{cancel: cancel}
	if ref == (l3ingress.FlowRef{}) {
		return ctx, admission
	}
	g.pendingMu.Lock()
	g.admissions[ref] = admission
	g.pendingMu.Unlock()
	return ctx, admission
}

func (g *Gateway) endTCPAdmission(ref l3ingress.FlowRef, admission *tcpAdmission) {
	if admission == nil {
		return
	}
	if ref != (l3ingress.FlowRef{}) {
		g.pendingMu.Lock()
		if g.admissions[ref] == admission {
			delete(g.admissions, ref)
		}
		g.pendingMu.Unlock()
	}
	admission.cancel()
}

func (g *Gateway) beginTCPFlow() bool {
	g.flowsMu.Lock()
	defer g.flowsMu.Unlock()
	if g.flowsStopped {
		return false
	}
	g.flows.Add(1)
	return true
}

func (g *Gateway) stopTCPFlows() {
	g.flowsMu.Lock()
	g.flowsStopped = true
	g.flowsMu.Unlock()
}

func (g *Gateway) completeTCPRequest(request *gtcp.ForwarderRequest, sendReset bool) bool {
	g.stackUseMu.Lock()
	defer g.stackUseMu.Unlock()
	if g.stackClosing {
		return false
	}
	request.Complete(sendReset)
	return true
}

func (g *Gateway) closeTCPStack() {
	g.stackUseMu.Lock()
	g.stackClosing = true
	g.stackUseMu.Unlock()
	g.stackClose.Do(g.stack.Close)
}

func (g *Gateway) waitTCPStack() {
	g.stackWait.Do(g.stack.Wait)
}

func (g *Gateway) currentTCPFlow(ref l3ingress.FlowRef) bool {
	if ref == (l3ingress.FlowRef{}) {
		return false
	}
	flowLock := g.tcpFlowLock(ref.Identity)
	flowLock.Lock()
	defer flowLock.Unlock()
	return g.currentTCPFlowLocked(ref)
}

func (g *Gateway) currentTCPFlowLocked(ref l3ingress.FlowRef) bool {
	snapshot, ok := g.table.Snapshot(ref.Identity)
	return ok && snapshot.Ref == ref
}

func (g *Gateway) finishTCPFlow(ctx context.Context, event l3ingress.PacketEvent, relayErr error) {
	reason := l3ingress.FlowCloseTCPFIN
	if relayErr != nil {
		reason = l3ingress.FlowCloseTCPRST
		if ctx != nil && ctx.Err() != nil {
			reason = l3ingress.FlowCloseDeviceClosed
		}
	}
	flowLock := g.tcpFlowLock(event.Meta.Identity)
	flowLock.Lock()
	var closed l3ingress.FlowSnapshot
	var ok bool
	if event.Ref != (l3ingress.FlowRef{}) {
		closed, ok = g.table.CloseRef(event.Ref, reason)
	} else {
		closed, ok = g.table.Close(event.Meta.Identity, reason)
	}
	flowLock.Unlock()
	if ok {
		g.closeReapedSession(closed)
	}
}

func (g *Gateway) tcpFlowLock(id l3ingress.L3Identity) *sync.Mutex {
	return &g.flowLocks[tcpFlowLockIndex(id)]
}

func tcpFlowLockIndex(id l3ingress.L3Identity) int {
	hash := uint64(id.Proto)<<32 | uint64(id.SrcPort)<<16 | uint64(id.DstPort)
	for _, addr := range []netip.Addr{id.SrcIP, id.DstIP} {
		if !addr.IsValid() {
			continue
		}
		bytes := addr.As16()
		for _, b := range bytes {
			hash = (hash ^ uint64(b)) * 1099511628211
		}
	}
	return int(hash % tcpFlowLockShards)
}

func (g *Gateway) lockAllTCPFlows() {
	for i := range g.flowLocks {
		g.flowLocks[i].Lock()
	}
}

func (g *Gateway) unlockAllTCPFlows() {
	for i := len(g.flowLocks) - 1; i >= 0; i-- {
		g.flowLocks[i].Unlock()
	}
}

func (g *Gateway) pumpOutbound(ctx context.Context) error {
	for {
		pkt := g.link.ReadContext(ctx)
		if pkt == nil {
			return ctx.Err()
		}
		view := pkt.ToView()
		packet := append([]byte(nil), view.AsSlice()...)
		view.Release()
		pkt.DecRef()
		n, err := g.device.WriteContext(ctx, packet)
		if err != nil {
			return err
		}
		if n != len(packet) {
			return io.ErrShortWrite
		}
	}
}

func (g *Gateway) reportFlowError(id l3ingress.L3Identity, err error) {
	if g == nil || err == nil || g.onFlowError == nil {
		return
	}
	if !g.flowErrorBusy.CompareAndSwap(false, true) {
		g.recordFlowErrorCallbackFailure(&l3ingress.CallbackError{
			Callback: "FlowErrorHandler",
			Reason:   l3ingress.CallbackFailureSaturated,
		})
		return
	}
	releaseProcess, ok := tryAcquireL3StackOptionalCallback()
	if !ok {
		g.flowErrorBusy.Store(false)
		g.recordFlowErrorCallbackFailure(&l3ingress.CallbackError{
			Callback: "FlowErrorHandler",
			Reason:   l3ingress.CallbackFailureSaturated,
		})
		return
	}
	done := make(chan struct{})
	callback := g.onFlowError
	go func() {
		returned := false
		defer func() {
			if recovered := recover(); recovered != nil {
				g.recordFlowErrorCallbackFailure(flowErrorCallbackPanic(recovered))
			} else if !returned {
				g.recordFlowErrorCallbackFailure(&l3ingress.CallbackError{
					Callback: "FlowErrorHandler",
					Reason:   l3ingress.CallbackFailureGoexit,
				})
			}
			releaseProcess()
			g.flowErrorBusy.Store(false)
			close(done)
		}()
		callback(id, err)
		returned = true
	}()
	timeout := g.observerTimeout
	if timeout <= 0 {
		timeout = l3ingress.DefaultFlowObserverTimeout
	}
	timer := time.NewTimer(timeout)
	defer stopAndDrainTimer(timer)
	select {
	case <-done:
	case <-timer.C:
		select {
		case <-done:
		default:
			g.recordFlowErrorCallbackFailure(&l3ingress.CallbackError{
				Callback: "FlowErrorHandler",
				Reason:   l3ingress.CallbackFailureTimeout,
			})
		}
	}
}

func (g *Gateway) recordFlowErrorCallbackFailure(failure *l3ingress.CallbackError) {
	if g == nil || failure == nil {
		return
	}
	g.callbackMu.Lock()
	switch failure.Reason {
	case l3ingress.CallbackFailurePanic:
		g.callbackStatus.Panics++
	case l3ingress.CallbackFailureGoexit:
		g.callbackStatus.Goexits++
	case l3ingress.CallbackFailureTimeout:
		g.callbackStatus.Timeouts++
	case l3ingress.CallbackFailureSaturated:
		g.callbackStatus.Drops++
	}
	g.callbackStatus.LastFailure = *failure
	g.callbackStatus.HasFailure = true
	g.callbackMu.Unlock()
}

func flowErrorCallbackPanic(recovered any) *l3ingress.CallbackError {
	panicType := "<nil>"
	if typ := reflect.TypeOf(recovered); typ != nil {
		panicType = typ.String()
	}
	return &l3ingress.CallbackError{
		Callback:  "FlowErrorHandler",
		Reason:    l3ingress.CallbackFailurePanic,
		PanicType: panicType,
	}
}

func identityFromEndpoint(id stack.TransportEndpointID) (l3ingress.L3Identity, error) {
	src, err := netipFromTCPIP(id.RemoteAddress)
	if err != nil {
		return l3ingress.L3Identity{}, err
	}
	dst, err := netipFromTCPIP(id.LocalAddress)
	if err != nil {
		return l3ingress.L3Identity{}, err
	}
	return l3ingress.L3Identity{
		Proto: l3ingress.ProtocolTCP, SrcIP: src, SrcPort: id.RemotePort,
		DstIP: dst, DstPort: id.LocalPort,
	}, nil
}

func netipFromTCPIP(address tcpip.Address) (netip.Addr, error) {
	switch address.Len() {
	case 4:
		return netip.AddrFrom4(address.As4()), nil
	case 16:
		return netip.AddrFrom16(address.As16()), nil
	default:
		return netip.Addr{}, fmt.Errorf("l3stack: unsupported address length %d", address.Len())
	}
}

func normalizeRunError(parent context.Context, err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if parent.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return nil
	}
	return err
}
