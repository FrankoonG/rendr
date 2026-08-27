package udpflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const (
	// inboxSize bounds the per-flow datagram buffer between the shared
	// reader and the engine. Datagrams in excess of this are dropped
	// silently; opaque UDP is a best-effort transport.
	inboxSize = 256

	acceptQueueSize  = 16
	maxListenerFlows = 1024

	readRetryInitialBackoff = 5 * time.Millisecond
	readRetryMaxBackoff     = 100 * time.Millisecond
)

var _ transport.PathQualityReader = (*ServerPathConn)(nil)

// ErrListenerRead identifies a terminal failure of the listener's shared
// PacketConn receive path. Accept returns an error wrapping this sentinel and
// the underlying read error.
var ErrListenerRead = errors.New("udpflow: listener packet read failed")

// Listener owns a single packet socket and dispatches inbound datagrams to
// per-flow_id virtual PathConns. The first datagram observed for a fresh
// flow_id allocates a ServerPathConn and makes it available to Accept;
// subsequent datagrams for that flow are pushed to the same PathConn's inbox.
//
// Migration is implicit: the listener tracks the most recently seen source
// address per flow_id. A datagram arriving from a new address with a known
// flow_id updates the virtual PathConn's RemoteAddr without involving the
// engine or application.
type Listener struct {
	conn             net.PacketConn
	maxDatagramSize  int
	callbackExecutor *listenerCallbackExecutor

	mu         sync.Mutex
	flows      map[[proto.UDPFlowIDSize]byte]*ServerPathConn
	accept     chan *ServerPathConn
	admitting  bool
	closed     chan struct{}
	connClosed chan struct{}

	connCloseSignal sync.Once
	connCloseMu     sync.Mutex
	connCloseTask   *listenerCallbackTask[struct{}]
	connCloseDone   bool
	connCloseErr    error
	terminalErr     error // protected by mu
}

// Listen binds a UDP socket and starts the reader.
func Listen(addr string) (*Listener, error) {
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("udpflow: bind %s: %w", addr, err)
	}
	return NewListenerFromPacketConn(c, MaxDatagram)
}

// NewListenerFromPacketConn starts a listener over conn. The listener takes
// ownership of conn: it closes conn once the listener is closed and every
// already accepted ServerPathConn has also closed.
func NewListenerFromPacketConn(conn net.PacketConn, maxDatagramSize int) (*Listener, error) {
	return newListenerFromPacketConnWithExecutor(conn, maxDatagramSize, listenerProcessCallbackExecutor)
}

func newListenerFromPacketConnWithExecutor(
	conn net.PacketConn,
	maxDatagramSize int,
	executor *listenerCallbackExecutor,
) (*Listener, error) {
	if conn == nil {
		return nil, errors.New("udpflow: nil packet connection")
	}
	if executor == nil {
		return nil, errors.New("udpflow: nil listener callback executor")
	}
	if err := ValidateDatagramSize(maxDatagramSize); err != nil {
		return nil, err
	}
	l := &Listener{
		conn:             conn,
		maxDatagramSize:  min(maxDatagramSize, MaxDatagram),
		callbackExecutor: executor,
		flows:            make(map[[proto.UDPFlowIDSize]byte]*ServerPathConn),
		accept:           make(chan *ServerPathConn, acceptQueueSize),
		admitting:        true,
		closed:           make(chan struct{}),
		connClosed:       make(chan struct{}),
	}
	go l.readLoop()
	return l, nil
}

// Addr is the bound local address.
func (l *Listener) Addr() net.Addr { return l.conn.LocalAddr() }

// Close stops admission and Accept immediately. ServerPathConns which Accept
// already returned remain usable over the shared packet socket until they
// close. Pending, unaccepted flows are rejected. The packet socket closes when
// the final accepted flow closes.
func (l *Listener) Close() error {
	var pending []*ServerPathConn

	l.mu.Lock()
	if l.admitting {
		l.admitting = false
		close(l.closed)
	}
	for flowID, pc := range l.flows {
		if pc.accepted {
			continue
		}
		delete(l.flows, flowID)
		pending = append(pending, pc)
	}
	closeConn := len(l.flows) == 0
	l.mu.Unlock()

	for _, pc := range pending {
		_ = pc.Close()
	}
	if closeConn {
		return l.closePacketConn()
	}
	return nil
}

// Accept blocks until the next fresh flow_id arrives. The returned
// ServerPathConn is already wired to receive the first inbound rendr frame.
func (l *Listener) Accept(ctx context.Context) (*ServerPathConn, error) {
	for {
		select {
		case <-l.closed:
			if pc := l.takeTerminalFlow(); pc != nil {
				return pc, nil
			}
			return nil, l.acceptError()
		default:
		}

		select {
		case <-ctx.Done():
			select {
			case <-l.closed:
				if pc := l.takeTerminalFlow(); pc != nil {
					return pc, nil
				}
				return nil, l.acceptError()
			default:
				return nil, ctx.Err()
			}
		case <-l.closed:
			if pc := l.takeTerminalFlow(); pc != nil {
				return pc, nil
			}
			return nil, l.acceptError()
		case pc := <-l.accept:
			if l.claimFlow(pc) {
				return pc, nil
			}
			if l.claimTerminalFlow(pc) {
				return pc, nil
			}
			_ = pc.Close()
		}
	}
}

func (l *Listener) takeTerminalFlow() *ServerPathConn {
	for {
		select {
		case pc := <-l.accept:
			if l.claimTerminalFlow(pc) {
				return pc
			}
			_ = pc.Close()
		default:
			return nil
		}
	}
}

func (l *Listener) claimTerminalFlow(pc *ServerPathConn) bool {
	if pc == nil || !pc.hasPendingPayload() {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.terminalErr == nil || pc.accepted {
		return false
	}
	pc.accepted = true
	return true
}

func (l *Listener) acceptError() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.terminalErr != nil {
		return l.terminalErr
	}
	return net.ErrClosed
}

func (l *Listener) claimFlow(pc *ServerPathConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.admitting || pc.dead.Load() || l.flows[pc.flowID] != pc {
		return false
	}
	pc.accepted = true
	return true
}

func (l *Listener) readLoop() {
	buf := make([]byte, l.maxDatagramSize+1)
	oob := make([]byte, packetReadOOBSize)
	backoff := readRetryInitialBackoff
	for {
		n, src, readErr := l.readPacket(buf, oob)
		if n == 0 && readErr != nil {
			select {
			case <-l.connClosed:
				return
			default:
			}
			if !retryablePacketReadError(readErr) {
				l.failRead(readErr)
				return
			}
			if !l.waitReadRetry(backoff) {
				return
			}
			if backoff < readRetryMaxBackoff {
				backoff *= 2
				if backoff > readRetryMaxBackoff {
					backoff = readRetryMaxBackoff
				}
			}
			continue
		}
		backoff = readRetryInitialBackoff
		if n < 0 || n > l.maxDatagramSize {
			l.failRead(errors.Join(readErr, ErrTruncatedPacket))
			return
		}
		if n < proto.UDPFlowHeaderSize {
			if readErr != nil {
				l.failRead(readErr)
				return
			}
			continue
		}
		packet, err := proto.DecodeUDPFlowFrame(buf[:n])
		if err != nil || packet.Header.Version != proto.UDPFlowVersion {
			if readErr != nil {
				l.failRead(readErr)
				return
			}
			continue
		}
		hdr := packet.Header
		payload := append([]byte(nil), packet.Payload...)

		l.mu.Lock()
		pc := l.flows[hdr.FlowID]
		if pc != nil {
			pc.observe(src)
			l.mu.Unlock()
			if readErr != nil {
				terminalErr := listenerReadError(readErr)
				staged := pc.deliverTerminal(payload, terminalErr)
				l.failReadWithError(terminalErr, staged)
				return
			} else {
				pc.deliver(payload)
			}
			continue
		}
		if !l.admitting || len(l.flows) >= maxListenerFlows {
			l.mu.Unlock()
			if readErr != nil {
				l.failRead(readErr)
				return
			}
			continue
		}

		pc = newServerPathConn(l, hdr.FlowID, src)
		l.flows[hdr.FlowID] = pc
		select {
		case l.accept <- pc:
			l.mu.Unlock()
			if readErr != nil {
				terminalErr := listenerReadError(readErr)
				staged := pc.deliverTerminal(payload, terminalErr)
				l.failReadWithError(terminalErr, staged)
				return
			} else {
				pc.deliver(payload)
			}
		default:
			// Admission must never stall the sole packet reader. Remove the
			// rejected flow before closing it so cleanup cannot disturb a
			// later flow which reuses the same ID.
			if l.flows[hdr.FlowID] == pc {
				delete(l.flows, hdr.FlowID)
			}
			l.mu.Unlock()
			_ = pc.Close()
		}
		if readErr != nil {
			l.failRead(readErr)
			return
		}
	}
}

func (l *Listener) readPacket(payload, oob []byte) (int, net.Addr, error) {
	reader, messageReader := l.conn.(packetMessageReader)
	callback := "PacketConn.ReadFrom"
	if messageReader {
		callback = "PacketConn.ReadMsgUDP"
	}
	task, err := startListenerCallback(
		l.callbackExecutor,
		callback,
		listenerCallbackRead,
		func() (listenerPacketReadResult, error) {
			result := listenerPacketReadResult{
				payload: make([]byte, len(payload)),
				oob:     make([]byte, len(oob)),
			}
			var readErr error
			if !messageReader {
				result.n, result.source, readErr = l.conn.ReadFrom(result.payload)
				return result, readErr
			}
			result.n, result.oobn, result.flags, result.udpSource, readErr =
				reader.ReadMsgUDP(result.payload, result.oob)
			result.source = result.udpSource
			return result, readErr
		},
	)
	if err != nil {
		return 0, nil, err
	}
	result, err := task.waitUntilStopped(l.connClosed)
	n, oobn, flags, source := result.n, result.oobn, result.flags, result.source
	if n < 0 || n > len(payload) {
		return 0, nil, errors.Join(err,
			fmt.Errorf("%w: read %d into %d-byte buffer", ErrInvalidPacketReadCount, n, len(payload)))
	}
	if oobn < 0 || oobn > len(oob) {
		return 0, nil, errors.Join(err,
			fmt.Errorf("%w: read %d into %d-byte OOB buffer", ErrInvalidPacketOOBCount, oobn, len(oob)))
	}
	if flags&packetMSGTruncated != 0 {
		return 0, nil, errors.Join(err, ErrTruncatedPacket)
	}
	copy(payload, result.payload[:n])
	copy(oob, result.oob[:oobn])
	return n, source, err
}

type listenerPacketReadResult struct {
	n         int
	oobn      int
	flags     int
	source    net.Addr
	udpSource *net.UDPAddr
	payload   []byte
	oob       []byte
}

func retryablePacketReadError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary())
}

func (l *Listener) waitReadRetry(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-l.connClosed:
		return false
	}
}

func (l *Listener) failRead(err error) {
	l.failReadWithError(listenerReadError(err), nil)
}

func listenerReadError(err error) error {
	return fmt.Errorf("%w: %w", ErrListenerRead, err)
}

func (l *Listener) failReadWithError(terminalErr error, staged *ServerPathConn) {

	l.mu.Lock()
	if l.terminalErr != nil {
		l.mu.Unlock()
		return
	}
	l.terminalErr = terminalErr
	if l.admitting {
		l.admitting = false
		close(l.closed)
	}
	paths := make([]*ServerPathConn, 0, len(l.flows))
	for _, pc := range l.flows {
		paths = append(paths, pc)
	}
	l.mu.Unlock()

	for _, pc := range paths {
		if pc == staged {
			continue
		}
		pc.declareDeath(terminalErr)
	}
	_ = l.closePacketConn()
}

func (l *Listener) removeFlow(flowID [proto.UDPFlowIDSize]byte, pc *ServerPathConn) error {
	l.mu.Lock()
	if l.flows[flowID] == pc {
		delete(l.flows, flowID)
	}
	closeConn := !l.admitting && len(l.flows) == 0
	l.mu.Unlock()
	if closeConn {
		return l.closePacketConn()
	}
	return nil
}

func (l *Listener) closePacketConn() error {
	l.connCloseSignal.Do(func() {
		close(l.connClosed)
	})

	l.connCloseMu.Lock()
	if l.connCloseDone {
		err := l.connCloseErr
		l.connCloseMu.Unlock()
		return err
	}
	task := l.connCloseTask
	if task == nil {
		// Executor saturation is transient and must not consume the listener's
		// sole authority to close its adopted PacketConn.
		var err error
		task, err = startListenerCallback(
			l.callbackExecutor,
			"PacketConn.Close",
			listenerCallbackClose,
			func() (struct{}, error) { return struct{}{}, l.conn.Close() },
		)
		if err != nil {
			l.connCloseMu.Unlock()
			return err
		}
		l.connCloseTask = task
	}
	l.connCloseMu.Unlock()

	_, waitErr := task.waitBounded()
	select {
	case <-task.done:
		_, finalErr := task.waitBounded()
		l.connCloseMu.Lock()
		if !l.connCloseDone && l.connCloseTask == task {
			l.connCloseDone = true
			l.connCloseErr = finalErr
		}
		err := l.connCloseErr
		l.connCloseMu.Unlock()
		return err
	default:
		return waitErr
	}
}

// ServerPathConn is the listener-side virtual PathConn. It shares the
// listener's packet socket; writes target the most recently observed peer for
// this flow_id.
type ServerPathConn struct {
	listener        *Listener
	conn            net.PacketConn
	flowID          [proto.UDPFlowIDSize]byte
	maxDatagramSize int
	claim           *leafmobility.Claim

	// accepted is protected by listener.mu.
	accepted bool

	remoteMu sync.RWMutex
	remote   net.Addr

	readMu sync.Mutex
	inbox  chan serverPathDatagram
	// inboxMu serializes sends with channel close. A dead-flag check alone is
	// not enough: Close could close inbox between deliver's check and send.
	inboxMu sync.RWMutex

	terminalMu        sync.Mutex
	terminalPayload   *serverPathDatagram
	terminalPending   bool
	terminalDelivered bool
	terminalCause     error

	qualityMu sync.RWMutex
	quality   transport.PathQuality

	dead     atomic.Bool
	byeSeen  atomic.Bool
	quiesced atomic.Bool

	deathMu    sync.Mutex
	deathFn    func(cause transport.DeathCause, err error)
	deathErr   error
	finishErr  error
	finishDone chan struct{}

	writes atomic.Uint64
	reads  atomic.Uint64
}

func newServerPathConn(l *Listener, flowID [proto.UDPFlowIDSize]byte, src net.Addr) *ServerPathConn {
	return &ServerPathConn{
		listener:        l,
		conn:            l.conn,
		flowID:          flowID,
		maxDatagramSize: l.maxDatagramSize,
		claim: leafmobility.MustNewClaim(leafmobility.Facts{
			Kind:       leafmobility.KindUDPFlow,
			Role:       leafmobility.RoleAcceptor,
			Scope:      leafmobility.ScopeSharedLink,
			Session:    leafmobility.SessionAny,
			Generation: leafmobility.NextGeneration(),
		}),
		remote:     src,
		inbox:      make(chan serverPathDatagram, inboxSize),
		finishDone: make(chan struct{}),
	}
}

type serverPathDatagram struct {
	payload  []byte
	terminal bool
}

func (p *ServerPathConn) LeafMobilityClaim() *leafmobility.Claim {
	if p == nil {
		return nil
	}
	return p.claim
}

func (p *ServerPathConn) FlowID() [proto.UDPFlowIDSize]byte { return p.flowID }
func (p *ServerPathConn) Writes() uint64                    { return p.writes.Load() }
func (p *ServerPathConn) Reads() uint64                     { return p.reads.Load() }

// MaxFrameSize reports the largest complete rendr frame that fits after the
// udpflow wire header in one datagram.
func (p *ServerPathConn) MaxFrameSize() int {
	if p == nil || p.maxDatagramSize <= proto.UDPFlowHeaderSize {
		return 0
	}
	return p.maxDatagramSize - proto.UDPFlowHeaderSize
}

var _ transport.PacketPathConn = (*ServerPathConn)(nil)

// observe records a newly seen source address for this flow. Subsequent writes
// target the new address.
func (p *ServerPathConn) observe(src net.Addr) {
	p.remoteMu.Lock()
	p.remote = src
	p.remoteMu.Unlock()
}

// deliver pushes an inbound rendr-frame payload to the inbox. If the inbox is
// full the datagram is dropped; opaque UDP is best-effort delivery.
func (p *ServerPathConn) deliver(payload []byte) {
	p.inboxMu.RLock()
	defer p.inboxMu.RUnlock()
	if p.dead.Load() {
		return
	}
	select {
	case p.inbox <- serverPathDatagram{payload: payload}:
	default:
	}
}

func (p *ServerPathConn) deliverTerminal(payload []byte, terminalErr error) *ServerPathConn {
	p.inboxMu.RLock()
	defer p.inboxMu.RUnlock()
	if p.dead.Load() {
		return nil
	}
	p.terminalMu.Lock()
	if p.terminalPending {
		p.terminalMu.Unlock()
		return p
	}
	p.terminalPending = true
	p.terminalCause = terminalErr
	p.terminalMu.Unlock()
	datagram := serverPathDatagram{payload: payload, terminal: true}
	select {
	case p.inbox <- datagram:
		return p
	default:
	}
	p.terminalMu.Lock()
	if p.terminalPayload == nil {
		p.terminalPayload = &datagram
	}
	p.terminalMu.Unlock()
	return p
}

func (p *ServerPathConn) hasPendingPayload() bool {
	if len(p.inbox) != 0 {
		return true
	}
	p.terminalMu.Lock()
	defer p.terminalMu.Unlock()
	return p.terminalPayload != nil
}

// Read blocks until the next rendr frame arrives. The returned payload is the
// bytes following the UDPFlowHeader in one packet.
func (p *ServerPathConn) Read(buf []byte) (int, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()

	p.terminalMu.Lock()
	if p.terminalPending && p.terminalDelivered {
		terminalErr := p.terminalCause
		p.terminalPending = false
		p.terminalCause = nil
		p.terminalMu.Unlock()
		_ = p.finish(terminalErr, true)
		return 0, net.ErrClosed
	}
	p.terminalMu.Unlock()

	var datagram serverPathDatagram
	var ok bool
	select {
	case datagram, ok = <-p.inbox:
	default:
		p.terminalMu.Lock()
		if p.terminalPayload != nil {
			datagram = *p.terminalPayload
			p.terminalPayload = nil
			ok = true
		}
		p.terminalMu.Unlock()
		if !ok {
			datagram, ok = <-p.inbox
		}
	}
	if !ok {
		p.terminalMu.Lock()
		if p.terminalPayload != nil {
			datagram = *p.terminalPayload
			p.terminalPayload = nil
		}
		p.terminalMu.Unlock()
		if datagram.payload == nil {
			return 0, net.ErrClosed
		}
	}
	if datagram.terminal {
		p.terminalMu.Lock()
		p.terminalDelivered = true
		p.terminalMu.Unlock()
	}
	if len(buf) < len(datagram.payload) {
		return 0, errors.New("udpflow: server read buf too small")
	}
	copy(buf, datagram.payload)
	p.reads.Add(1)
	return len(datagram.payload), nil
}

// Write sends frame to the current peer with UDPFlowHeader prepended.
func (p *ServerPathConn) Write(frame []byte) (int, error) {
	if len(frame) == 0 {
		return 0, errors.New("udpflow: empty frame")
	}
	if len(frame)+proto.UDPFlowHeaderSize > p.maxDatagramSize {
		return 0, fmt.Errorf("udpflow: frame %d + %d header > datagram capacity %d", len(frame), proto.UDPFlowHeaderSize, p.maxDatagramSize)
	}
	if p.dead.Load() {
		return 0, net.ErrClosed
	}

	p.remoteMu.RLock()
	dst := p.remote
	p.remoteMu.RUnlock()
	if dst == nil {
		return 0, errors.New("udpflow: server side has no observed peer yet")
	}

	out := make([]byte, proto.UDPFlowHeaderSize+len(frame))
	hdr := proto.UDPFlowHeader{Version: proto.UDPFlowVersion, FlowID: p.flowID, PayloadSize: uint32(len(frame))}
	if err := hdr.Encode(out[:proto.UDPFlowHeaderSize]); err != nil {
		return 0, err
	}
	copy(out[proto.UDPFlowHeaderSize:], frame)

	written, err := p.conn.WriteTo(out, dst)
	_, err = normalizePacketWriteResult(len(out), written, err)
	if err != nil {
		p.declareDeath(err)
		return 0, net.ErrClosed
	}
	p.writes.Add(1)
	return len(frame), nil
}

func (p *ServerPathConn) Close() error {
	return p.finish(nil, false)
}

func (p *ServerPathConn) Quality() transport.PathQuality {
	p.qualityMu.RLock()
	defer p.qualityMu.RUnlock()
	return p.quality
}

func (p *ServerPathConn) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	if err := ctx.Err(); err != nil {
		return transport.PathQuality{}, err
	}
	return p.Quality(), nil
}

func (p *ServerPathConn) SetQuality(q transport.PathQuality) {
	p.qualityMu.Lock()
	p.quality = q
	p.qualityMu.Unlock()
}

func (p *ServerPathConn) OnDeath(fn func(cause transport.DeathCause, err error)) {
	p.deathMu.Lock()
	defer p.deathMu.Unlock()
	if p.dead.Load() {
		err := p.deathErr
		go fn(transport.Classify(err, p.quiesced.Load(), p.byeSeen.Load()), err)
		return
	}
	p.deathFn = fn
}

func (p *ServerPathConn) MarkByeSeen()  { p.byeSeen.Store(true) }
func (p *ServerPathConn) MarkQuiesced() { p.quiesced.Store(true) }

func (p *ServerPathConn) LocalAddr() string {
	if a := p.conn.LocalAddr(); a != nil {
		return a.String()
	}
	return ""
}

func (p *ServerPathConn) RemoteAddr() string {
	p.remoteMu.RLock()
	defer p.remoteMu.RUnlock()
	if p.remote != nil {
		return p.remote.String()
	}
	return ""
}

func (p *ServerPathConn) declareDeath(err error) {
	p.terminalMu.Lock()
	if p.terminalPending {
		if p.terminalCause == nil {
			p.terminalCause = err
		}
		p.terminalMu.Unlock()
		return
	}
	p.terminalMu.Unlock()
	_ = p.finish(err, true)
}

func (p *ServerPathConn) finish(err error, notify bool) error {
	p.claim.RetireUnbound()
	var fn func(cause transport.DeathCause, err error)

	p.deathMu.Lock()
	if p.dead.Load() {
		done := p.finishDone
		p.deathMu.Unlock()
		if done != nil {
			<-done
		}
		p.deathMu.Lock()
		finishErr := p.finishErr
		p.deathMu.Unlock()
		return finishErr
	}
	p.deathErr = err
	if notify {
		fn = p.deathFn
	}
	p.deathFn = nil
	p.dead.Store(true)
	p.deathMu.Unlock()

	p.inboxMu.Lock()
	close(p.inbox)
	p.inboxMu.Unlock()

	finishErr := p.listener.removeFlow(p.flowID, p)
	p.deathMu.Lock()
	p.finishErr = finishErr
	if p.finishDone != nil {
		close(p.finishDone)
	}
	p.deathMu.Unlock()
	if fn != nil {
		fn(transport.Classify(err, p.quiesced.Load(), p.byeSeen.Load()), err)
	}
	return finishErr
}
