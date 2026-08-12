package l3ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/virtualif"
)

const defaultReadBufferSize = 64 << 10

// PacketEvent is emitted after one raw IP packet has been parsed and
// optionally passed through an external routing decision hook.
type PacketEvent struct {
	Packet   []byte
	Meta     PacketMeta
	Flow     FlowMeta
	Ref      FlowRef
	Decision FlowDecision
	Decided  bool
}

// PacketHandler consumes parsed packet events. Later TUN flow adapters
// plug in here to create rendr Conn / PacketConn sessions.
type PacketHandler interface {
	HandlePacket(context.Context, PacketEvent) error
}

// PacketHandlerFunc adapts a function into PacketHandler.
type PacketHandlerFunc func(context.Context, PacketEvent) error

func (f PacketHandlerFunc) HandlePacket(ctx context.Context, ev PacketEvent) error {
	return f(ctx, ev)
}

// ParseErrorHandler observes packets that cannot become a flow.
type ParseErrorHandler func(packet []byte, err error)

// PacketFailureStage identifies which packet-local Pump operation failed.
type PacketFailureStage string

const (
	// PacketFailureResolve means routing or flow-table admission failed.
	PacketFailureResolve PacketFailureStage = "resolve"
	// PacketFailureHandle means PacketHandler.HandlePacket rejected the packet
	// or failed its flow-local work.
	PacketFailureHandle PacketFailureStage = "handle"
)

// PacketFailure is bounded evidence for one packet-local failure. Event owns
// its Packet bytes and may be retained by the caller.
type PacketFailure struct {
	Stage PacketFailureStage
	Event PacketEvent
	Err   error
}

// PacketFailureHandler observes packet-local failures. Delivery is best
// effort: Pump permits at most one callback invocation at a time and records
// skipped or panicking callbacks in Status. Status counts every failure and
// retains the latest evidence even when callback delivery is skipped.
type PacketFailureHandler func(PacketFailure)

// PumpStatus is a concurrency-safe snapshot of packet-local failure evidence.
type PumpStatus struct {
	PacketFailures uint64
	ObserverDrops  uint64
	ObserverPanics uint64
	LastFailure    PacketFailure
	HasLastFailure bool
}

// Pump connects a raw virtual interface to the l3ingress classifier.
// It owns no routing policy and starts no rendr flows by itself.
type Pump struct {
	Device       virtualif.CancellableDevice
	Direction    Direction
	FlowTable    *FlowTable
	Router       FlowDecisionFunc
	Handler      PacketHandler
	OnParseError ParseErrorHandler
	// OnPacketFailure is optional and must not be used as the authoritative
	// failure record; Status counts every failure even when this callback is
	// blocked, skipped, or panics, and retains the latest evidence.
	OnPacketFailure PacketFailureHandler
	BufferSize      int
	Now             func() time.Time

	statusMu     sync.Mutex
	status       PumpStatus
	observerBusy atomic.Bool
}

// Status returns bounded packet-local failure evidence accumulated by Pump.
func (p *Pump) Status() PumpStatus {
	if p == nil {
		return PumpStatus{}
	}
	p.statusMu.Lock()
	status := p.status
	p.statusMu.Unlock()
	if status.HasLastFailure {
		status.LastFailure = clonePacketFailure(status.LastFailure)
	}
	return status
}

// Run reads packets until the context is canceled or the device reaches a
// terminal read result. Routing and handler errors reject only their packet;
// Pump records them in Status and continues serving unrelated flows.
func (p *Pump) Run(ctx context.Context) error {
	if p.Device == nil {
		return errors.New("l3ingress: nil device")
	}
	if p.Handler == nil {
		return errors.New("l3ingress: nil packet handler")
	}
	bufSize := p.BufferSize
	if bufSize <= 0 {
		bufSize = p.Device.MTU()
	}
	if bufSize <= 0 {
		bufSize = defaultReadBufferSize
	}
	if bufSize < 1 {
		return fmt.Errorf("l3ingress: invalid buffer size %d", bufSize)
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}
	onPacketFailure := p.OnPacketFailure
	direction := p.Direction
	if direction == 0 {
		direction = DirectionIngress
	}
	table := p.FlowTable
	if table == nil && p.Router != nil {
		table = NewFlowTable(p.Router, FlowTableOptions{Now: now})
	}
	buf := make([]byte, bufSize)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := p.Device.ReadContext(ctx, buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, io.ErrShortBuffer) && len(buf) < defaultReadBufferSize {
				buf = make([]byte, defaultReadBufferSize)
				continue
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n == 0 {
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		meta, err := ParsePacket(packet)
		if err != nil {
			if p.OnParseError != nil {
				p.OnParseError(packet, err)
			}
			continue
		}
		flow := FlowMeta{
			L3Identity: meta.Identity,
			Direction:  direction,
			CreatedAt:  now(),
		}
		ev := PacketEvent{
			Packet: packet,
			Meta:   meta,
			Flow:   flow,
		}
		if table != nil {
			decision, _, snapshot, err := table.Resolve(ctx, flow, len(packet))
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return ctxErr
				}
				p.recordPacketFailure(onPacketFailure, PacketFailure{
					Stage: PacketFailureResolve,
					Event: ev,
					Err:   err,
				})
				continue
			}
			ev.Decision = decision
			ev.Decided = snapshot.Decided
			ev.Flow = snapshot.Flow
			ev.Ref = snapshot.Ref
		}
		if ev.Decision.Deny {
			if table != nil {
				if reason, ok := TCPFlowCloseReason(meta); ok {
					table.Close(meta.Identity, reason)
				}
			}
			continue
		}
		handlerErr := p.Handler.HandlePacket(ctx, ev)
		if table != nil {
			if reason, ok := TCPFlowCloseReason(meta); ok {
				table.Close(meta.Identity, reason)
			}
		}
		if handlerErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			p.recordPacketFailure(onPacketFailure, PacketFailure{
				Stage: PacketFailureHandle,
				Event: ev,
				Err:   handlerErr,
			})
		}
	}
}

func (p *Pump) recordPacketFailure(observer PacketFailureHandler, failure PacketFailure) {
	retained := clonePacketFailure(failure)
	p.statusMu.Lock()
	p.status.PacketFailures++
	p.status.LastFailure = retained
	p.status.HasLastFailure = true
	p.statusMu.Unlock()

	if observer == nil {
		return
	}
	if !p.observerBusy.CompareAndSwap(false, true) {
		p.statusMu.Lock()
		p.status.ObserverDrops++
		p.statusMu.Unlock()
		return
	}
	observed := clonePacketFailure(retained)
	go func() {
		defer func() {
			if recover() != nil {
				p.statusMu.Lock()
				p.status.ObserverPanics++
				p.statusMu.Unlock()
			}
			p.observerBusy.Store(false)
		}()
		observer(observed)
	}()
}

func clonePacketFailure(failure PacketFailure) PacketFailure {
	failure.Event.Packet = append([]byte(nil), failure.Event.Packet...)
	failure.Event.Flow = cloneFlowMeta(failure.Event.Flow)
	failure.Event.Decision = cloneDecision(failure.Event.Decision)
	return failure
}
