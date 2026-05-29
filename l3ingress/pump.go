package l3ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
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

// Pump connects a raw virtual interface to the l3ingress classifier.
// It owns no routing policy and starts no rendr flows by itself.
type Pump struct {
	Device       virtualif.Device
	Direction    Direction
	FlowTable    *FlowTable
	Router       FlowDecisionFunc
	Handler      PacketHandler
	OnParseError ParseErrorHandler
	BufferSize   int
	Now          func() time.Time
}

// Run reads packets until the context is canceled, the device is
// closed, or the router/handler returns an error.
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
		n, err := p.Device.Read(buf)
		if err != nil {
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
				return err
			}
			ev.Decision = decision
			ev.Decided = snapshot.Decided
			ev.Flow = snapshot.Flow
		}
		if ev.Decision.Deny {
			if table != nil {
				if reason, ok := TCPFlowCloseReason(meta); ok {
					table.Close(meta.Identity, reason)
				}
			}
			continue
		}
		if err := p.Handler.HandlePacket(ctx, ev); err != nil {
			return err
		}
		if table != nil {
			if reason, ok := TCPFlowCloseReason(meta); ok {
				table.Close(meta.Identity, reason)
			}
		}
	}
}
