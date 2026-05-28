package l3ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/FrankoonG/rendr/virtualif"
)

// UDPFlowRelay forwards classified UDP flow payloads to an embedding
// egress hook and writes egress replies back as raw IP packets.
type UDPFlowRelay struct {
	Device   virtualif.Device
	Egresses *EgressRegistry

	mu       sync.Mutex
	sessions map[L3Identity]*udpFlowSession
}

type udpFlowSession struct {
	id     L3Identity
	pc     net.PacketConn
	remote netip.AddrPort
	cancel context.CancelFunc
}

// HandlePacket implements PacketHandler for UDP flow smoke paths.
func (r *UDPFlowRelay) HandlePacket(ctx context.Context, ev PacketEvent) error {
	if r.Device == nil {
		return errors.New("l3ingress: nil UDP relay device")
	}
	if ev.Meta.Identity.Proto != ProtocolUDP {
		return fmt.Errorf("l3ingress: UDP relay cannot handle %s", ev.Meta.Identity.Proto)
	}
	if !ev.Decided {
		return errors.New("l3ingress: UDP relay requires a flow decision")
	}
	payload, err := UDPPayload(ev.Packet, ev.Meta)
	if err != nil {
		return err
	}
	session, err := r.session(ctx, ev)
	if err != nil {
		return err
	}
	_, err = session.pc.WriteTo(payload, net.UDPAddrFromAddrPort(session.remote))
	return err
}

// Close closes all active UDP relay sessions.
func (r *UDPFlowRelay) Close() error {
	r.mu.Lock()
	sessions := r.sessions
	r.sessions = nil
	r.mu.Unlock()
	var firstErr error
	for _, s := range sessions {
		s.cancel()
		if err := s.pc.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (r *UDPFlowRelay) session(ctx context.Context, ev PacketEvent) (*udpFlowSession, error) {
	id := ev.Meta.Identity
	r.mu.Lock()
	if r.sessions == nil {
		r.sessions = make(map[L3Identity]*udpFlowSession)
	}
	if session := r.sessions[id]; session != nil {
		r.mu.Unlock()
		return session, nil
	}
	r.mu.Unlock()

	pc, remote, err := r.Egresses.DialUDP(ctx, ev.Decision.Egress, id)
	if err != nil {
		return nil, err
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	session := &udpFlowSession{id: id, pc: pc, remote: remote, cancel: cancel}

	r.mu.Lock()
	if existing := r.sessions[id]; existing != nil {
		r.mu.Unlock()
		cancel()
		_ = pc.Close()
		return existing, nil
	}
	r.sessions[id] = session
	r.mu.Unlock()
	go r.readReplies(sessionCtx, session)
	return session, nil
}

func (r *UDPFlowRelay) readReplies(ctx context.Context, session *udpFlowSession) {
	buf := make([]byte, 64<<10)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, _, err := session.pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		packet, err := BuildUDPPacket(session.id.Reverse(), append([]byte(nil), buf[:n]...))
		if err != nil {
			return
		}
		if _, err := r.Device.Write(packet); err != nil {
			return
		}
	}
}
