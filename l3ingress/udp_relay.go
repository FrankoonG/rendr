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
	Device   virtualif.CancellableWriterDevice
	Egresses *EgressRegistry

	mu       sync.Mutex
	sessions map[L3Identity]*udpFlowSession
	closed   bool
}

type udpFlowSession struct {
	id     L3Identity
	pc     net.PacketConn
	remote netip.AddrPort
	cancel context.CancelFunc
	done   chan struct{}
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
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	sessions := r.sessions
	r.sessions = nil
	r.mu.Unlock()
	var firstErr error
	for _, s := range sessions {
		s.cancel()
		if err := s.pc.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		<-s.done
	}
	return firstErr
}

// CloseFlow closes one active UDP relay session.
func (r *UDPFlowRelay) CloseFlow(id L3Identity) bool {
	r.mu.Lock()
	session := r.sessions[id]
	if session != nil {
		delete(r.sessions, id)
	}
	r.mu.Unlock()
	if session == nil {
		return false
	}
	session.cancel()
	_ = session.pc.Close()
	<-session.done
	return true
}

func (r *UDPFlowRelay) session(ctx context.Context, ev PacketEvent) (*udpFlowSession, error) {
	id := ev.Meta.Identity
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, net.ErrClosed
	}
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
	if pc == nil || !remote.IsValid() {
		if pc != nil {
			_ = pc.Close()
		}
		return nil, errors.New("l3ingress: UDP egress returned an invalid socket or remote address")
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	session := &udpFlowSession{id: id, pc: pc, remote: remote, cancel: cancel, done: make(chan struct{})}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		cancel()
		_ = pc.Close()
		return nil, net.ErrClosed
	}
	if existing := r.sessions[id]; existing != nil {
		r.mu.Unlock()
		cancel()
		_ = pc.Close()
		return existing, nil
	}
	r.sessions[id] = session
	go r.readReplies(sessionCtx, session)
	r.mu.Unlock()
	return session, nil
}

func (r *UDPFlowRelay) readReplies(ctx context.Context, session *udpFlowSession) {
	defer close(session.done)
	defer r.forgetSession(session)
	defer session.cancel()
	defer session.pc.Close()
	stopOnCancel := context.AfterFunc(ctx, func() { _ = session.pc.Close() })
	defer stopOnCancel()
	buf := make([]byte, 64<<10)
	replyID := session.id.Reverse()
	packet := make([]byte, 0, len(buf)+28)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, source, err := session.pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		if !udpReplySourceMatches(source, session.remote) {
			continue
		}
		packet = packet[:0]
		packet, err = AppendUDPPacket(packet, replyID, buf[:n])
		if err != nil {
			return
		}
		if _, err := r.Device.WriteContext(ctx, packet); err != nil {
			return
		}
	}
}

func udpReplySourceMatches(source net.Addr, expected netip.AddrPort) bool {
	if source == nil || !expected.IsValid() {
		return false
	}
	var actual netip.AddrPort
	switch address := source.(type) {
	case *net.UDPAddr:
		actual = address.AddrPort()
	default:
		parsed, err := netip.ParseAddrPort(source.String())
		if err != nil {
			return false
		}
		actual = parsed
	}
	return actual.Addr().Unmap() == expected.Addr().Unmap() && actual.Port() == expected.Port()
}

func (r *UDPFlowRelay) forgetSession(session *udpFlowSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[session.id] == session {
		delete(r.sessions, session.id)
	}
}
