package l3session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/virtualif"
)

// UDPRelay bridges classified TUN UDP packets to per-flow rendr PacketConn
// sessions, then writes PacketConn replies back to the virtual interface as
// raw UDP packets.
type UDPRelay struct {
	Device  virtualif.Device
	Manager *Manager

	BufferSize int

	mu       sync.Mutex
	owned    *Manager
	sessions map[l3ingress.L3Identity]context.CancelFunc
	packets  map[l3ingress.L3Identity]*Session
}

// HandlePacket implements l3ingress.PacketHandler for UDP ingress flows.
func (r *UDPRelay) HandlePacket(ctx context.Context, ev l3ingress.PacketEvent) error {
	if r.Device == nil {
		return errors.New("l3session: nil UDP relay device")
	}
	if ev.Meta.Identity.Proto != l3ingress.ProtocolUDP {
		return fmt.Errorf("l3session: UDP relay cannot handle %s", ev.Meta.Identity.Proto)
	}
	payload, err := l3ingress.UDPPayload(ev.Packet, ev.Meta)
	if err != nil {
		return err
	}
	id := ev.Meta.Identity
	sess := r.packetSession(id)
	if sess == nil {
		manager := r.manager()
		if err := manager.HandlePacket(ctx, ev); err != nil {
			return err
		}
		var ok bool
		sess, ok = manager.Session(id)
		if !ok || sess.PacketConn == nil {
			return errors.New("l3session: UDP relay missing packet session")
		}
		r.setPacketSession(id, sess)
		r.startReplyLoop(ctx, id, sess)
	}
	_, err = sess.PacketConn.WriteTo(payload, packetAddr("rendr-peer"))
	return err
}

// ObserveFlow implements l3ingress.FlowObserver. Closed flows tear down the
// matching packet session and reply loop.
func (r *UDPRelay) ObserveFlow(snapshot l3ingress.FlowSnapshot) {
	if snapshot.Closed {
		_ = r.CloseFlow(snapshot.Flow.L3Identity)
		return
	}
	r.manager().ObserveFlow(snapshot)
}

// CloseFlow closes one active UDP packet session.
func (r *UDPRelay) CloseFlow(id l3ingress.L3Identity) bool {
	r.mu.Lock()
	cancel := r.sessions[id]
	if cancel != nil {
		delete(r.sessions, id)
	}
	delete(r.packets, id)
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return r.manager().Close(id) == nil && cancel != nil
}

// Close closes all UDP packet sessions.
func (r *UDPRelay) Close() error {
	r.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(r.sessions))
	for id, cancel := range r.sessions {
		cancels = append(cancels, cancel)
		delete(r.sessions, id)
	}
	for id := range r.packets {
		delete(r.packets, id)
	}
	r.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return r.manager().CloseAll()
}

func (r *UDPRelay) manager() *Manager {
	if r.Manager != nil {
		return r.Manager
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.owned == nil {
		r.owned = &Manager{}
	}
	return r.owned
}

func (r *UDPRelay) startReplyLoop(ctx context.Context, id l3ingress.L3Identity, sess *Session) {
	r.mu.Lock()
	if r.sessions == nil {
		r.sessions = make(map[l3ingress.L3Identity]context.CancelFunc)
	}
	if r.sessions[id] != nil {
		r.mu.Unlock()
		return
	}
	loopCtx, cancel := context.WithCancel(ctx)
	r.sessions[id] = cancel
	r.mu.Unlock()
	go r.readReplies(loopCtx, id, sess)
}

func (r *UDPRelay) packetSession(id l3ingress.L3Identity) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.packets[id]
}

func (r *UDPRelay) setPacketSession(id l3ingress.L3Identity, sess *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.packets == nil {
		r.packets = make(map[l3ingress.L3Identity]*Session)
	}
	r.packets[id] = sess
}

func (r *UDPRelay) readReplies(ctx context.Context, id l3ingress.L3Identity, sess *Session) {
	defer r.forgetSession(id)
	size := r.BufferSize
	if size <= 0 {
		size = 64 << 10
	}
	buf := make([]byte, size)
	replyID := id.Reverse()
	packet := make([]byte, 0, size+28)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, _, err := sess.PacketConn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		packet = packet[:0]
		packet, err = l3ingress.AppendUDPPacket(packet, replyID, buf[:n])
		if err != nil {
			return
		}
		if _, err := r.Device.Write(packet); err != nil {
			return
		}
	}
}

func (r *UDPRelay) forgetSession(id l3ingress.L3Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
	delete(r.packets, id)
}

type packetAddr string

func (a packetAddr) Network() string { return "rendr" }
func (a packetAddr) String() string  { return string(a) }
