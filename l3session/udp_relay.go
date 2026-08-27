package l3session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/virtualif"
)

// UDPRelay bridges classified TUN UDP packets to per-flow rendr PacketConn
// sessions, then writes PacketConn replies back to the virtual interface as
// raw UDP packets.
type UDPRelay struct {
	Device  virtualif.CancellableWriterDevice
	Manager *Manager
	// ReplyActivity lets the gateway linearize reply delivery with idle
	// reaping. It does not own scheduling.
	ReplyActivity UDPReplyActivity

	BufferSize int

	mu       sync.Mutex
	owned    *Manager
	sessions map[l3ingress.L3Identity]packetReplyLoop
	packets  map[l3ingress.L3Identity]*Session
	closed   bool
	fast     atomic.Pointer[packetSessionCache]
}

// UDPReplyActivity brackets one reply packet after it has been read from the
// rendr session and before it is delivered to the virtual interface.
type UDPReplyActivity interface {
	BeginUDPReply(l3ingress.FlowRef) bool
	EndUDPReply(l3ingress.FlowRef, bool)
}

type packetReplyLoop struct {
	session *Session
	cancel  context.CancelFunc
	done    <-chan struct{}
}

type packetSessionCache struct {
	id   l3ingress.L3Identity
	sess *Session
}

// HandlePacket implements l3ingress.PacketHandler for UDP ingress flows.
func (r *UDPRelay) HandlePacket(ctx context.Context, ev l3ingress.PacketEvent) error {
	if r.Device == nil {
		return errors.New("l3session: nil UDP relay device")
	}
	if ev.Meta.Identity.Proto != l3ingress.ProtocolUDP {
		return fmt.Errorf("l3session: UDP relay cannot handle %s", ev.Meta.Identity.Proto)
	}
	if err := requireCanonicalIdentity(ev.Meta.Identity, l3ingress.ProtocolUDP); err != nil {
		return err
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	payload, err := l3ingress.UDPPayload(ev.Packet, ev.Meta)
	if err != nil {
		return err
	}
	id := ev.Meta.Identity
	var sess *Session
	if cached := r.fast.Load(); cached != nil && cached.id == id && sessionMatchesFlowRef(cached.sess, ev.Ref) {
		sess = cached.sess
	} else {
		sess = r.packetSession(id, ev.Ref)
	}
	if sess == nil {
		r.retireStalePacketSession(id, ev.Ref)
		manager := r.manager()
		if err := manager.HandlePacket(ctx, ev); err != nil {
			return err
		}
		var ok bool
		sess, ok = manager.Session(id)
		if !ok || sess.packetConn == nil {
			return errors.New("l3session: UDP relay missing packet session")
		}
		if !r.setPacketSession(id, sess) || !r.startReplyLoop(ctx, id, sess) {
			_ = manager.CloseSession(sess)
			return net.ErrClosed
		}
	}
	wirePacket, err := appendUDPEnvelope(nil, id, sess.request.Egress, payload)
	if err != nil {
		return err
	}
	packet := newDataPlanePacket(sess.packetConn, "UDPRelay rendr PacketConn", nil)
	written, err := packet.writeTo(ctx, wirePacket, nil)
	if err == nil && written != len(wirePacket) {
		return fmt.Errorf("l3session: short rendr UDP request write: %d of %d", written, len(wirePacket))
	}
	return err
}

// ObserveFlow implements l3ingress.FlowObserver. Closed flows tear down the
// matching packet session and reply loop.
func (r *UDPRelay) ObserveFlow(snapshot l3ingress.FlowSnapshot) {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return
	}
	if snapshot.Closed {
		if snapshot.Ref != (l3ingress.FlowRef{}) {
			_ = r.CloseFlowRef(snapshot.Ref)
		} else {
			_ = r.CloseFlow(snapshot.Flow.L3Identity)
		}
		return
	}
	r.manager().ObserveFlow(snapshot)
}

// CloseFlow closes one active UDP packet session.
func (r *UDPRelay) CloseFlow(id l3ingress.L3Identity) bool {
	return r.closeFlow(id, l3ingress.FlowRef{})
}

// CloseFlowRef closes only the activation named by ref. It is safe to call
// from delayed idle-reap or observer work after the tuple has been reused.
func (r *UDPRelay) CloseFlowRef(ref l3ingress.FlowRef) bool {
	if ref == (l3ingress.FlowRef{}) {
		return false
	}
	return r.closeFlow(ref.Identity, ref)
}

func (r *UDPRelay) closeFlow(id l3ingress.L3Identity, ref l3ingress.FlowRef) bool {
	r.mu.Lock()
	sess := r.packets[id]
	if sess == nil || ref != (l3ingress.FlowRef{}) && sess.request.Ref != ref {
		r.mu.Unlock()
		return false
	}
	loop := r.sessions[id]
	if loop.session == sess {
		delete(r.sessions, id)
	}
	delete(r.packets, id)
	r.clearFastSessionLocked(id)
	r.mu.Unlock()
	if loop.cancel != nil {
		loop.cancel()
	}
	err := r.manager().CloseSession(sess)
	if loop.done != nil {
		<-loop.done
	}
	return err == nil
}

// Close closes all UDP packet sessions.
func (r *UDPRelay) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	loops := make([]packetReplyLoop, 0, len(r.sessions))
	sessions := make([]*Session, 0, len(r.packets))
	for id, loop := range r.sessions {
		loops = append(loops, loop)
		delete(r.sessions, id)
	}
	for id, sess := range r.packets {
		sessions = append(sessions, sess)
		delete(r.packets, id)
	}
	r.fast.Store(nil)
	r.mu.Unlock()
	for _, loop := range loops {
		if loop.cancel != nil {
			loop.cancel()
		}
	}
	var err error
	for _, sess := range sessions {
		err = errors.Join(err, r.manager().CloseSession(sess))
	}
	for _, loop := range loops {
		if loop.done != nil {
			<-loop.done
		}
	}
	return err
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

func (r *UDPRelay) startReplyLoop(ctx context.Context, id l3ingress.L3Identity, sess *Session) bool {
	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		cancel()
		return false
	}
	if r.sessions == nil {
		r.sessions = make(map[l3ingress.L3Identity]packetReplyLoop)
	}
	previous := r.sessions[id]
	if previous.session == sess {
		r.mu.Unlock()
		cancel()
		return true
	}
	r.sessions[id] = packetReplyLoop{session: sess, cancel: cancel, done: done}
	go func() {
		defer close(done)
		r.readReplies(loopCtx, id, sess)
	}()
	r.mu.Unlock()
	if previous.cancel != nil {
		previous.cancel()
	}
	if previous.done != nil {
		<-previous.done
	}
	return true
}

func (r *UDPRelay) packetSession(id l3ingress.L3Identity, ref l3ingress.FlowRef) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	sess := r.packets[id]
	if !sessionMatchesFlowRef(sess, ref) {
		return nil
	}
	return sess
}

func (r *UDPRelay) retireStalePacketSession(id l3ingress.L3Identity, ref l3ingress.FlowRef) {
	if ref == (l3ingress.FlowRef{}) {
		return
	}
	r.mu.Lock()
	sess := r.packets[id]
	if sess == nil || sessionMatchesFlowRef(sess, ref) {
		r.mu.Unlock()
		return
	}
	loop := r.sessions[id]
	if loop.session == sess {
		delete(r.sessions, id)
	}
	delete(r.packets, id)
	r.clearFastSessionLocked(id)
	r.mu.Unlock()
	if loop.cancel != nil {
		loop.cancel()
	}
	_ = r.manager().CloseSession(sess)
	if loop.done != nil {
		<-loop.done
	}
}

func sessionMatchesFlowRef(sess *Session, ref l3ingress.FlowRef) bool {
	if sess == nil {
		return false
	}
	return ref == (l3ingress.FlowRef{}) || sess.request.Ref == ref
}

func (r *UDPRelay) setPacketSession(id l3ingress.L3Identity, sess *Session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	if r.packets == nil {
		r.packets = make(map[l3ingress.L3Identity]*Session)
	}
	r.packets[id] = sess
	r.fast.Store(&packetSessionCache{id: id, sess: sess})
	return true
}

func (r *UDPRelay) readReplies(ctx context.Context, id l3ingress.L3Identity, sess *Session) {
	defer r.forgetSession(id, sess)
	packetConn := newDataPlanePacket(sess.packetConn, "UDPRelay rendr PacketConn", nil)
	stopOnCancel := context.AfterFunc(ctx, func() {
		_ = packetConn.setReadDeadline(time.Now())
	})
	defer stopOnCancel()
	size := r.BufferSize
	if size < maxUDPPeerPayloadSize {
		size = maxUDPPeerPayloadSize
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
		n, _, readErr := packetConn.readFrom(ctx, buf)
		if n < 0 || n > len(buf) {
			return
		}
		if n == 0 && readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) {
				return
			}
			return
		}
		packet = packet[:0]
		var appendErr error
		packet, appendErr = l3ingress.AppendUDPPacket(packet, replyID, buf[:n])
		if appendErr != nil {
			return
		}
		if r.ReplyActivity != nil && !r.ReplyActivity.BeginUDPReply(sess.request.Ref) {
			return
		}
		written, writeErr := r.Device.WriteContext(ctx, packet)
		delivered := writeErr == nil && written == len(packet)
		if r.ReplyActivity != nil {
			r.ReplyActivity.EndUDPReply(sess.request.Ref, delivered)
		} else if delivered {
			r.manager().FlowTable.TouchRef(sess.request.Ref)
		}
		if writeErr != nil {
			return
		}
		if written != len(packet) {
			return
		}
		if readErr != nil {
			return
		}
	}
}

func (r *UDPRelay) forgetSession(id l3ingress.L3Identity, sess *Session) {
	r.mu.Lock()
	if r.packets[id] != sess {
		r.mu.Unlock()
		_ = r.manager().CloseSession(sess)
		return
	}
	loop := r.sessions[id]
	if loop.session == sess {
		delete(r.sessions, id)
	}
	delete(r.packets, id)
	r.clearFastSessionLocked(id)
	r.mu.Unlock()
	_ = r.manager().CloseSession(sess)
}

func (r *UDPRelay) clearFastSessionLocked(id l3ingress.L3Identity) {
	if cached := r.fast.Load(); cached != nil && cached.id == id {
		r.fast.Store(nil)
	}
}

type packetAddr string

func (a packetAddr) Network() string { return "rendr" }
func (a packetAddr) String() string  { return string(a) }

var rendrPeerAddr packetAddr = "rendr-peer"
