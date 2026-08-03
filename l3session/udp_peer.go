package l3session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

const defaultUDPPeerBufferSize = 64 << 10

// UDPPeerRelay terminates one TUN-originated rendr packet session and
// dispatches its preserved identity to an embedding-provided UDP egress.
// Callers accept the PacketConn and own closing it after Run returns.
type UDPPeerRelay struct {
	PacketConn rendr.PacketConn
	Egresses   *l3ingress.EgressRegistry
	BufferSize int
}

// Run bridges packets until the context is canceled or either side closes.
// Every request carries the same versioned identity/egress envelope; replies
// are raw UDP payload because the ingress side already owns the reverse tuple.
func (r *UDPPeerRelay) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("l3session: nil UDP peer context")
	}
	if r.PacketConn == nil {
		return errors.New("l3session: nil UDP peer PacketConn")
	}
	if err := l3ingress.RequirePeerEgress(r.Egresses != nil); err != nil {
		return err
	}
	size := r.BufferSize
	if size <= 0 {
		size = defaultUDPPeerBufferSize
	}
	if size < udpEnvelopeHeaderSize+l3ingress.IdentityWireSize+1 {
		return fmt.Errorf("l3session: UDP peer buffer size %d is too small", size)
	}

	stopFirstRead := context.AfterFunc(ctx, func() {
		_ = r.PacketConn.SetReadDeadline(time.Now())
	})
	buf := make([]byte, size)
	n, _, err := r.PacketConn.ReadFrom(buf)
	stopFirstRead()
	if err != nil {
		return normalizeUDPPeerError(ctx, err)
	}
	first, err := decodeUDPEnvelope(buf[:n])
	if err != nil {
		return err
	}
	egressConn, remote, err := r.Egresses.DialUDP(ctx, first.Egress, first.Identity)
	if err != nil {
		return err
	}
	defer egressConn.Close()
	remoteAddr := net.UDPAddrFromAddrPort(remote)
	if n, err := egressConn.WriteTo(first.Payload, remoteAddr); err != nil {
		return fmt.Errorf("l3session: write first UDP egress payload: %w", err)
	} else if n != len(first.Payload) {
		return fmt.Errorf("l3session: short first UDP egress write: %d of %d", n, len(first.Payload))
	}

	bridgeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopIO := context.AfterFunc(bridgeCtx, func() {
		now := time.Now()
		_ = r.PacketConn.SetReadDeadline(now)
		_ = r.PacketConn.SetWriteDeadline(now)
		_ = egressConn.SetReadDeadline(now)
		_ = egressConn.SetWriteDeadline(now)
	})
	defer stopIO()

	errCh := make(chan error, 2)
	go func() {
		errCh <- r.forwardUDPRequests(bridgeCtx, first, egressConn, remoteAddr, size)
	}()
	go func() {
		errCh <- r.forwardUDPReplies(bridgeCtx, egressConn, size)
	}()

	var firstErr error
	select {
	case firstErr = <-errCh:
	case <-ctx.Done():
		firstErr = ctx.Err()
	}
	cancel()
	secondErr := <-errCh
	return errors.Join(normalizeUDPPeerError(bridgeCtx, firstErr), normalizeUDPPeerError(bridgeCtx, secondErr))
}

func (r *UDPPeerRelay) forwardUDPRequests(
	ctx context.Context,
	first udpEnvelope,
	egressConn net.PacketConn,
	remote net.Addr,
	bufferSize int,
) error {
	buf := make([]byte, bufferSize)
	for {
		n, _, err := r.PacketConn.ReadFrom(buf)
		if err != nil {
			return err
		}
		envelope, err := decodeUDPEnvelope(buf[:n])
		if err != nil {
			return err
		}
		if envelope.Identity != first.Identity || envelope.Egress != first.Egress {
			return fmt.Errorf("l3session: UDP session identity or egress changed: got %s/%q want %s/%q",
				envelope.Identity, envelope.Egress, first.Identity, first.Egress)
		}
		written, err := egressConn.WriteTo(envelope.Payload, remote)
		if err != nil {
			return err
		}
		if written != len(envelope.Payload) {
			return fmt.Errorf("l3session: short UDP egress write: %d of %d", written, len(envelope.Payload))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func (r *UDPPeerRelay) forwardUDPReplies(ctx context.Context, egressConn net.PacketConn, bufferSize int) error {
	buf := make([]byte, bufferSize)
	for {
		n, _, err := egressConn.ReadFrom(buf)
		if err != nil {
			return err
		}
		written, err := r.PacketConn.WriteTo(buf[:n], rendrPeerAddr)
		if err != nil {
			return err
		}
		if written != n {
			return fmt.Errorf("l3session: short rendr UDP reply write: %d of %d", written, n)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func normalizeUDPPeerError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
	}
	return err
}
