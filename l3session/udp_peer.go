package l3session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

const (
	maxUDPPeerPayloadSize        = 1<<16 - 1 - 8
	defaultUDPPeerBufferSize     = udpEnvelopeHeaderSize + l3ingress.IdentityWireSize + udpEnvelopeMaxEgressName + maxUDPPeerPayloadSize
	udpPeerWorkerShutdownTimeout = time.Second
)

// UDPPeerRelay terminates one TUN-originated rendr packet session and
// dispatches its preserved identity to an embedding-provided UDP egress.
// Callers accept the PacketConn and own closing it after Run returns.
type UDPPeerRelay struct {
	PacketConn rendr.PacketConn
	Egresses   *l3ingress.EgressRegistry
	// BufferSize may raise the per-direction read buffer above the largest UDP
	// envelope. Smaller positive values are promoted to that safe floor.
	BufferSize int

	dataPlaneExecutor *dataPlaneCallbackExecutor
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
	rendrPacket := newDataPlanePacket(r.PacketConn, "UDPPeerRelay rendr PacketConn", nil)
	size := r.BufferSize
	if size < defaultUDPPeerBufferSize {
		size = defaultUDPPeerBufferSize
	}

	stopFirstRead := context.AfterFunc(ctx, func() { _ = rendrPacket.setReadDeadline(time.Now()) })
	buf := make([]byte, size)
	n, _, readErr := rendrPacket.readFrom(ctx, buf)
	stopFirstRead()
	if n < 0 || n > len(buf) {
		return errors.Join(readErr, fmt.Errorf("l3session: invalid first rendr UDP read count %d", n))
	}
	if n == 0 && readErr != nil {
		return normalizeUDPPeerError(ctx, readErr)
	}
	first, err := decodeUDPEnvelope(buf[:n])
	if err != nil {
		return err
	}
	cleanup, err := reserveDataPlaneCleanupWithExecutor(
		dataPlaneExecutorOrProcess(r.dataPlaneExecutor),
		"UDPPeerRelay egress PacketConn Close",
	)
	if err != nil {
		return err
	}
	egressConn, remote, err := r.Egresses.DialUDP(ctx, first.Egress, first.Identity)
	if err != nil {
		cleanup.Release()
		return err
	}
	egressPacket := newDataPlanePacketWithCloseAuthority(
		egressConn,
		"UDPPeerRelay egress PacketConn",
		cleanup.Bind(egressConn.Close),
	)
	closeEgress := egressPacket.close
	remote, remoteOK := canonicalAddrPort(remote)
	if !remoteOK {
		return errors.Join(
			errors.New("l3session: UDP egress returned an invalid remote address"),
			closeEgress(),
		)
	}
	defer closeEgress()
	if n, err := egressPacket.writeTo(ctx, first.Payload, net.UDPAddrFromAddrPort(remote)); err != nil {
		return fmt.Errorf("l3session: write first UDP egress payload: %w", err)
	} else if n != len(first.Payload) {
		return fmt.Errorf("l3session: short first UDP egress write: %d of %d", n, len(first.Payload))
	}
	if readErr != nil {
		return normalizeUDPPeerError(ctx, readErr)
	}

	bridgeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopIO := context.AfterFunc(bridgeCtx, func() {
		_ = rendrPacket.interrupt()
		_ = egressPacket.interrupt()
	})
	defer stopIO()

	type workerResult struct {
		direction string
		err       error
	}
	errCh := make(chan workerResult, 2)
	go func() {
		errCh <- workerResult{
			direction: "request forwarding",
			err:       r.forwardUDPRequests(bridgeCtx, first, rendrPacket, egressPacket, remote, size),
		}
	}()
	go func() {
		errCh <- workerResult{
			direction: "reply forwarding",
			err:       r.forwardUDPReplies(bridgeCtx, rendrPacket, egressPacket, remote, size),
		}
	}()

	remaining := 2
	var relayErr error
	select {
	case result := <-errCh:
		relayErr = normalizeUDPPeerWorkerError(bridgeCtx, result.direction, result.err)
		remaining--
	case <-ctx.Done():
		// The parent Done channel can win this select before cancellation has
		// propagated into bridgeCtx. Normalize against the context whose Done
		// channel was actually observed so pure caller cancellation stays clean.
		relayErr = normalizeUDPPeerError(ctx, ctx.Err())
	}
	cancel()
	closeErr := closeEgress()
	if closeErr != nil {
		closeErr = fmt.Errorf("l3session: close UDP peer egress: %w", closeErr)
	}

	timer := time.NewTimer(udpPeerWorkerShutdownTimeout)
	defer timer.Stop()
	for remaining > 0 {
		select {
		case result := <-errCh:
			relayErr = errors.Join(relayErr, normalizeUDPPeerWorkerError(bridgeCtx, result.direction, result.err))
			remaining--
		case <-timer.C:
			return errors.Join(
				relayErr,
				closeErr,
				fmt.Errorf("l3session: UDP peer shutdown timed out with %d worker(s) still running", remaining),
			)
		}
	}
	return errors.Join(relayErr, closeErr)
}

func normalizeUDPPeerWorkerError(ctx context.Context, direction string, err error) error {
	err = normalizeUDPPeerError(ctx, err)
	if err == nil {
		return nil
	}
	return fmt.Errorf("l3session: UDP peer %s: %w", direction, err)
}

func (r *UDPPeerRelay) forwardUDPRequests(
	ctx context.Context,
	first udpEnvelope,
	rendrPacket *dataPlanePacket,
	egressPacket *dataPlanePacket,
	remote netip.AddrPort,
	bufferSize int,
) error {
	buf := make([]byte, bufferSize)
	for {
		n, _, readErr := rendrPacket.readFrom(ctx, buf)
		if n < 0 || n > len(buf) {
			return errors.Join(readErr, fmt.Errorf("l3session: invalid rendr UDP request read count %d", n))
		}
		if n == 0 && readErr != nil {
			return readErr
		}
		envelope, err := decodeUDPEnvelope(buf[:n])
		if err != nil {
			return err
		}
		if envelope.Identity != first.Identity || envelope.Egress != first.Egress {
			return fmt.Errorf("l3session: UDP session identity or egress changed: got %s/%q want %s/%q",
				envelope.Identity, envelope.Egress, first.Identity, first.Egress)
		}
		written, err := egressPacket.writeTo(ctx, envelope.Payload, net.UDPAddrFromAddrPort(remote))
		if err != nil {
			return err
		}
		if written != len(envelope.Payload) {
			return fmt.Errorf("l3session: short UDP egress write: %d of %d", written, len(envelope.Payload))
		}
		if readErr != nil {
			return readErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func (r *UDPPeerRelay) forwardUDPReplies(
	ctx context.Context,
	rendrPacket *dataPlanePacket,
	egressPacket *dataPlanePacket,
	remote netip.AddrPort,
	bufferSize int,
) error {
	buf := make([]byte, bufferSize)
	for {
		n, source, readErr := egressPacket.readFrom(ctx, buf)
		if n < 0 || n > len(buf) {
			return errors.Join(readErr, fmt.Errorf("l3session: invalid UDP egress reply read count %d", n))
		}
		if n == 0 && readErr != nil {
			return readErr
		}
		if !packetSourceMatches(source, remote) {
			if readErr != nil {
				return readErr
			}
			continue
		}
		written, err := rendrPacket.writeTo(ctx, buf[:n], nil)
		if err != nil {
			return err
		}
		if written != n {
			return fmt.Errorf("l3session: short rendr UDP reply write: %d of %d", written, n)
		}
		if readErr != nil {
			return readErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func packetSourceMatches(source net.Addr, expected netip.AddrPort) bool {
	actual, actualOK := canonicalUDPAddr(source)
	expected, expectedOK := canonicalAddrPort(expected)
	if !actualOK || !expectedOK {
		return false
	}
	return actual == expected
}

func normalizeUDPPeerError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var callbackErr *CallbackError
	if errors.As(err, &callbackErr) {
		return err
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
