package l3session

import (
	"context"
	"errors"
	"fmt"
	"net"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

// TCPPeerRelay terminates one TUN-originated rendr stream, validates its
// versioned L3 identity envelope, and dispatches it to an embedding-provided
// TCP egress. Callers own Conn and may close it after Run returns.
type TCPPeerRelay struct {
	Conn       rendr.Conn
	Egresses   *l3ingress.EgressRegistry
	BufferSize int

	dataPlaneExecutor *dataPlaneCallbackExecutor
}

func (r *TCPPeerRelay) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("l3session: nil TCP peer context")
	}
	if r.Conn == nil {
		return errors.New("l3session: nil TCP peer Conn")
	}
	envelope, err := readTCPEnvelopeContext(ctx, r.Conn)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	stream, halfCloseOK := r.Conn.(l3ingress.TCPConn)
	if !halfCloseOK {
		statusErr := writeTCPReadyContext(ctx, r.Conn, tcpReadyHalfCloseUnsupported)
		return errors.Join(fmt.Errorf("%w: peer rendr stream %T", ErrTCPHalfCloseUnsupported, r.Conn), statusErr)
	}
	if err := l3ingress.RequirePeerEgress(r.Egresses != nil); err != nil {
		statusErr := writeTCPReadyContext(ctx, stream, tcpReadyEgressUnavailable)
		return errors.Join(err, statusErr)
	}
	cleanup, err := reserveDataPlaneCleanupWithExecutor(
		dataPlaneExecutorOrProcess(r.dataPlaneExecutor),
		"TCPPeerRelay egress Close",
	)
	if err != nil {
		statusErr := writeTCPReadyContext(ctx, stream, tcpReadyEgressUnavailable)
		return errors.Join(err, statusErr)
	}
	egress, err := r.Egresses.DialTCP(ctx, envelope.Egress, envelope.Identity)
	if err != nil {
		cleanup.Release()
		status := tcpReadyEgressDialFailed
		if _, ok := l3ingress.EgressErrorReasonOf(err); ok {
			status = tcpReadyEgressUnavailable
		}
		statusErr := writeTCPReadyContext(ctx, stream, status)
		return errors.Join(err, statusErr)
	}
	egressClose := cleanup.Bind(egress.Close)
	if err := writeTCPReadyContext(ctx, stream, tcpReadyOK); err != nil {
		return errors.Join(err, egressClose.Close())
	}
	return relayTCPWithCloseAuthorities(
		ctx,
		stream,
		egress,
		r.BufferSize,
		stream.Close,
		egress.Close,
		nil,
		egressClose,
	)
}

func readTCPEnvelopeContext(ctx context.Context, conn net.Conn) (tcpEnvelope, error) {
	stream := newDataPlaneStream(conn, "TCP peer envelope", conn.Close)
	stopInterrupt := context.AfterFunc(ctx, func() { _ = stream.interrupt() })
	defer stopInterrupt()
	envelope, err := invokeDataPlaneCallback(ctx, dataPlaneProcessExecutor, "TCP peer envelope Read", dataPlaneReadCallback,
		func() (tcpEnvelope, error) { return readTCPEnvelope(conn) })
	if err != nil && ctx != nil && ctx.Err() != nil {
		_ = stream.interrupt()
		return tcpEnvelope{}, ctx.Err()
	}
	return envelope, err
}

func writeTCPReadyContext(ctx context.Context, conn net.Conn, status tcpReadyStatus) error {
	wire, err := encodeTCPReady(status)
	if err != nil {
		return err
	}
	return writeAllContext(ctx, conn, wire)
}

var _ net.Conn = (rendr.Conn)(nil)
