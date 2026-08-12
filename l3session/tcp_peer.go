package l3session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

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
}

func (r *TCPPeerRelay) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("l3session: nil TCP peer context")
	}
	if r.Conn == nil {
		return errors.New("l3session: nil TCP peer Conn")
	}
	stopFirstRead := context.AfterFunc(ctx, func() { _ = r.Conn.SetReadDeadline(time.Now()) })
	envelope, err := readTCPEnvelope(r.Conn)
	stopFirstRead()
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
	egress, err := r.Egresses.DialTCP(ctx, envelope.Egress, envelope.Identity)
	if err != nil {
		status := tcpReadyEgressDialFailed
		if _, ok := l3ingress.EgressErrorReasonOf(err); ok {
			status = tcpReadyEgressUnavailable
		}
		statusErr := writeTCPReadyContext(ctx, stream, status)
		return errors.Join(err, statusErr)
	}
	defer egress.Close()
	if err := writeTCPReadyContext(ctx, stream, tcpReadyOK); err != nil {
		return err
	}
	return relayTCP(ctx, stream, egress, r.BufferSize)
}

func writeTCPReadyContext(ctx context.Context, conn net.Conn, status tcpReadyStatus) error {
	wire, err := encodeTCPReady(status)
	if err != nil {
		return err
	}
	return writeAllContext(ctx, conn, wire)
}

var _ net.Conn = (rendr.Conn)(nil)
