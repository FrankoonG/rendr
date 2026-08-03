package tunfull

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/l3ingress"
)

type tunG3PayloadHandler struct {
	observe func([]byte)
}

// tunG3PeerPacketConn is the embedding-owned UDP egress used by the synthetic
// TUN G3 fixture. Writes have already traversed the production peer relay and
// therefore contain application payload rather than rendr's L3 envelope.
type tunG3PeerPacketConn struct {
	bootstrap      chan []byte
	bootstrapCount atomic.Int64
	handler        atomic.Pointer[tunG3PayloadHandler]
	done           chan struct{}
	readDeadline   chan struct{}
	closeOnce      sync.Once
	deadlineOnce   sync.Once
}

func newTunG3PeerPacketConn() *tunG3PeerPacketConn {
	c := &tunG3PeerPacketConn{
		bootstrap:    make(chan []byte, 1),
		done:         make(chan struct{}),
		readDeadline: make(chan struct{}),
	}
	c.handler.Store(&tunG3PayloadHandler{observe: func(payload []byte) {
		if c.bootstrapCount.Add(1) == 1 {
			c.bootstrap <- append([]byte(nil), payload...)
		}
	}})
	return c
}

func (c *tunG3PeerPacketConn) setObserver(observe func([]byte)) {
	c.handler.Store(&tunG3PayloadHandler{observe: observe})
}

func (c *tunG3PeerPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	select {
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-c.readDeadline:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *tunG3PeerPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	handler := c.handler.Load()
	if handler == nil || handler.observe == nil {
		return 0, errors.New("tunfull: G3 peer egress has no payload observer")
	}
	handler.observe(payload)
	return len(payload), nil
}

func (c *tunG3PeerPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}

func (c *tunG3PeerPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *tunG3PeerPacketConn) SetDeadline(deadline time.Time) error {
	return c.SetReadDeadline(deadline)
}

func (c *tunG3PeerPacketConn) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		return nil
	}
	delay := time.Until(deadline)
	if delay <= 0 {
		c.deadlineOnce.Do(func() { close(c.readDeadline) })
		return nil
	}
	time.AfterFunc(delay, func() {
		c.deadlineOnce.Do(func() { close(c.readDeadline) })
	})
	return nil
}

func (c *tunG3PeerPacketConn) SetWriteDeadline(time.Time) error { return nil }

type tunG3PeerEgress struct {
	mu       sync.Mutex
	conn     *tunG3PeerPacketConn
	dials    int
	identity l3ingress.L3Identity
}

func (e *tunG3PeerEgress) DialTCP(context.Context, l3ingress.L3Identity) (net.Conn, error) {
	return nil, errors.New("tunfull: G3 peer egress only supports UDP")
}

func (e *tunG3PeerEgress) DialUDP(
	_ context.Context,
	id l3ingress.L3Identity,
) (net.PacketConn, netip.AddrPort, error) {
	e.mu.Lock()
	e.dials++
	e.identity = id
	e.mu.Unlock()
	return e.conn, netip.MustParseAddrPort("127.0.0.1:9"), nil
}

func (e *tunG3PeerEgress) snapshot() (int, l3ingress.L3Identity) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dials, e.identity
}

type tunG3Collector struct {
	recvBmp    []uint8
	payloadLen int
	sendEpoch  time.Time
	outcome    tunG3ReceiveOutcome
	processed  atomic.Int64
	delivered  atomic.Int64
}

func newTunG3Collector(expected, payloadLen int, sendEpoch time.Time) *tunG3Collector {
	return &tunG3Collector{
		recvBmp:    make([]uint8, expected),
		payloadLen: payloadLen,
		sendEpoch:  sendEpoch,
		outcome: tunG3ReceiveOutcome{
			latencies: make([]time.Duration, 0, expected/tunG3LatencySampleEvery+8),
		},
	}
}

func (c *tunG3Collector) observe(payload []byte) {
	defer c.processed.Add(1)
	if len(payload) != c.payloadLen {
		c.outcome.malformedPackets++
		return
	}
	seq := binary.BigEndian.Uint64(payload[:8])
	if seq >= uint64(len(c.recvBmp)) {
		c.outcome.outOfRangePackets++
		return
	}
	if marker := binary.BigEndian.Uint64(payload[len(payload)-8:]); marker != seq^tunG3PacketIntegrityMask {
		c.outcome.corruptPackets++
		return
	}
	if c.recvBmp[seq] != 0 {
		c.outcome.duplicatePackets++
		return
	}
	c.recvBmp[seq] = 1
	if seq%tunG3LatencySampleEvery == 0 {
		sentElapsed := time.Duration(binary.BigEndian.Uint64(payload[8:16]))
		latency := time.Since(c.sendEpoch) - sentElapsed
		if latency < 0 {
			c.outcome.corruptPackets++
		} else {
			c.outcome.latencies = append(c.outcome.latencies, latency)
		}
	}
	c.outcome.uniquePackets++
	c.delivered.Store(c.outcome.uniquePackets)
}

func (c *tunG3Collector) deliveredPackets() int64 { return c.delivered.Load() }

func (c *tunG3Collector) processedPackets() int64 { return c.processed.Load() }

// snapshot is called only after the peer relay has stopped, which gives a
// happens-before edge for all non-atomic outcome fields.
func (c *tunG3Collector) snapshot() tunG3ReceiveOutcome {
	out := c.outcome
	out.latencies = append([]time.Duration(nil), c.outcome.latencies...)
	return out
}

var _ net.PacketConn = (*tunG3PeerPacketConn)(nil)
var _ l3ingress.Egress = (*tunG3PeerEgress)(nil)
