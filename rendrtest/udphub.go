package rendrtest

import (
	"net"
	"net/netip"
	"os"
	"time"
)

// UDPSocketHubConfig configures NewUDPSocketHub.
type UDPSocketHubConfig struct {
	Addr  netip.AddrPort // the socket's LocalAddr (loopback by default)
	Queue int            // datagrams buffered per client and direction (256)
	Seed  uint64         // reserved: the hub draws no randomness (it has no loss, duplication or delay)
}

// dpHubAddr is a hub socket's default LocalAddr.
var dpHubAddr = netip.MustParseAddrPort("127.0.0.1:40000")

// UDPSocketHub is an in-memory UDP "port": Socket is an unconnected socket
// with l4.UDPSocket's method set plus RemoteAddr (always nil); Client
// returns a connected client whose datagrams reach the socket with source
// src and which receives what the socket writes to src; a closed client's
// src may be used again by a later Client call (a stub resolver reusing a
// source port). Deterministic, bounded, synctest-safe.
//
// The socket reads the clients' datagrams in the order they were written,
// each with its client's source exactly as given to Client, and writes to
// exactly the client whose source equals the address (no IPv4-mapped
// matching). Each client's datagrams toward the socket, and the socket's
// toward each client, are bounded by Queue: beyond it, and toward a closed
// socket, a datagram is dropped and counted (the hub's Dropped toward the
// socket, the client's Dropped toward a client). A datagram the socket
// writes to a source without a live client is lost, as UDP to a closed
// port: the write succeeds and the source's Dropped counts it. A client is
// a DatagramConn with the pipe's deadlines, injections and counters
// (TruncLinux; no loss, duplication or delay); the socket truncates as a
// Linux socket does (n = len(b), the rest discarded).
type UDPSocketHub struct {
	dpNet
	queue   int
	sock    HubSocket
	clients map[netip.AddrPort]*DatagramConn // the live clients
	hist    map[netip.AddrPort]DatagramConnCounts
	dropped uint64 // toward the socket
	reads   uint64
	writes  uint64
	rerr    error // the injected socket read error, for the next rleft reads
	rleft   int
}

// NewUDPSocketHub returns a hub configured by cfg.
func NewUDPSocketHub(cfg UDPSocketHubConfig) *UDPSocketHub {
	h := &UDPSocketHub{queue: cfg.Queue, clients: map[netip.AddrPort]*DatagramConn{},
		hist: map[netip.AddrPort]DatagramConnCounts{}}
	if h.queue <= 0 {
		h.queue = defaultDpQueue
	}
	addr := cfg.Addr
	if !addr.IsValid() {
		addr = dpHubAddr
	}
	h.sock = HubSocket{h: h, laddr: net.UDPAddrFromAddrPort(addr)}
	h.sock.rx.cond.L = &h.mu
	return h
}

// Socket returns the hub's unconnected socket.
func (h *UDPSocketHub) Socket() *HubSocket { return &h.sock }

// Client returns a connected client with source address src: its
// LocalAddr is src, its RemoteAddr the socket's address. It panics when src
// is invalid or already has a live client (two sockets cannot share one
// source address).
func (h *UDPSocketHub) Client(src netip.AddrPort) *DatagramConn {
	if !src.IsValid() {
		panic("rendrtest: UDPSocketHub.Client: invalid source address")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients[src] != nil {
		panic("rendrtest: UDPSocketHub.Client: " + src.String() + " already has a live client")
	}
	c := &DatagramConn{n: &h.dpNet, hub: h, src: src, laddr: net.UDPAddrFromAddrPort(src), raddr: h.sock.laddr}
	c.rx.cond.L = &h.mu
	h.clients[src] = c
	return c
}

// fromClient queues datagram b of client c toward the socket. h.mu held.
func (h *UDPSocketHub) fromClient(c *DatagramConn, b []byte) {
	if h.sock.closed || c.up >= h.queue {
		h.dropped++
		return
	}
	c.up++
	h.sock.rx.push(dpItem{b: h.clone(b), src: c.src, from: c})
	h.sock.rx.cond.Broadcast()
}

// leave removes the closed client c: its queued datagrams are dropped and
// counted, its counters kept under its source. Its datagrams already
// queued toward the socket stay there. h.mu held.
func (h *UDPSocketHub) leave(c *DatagramConn) {
	c.ctr.Dropped += c.rx.drain(&h.dpNet)
	if h.clients[c.src] == c {
		delete(h.clients, c.src)
	}
	h.hist[c.src] = h.hist[c.src].plus(c.ctr)
}

// InjectRead makes the socket's next n reads return err (ICMP-class noise,
// WSAECONNRESET). The error is returned as given, with n = 0 and no
// address, consumes no datagram and wakes a waiting read; a nil err or an
// n below 1 clears an earlier injection. A passed read deadline and Close
// take precedence, as on a real socket. The hub does not count injected
// reads: a test that counts the reader's calls wraps the socket.
func (h *UDPSocketHub) InjectRead(err error, n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil || n < 1 {
		err, n = nil, 0
	}
	h.rerr, h.rleft = err, n
	h.sock.rx.cond.Broadcast()
}

// Counts returns the hub's counters.
func (h *UDPSocketHub) Counts() HubCounts {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := make(map[netip.AddrPort]DatagramConnCounts, len(h.hist)+len(h.clients))
	for src, v := range h.hist {
		m[src] = v
	}
	for src, c := range h.clients {
		m[src] = m[src].plus(c.ctr)
	}
	return HubCounts{Clients: m, Dropped: h.dropped, Reads: h.reads, Writes: h.writes}
}

// HubCounts are a UDPSocketHub's counters.
type HubCounts struct {
	Clients       map[netip.AddrPort]DatagramConnCounts // per client source: In (from the socket), Out (to the socket), Dropped toward it
	Dropped       uint64                                // datagrams toward the socket dropped (a full queue, or a closed socket)
	Reads, Writes uint64                                // the socket's reads and writes that moved a datagram
}

// HubSocket is a UDPSocketHub's unconnected socket: l4.UDPSocket's method
// set plus RemoteAddr, which returns nil.
type HubSocket struct {
	h      *UDPSocketHub
	rx     dpQueue // the clients' datagrams
	laddr  net.Addr
	closed bool
}

func (s *HubSocket) opErr(op string, addr net.Addr, err error) error {
	return &net.OpError{Op: op, Net: "udp", Source: s.laddr, Addr: addr, Err: err}
}

// ReadFromUDPAddrPort returns the next datagram from any client and its
// source address. It checks, in order: Close, the read deadline, an
// injected error (which consumes no datagram), then the next datagram;
// otherwise it waits for one of them.
func (s *HubSocket) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	h := s.h
	h.mu.Lock()
	defer h.mu.Unlock()
	q := &s.rx
	for {
		now := time.Now()
		switch {
		case s.closed:
			return 0, netip.AddrPort{}, s.opErr("read", nil, net.ErrClosed)
		case q.expired(now):
			return 0, netip.AddrPort{}, s.opErr("read", nil, os.ErrDeadlineExceeded)
		case h.rleft > 0:
			err := h.rerr
			if h.rleft--; h.rleft == 0 {
				h.rerr = nil
			}
			return 0, netip.AddrPort{}, err
		case q.ready(now):
			it := q.pop()
			it.from.up--
			k := copy(b, it.b)
			h.reads++
			h.recycle(it.b)
			return k, it.src, nil
		}
		q.wait(now)
	}
}

// WriteToUDPAddrPort sends b as one datagram to the client at addr. It
// never blocks; it fails only after Close or for an invalid addr.
func (s *HubSocket) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	h := s.h
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case s.closed:
		return 0, s.opErr("write", nil, net.ErrClosed)
	case !addr.IsValid():
		return 0, s.opErr("write", nil, errMissingAddress)
	}
	h.writes++
	switch c := h.clients[addr]; {
	case c == nil:
		r := h.hist[addr]
		r.Dropped++
		h.hist[addr] = r
	case c.rx.n >= h.queue:
		c.ctr.Dropped++
	default:
		c.rx.push(dpItem{b: h.clone(b)})
		c.rx.cond.Broadcast()
	}
	return len(b), nil
}

// LocalAddr returns the socket's address (UDPSocketHubConfig.Addr).
func (s *HubSocket) LocalAddr() net.Addr { return s.laddr }

// RemoteAddr returns nil: the socket is unconnected.
func (s *HubSocket) RemoteAddr() net.Addr { return nil }

// SetReadDeadline sets the read deadline, as net.Conn; a waiting read
// honours a new deadline at once.
func (s *HubSocket) SetReadDeadline(t time.Time) error {
	h := s.h
	h.mu.Lock()
	defer h.mu.Unlock()
	if s.closed {
		return s.opErr("set", nil, net.ErrClosed)
	}
	s.rx.setDeadline(t)
	return nil
}

// Close closes the socket; its later calls return net.ErrClosed. The
// clients' datagrams still queued toward it, and those they write later,
// are counted in the hub's Dropped. A second Close returns net.ErrClosed.
func (s *HubSocket) Close() error {
	h := s.h
	h.mu.Lock()
	defer h.mu.Unlock()
	if s.closed {
		return s.opErr("close", nil, net.ErrClosed)
	}
	s.closed = true
	h.dropped += s.rx.drain(&h.dpNet)
	return nil
}
