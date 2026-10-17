package rendrtest

import (
	"net"
	"net/netip"
	"time"
)

// UDPSocketHubConfig configures NewUDPSocketHub.
type UDPSocketHubConfig struct {
	Addr  netip.AddrPort // the socket's LocalAddr (loopback by default)
	Queue int            // datagrams buffered per client and direction (256)
	Seed  uint64
}

// UDPSocketHub is an in-memory UDP "port": Socket is an unconnected socket
// with l4.UDPSocket's method set plus RemoteAddr (always nil); Client
// returns a connected client whose datagrams reach the socket with source
// src and which receives what the socket writes to src; a closed client's
// src may be used again by a later Client call (a stub resolver reusing a
// source port). Deterministic, bounded, synctest-safe.
type UDPSocketHub struct{}

// NewUDPSocketHub returns a hub configured by cfg.
//
// Skeleton (M6 wave 0): not implemented yet; it panics.
func NewUDPSocketHub(cfg UDPSocketHubConfig) *UDPSocketHub {
	panic("rendrtest: NewUDPSocketHub not implemented")
}

// Socket returns the hub's unconnected socket.
func (h *UDPSocketHub) Socket() *HubSocket { panic("rendrtest: UDPSocketHub not implemented") }

// Client returns a connected client with source address src.
func (h *UDPSocketHub) Client(src netip.AddrPort) *DatagramConn {
	panic("rendrtest: UDPSocketHub not implemented")
}

// InjectRead makes the socket's next n reads return err (ICMP-class noise,
// WSAECONNRESET).
func (h *UDPSocketHub) InjectRead(err error, n int) {
	panic("rendrtest: UDPSocketHub not implemented")
}

// Counts returns the hub's counters.
func (h *UDPSocketHub) Counts() HubCounts { panic("rendrtest: UDPSocketHub not implemented") }

// HubCounts are a UDPSocketHub's counters.
type HubCounts struct {
	Clients       map[netip.AddrPort]DatagramConnCounts // per client source: In (from the socket), Out (to the socket), Dropped toward it
	Dropped       uint64                                // datagrams toward the socket dropped (a full queue)
	Reads, Writes uint64                                // the socket's reads and writes that moved a datagram
}

// HubSocket is a UDPSocketHub's unconnected socket: l4.UDPSocket's method
// set plus RemoteAddr, which returns nil.
type HubSocket struct{}

// ReadFromUDPAddrPort returns the next datagram from any client and its
// source address.
func (s *HubSocket) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	panic("rendrtest: HubSocket not implemented")
}

// WriteToUDPAddrPort sends b as one datagram to the client at addr.
func (s *HubSocket) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	panic("rendrtest: HubSocket not implemented")
}

// LocalAddr returns the socket's address (UDPSocketHubConfig.Addr).
func (s *HubSocket) LocalAddr() net.Addr { panic("rendrtest: HubSocket not implemented") }

// RemoteAddr returns nil: the socket is unconnected.
func (s *HubSocket) RemoteAddr() net.Addr { panic("rendrtest: HubSocket not implemented") }

// SetReadDeadline sets the read deadline, as net.Conn.
func (s *HubSocket) SetReadDeadline(t time.Time) error {
	panic("rendrtest: HubSocket not implemented")
}

// Close closes the socket; its later calls return net.ErrClosed.
func (s *HubSocket) Close() error { panic("rendrtest: HubSocket not implemented") }
