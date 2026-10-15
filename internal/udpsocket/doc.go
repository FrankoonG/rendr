// Package udpsocket moves datagrams on rendr's own UDP sockets — the
// carrier/udp dialer sockets (carrier.OwnedUDP) and the carrier/udp Listen
// sockets that FromPacketConn adopts (carrier.OwnedUDPSocket) — several per
// system call where the platform allows it (M5 design §A4.2, plan:544).
//
// On Linux amd64 and arm64 a Conn in ModeBatch writes with sendmmsg and
// reads with recvmmsg through the socket's syscall.RawConn, so the Go
// netpoller and the deadlines keep their meaning. Every other target, a
// Conn in ModePlain and a call that moves one datagram use one
// WriteToUDPAddrPort or ReadMsgUDPAddrPort per datagram. A socket moves
// from ModeBatch to ModePlain at most once, when the kernel or a sandbox
// refuses the batch calls (M5-D15, Revision 1 R1-3); it never moves back.
//
// Datagram contents, order, the per-datagram error classification and the
// commit points are the caller's and are the same in both modes (L55,
// L23): WriteBatch reports how many datagrams left and the error of the
// first one that did not; ReadBatch reports each datagram's length,
// source and truncation. Counters count the calls that moved at least one
// datagram and the datagrams they moved (Revision 1 R1-2).
//
// Embedder sockets (net.PacketConn values rendr did not open) and the
// quic module's sockets never reach this package (L57, M5-D10, M5-D26);
// it imports the standard library and golang.org/x/sys/unix only, and
// never package carrier. The two reader call sites — the dialer carrier's
// batched reader (internal/carrier, dgread.go) and the owned Source's
// reader (internal/udpflow, demux.go) — are the only places a receive
// offload would be enabled, if one ships (M5 design §A5, conditional).
package udpsocket
