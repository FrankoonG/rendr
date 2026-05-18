// Package udpflow is the opaque-UDP transport adapter.
//
// Each PathConn wraps a single (local UDP socket, remote endpoint)
// pair. Every outbound datagram carries an 8-byte UDPFlowHeader
// (proto.UDPFlowHeader) so the peer can route the datagram to the
// correct rendr engine by flow_id alone, independent of the
// originating 4-tuple. That is the migration primitive: the same
// flow_id arriving from a fresh 4-tuple becomes the new active
// path entry, and the application sees no change.
//
// Wire layout for one outbound datagram:
//
//	+--------+----------------+----------------+
//	|VER(1)  | FLOW_ID(7)     | rendr frame... |
//	+--------+----------------+----------------+
//
// where the trailing bytes are the proto.Header + payload the
// engine produced. The engine itself never sees the UDPFlowHeader -
// the adapter strips it before handing bytes to engine recv, and
// prepends it before transmit.
//
// Hard rule #2 compliance: a UDP socket errno (net.ErrClosed,
// ECONNREFUSED on ICMP unreach, syscall.EAGAIN if Read returns 0,
// ...) classifies as TransportError; BYE / quiesced EOF stay
// CleanClose. See transport.Classify.
//
// M5(2/n) ships the client-side adapter only. Server-side multiplex
// (one UDP socket fan-out into N per-flow engines) lands in M5(3/n).
package udpflow
