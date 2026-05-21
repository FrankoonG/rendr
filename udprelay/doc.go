// Package udprelay adapts self-managed UDP applications to rendr
// packet-mode connections.
//
// A Relay owns one local UDP socket and one rendr PacketConn. Packets
// read from UDP are forwarded over rendr; packets read from rendr are
// written back to UDP. When TargetAddr is set, rendr packets are sent
// to that fixed UDP target and target replies are forwarded back over
// rendr. When TargetAddr is empty, the relay learns the most recent
// local UDP peer and sends rendr replies back to that peer.
//
// This is the M11 foundation for applications that own their UDP
// sockets, such as tunnels or custom datagram protocols: point the
// application at Relay.LocalAddr(), and let rendr migrate the
// PacketConn paths underneath.
package udprelay
