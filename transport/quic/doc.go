// Package quic is the QUIC transport adapter.
//
// Per docs/udp-quic-migration.md: one QUIC connection corresponds to
// exactly one rendr PathConn. The adapter opens a single bidirectional
// stream on the QUIC connection and carries length-prefixed rendr
// frames over that stream (same framing as the TCP adapter). Stream
// boundaries from QUIC are NOT used for rendr frame boundaries -
// QUIC streams are byte-oriented just like TCP, so the 2-byte
// length prefix is still required.
//
// Path-layer migration in rendr remains "swap which PathConn is
// active". QUIC's own ConnID-based migration (RFC 9000 §9) handles
// intra-path UDP rebinding (e.g. NIC change) automatically through
// quic-go; rendr does not generally drive that machinery in M2.
//
// Hard rule #2 compliance: a quic-go ApplicationError /
// TransportError / IdleTimeoutError / HandshakeTimeoutError surfaces
// as DeathCause = TransportError; an orderly remote CloseWithError
// with a "clean" application code OR an inbound BYE (engine-level)
// is CleanClose.
package quic
