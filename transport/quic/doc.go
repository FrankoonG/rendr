// Package quic is the QUIC transport adapter.
//
// One QUIC connection corresponds to exactly one rendr PathConn.
// The adapter opens a single bidirectional
// stream on the QUIC connection and carries length-prefixed rendr
// frames over that stream (same framing as the TCP adapter). Stream
// boundaries from QUIC are NOT used for rendr frame boundaries -
// QUIC streams are byte-oriented just like TCP, so the 2-byte
// length prefix is still required.
//
// Dialed paths own the quic-go connection and a bounded active/standby UDP
// transport pair. A factual route/source refresh automatically enters rendr's
// leaf-mobility transaction, which validates a private path with AddPath and
// Probe before Publish calls Switch on the same QUIC connection. Accepted
// endpoints provide peer evidence but never initiate unsupported server-side
// quic-go migration. There is no public mobility selector.
//
// Hard rule #2 compliance: a quic-go ApplicationError /
// TransportError / IdleTimeoutError / HandshakeTimeoutError surfaces
// as DeathCause = TransportError; an orderly remote CloseWithError
// with a "clean" application code OR an inbound BYE (engine-level)
// is CleanClose.
package quic
