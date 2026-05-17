// Package tcp is the TCP byte-stream transport adapter.
//
// Each PathConn is a single TCP socket carrying length-prefixed rendr
// frames: 2-byte big-endian length followed by an 8-byte proto.Header
// and an opaque payload. The length covers header + payload only and
// is itself excluded.
//
// Hard rule #1 compliance: Read and Write surface only the framing
// errors. Underlying-socket failure is converted to a single OnDeath
// callback; subsequent Read/Write returns net.ErrClosed (the
// application never sees raw TCP RST through this path).
//
// Hard rule #2 compliance: io.EOF on a quiesced (peer-sent-BYE)
// stream is CleanClose; everything else is TransportError. See
// transport.Classify.
package tcp
