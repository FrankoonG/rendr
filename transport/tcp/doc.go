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
//
// On Linux/amd64, owned dialer and listener endpoints include the sealed
// TCP_REPAIR driver, implementation provider, and route/source refresh monitor.
// Fresh endpoint, kernel, permission, tuple, quarantine, and peer-agreement
// checks still decide whether a leaf may use TCP_REPAIR; otherwise the
// negotiated framed redial/attach fallback remains authoritative. Generic Wrap
// connections and other platforms never acquire owned TCP_REPAIR authority.
package tcp
