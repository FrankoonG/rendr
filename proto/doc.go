// Package proto defines the rendr control-plane wire format.
//
// Every rendr frame on the wire carries an 8-byte header:
//
//		 0                   1                   2                   3
//		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//		|VER|T|F|       FLAGS         |          SEQ (low 16 bits)      |
//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//		|                     SEQ (high 32 bits)                         |
//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//	  VER 2 bits, current value 3
//	  T   1 bit, 0=DATA 1=CTRL
//	  F   1 bit, last-frame-of-message (reliable streams only)
//	  FLAGS 12 bits, mode-dependent; for CTRL frames the low 8 bits are
//	                 the control code (see Ctrl* constants).
//	  SEQ 48 bits, big-endian, monotonically increasing per-Conn,
//	               spanning both DATA and CTRL frames.
//
// Wire framing on a TCP byte-stream path prepends a 2-byte big-endian
// length to each frame. QUIC paths use one frame per STREAM/DATAGRAM
// and need no length prefix. The length prefix is the transport
// adapter's responsibility, not part of the Frame.
//
// Any change to bytes on the wire MUST bump Version. See CLAUDE.md
// hard rule #7.
package proto
