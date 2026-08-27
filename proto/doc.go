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
//	  FLAGS 12 bits, frame-type-dependent. For CTRL frames the low 8 bits
//	                 are the control code (see Ctrl* constants). For DATA
//	                 under a PeakTransfer selector root, bits 0..9 are the
//	                 one-based immediate-child ordinal and bit 10 says the
//	                 selected child was effective at publication. Bit 11 says
//	                 the sender had sustained unacknowledged application demand.
//	                 DATA under every other root requires FLAGS=0.
//	  SEQ 48 bits, big-endian, monotonically increasing per-Conn,
//	               spanning both DATA and CTRL frames.
//
// Protocol minor 17 prefixes DATA under a PeakTransfer selector root with the
// sender's non-zero 8-byte selector generation. The receiver strips this prefix
// before application delivery, so stream bytes and packet boundaries are
// unchanged. Self-description preserves packet out-of-order delivery without a
// separate control-frame ordering dependency.
//
// Protocol minor 18 permits byte-exact policy transaction frames to enter a
// bounded control FIFO when received, before a lower DATA gap closes. The
// cumulative ACK proof and stream application-delivery frontier remain ordered
// by SEQ; packet sessions retain their documented out-of-order delivery.
//
// Protocol minor 19 binds every FINAL policy acknowledgement to a fresh,
// requester-generated challenge first disclosed by the matching COMMIT.
//
// Protocol minor 20 makes policy ACK wire version 4 mandatory. Every accepted
// PREPARE and FINAL carries the non-zero selector execution generation used by
// DATA root attribution. Requesters validate an unchanged target at the same
// generation and a changed target at exactly the next generation; older peers
// fail feature negotiation instead of being decoded under the new layout.
//
// Protocol minor 21 adds the mandatory SELECTOR_STATE control message. It
// publishes a canonical, complete selector vector bound to one session,
// sender direction, graph, and non-zero state epoch. Minor-20 peers cannot
// satisfy the mandatory feature contract and fail negotiation before state is
// allocated.
//
// Wire framing on a TCP byte-stream path prepends a 2-byte big-endian
// length to each frame. QUIC paths use one frame per STREAM/DATAGRAM
// and need no length prefix. The length prefix is the transport
// adapter's responsibility, not part of the Frame.
//
// Reassigning existing fields requires a mandatory protocol-minor feature;
// changing the frame envelope bytes requires bumping Version.
package proto
