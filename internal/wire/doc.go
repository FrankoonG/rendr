// Package wire implements rendr wire format v2 for stream and datagram
// carriers: the 40-byte PREFACE and PREFACE_ACK, the frame header and
// CRC32C trailer, the payload codec of every frame type (the stream-session
// frames of M1; DGRAM and PACK of packet sessions, REL and RACK of the
// reliable control sublayer of datagram carriers in M2; DETACH of rendr
// mux in M3), the raw-UDP flow header, and the two receive windows of M2
// (FseqWindow, SeqWindow).
//
// M3 (rendr mux, race) adds no new encoding of an existing structure: the
// optional PREFACE bit OptMux (EchoOpt, MuxNegotiated), the carrier-level
// type DETACH 0x36, mode 3 (ModeRace) in OPEN and JOIN, the codes
// CodeDuplicateView, CodeMuxFull and CodeListenerClosed, and the handle
// rule "any non-zero handle on a session frame" (the carrier decides which
// handles it carries: SessionHandle only on a dedicated carrier).
//
// Contracts shared by every function in this package:
//   - Put* functions write into caller memory and never allocate.
//   - Parse* and Decode* functions never panic, never write to their input,
//     never allocate, and check every length against the bytes actually
//     present before using it. Variable parts of a decoded value (metadata,
//     messages, datagram bytes, a REL's inner payload, the rendr bytes
//     behind a flow header) alias the input; callers copy what they keep.
//     DataEnd and CheckPad (the DATA end and PING pad rules for a reader
//     that does not hold a payload contiguously) obey the same contract.
//   - Fixed-size payloads must be exactly their size; variable tails must be
//     described exactly by their explicit length field; trailing bytes,
//     undefined flag bits and non-zero reserved fields are rejected.
//     Extension frames (type ≥ 0x80) are opaque apart from their length.
//   - Every valid encoding is accepted by exactly one decoder and
//     decode(encode(x)) == x.
//
// Frame layout (big-endian):
//
//	type u8 | flags u8 | len u24 | fseq u32 | handle u32 | payload[len] | crc32c u32
//
// Datagram layout (M2): [flow header] ‖ [PREFACE | PREFACE_ACK] ‖ frame*,
// frames whole and filling the datagram exactly.
//
// The package does no I/O and holds no global state (the windows are
// values their owner keeps). Golden vectors live in testdata/; fuzz targets
// cover the preface, the header, every payload (DETACH included), REL
// nesting, the flow header, whole datagrams, a frame stream and both
// windows.
package wire
