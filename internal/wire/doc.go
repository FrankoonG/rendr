// Package wire implements rendr wire format v2 for stream carriers: the
// 40-byte PREFACE and PREFACE_ACK, the frame header and CRC32C trailer, and
// the payload codec of every frame type an M1 stream session uses.
//
// Contracts shared by every function in this package:
//   - Put* functions write into caller memory and never allocate.
//   - Parse* and Decode* functions never panic, never write to their input,
//     never allocate, and check every length against the bytes actually
//     present before using it. Variable parts of a decoded value (metadata,
//     messages) alias the input; callers copy what they keep. DataEnd and
//     CheckPad (the DATA end and PING pad rules for a reader that does not
//     hold a payload contiguously) obey the same contract.
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
// The package has no state and does no I/O. Golden vectors live in
// testdata/; fuzz targets cover the preface, the header, every payload and
// a frame stream.
package wire
