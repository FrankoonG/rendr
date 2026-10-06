// Package rendrtest provides in-memory fault-injecting carriers, far-end
// behaviours, strict integrity verifiers and leak assertions for testing
// rendr and code that embeds it.
//
// A Link is a stream path: every Dial creates a carrier from two net.Pipe
// pairs joined by pumps. Each direction holds up to LinkConfig.Buffer bytes
// that a Write returned for but the far end has not read; Kill loses them,
// as a broken connection loses what sat in its socket buffers, so a
// returned Write never proves delivery. Delay, jitter, a rate limit (one
// shared bottleneck per direction), blackhole and stall act on that buffer.
// A frame tracker per direction follows the PREFACE and the frame
// boundaries, so that faults can target single frames (corrupt, drop,
// inject, capture, splice) while every other byte passes untouched.
//
// A DatagramLink is a datagram path: every Dial creates a carrier, a pair
// of net.PacketConns with fake UDP addresses whose passive end goes to
// Listener.HandlePacket. Each direction applies delay and jitter, a rate
// limit (one shared bottleneck), seeded loss, duplication and reordering,
// an MTU, blackhole, stall and kill; one-shot controls find frames inside
// REL (DropNext, CaptureNext), and conn and factory misbehaviour test
// rendr's distrust of embedder conns. A DatagramHub is a shared passive
// socket for FromPacketConn whose clients add and strip the raw-UDP flow
// header, with Rebind, Spoof, Replay and Flood. PacketGen, PacketEcho,
// PacketSink and PacketVerifier send and check test datagrams.
//
// Everything works inside testing/synctest bubbles: links and hubs are
// built from net.Pipe, mutex-guarded queues, channels and timers created
// by the caller, and their Close joins every goroutine they started. The
// package imports only the standard library and rendr's wire codec (it
// never imports package rendr), so rendr's own package-internal tests can
// use it.
//
// Stimulus proofs: every fault control has a counter, split into all
// carriers, session carriers and probe carriers, so a test can prove that a
// fault actually touched a session. A stream carrier is classified by its
// first frame after the PREFACE (OPEN or JOIN = session, PING = probe), a
// datagram carrier by its dialer's first datagram (PREFACE ‖ REL{OPEN or
// JOIN} = session, PREFACE ‖ PING = probe).
package rendrtest
