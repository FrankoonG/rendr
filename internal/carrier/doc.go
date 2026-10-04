// Package carrier is rendr's carrier runtime: one Conn per carrier
// incarnation with exactly one reader goroutine and one batch-writer
// goroutine, fseq + CRC32C verification of every frame, the per-carrier
// estimator (srtt, minRTT, PONG-watermark rate, receive rate, capacity cap,
// death deadline, write-stall watchdog, backlog), carrier-level control
// (PING/PONG, CLOSE, GOAWAY), dialer-side establishment, passive-side
// handshake reading, the guarded embedder-call wrappers, the receive/send
// buffer pool and memory budget, and the Peer health layer (probe carriers,
// evidence publication, the self-load gauges).
//
// A session reaches a carrier only through the Endpoint interface declared
// here; this package never imports internal/session. That is the M3 seam: a
// mux carrier will dispatch to several endpoints by handle. Probe and
// passive sessionless carriers are ordinary Conns without an endpoint.
//
// Concurrency contract: a Conn calls its Endpoint only from its own reader
// and writer goroutines and never while holding its own lock; the Endpoint
// may call Conn accessors while holding the session lock (lock order:
// session.mu → Conn.mu). Facts about a carrier (death, peer CLOSE, peer
// GOAWAY) are recorded in the Conn and announced by ringing the owner's
// Doorbell; owners re-read them from the Conn objects they hold, so a fact
// of a dead incarnation can never reach its successor (L21).
package carrier
