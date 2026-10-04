// Package session implements one rendr stream session: the passive stream
// state (chunked send buffer with reserve/copy/commit, retransmit spans,
// receive queue with bounded reorder, window and memory pressure, ACK/FIN/
// DONE, Close/linger/RST, deadlines, the application Read/Write/Close API),
// its lanes (one carrier.Endpoint per carrier), and the per-session
// scheduling actor that exclusively owns every control decision: lane roles
// and routing publication, the selector quality policy and failover race,
// bond membership and rescue, SCHED, the redial cadence, no-path episodes,
// termination and migration counting (L09).
//
// The data path (application copies, DATA, ACK, FIN, batch fills) never
// passes through the actor; the actor changes control state under the
// session lock in short O(carriers) steps and is woken by a coalescing
// mailbox. Carriers report facts by recording them in their own carrier.Conn
// and ringing the actor; the actor reconciles from the Conns it still holds,
// so a stale incarnation can never affect its successor (L21).
//
// Errors returned to applications are defined here and re-exported by
// package rendr so that errors.Is and errors.As match across the boundary.
package session
