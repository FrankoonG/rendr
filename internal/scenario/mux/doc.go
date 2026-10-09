// Package mux holds rendr mux scenarios (M3 design §A11.2, WP13): the
// sessions of one Peer sharing the carriers of its factories (Props
// without CheapSubflow). It covers the mux lessons — L10 and L27 (a shared
// carrier's death requeues every session on it, also when a second
// carrier dies during the requeue), L15 and L16 (a session whose
// application stops reading never blocks the shared reader or its
// neighbours' control frames), L22 (rejoin after a DROP), L39 and L40
// (packet sessions on a shared datagram carrier), L52 (churn leaves
// nothing behind) — the pool's fast path and coalescing, the close at the
// last session, and the G4 and G5 gold criteria of the mux variants at
// reduced scale.
//
// The scenarios run two Runtimes joined by rendrtest.Links (stream) and
// rendrtest.DatagramLinks (packet) inside testing/synctest bubbles and
// drive them only through the public API; internal packages appear only as
// testhooks (Overrides, a hook and the session registry gauges). Every
// scenario proves that its stimulus happened (link counters, factory calls,
// carrier and session status, events), that the load was reached, and that
// the data arrived intact (PRNG-verified bytes, verified datagrams), and
// leaves nothing behind after Runtime.Close. The package has no production
// code.
package mux
