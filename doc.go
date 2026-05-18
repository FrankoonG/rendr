// Package rendr is a connection-migration framework. An application
// holds a stable net.Conn whose underlying network path rendr can
// swap (TCP socket, QUIC connection, opaque-UDP flow) without
// surfacing any reset, EOF, or read-zero to the application.
//
// rendr does only this. It does not implement proxy protocols, peer
// discovery, configuration management, or path-quality probing
// policies beyond the built-in defaults; those belong to the
// embedder.
//
// # Quickstart
//
// Server:
//
//	ln, _ := rendr.ListenTCP("0.0.0.0:5555")
//	for {
//	    c, err := ln.Accept(context.Background())
//	    if err != nil { return }
//	    go handle(c) // c implements net.Conn
//	}
//
// Client:
//
//	d := &rendr.Dialer{
//	    Mode: rendr.ModePrime,
//	    Paths: []rendr.PathSpec{
//	        {Transport: "tcp",  Address: "h1:5555"},
//	        {Transport: "quic", Address: "h2:5555"},
//	    },
//	}
//	c, err := d.Dial(context.Background())
//	// c.Read / c.Write survive a path swap; c.FlowID() stays
//	// constant for the connection's lifetime.
//
// # Operational modes
//
// Three modes share the same migration engine. Set on Dialer.Mode
// or change at runtime via Conn.SetMode (subject to the legality
// rules below):
//
//   - ModePrime: pick the lowest-scoring path; migrate to a
//     better path only when it beats the current by Hysteresis
//     for Dwell, with Cooldown between switches. Quality is
//     scored as rtt + jitter + 10 ms per percent loss.
//   - ModeRace: every frame fans out to every attached path; the
//     receiver dedupes by SEQ. Bandwidth equals the best single
//     path; latency equals the minimum across paths. Tolerates
//     loss on individual paths.
//   - ModeBond: frames are round-robined across paths with N-frame
//     pinning to bound reorder windows under RTT skew. Bandwidth
//     approximates the sum of paths.
//
// Legal SetMode transitions:
//
//	prime <-> race   allowed
//	prime <-> bond   allowed
//	race  <-> bond   forbidden (race has no per-path order)
//
// # Acceptance contracts
//
// rendr is gated on five invariants (the implementation is not
// considered done until all five hold in chaos-scale tests):
//
//	G1 - large file (>= 1 GiB) with forced mid-stream migrations
//	     finishes with identical SHA-256 and < 10% baseline
//	     throughput regression
//	G2 - 30 min echo loop with 30+ migrations, zero loss, P99
//	     RTT < baseline x 2
//	G3 - 100k pps QUIC datagrams + 10 ConnID migrations, zero
//	     application loss, P95 RTT < baseline x 2
//	G4 - path A force-killed (network DROP) with path B intact;
//	     app sees no error; failover <= 5 s; in-flight data
//	     reaches the peer via path B
//	G5 - after G4, recover path A (via AdminConn.AddPath); it
//	     re-joins the path set without spurious reorder
//
// # AdminConn observability and control
//
// The public Conn returned by Dial / Accept also implements
// AdminConn (assert if you need it). AdminConn exposes path
// migration (Migrate, AddPath, ActivePath), mode read/write
// (Mode, inherited SetMode), lifecycle (State), and a one-call
// monitoring snapshot (Stats), plus the recv-queue HWM diagnostic
// (RecvQueueHWM) that flags race-mode dedup-window overflow.
//
// # Hard rules
//
//   - A migration in flight NEVER surfaces an error from the
//     application's Read or Write. Read may block during the
//     migration budget (default 90 s); after the budget elapses
//     with no usable path, Read returns ErrMigrationBudgetExceeded.
//   - Transport errors and application EOF are NEVER conflated.
//     A clean peer BYE surfaces as io.EOF; everything else
//     triggers migration.
//   - Default has NO active-migration trigger. Migration fires
//     only on path death or explicit ModePrime quality-scoring
//     decisions; quality scoring itself is OFF unless armed by
//     setting Mode=ModePrime on the Dialer.
//   - All wire formats are versioned (see package proto). Any
//     change to the bytes on the wire requires bumping the
//     version constant.
package rendr
