// Package l4 holds the scenarios of rendr's L4 TCP module (M4 design
// §A12.2, WP11): forwarded TCP connections — a client on a
// rendrtest.TargetPipe, the ingress l4.Forward on an l4.Dial Conn, an
// l4.Server on the passive whose Dial hook connects to rendrtest.Targets —
// through carrier kills, blackholes, migrations, rendr mux and race mode;
// the G1, G2 and G4 gold criteria of the L4 variants at reduced scale; a
// churn of 2,000 connections of every outcome class that must leave
// nothing behind (L52); the two msess target tests (plan:661: a stalled
// target released after the dialer's Close, an idle session that expires);
// an EarlyReturn refusal through l4 (L49); and the destination's single
// appearance on the wire, inside the OPEN (L37). The time-to-first-byte
// rows of EarlyReturn live in early_ttfb_test.go (the I2 integrator's file,
// R1-18).
//
// The scenarios run two Runtimes joined by rendrtest.Links inside
// testing/synctest bubbles and drive them only through the public API (rendr,
// l4, rendrtest); internal packages appear only as testhooks (Overrides and
// the session registry gauges). Every scenario proves that its stimulus
// happened (link and target counters, carrier and session status, events),
// that the load was reached, and that the data arrived intact
// (PRNG-verified bytes, target checksums), and leaves nothing behind after
// Runtime.Close. The package has no production code.
package l4
