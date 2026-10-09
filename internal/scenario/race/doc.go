// Package race holds rendr's race-mode scenarios (M3 design §A11.2, WP12):
// the G1, G2, G3, G4 and G5 gold criteria of the race variants at reduced
// scale, and the race lessons L08 (a slow member never drags a fast one),
// L39 (every datagram exactly once across member deaths) and the fate-group
// rule (one member per fate group, M3-D37).
//
// The scenarios run two Runtimes joined by rendrtest.Links (stream) or
// rendrtest.DatagramLinks (packet) inside testing/synctest bubbles and
// drive them only through the public API; internal packages appear only as
// testhooks (Overrides and the session registry gauges). Every scenario
// proves that its stimulus happened (link counters, carrier and session
// status, events), that the load was reached, and that the data arrived
// intact (PRNG-verified bytes, verified datagrams), and leaves nothing
// behind after Runtime.Close. The package has no production code.
package race
