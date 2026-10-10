// Package timers holds rendr's scenarios of the Runtime-level timers (M3
// design §A8, §A11.2, WP12; plan:566, plan:649; L09, L52): a session's
// actor runs on demand and parks on one Go runtime timer after a second
// without work, so idle sessions hold no goroutine, wake for traffic and
// for their deadlines, and stay parked while the Peer's probes publish
// health snapshots (R1-22).
//
// The scenarios run two Runtimes joined by rendrtest.Links inside
// testing/synctest bubbles and drive them only through the public API;
// internal packages appear only as testhooks (Overrides, the AtPark hook
// and the session registry gauges). Every scenario proves its premise
// (sessions parked, traffic sent, probes published), its load (the
// session population) and the delivered bytes, and leaves nothing behind
// after Runtime.Close. The package has no production code.
package timers
