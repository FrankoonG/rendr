// Package l4u holds the scenarios of rendr's L4 UDP module (M6 design
// §A16.2, WP9): UDP flows forwarded through an l4.PortForward ingress on a
// rendrtest.UDPSocketHub, one packet session per client source address, to
// an l4.Server{UDP: true} on the passive whose Dial hook gives every flow a
// rendrtest.DatagramPipe toward the target application. The rows are a
// Moonlight-like stream miniature per mode through carrier kills and a
// blackhole (L39, L40, L70); 64 flows failing over at once (L27); a
// DNS-like churn of one-shot flows that must leave nothing behind, under
// the rule in force and its DNS recipe (L48, L72); a flow churn in the
// tombstone-eviction regime with every OPEN duplicated on a second carrier
// (L47); the two size rows that need stream members, stream carriers only
// and a mixed bond (L37); two rules many views of one datagram MUX trunk
// must keep at once (mux_test.go: an idle end crosses, a reply written at
// Confirm arrives); a mixed bond's or race's start, where datagrams wider
// than the datagram member written while the stream member is joining are
// dropped, the limitation l4 documents (joining_test.go); and a bond
// member's silent death, through which the stream recovers within the
// death-detection bound (bonddrop_test.go).
//
// The scenarios run two Runtimes joined by rendrtest datagram and stream
// links inside testing/synctest bubbles and drive them only through the
// public API (rendr, l4, rendrtest); internal packages appear only as
// testhooks (Overrides and the session registry gauges). Every scenario
// proves that its stimulus happened (link and hub counters, carrier and
// session status, events, flow snapshots), that the load was reached, and
// that the datagrams arrived intact (rendrtest test datagrams, each
// checked by a PacketVerifier or the profile's own CRC), and leaves
// nothing behind after Runtime.Close. The rows run the promotion rule in
// force (l4's internal promoteRule, O-1 (a) since 2026-10-17): the other
// rule is not reachable from outside package l4, whose own rows cover it.
// The package has no production code.
package l4u
