// Package lessons1 holds the lesson scenario tests for L01–L15 (design
// §11.4, WP11 rows): two Runtimes built with testhooks.NewRuntime and joined
// by rendrtest.Links inside testing/synctest bubbles, driven only through
// the public rendr API. Every scenario asserts that its stimulus happened
// (link, tap or Status counters), that its load was reached, and that the
// data arrived intact (PRNG verification or SHA-256). Carrier conns are
// wrapped in wire taps that parse the frames each side writes and reads, so
// the tests can name the carrier a FIN, ACK, SCHED or RST travelled on and
// inject faults at exact frames. The package has no production code.
package lessons1
