// Package lessons2 holds the scenario tests of lessons L16–L20 (design
// §11.4, WP11b): control credit when the window is full (L16), the
// application Write decoupled from carrier writes (L17), no-path episodes
// and their grace (L18), session loss only on deterministic signals (L19)
// and the redial loop (L20). The fixes of the M1b close (design §0.14) added
// the refusal cadence (B6, L18 and L20: g3_*), IdleTimeout counting
// delivery (B5, L19) and concurrent calls in a bubble (B12, L41: g7_*), and
// the selector failover against a passive that still holds the lost
// carrier (integ_d27_test.go, L18).
//
// Every test runs two Runtimes built with testhooks.NewRuntime inside a
// testing/synctest bubble, joined by rendrtest.Links created in that
// bubble, and asserts the stimulus (link and status counters), the load
// reached and the integrity of the delivered bytes. The package has no
// production code.
package lessons2
