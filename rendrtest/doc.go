// Package rendrtest provides in-memory fault-injecting stream carriers,
// far-end behaviours, a strict integrity verifier and leak assertions for
// testing rendr and code that embeds it.
//
// Everything works inside testing/synctest bubbles: links are built from
// net.Pipe, channels and timers created by the caller, and Link.Close joins
// every goroutine a link started. The package imports only the standard
// library and rendr's wire codec (it never imports package rendr), so
// rendr's own package-internal tests can use it.
//
// Stimulus proofs: every fault control has a counter, split into all
// carriers and session carriers (a carrier is classified by its first frame
// after the PREFACE: OPEN or JOIN = session, PING = probe), so a test can
// prove that a fault actually touched a session (L60, L63).
package rendrtest
