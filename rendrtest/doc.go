// Package rendrtest provides in-memory fault-injecting stream carriers,
// far-end behaviours, a strict integrity verifier and leak assertions for
// testing rendr and code that embeds it.
//
// A Link is a path: every Dial creates a carrier from two net.Pipe pairs
// joined by pumps. Each direction holds up to LinkConfig.Buffer bytes that
// a Write returned for but the far end has not read; Kill loses them, as a
// broken connection loses what sat in its socket buffers, so a returned
// Write never proves delivery. Delay, jitter, a rate limit (one shared
// bottleneck per direction), blackhole and stall act on that buffer. A frame
// tracker per direction follows the PREFACE and the frame boundaries, so
// that faults can target single frames (corrupt, drop, inject, capture,
// splice) while every other byte passes untouched.
//
// Everything works inside testing/synctest bubbles: links are built from
// net.Pipe, channels and timers created by the caller, and Link.Close joins
// every goroutine a link started. The package imports only the standard
// library and rendr's wire codec (it never imports package rendr), so
// rendr's own package-internal tests can use it.
//
// Stimulus proofs: every fault control has a counter, split into all
// carriers, session carriers and probe carriers (a carrier is classified by
// its first frame after the PREFACE: OPEN or JOIN = session, PING = probe),
// so a test can prove that a fault actually touched a session.
package rendrtest
