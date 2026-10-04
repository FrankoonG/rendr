// Package lessons3 holds rendr's scenario tests for lessons L21–L30 (design
// §11.4, AA3): stale carrier incarnations (L21), carrier joining and
// rejoining (L22), the three death causes and receiver-side drop detection
// (L24, L25), synchronous death failover (L27), the selector self-load guard
// (L29, design §8) and traffic-pattern trigger discipline (L30).
//
// Every test builds two Runtimes with testhooks.NewRuntime, joined by
// rendrtest Links created inside the testing/synctest bubble that uses them,
// and asserts that its stimulus happened, that its load was reached and that
// the data arrived intact. The package has no production code.
//
// Reproductions of open product findings live in findings_test.go behind
// the rendr_findings build tag: they fail on the current code by design and
// run only with go test -tags rendr_findings.
package lessons3
