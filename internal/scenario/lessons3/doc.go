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
// A reproduction of an open product finding, which fails on the current
// code by design, goes to findings_test.go behind the rendr_findings build
// tag and runs only with go test -tags rendr_findings; once its product fix
// lands it moves to the package's normal tests (design §0.13 Revision 8).
// None is open: the last one, TestDownloadGuardEdges_L29, moved to
// l29_test.go with the self-load guard's volume rule (§0.13 A7a).
package lessons3
