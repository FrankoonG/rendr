// Package lessons4 holds rendr's lesson scenario tests L32–L61 (design
// §11.4, the WP11 rows of L32, L33, L34, L42, L43, L45, L52, L53, L60 and
// L61): two Runtimes built with testhooks.NewRuntime, joined by
// rendrtest.Links inside testing/synctest bubbles, driven only through the
// public API. Every scenario proves that its stimulus happened (link,
// status and frame counters), that the load was reached, and that the data
// arrived intact (PRNG verification). The package has no production code.
package lessons4
