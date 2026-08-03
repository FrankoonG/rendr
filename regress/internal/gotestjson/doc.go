// Package gotestjson runs go test with JSON output and validates the event
// stream against an explicit list of expected top-level tests.
//
// The package is intentionally fail-closed. A successful command is not
// sufficient: every expected test must run and reach a terminal event, and a
// skipped test fails unless its expectation explicitly permits skipping.
package gotestjson
