// Package scenario holds rendr's scenario tests: the M1a fixture
// (fixture_test.go, the only file that touches the rendr API) with its
// in-memory links built on rendrtest, and the 20 scenario tests moved from
// internal/msess with their bodies unchanged. They run on real time, two
// Runtimes per test. The lesson-tagged scenario tests live in the
// subpackages lessons1 to lessons4, split by lesson range. The package has
// no production code.
package scenario
