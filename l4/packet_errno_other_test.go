//go:build !unix && !plan9

package l4

// No errno symbols here (Windows, js, wasip1): the Windows numbers are in
// packet_errno_test.go's lists.
func pfSymNoise() []pfErrno { return nil }
func pfSymFatal() []pfErrno { return nil }
func pfSymSize() []pfErrno  { return nil }
