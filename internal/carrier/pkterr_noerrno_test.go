//go:build plan9 || wasip1

package carrier

// pktErrnoRows: no errno table on these platforms (pkterr_noerrno.go).
func pktErrnoRows() []pktErrRow { return nil }
