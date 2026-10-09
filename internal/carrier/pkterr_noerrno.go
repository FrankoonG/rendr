//go:build plan9 || wasip1

package carrier

// packetErrnoClass: Plan 9 has no numeric errnos and WASI lacks part of the
// table, so there only ErrNoise, Temporary() and the deadline classify an
// embedder conn's error.
func packetErrnoClass(err error, write bool) (PacketErrClass, bool) {
	return 0, false
}
