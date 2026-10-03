// Package msess is the end-to-end multi-path session layer that rendr 2.0
// is built from: a dialer↔server byte stream (or datagram flow) carried over
// any number of carriers ("subflows") that survives carriers dying,
// degrading or being replaced, without losing, duplicating or reordering a
// byte.
//
// Provenance: this package is derived from hy2scale internal/msess at commit
// bfbd1e8 (same author, GPL-3.0). At this checkpoint (M1a, port parity) its
// behaviour is identical to that commit: only the package path, the package
// documentation and comments that described hy2scale-specific deployment
// details were changed. Its package-level tunables are kept as they were;
// they move to per-runtime configuration in a later checkpoint.
package msess
