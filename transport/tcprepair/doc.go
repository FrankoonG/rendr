// Package tcprepair productizes the M3 spike: server-side TCP socket
// migration via Linux TCP_REPAIR. The package is Linux-only by build
// tag; non-Linux GOOS gets a stub that errors on any call.
//
// What the package provides
//
//   - Snapshot(*net.TCPConn) (*State, error): capture all TCP state
//     (snd_nxt, rcv_nxt, send/recv queue contents, TCP_INFO,
//     TCP_TIMESTAMP, TCP_REPAIR_WINDOW) without disturbing the
//     ongoing connection. Toggles TCP_REPAIR on/off internally.
//   - Restore(*State) (int, error): build a new socket on the same
//     5-tuple, restore SEQ/ACK + queues + window, exit TCP_REPAIR.
//     Returns the file descriptor; caller wraps via os.NewFile +
//     net.FileConn.
//
// # What is NOT yet provided
//
// Production integration with rendr's path migration machinery is
// the follow-up M3-prod-stage-2 work — see docs/tcp-migration.md.
// Specifically:
//
//   - Only an iptables-backed migration window is provided today.
//     PathConn.MigratePathLocalAddr installs temporary DROP rules
//     around the snapshot/restore window; nftables/conntrack policy
//     backends are follow-up work.
//   - Server-side only. The client socket is untouched. Symmetric
//     client-side TCP_REPAIR (for true two-end migration) is a
//     larger design; see docs/tcp-migration.md "对称迁移".
//   - Same 5-tuple. Restoring to a DIFFERENT local addr is what
//     enables real network migration (wifi→cellular); not in
//     v0.1.0 scope.
//   - Single process. The snapshot lives in-memory; surviving a
//     server-process crash needs persistence to disk + a recovery
//     handshake. Out of scope.
//
// Requires Linux ≥ 3.5 (TCP_REPAIR was added in kernel 3.5). Caller
// must hold CAP_NET_ADMIN (scripts/regress.sh's docker
// --cap-add=NET_ADMIN provides it).
package tcprepair
