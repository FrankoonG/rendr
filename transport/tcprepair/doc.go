// Package tcprepair provides a factual Linux TCP_REPAIR capability probe.
// Snapshot/restore primitives remain internal until rendr can wrap them in an
// owned, peer-negotiated, rollback-safe transaction.
//
// # Ownership and planning boundary
//
// This package deliberately does not register a transport and cannot be named
// by PathSpec. Calling Available does not select a rendr mobility
// implementation. Internal snapshot/restore may be used only for a raw TCP
// endpoint that rendr owned from session establishment and only after local
// eligibility and peer agreement have both succeeded.
//
// What is not yet provided:
//
//   - A planner-owned prepare/commit/rollback transaction around the
//     snapshot/restore window.
//   - Server-side only. The client socket is untouched. Symmetric
//     client-side TCP_REPAIR is required for true two-end migration.
//   - Same 5-tuple. Restoring to a DIFFERENT local addr is what
//     enables real network migration (wifi→cellular); it is not
//     currently supported.
//   - Single process. The snapshot lives in-memory; surviving a
//     server-process crash needs persistence to disk + a recovery
//     handshake. Out of scope.
//
// Requires Linux >= 4.5 for full TCP_REPAIR_WINDOW support (base
// TCP_REPAIR was added in kernel 3.5). Caller must hold
// CAP_NET_ADMIN; the private Linux regression environment verifies
// both privileged and permission-denied behavior. TCP_REPAIR failure does not
// imply that an existing kernel socket can be converted into a gVisor endpoint.
package tcprepair
