// Package xray provides the rendr-as-xray-transport binding.
//
// rendr is a transport-of-transports: it does not define a new wire
// protocol; it wraps existing xray transports (tcp / quic / mkcp /
// ws / grpc / h2) and adds the migration layer on top. See
// docs/xray-integration.md for the protobuf shape and X1-X7 sub-stages.
//
// M0 deliverable: an empty Go package and a checklist
// (xray/CHECKLIST.md) documenting every assumption the rendr core
// makes about the xray transport contract. The implementation lands
// no earlier than M9.
package xray
