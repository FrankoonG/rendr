// Package xray provides the rendr-as-xray-transport binding.
//
// rendr is a transport-of-transports: it does not define a new wire
// protocol; it wraps existing xray transports (tcp / quic / mkcp /
// ws / grpc / h2) and adds the migration layer on top.
//
// The package exposes Config + Dialer + Listener (stream) and
// PacketListener (datagram) so embedders that import xray-core can
// wire rendr into the transport.internet.Dialer contract, and
// standalone embedders can use the API directly without an
// xray-core dependency.
package xray
