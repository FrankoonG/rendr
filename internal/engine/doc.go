// Package engine houses the rendr migration engine: bridge table,
// per-Conn state machine, cleanClose discrimination, zombie protection.
//
// This package is internal. The only public surface is the top-level
// rendr.Conn / rendr.PacketConn / rendr.Dialer / rendr.Listener,
// which wrap the engine.
//
// M0 publishes only the state-machine enums and the bridge-table
// shape; the actual implementation lands in M1.
package engine
