// Package rendr provides connection-preserving migration for Go streams and
// packet connections.
//
// A Dialer accepts one root Target graph. Path constructs leaves, while
// Selector, Race, and Bond compose leaves or other groups. Selector keeps one
// immediate child active, Race sends through every eligible child, and Bond
// aggregates frames across its children.
//
//	root := rendr.Selector("root", []rendr.Target{
//		rendr.Path("primary", rendr.PathSpec{Transport: "tcp", Address: "host-a:443"}),
//		rendr.Path("backup", rendr.PathSpec{Transport: "tcp", Address: "host-b:443"}),
//	})
//	c, err := (&rendr.Dialer{Root: root}).Dial(ctx)
//
// Dial and DialPacket return net.Conn and net.PacketConn compatible values.
// Transport failure is handled below those interfaces: migration does not
// surface reset, zero-read, or write errors to the application while the
// migration budget remains available. Clean application close remains distinct
// from transport death.
//
// The normal connection interfaces expose path and status snapshots. Optional
// narrow administrative interfaces provide explicit migration and path-set
// management for embedders and tests. Runtime mobility is planned from factual
// carrier capabilities; callers select targets, not socket migration backends.
package rendr
