// Package rendr provides connection-preserving migration for Go streams and
// packet connections.
//
// A Runtime accepts one root Target graph per SessionConfig. Path constructs leaves, while
// Selector, Race, and Bond compose leaves or other groups. Selector keeps one
// immediate child active, Race sends through every eligible child, and Bond
// aggregates frames across its children.
//
//	runtime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
//	if err != nil {
//		return err
//	}
//	err = runtime.RegisterStreamFactory("edge-tcp", rendr.StreamFactory{
//		Carrier: rendr.CarrierTCP,
//		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
//			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
//		},
//	})
//	if err != nil {
//		return err
//	}
//	root := rendr.Selector("root", []rendr.Target{
//		rendr.Path("primary", rendr.PathSpec{Transport: "edge-tcp", Address: "host-a:443"}),
//		rendr.Path("backup", rendr.PathSpec{Transport: "edge-tcp", Address: "host-b:443"}),
//	})
//	c, err := runtime.Dial(ctx, rendr.SessionConfig{Root: root})
//
// Dial and DialPacket return net.Conn and net.PacketConn compatible values.
// Transport failure is handled below those interfaces: migration does not
// surface reset, zero-read, or write errors to the application while the
// migration budget remains available. Clean application close remains distinct
// from transport death.
//
// The normal connection interfaces expose path and status snapshots. Optional
// narrow MigrationController, PathController, and ConnectionObserver
// interfaces expose only the control or telemetry capability an embedder
// requests. Runtime mobility is planned from factual carrier capabilities;
// callers select targets, not socket migration backends.
package rendr
