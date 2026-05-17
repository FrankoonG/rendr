// Package rendr is a connection-migration framework: an application
// holds a stable net.Conn / net.PacketConn while rendr swaps the
// underlying network path underneath it without surfacing any error
// to the application.
//
// rendr does only this. It does not implement proxy protocols, mesh
// discovery, or configuration management; those belong to the embedder.
//
// The hard contract is in docs/success-criteria.md (G1-G5). An
// implementation that fails any of G1-G5 cannot claim completion.
package rendr
