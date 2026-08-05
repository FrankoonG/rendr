package rendr

// These aggregates keep package-local historical tests concise. They are not
// part of the production API; external callers compose only the narrow
// interfaces they actually need.
type testConnectionControl interface {
	Conn
	MigrationController
	PathController
	ConnectionObserver
}

type testPacketConnectionControl interface {
	PacketConn
	MigrationController
	PathController
	ConnectionObserver
}
