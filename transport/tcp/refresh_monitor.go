package tcp

type pathRefreshMonitor interface {
	Stop()
	Done() <-chan struct{}
	Commit([32]byte)
}
