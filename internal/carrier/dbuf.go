package carrier

// NewDatagramBufPool returns the datagram buffer pool (M2-D28): the size
// classes 2 KiB, 4 KiB, … 64 KiB (each + ClassSlack) for datagram reader
// buffers, writer scratches and udpflow inbox buffers. The stream pool
// (NewBufPool) keeps its M1 classes (16 KiB … 1 MiB), so no stream buffer,
// charge or allocation gate changes. The class layout is a property of the
// pool (M2 design Revision 1, R1-20); Buf, Release and the Budget charges
// are shared: a Buf charges its class capacity and returns to the pool it
// came from. The largest datagram buffer — wire.MaxDatagram plus a raw-UDP
// flow header plus the truncation byte — fits the largest class; a Get
// above 64 KiB + ClassSlack panics (programming error).
func NewDatagramBufPool() *BufPool {
	return newBufPool(dgramLayout)
}
