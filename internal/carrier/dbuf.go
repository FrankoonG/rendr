package carrier

// NewDatagramBufPool returns the datagram buffer pool (M2-D28): the size
// classes 2 KiB, 4 KiB, … 64 KiB (each + ClassSlack) for datagram reader
// buffers, writer scratches and udpflow inbox buffers. The stream pool
// (NewBufPool) keeps its M1 classes (16 KiB … 1 MiB), so no stream buffer,
// charge or allocation gate changes. WP3c (wave 1; M2 design Revision 1,
// R1-20) makes the class layout a property of the pool instead of package
// constants; Buf and Release are shared.
func NewDatagramBufPool() *BufPool {
	panic("unimplemented: M2")
}
