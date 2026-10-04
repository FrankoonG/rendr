package rendrtest

import (
	"net"
	"sync/atomic"
)

// Behaviour is a far-end application handler run on the passive end of a
// session (any net.Conn). It returns its own verdict: nil when it behaved
// as specified. Behaviours use CloseWrite through the optional interface
// { CloseWrite() error } of the conn they are given.
type Behaviour func(c net.Conn) error

// Echo copies everything it reads back until EOF, then CloseWrite, drains
// until the read side ends, and closes.
func Echo() Behaviour {
	panic("unimplemented: M1b")
}

// Gen writes n bytes of PRNG(seed) while discarding anything it reads, then
// closes; it returns when a Write fails or the n bytes were written.
func Gen(n int64, seed uint64) Behaviour {
	panic("unimplemented: M1b")
}

// Sink reads and counts into count until EOF, then closes.
func Sink(count *atomic.Int64) Behaviour {
	panic("unimplemented: M1b")
}

// Stall reads until EOF, then holds the conn open without answering until
// release is closed, then closes.
func Stall(release <-chan struct{}) Behaviour {
	panic("unimplemented: M1b")
}

// HalfCloseCheck (L04) reads exactly want bytes of PRNG(seed) followed by
// io.EOF, then writes reply bytes of PRNG(seed+1) and CloseWrite, then
// closes. Any deviation is its error.
func HalfCloseCheck(want int64, seed uint64, reply int64) Behaviour {
	panic("unimplemented: M1b")
}
