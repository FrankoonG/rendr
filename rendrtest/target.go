package rendrtest

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// TCP-like target fakes for package l4 and its scenario tests (M4 design
// §A2.4, M4-D49): an in-memory duplex with half-close and reset, target
// behaviours with counters, and scripted dial outcomes. Standard library
// only, synctest-safe. The dial functions take the address as a string,
// so rendrtest needs no l4 import; tests adapt them with a one-line
// closure.
//
// Not implemented yet: this is the M4 skeleton (WP3 implements it); every
// call returns errors.ErrUnsupported or a zero value.

// ErrReset is the error a TargetConn's Read and Write return after the
// other end reset the connection (SetLinger(0) then Close, or a Close with
// unread bytes). It matches syscall.ECONNRESET with errors.Is.
var ErrReset error = resetError{}

type resetError struct{}

func (resetError) Error() string        { return "rendrtest: connection reset by peer" }
func (resetError) Is(target error) bool { return target == errConnReset }

// TargetPipe returns the two ends of an in-memory TCP-like connection:
// Read and Write with a bounded buffer per direction (a writer blocks while
// the other end does not read), deadlines, CloseWrite (the other end reads
// io.EOF after the buffered bytes), Close, and SetLinger(0) followed by
// Close (the other end's Read and Write then return ErrReset, which
// matches syscall.ECONNRESET with errors.Is). As TCP: a Close after
// CloseWrite with nothing unread is invisible to the other end; a Close
// with unread bytes is a reset.
func TargetPipe(buf int) (client, server *TargetConn) {
	return &TargetConn{}, &TargetConn{} // M4 WP3
}

// TargetConn is one end of a TargetPipe: a net.Conn with CloseWrite and
// SetLinger.
type TargetConn struct {
	_ [0]func() // not comparable; WP3 adds the state
}

var _ net.Conn = (*TargetConn)(nil)

// Read implements net.Conn.
func (c *TargetConn) Read(p []byte) (int, error) { return 0, errors.ErrUnsupported }

// Write implements net.Conn.
func (c *TargetConn) Write(p []byte) (int, error) { return 0, errors.ErrUnsupported }

// Close implements net.Conn: with unread bytes, or after SetLinger(0), a
// reset of the other end.
func (c *TargetConn) Close() error { return errors.ErrUnsupported }

// CloseWrite half-closes: the other end reads io.EOF after the buffered
// bytes.
func (c *TargetConn) CloseWrite() error { return errors.ErrUnsupported }

// SetLinger(0) makes the next Close a reset (as *net.TCPConn).
func (c *TargetConn) SetLinger(sec int) error { return errors.ErrUnsupported }

// LocalAddr implements net.Conn.
func (c *TargetConn) LocalAddr() net.Addr { return targetAddr("target") }

// RemoteAddr implements net.Conn.
func (c *TargetConn) RemoteAddr() net.Addr { return targetAddr("target") }

// SetDeadline implements net.Conn.
func (c *TargetConn) SetDeadline(t time.Time) error { return errors.ErrUnsupported }

// SetReadDeadline implements net.Conn.
func (c *TargetConn) SetReadDeadline(t time.Time) error { return errors.ErrUnsupported }

// SetWriteDeadline implements net.Conn.
func (c *TargetConn) SetWriteDeadline(t time.Time) error { return errors.ErrUnsupported }

// targetAddr is a TargetConn's logical address.
type targetAddr string

func (a targetAddr) Network() string { return "rendrtest-target" }
func (a targetAddr) String() string  { return string(a) }

// Target serves the server ends of TargetPipes with one behaviour and
// counts Accepted, Open (now), FINIn, FINOut, RSTIn, RSTOut, BytesIn,
// BytesOut and the SHA-256 of each direction per connection.
type Target struct {
	_ [0]func() // WP3 adds the state
}

// NewTarget returns a Target whose connections run b, each direction
// buffering buf bytes.
func NewTarget(b TargetBehaviour, buf int) *Target {
	return &Target{} // M4 WP3
}

// Dial returns a new client end whose server end runs the Target's
// behaviour; addr is recorded, not used.
func (t *Target) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return nil, errors.ErrUnsupported // M4 WP3
}

// Counts returns a snapshot of the Target's counters.
func (t *Target) Counts() TargetCounts {
	return TargetCounts{} // M4 WP3
}

// TargetCounts is a Target's counters: totals over its connections (FIN
// and RST "In" as the target saw them from its client, "Out" as it sent
// them) and one record per connection in accept order.
type TargetCounts struct {
	Accepted, Open    int // connections accepted; open now
	FINIn, FINOut     int
	RSTIn, RSTOut     int
	BytesIn, BytesOut int64
	Conns             []TargetConnCounts
}

// TargetConnCounts is one connection of a Target.
type TargetConnCounts struct {
	Addr              string   // the address Dial was called with
	BytesIn, BytesOut int64    // bytes the target read and wrote
	SHAIn, SHAOut     [32]byte // SHA-256 of each direction
	FINIn, FINOut     bool
	RSTIn, RSTOut     bool
	Open              bool
}

// TargetBehaviour is what a Target does with each connection.
type TargetBehaviour struct {
	_ [0]func() // WP3 adds the behaviour
}

// TargetEcho echoes every byte and answers the client's FIN with its own.
func TargetEcho() TargetBehaviour { return TargetBehaviour{} }

// TargetGen sends n bytes of the seeded stream (PRNG(seed)), then FIN.
func TargetGen(n int64, seed uint64) TargetBehaviour { return TargetBehaviour{} }

// TargetSink reads and discards to FIN, then FINs back.
func TargetSink() TargetBehaviour { return TargetBehaviour{} }

// TargetStall reads to FIN, then holds the connection open.
func TargetStall() TargetBehaviour { return TargetBehaviour{} }

// TargetNoRead never reads.
func TargetNoRead() TargetBehaviour { return TargetBehaviour{} }

// TargetRSTAfter resets the connection after sending n bytes.
func TargetRSTAfter(n int64) TargetBehaviour { return TargetBehaviour{} }

// TargetHalf reads to FIN, sends n bytes, then FIN.
func TargetHalf(n int64) TargetBehaviour { return TargetBehaviour{} }

// TargetReqResp reads req bytes, answers resp bytes, then FIN.
func TargetReqResp(req, resp int64) TargetBehaviour { return TargetBehaviour{} }

// TargetIgnoreFIN reads to FIN, then keeps sending 1 KiB every 100 ms and
// never FINs back (the msess target that ignores FIN; R1-22).
func TargetIgnoreFIN() TargetBehaviour { return TargetBehaviour{} }

// DialOutcome is one scripted result of a ScriptedDial call.
type DialOutcome struct {
	_ [0]func() // WP3 adds the outcome
}

// OutcomeRefuse fails like a target that answered the SYN with RST (this
// OS's connection-refused errno inside a *net.OpError).
func OutcomeRefuse() DialOutcome { return DialOutcome{} }

// OutcomeNetUnreachable fails with this OS's network-unreachable errno.
func OutcomeNetUnreachable() DialOutcome { return DialOutcome{} }

// OutcomeHostUnreachable fails with this OS's host-unreachable errno.
func OutcomeHostUnreachable() DialOutcome { return DialOutcome{} }

// OutcomeHang blocks until ctx ends, then returns ctx's error.
func OutcomeHang() DialOutcome { return DialOutcome{} }

// OutcomeIgnoreCtx ignores ctx and fails after d.
func OutcomeIgnoreCtx(d time.Duration) DialOutcome { return DialOutcome{} }

// OutcomeLate ignores ctx and returns a conn after d (after ctx ended: the
// caller must close it).
func OutcomeLate(d time.Duration) DialOutcome { return DialOutcome{} }

// OutcomeDNSNotFound fails with a *net.DNSError whose IsNotFound is set.
func OutcomeDNSNotFound() DialOutcome { return DialOutcome{} }

// OutcomeDNSFailure fails with a *net.DNSError of a failed resolution.
func OutcomeDNSFailure() DialOutcome { return DialOutcome{} }

// OutcomePanic panics.
func OutcomePanic() DialOutcome { return DialOutcome{} }

// OutcomeGoexit calls runtime.Goexit.
func OutcomeGoexit() DialOutcome { return DialOutcome{} }

// OutcomeNilNil returns (nil, nil).
func OutcomeNilNil() DialOutcome { return DialOutcome{} }

// OutcomeOK returns a new client end of t.
func OutcomeOK(t *Target) DialOutcome { return DialOutcome{} }

// ScriptedDial returns a dial function with one scripted outcome per call
// (the last one repeats once the script is used up) and its counters.
func ScriptedDial(outcomes ...DialOutcome) (dial func(ctx context.Context, addr string) (net.Conn, error), counts *DialCounts) {
	return func(context.Context, string) (net.Conn, error) { return nil, errors.ErrUnsupported }, &DialCounts{} // M4 WP3
}

// DialCounts counts a ScriptedDial's calls and the conns it returned that
// were never closed.
type DialCounts struct {
	calls, unclosed atomic.Int64
}

// Calls returns how many times the dial function was called.
func (c *DialCounts) Calls() int64 { return c.calls.Load() }

// Unclosed returns how many returned conns are not closed yet.
func (c *DialCounts) Unclosed() int64 { return c.unclosed.Load() }
