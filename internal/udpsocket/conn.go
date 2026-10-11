package udpsocket

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
)

// MaxMsgs is the most datagrams one call moves (carrier/udp clamps
// Options.MaxBatch to it).
const MaxMsgs = 64

// Mode is a socket's I/O mode. It moves one way only: ModeBatch →
// ModePlain (M5-D15).
type Mode uint32

// Modes.
const (
	ModePlain Mode = iota // one datagram per system call
	ModeBatch             // sendmmsg/recvmmsg (Linux amd64/arm64)
)

// ErrInvalidCount is returned for the message at which a call reported a
// count outside the range it was asked for (L42): the caller treats it as
// a transport failure, never retries it on the socket.
var ErrInvalidCount = errors.New("rendr/udpsocket: invalid datagram count")

// Msg is one datagram of a WriteBatch or ReadBatch call.
type Msg struct {
	Buf   []byte         // send: the datagram; receive: the slot it is read into
	Addr  netip.AddrPort // send: destination; receive: source
	N     int            // receive: bytes read
	Trunc bool           // receive: MSG_TRUNC, or N == len(Buf) (the slot is one byte longer than the caller's limit, M2's rule)
}

// Batch is the reusable per-call state of the batch calls: up to Cap()
// message headers, iovecs and socket addresses, allocated once in NewBatch
// and never per call. A Batch is used by one call at a time; callers take
// it from a pool per capacity class while they need it (R1-5).
type Batch struct {
	max int
	sys batchSys // the platform's arrays and the RawConn callbacks bound once (R1-13)
}

// NewBatch returns a Batch for calls of up to max datagrams (clamped to
// 1 … MaxMsgs).
func NewBatch(max int) *Batch {
	b := &Batch{max: clampBatch(max)}
	b.sys.init(b)
	return b
}

// Cap returns the most datagrams one call with b moves.
func (b *Batch) Cap() int { return b.max }

// Counters count the I/O of the Conns created with them (one set per
// Runtime): system calls that moved at least one datagram and the
// datagrams they moved, per direction — a call ending in EAGAIN, EINTR or
// an error before its first datagram is not counted (R1-2) — and the
// sockets that fell back to ModePlain (each at most once). Each counter is
// updated once per call, at its return.
type Counters struct {
	sendCalls, sent, recvCalls, recvd, fallbacks atomic.Uint64
}

// Load returns the counters (rendr.DatagramStatus SendCalls,
// SentDatagrams, RecvCalls, RecvDatagrams, BatchFallbacks).
func (c *Counters) Load() (sendCalls, sent, recvCalls, recvd, fallbacks uint64) {
	return c.sendCalls.Load(), c.sent.Load(), c.recvCalls.Load(), c.recvd.Load(), c.fallbacks.Load()
}

func (c *Counters) addSend(k int) {
	if c != nil && k > 0 {
		c.sendCalls.Add(1)
		c.sent.Add(uint64(k))
	}
}

func (c *Counters) addRecv(k int) {
	if c != nil && k > 0 {
		c.recvCalls.Add(1)
		c.recvd.Add(uint64(k))
	}
}

func (c *Counters) addFallback() {
	if c != nil {
		c.fallbacks.Add(1)
	}
}

// Conn is a rendr-owned UDP socket. It holds no per-call state, so
// concurrent writers (the flows sharing a listening socket) may call
// WriteBatch at once, each with its own Batch; one reader calls ReadBatch.
type Conn struct {
	u    *net.UDPConn
	rc   syscall.RawConn // set in ModeBatch only
	max  int
	mode atomic.Uint32 // Mode; moves ModeBatch → ModePlain once, by CAS
	ctr  *Counters     // nil: not counted
	sys  connSys       // the platform's per-socket state (the R1-3 probe cache)
}

// New returns the Conn for u, a socket rendr opened, moving at most
// maxBatch datagrams per call (clamped to 1 … MaxMsgs). It starts in
// ModeBatch on Linux amd64/arm64 when maxBatch ≥ 2 and the process probe
// found the batch calls permitted, else in ModePlain. ctr may be nil.
// Ownership of u stays with the caller.
func New(u *net.UDPConn, maxBatch int, ctr *Counters) (*Conn, error) {
	if u == nil {
		return nil, errors.New("rendr/udpsocket: nil socket")
	}
	c := &Conn{u: u, max: clampBatch(maxBatch), ctr: ctr}
	mode := ModePlain
	if accelerated && c.max >= 2 {
		rc, err := u.SyscallConn()
		if err != nil {
			return nil, err
		}
		c.rc = rc
		if batchPermitted() {
			mode = ModeBatch
		}
	}
	c.mode.Store(uint32(mode))
	return c, nil
}

// Mode returns the socket's current mode.
func (c *Conn) Mode() Mode { return Mode(c.mode.Load()) }

// WriteBatch writes ms in order, each ms[i].Buf as one datagram to
// ms[i].Addr: ms[:n] were sent; err, if any, belongs to ms[n] and is the
// socket's error for it (classified by the caller as a single write's
// error would be) or ErrInvalidCount. b may be nil, and is not used, when
// len(ms) ≤ 1 or in ModePlain: then one call per datagram.
func (c *Conn) WriteBatch(b *Batch, ms []Msg) (n int, err error) {
	if len(ms) <= 1 || b == nil || b.max < 2 || c.Mode() != ModeBatch {
		return c.writePlain(ms)
	}
	return c.writeBatch(b, ms)
}

// ReadBatch waits like ReadMsgUDPAddrPort (the read deadline applies) and
// fills ms[:n] with n ≥ 1 datagrams in arrival order — up to len(ms) and
// b.Cap() in ModeBatch, one otherwise — or returns n = 0 and the socket's
// error. b may be nil when len(ms) == 1 or in ModePlain.
func (c *Conn) ReadBatch(b *Batch, ms []Msg) (n int, err error) {
	if len(ms) == 0 {
		return 0, errors.New("rendr/udpsocket: ReadBatch without a slot")
	}
	if len(ms) == 1 || b == nil || b.max < 2 || c.Mode() != ModeBatch {
		return c.readPlain(&ms[0])
	}
	return c.readBatch(b, ms)
}

// writePlain writes ms with one WriteToUDPAddrPort each, stopping at the
// first error; each call that sent its datagram is counted.
func (c *Conn) writePlain(ms []Msg) (int, error) {
	for i := range ms {
		m := &ms[i]
		k, err := c.u.WriteToUDPAddrPort(m.Buf, m.Addr)
		if err != nil {
			return i, err
		}
		if k != len(m.Buf) {
			return i, ErrInvalidCount
		}
		c.ctr.addSend(1)
	}
	return len(ms), nil
}

// readPlain reads one datagram into m.Buf with ReadMsgUDPAddrPort. A
// Windows WSAEMSGSIZE is returned as the error, for the caller's
// classification (M2: a truncation drop).
func (c *Conn) readPlain(m *Msg) (int, error) {
	k, _, _, src, err := c.u.ReadMsgUDPAddrPort(m.Buf, nil)
	if err != nil {
		return 0, err
	}
	if k < 0 || k > len(m.Buf) {
		return 0, ErrInvalidCount
	}
	m.N, m.Addr = k, src
	m.Trunc = k == len(m.Buf) // a cut datagram fills the slot on every OS (MSG_TRUNC implies it)
	c.ctr.addRecv(1)
	return 1, nil
}

// fallback moves the socket to ModePlain; the caller that wins the CAS
// counts it (M5-D15: exactly one transition per socket).
func (c *Conn) fallback() {
	if c.mode.CompareAndSwap(uint32(ModeBatch), uint32(ModePlain)) {
		c.ctr.addFallback()
	}
}

// The process probe (M5-D15): sendmmsg and recvmmsg on fd −1 run once;
// EBADF from both means the calls are permitted.
var (
	probeOnce sync.Once
	probeOK   bool
)

func batchPermitted() bool {
	probeOnce.Do(func() { probeOK = probeFn() == nil })
	return probeOK
}

// Test seams: tests replace them; production code never does.
var (
	sendmmsgFn = sendmmsg
	recvmmsgFn = recvmmsg
	probeFn    = probe
)

func clampBatch(n int) int {
	return min(max(n, 1), MaxMsgs)
}
