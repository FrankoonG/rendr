package udpsocket

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
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
// count outside the range it was asked for, or a datagram length other
// than the one written or outside the slot (L42): the caller treats it as
// a transport failure, never retries it on the socket.
var ErrInvalidCount = errors.New("rendr/udpsocket: invalid datagram count")

var errNoSlot = errors.New("rendr/udpsocket: ReadBatch without a slot")

// probeCache is how long a re-probe that found the batch calls permitted
// is trusted (R1-3 rule 3): an EPERM storm costs at most one fd −1 probe
// per socket per period, and a policy installed mid-run is seen within it.
const probeCache = time.Second

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
//
// The RawConn callbacks are the method values send and recv, bound once
// in NewBatch; a call's arguments and results travel through the fields
// below, so no closure is built per call (R1-13).
type Batch struct {
	max int

	// Per-call arguments and results; set by the Conn or Reader that runs
	// the call and cleared at its end (reset).
	ms    []Msg // the call's messages
	base  int   // send: the index in ms of header 0
	k     int   // send: the next index in ms to send
	end   int   // send: the index in ms after the last prepared message; receive: the headers prepared
	got   int   // receive: messages read
	calls int   // send: system calls that moved at least one datagram
	err   error // the error that ended the call: an errno or ErrInvalidCount

	send, recv func(uintptr) bool // b.doSend and b.doRecv
	sys        batchSys           // the platform's arrays (R1-13)
}

// NewBatch returns a Batch for calls of up to max datagrams (clamped to
// 1 … MaxMsgs).
func NewBatch(max int) *Batch {
	b := &Batch{max: clampBatch(max)}
	b.send, b.recv = b.doSend, b.doRecv
	b.sys.init(b)
	return b
}

// Cap returns the most datagrams one call with b moves.
func (b *Batch) Cap() int { return b.max }

// doSend is the RawConn.Write callback of a batched write: sendmmsg from
// message k until every prepared message left, EINTR repeating the call
// and EAGAIN returning to the netpoller (the write deadline applies while
// it waits). A call that sent some messages and failed later reports the
// count; the next call reports the error of the first unsent message,
// which ends the callback with b.err set.
func (b *Batch) doSend(fd uintptr) bool {
	for b.k < b.end {
		want := b.end - b.k
		cnt, err := sendmmsgFn(fd, b, b.k-b.base, want)
		if cnt < 0 || cnt > want {
			b.err = ErrInvalidCount
			return true
		}
		if cnt > 0 {
			b.k += cnt
			b.calls++
		}
		switch {
		case err == nil:
			if cnt == 0 {
				b.err = ErrInvalidCount
				return true
			}
		case err == syscall.EINTR:
		case err == syscall.EAGAIN:
			return false
		default:
			b.err = err
			return true
		}
	}
	return true
}

// doRecv is the RawConn.Read callback of a batched read: one recvmmsg of
// up to b.end messages, EINTR repeating it and EAGAIN returning to the
// netpoller (the read deadline applies while it waits). recvmmsg never
// waits for more datagrams than are queued (L55).
func (b *Batch) doRecv(fd uintptr) bool {
	for {
		cnt, err := recvmmsgFn(fd, b, b.end)
		switch {
		case err == syscall.EINTR:
			continue
		case err == syscall.EAGAIN:
			return false
		case err != nil:
			b.err = err
		case cnt < 1 || cnt > b.end:
			b.err = ErrInvalidCount
		default:
			b.got = cnt
		}
		return true
	}
}

// prepRecv prepares b to read into ms (len(ms) ≤ b.max).
func (b *Batch) prepRecv(ms []Msg) {
	b.ms, b.end, b.got, b.err = ms, len(ms), 0, nil
	b.sys.prepRecv(ms)
}

// reset ends a call: b keeps no reference to the call's messages or
// buffers (a pooled Batch holds nothing of its last user).
func (b *Batch) reset() {
	n := b.end - b.base
	b.sys.clear(n)
	b.ms, b.err = nil, nil
	b.base, b.k, b.end, b.got, b.calls = 0, 0, 0, 0, 0
}

// Counters count the I/O of the Conns created with them (one set per
// Runtime): system calls that moved at least one datagram and the
// datagrams they moved, per direction — a call ending in EAGAIN, EINTR or
// an error before its first datagram is not counted (R1-2) — and the
// sockets that fell back to ModePlain (each at most once). They are
// updated when a WriteBatch or ReadBatch returns, from the calls it made,
// never per datagram and never inside a lock.
type Counters struct {
	sendCalls, sent, recvCalls, recvd, fallbacks atomic.Uint64
}

// Load returns the counters (rendr.DatagramStatus SendCalls,
// SentDatagrams, RecvCalls, RecvDatagrams, BatchFallbacks).
func (c *Counters) Load() (sendCalls, sent, recvCalls, recvd, fallbacks uint64) {
	return c.sendCalls.Load(), c.sent.Load(), c.recvCalls.Load(), c.recvd.Load(), c.fallbacks.Load()
}

func (c *Counters) addSend(calls, n int) {
	if c != nil && calls > 0 {
		c.sendCalls.Add(uint64(calls))
		c.sent.Add(uint64(n))
	}
}

func (c *Counters) addRecv(calls, n int) {
	if c != nil && calls > 0 {
		c.recvCalls.Add(uint64(calls))
		c.recvd.Add(uint64(n))
	}
}

func (c *Counters) addFallback() {
	if c != nil {
		c.fallbacks.Add(1)
	}
}

// Conn is a rendr-owned UDP socket. It holds no per-call state, so
// concurrent writers (the flows sharing a listening socket) may call
// WriteBatch at once, each with its own Batch; one reader calls ReadBatch
// (or a Reader's ReadBatch).
type Conn struct {
	u     *net.UDPConn
	laddr net.Addr
	max   int
	mode  atomic.Uint32 // Mode; moves ModeBatch → ModePlain once, by CAS
	ctr   *Counters     // nil: not counted

	// rawRead and rawWrite are the socket's RawConn.Read and Write, bound
	// once in New (ModeBatch only; tests replace them with a fake
	// netpoller).
	rawRead, rawWrite func(func(uintptr) bool) error

	// permittedAt is the time (Unix nanoseconds) of the last fd −1 probe
	// that found the batch calls permitted (R1-3 rule 3).
	permittedAt atomic.Int64

	sys connSys // the platform's per-socket state (the socket's family)
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
	c := &Conn{u: u, laddr: u.LocalAddr(), max: clampBatch(maxBatch), ctr: ctr}
	mode := ModePlain
	if batchTarget && c.max >= 2 {
		rc, err := u.SyscallConn()
		if err != nil {
			return nil, err
		}
		if err := c.sys.init(rc); err != nil {
			return nil, err
		}
		c.rawRead, c.rawWrite = rc.Read, rc.Write
		if batchPermitted() {
			mode = ModeBatch
		}
	}
	c.mode.Store(uint32(mode))
	return c, nil
}

// Mode returns the socket's current mode.
func (c *Conn) Mode() Mode { return Mode(c.mode.Load()) }

// MaxBatch returns the most datagrams one call moves (New's maxBatch,
// clamped).
func (c *Conn) MaxBatch() int { return c.max }

// WriteBatch writes ms in order, each ms[i].Buf as one datagram to
// ms[i].Addr: ms[:n] were sent; err, if any, belongs to ms[n] and is the
// socket's error for it (classified by the caller as a single write's
// error would be) or ErrInvalidCount. b may be nil, and is not used, when
// len(ms) ≤ 1 or in ModePlain: then one call per datagram.
//
// In ModeBatch an EPERM at ms[n] is a filter drop (M2: the datagram is
// lost, the carrier lives; the caller continues at n + 1) unless a fresh
// fd −1 probe finds the batch calls denied; that, or ENOSYS, moves the
// socket to ModePlain and the rest of ms is written plainly in the same
// call (M5-D15, R1-3).
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
		return 0, errNoSlot
	}
	if len(ms) == 1 || b == nil || b.max < 2 || c.Mode() != ModeBatch {
		return c.readPlain(&ms[0])
	}
	b.prepRecv(ms[:min(len(ms), b.max)])
	err = c.rawRead(b.recv)
	return c.endRead(b, &ms[0], err)
}

// writePlain writes ms with one WriteToUDPAddrPort each, stopping at the
// first error; the calls that sent their datagram are counted.
func (c *Conn) writePlain(ms []Msg) (int, error) {
	for i := range ms {
		m := &ms[i]
		k, err := c.u.WriteToUDPAddrPort(m.Buf, m.Addr)
		if err == nil && k != len(m.Buf) {
			err = ErrInvalidCount
		}
		if err != nil {
			c.ctr.addSend(i, i)
			return i, err
		}
	}
	c.ctr.addSend(len(ms), len(ms))
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
	c.ctr.addRecv(1, 1)
	return 1, nil
}

// writeBatch writes ms (len ≥ 2) in ModeBatch: chunks of up to b.max
// messages, each prepared and sent through sendmmsg on the netpoller.
func (c *Conn) writeBatch(b *Batch, ms []Msg) (int, error) {
	k, calls := 0, 0
	var err error
	for k < len(ms) && err == nil {
		end := min(len(ms), k+b.max)
		e, perr := b.sys.prepSend(c, ms, k, end)
		if e == k {
			err = perr // ms[k] cannot be addressed on this socket
			break
		}
		b.ms, b.base, b.k, b.end, b.calls, b.err = ms, k, k, e, 0, nil
		werr := c.rawWrite(b.send)
		k, calls = b.k, calls+b.calls
		cerr := b.err
		b.reset()
		switch {
		case werr != nil:
			err = werr // the write deadline, or a closed socket
		case cerr != nil:
			if c.denied(cerr) {
				c.ctr.addSend(calls, k)
				c.fallback()
				n, perr := c.writePlain(ms[k:])
				return k + n, perr
			}
			err = c.opError("write", "sendmmsg", cerr)
		case k < e:
			err = ErrInvalidCount // the callback ended without an error short of e
		default:
			err = perr // nil, or the error of ms[e], which cannot be addressed
		}
	}
	c.ctr.addSend(calls, k)
	return k, err
}

// endRead ends a batched read with b (ModeBatch): err is the RawConn's,
// b.err the call's. A call refused by the kernel or a sandbox moves the
// socket to ModePlain and reads into m0 plainly (M5-D15, R1-3).
func (c *Conn) endRead(b *Batch, m0 *Msg, err error) (int, error) {
	got, cerr := b.got, b.err
	b.reset()
	if err != nil {
		return 0, err
	}
	if cerr != nil {
		if c.denied(cerr) {
			c.fallback()
			return c.readPlain(m0)
		}
		return 0, c.opError("read", "recvmmsg", cerr)
	}
	c.ctr.addRecv(1, got)
	return got, nil
}

// denied reports whether err, from a batch call, means the call itself is
// refused: ENOSYS, or EPERM confirmed by a fresh fd −1 probe. An EPERM the
// probe does not confirm is a filter drop of one datagram (R1-3).
func (c *Conn) denied(err error) bool {
	switch err {
	case syscall.ENOSYS:
		return true
	case syscall.EPERM:
		return !c.permitted()
	}
	return false
}

// permitted re-runs the fd −1 probe, or trusts one that found the batch
// calls permitted less than probeCache ago (R1-3 rule 3).
func (c *Conn) permitted() bool {
	now := time.Now().UnixNano()
	if t := c.permittedAt.Load(); t != 0 && now >= t && now-t < int64(probeCache) {
		return true
	}
	if !probeAllows(probeFn()) {
		return false
	}
	c.permittedAt.Store(now)
	return true
}

// fallback moves the socket to ModePlain; the caller that wins the CAS
// counts it (M5-D15: exactly one transition per socket).
func (c *Conn) fallback() {
	if c.mode.CompareAndSwap(uint32(ModeBatch), uint32(ModePlain)) {
		c.ctr.addFallback()
	}
}

// opError wraps an errno of a batch call as the net package wraps a
// single call's (an *net.OpError around an *os.SyscallError), so the
// caller's classification (errors.As to syscall.Errno) is the same in
// both modes.
func (c *Conn) opError(op, call string, err error) error {
	if errno, ok := err.(syscall.Errno); ok {
		return &net.OpError{Op: op, Net: "udp", Source: c.laddr, Err: os.NewSyscallError(call, errno)}
	}
	return err
}

// The idle release of a dialer reader's extras (R1-5): the four states of
// Reader.state.
const (
	rIdle      uint32 = iota // no extras: the reader reads one datagram through its fixed header
	rHeld                    // the reader goroutine holds the extras (and uses them)
	rParked                  // the reader is parked in the netpoller holding the extras
	rReleasing               // the idle release owns the extras and is returning them
)

// Reader is the batched reader of a dialer carrier's socket (R1-5,
// M5-D61). It keeps a fixed one-message header for its life and, while the
// carrier reads at depth K ≥ 2, a pooled Batch (the extras: that header
// and, in the caller, the slots 1 … K−1). A four-state word (idle, held,
// parked, releasing) says who owns the extras: the reader goroutine while
// held, nobody while parked — the read callback takes them back by CAS
// when it wakes, and the idle release by CAS when the reader stayed parked
// for a whole period — and the idle release while releasing. A callback
// that loses the CAS reads one datagram into slot 0 through the fixed
// header; it never touches the released Batch or slots.
//
// One goroutine (the carrier's reader) calls ReadBatch, Hold, Held and
// Drop; the idle-release timer calls Parks, Holding and TryRelease.
type Reader struct {
	c       *Conn
	state   atomic.Uint32
	parks   atomic.Uint64 // parks while holding the extras
	one     *Batch        // the fixed one-message header
	b       *Batch        // the extras' header; owned per state
	cur     *Batch        // the header of the callback's last call
	depth   int           // this call's depth
	release func(*Batch)
	cb      func(uintptr) bool // r.doRead
}

// NewReader returns the Reader of c, holding no extras. release returns
// the extras of an idle reader — the Batch given (the one Hold gave) and
// the caller's slots 1 … K−1 — and is called by TryRelease, on the
// timer's goroutine, while the reader may be reading into slot 0.
func NewReader(c *Conn, release func(*Batch)) *Reader {
	r := &Reader{c: c, one: NewBatch(1), release: release}
	r.cb = r.doRead
	return r
}

// Hold gives the reader b (Cap ≥ 2) as the header of its extras. It
// returns the Batch b replaces, if the reader held one, and false — nothing
// changed — while an idle release is still returning the previous extras;
// the caller then keeps depth 1 and returns b to its pool.
func (r *Reader) Hold(b *Batch) (old *Batch, ok bool) {
	switch r.state.Load() {
	case rIdle:
		r.b = b
		r.state.Store(rHeld)
		return nil, true
	case rHeld:
		old, r.b = r.b, b
		return old, true
	}
	return nil, false
}

// Held reports whether the reader goroutine holds the extras. False after
// a ReadBatch means an idle release took them (or is returning them): the
// caller treats its slots 1 … K−1 as gone and reads at depth 1.
func (r *Reader) Held() bool { return r.state.Load() == rHeld }

// Drop takes the extras back from the reader (when the carrier ends, or
// when the socket left ModeBatch) and returns their Batch; nil if it holds
// none.
func (r *Reader) Drop() *Batch {
	if r.state.Load() != rHeld {
		return nil
	}
	b := r.b
	r.b = nil
	r.state.Store(rIdle)
	return b
}

// Parks returns the number of times the reader parked while holding the
// extras.
func (r *Reader) Parks() uint64 { return r.parks.Load() }

// Holding reports whether the reader holds extras (held or parked): the
// idle-release timer stays armed while it does.
func (r *Reader) Holding() bool {
	s := r.state.Load()
	return s == rHeld || s == rParked
}

// TryRelease releases the extras of a reader that is parked and has not
// parked again since Parks returned seq (the timer's previous firing):
// parked → releasing by CAS, then release, then idle. It reports whether
// it released.
func (r *Reader) TryRelease(seq uint64) bool {
	if r.parks.Load() != seq || !r.state.CompareAndSwap(rParked, rReleasing) {
		return false
	}
	b := r.b
	r.b = nil
	b.reset()
	r.release(b)
	r.state.Store(rIdle)
	return true
}

// ReadBatch waits like Conn.ReadBatch and fills ms[:n], n ≥ 1, in arrival
// order: up to len(ms) datagrams while the reader holds the extras (ms
// holds the caller's K slots), else one into ms[0]. A read callback that
// finds the extras released reads into ms[0] only.
func (r *Reader) ReadBatch(ms []Msg) (int, error) {
	c := r.c
	if len(ms) == 0 {
		return 0, errNoSlot
	}
	if c.Mode() != ModeBatch {
		return c.readPlain(&ms[0])
	}
	r.depth = 1
	if r.state.Load() == rHeld {
		r.depth = min(len(ms), r.b.max)
	}
	r.one.prepRecv(ms[:1])
	if r.depth > 1 {
		r.b.prepRecv(ms[:r.depth])
	}
	r.cur = nil
	err := c.rawRead(r.cb)
	held := r.depth > 1 && (r.state.CompareAndSwap(rParked, rHeld) || r.state.Load() == rHeld)
	b := r.cur
	if held && b != r.b {
		r.b.reset()
	}
	if b != r.one {
		r.one.reset()
	}
	if b == nil || (b != r.one && !held) {
		// The callback never ran, or its last call used the extras and
		// parked, and the idle release took them: the read ended in an
		// error (deadline, closed socket).
		if err == nil {
			err = ErrInvalidCount
		}
		return 0, err
	}
	return c.endRead(b, &ms[0], err)
}

// doRead is the RawConn.Read callback of a Reader: it takes the extras
// back (parked → held) or reads through the fixed header if the idle
// release won; on EAGAIN with the extras it counts a park and leaves them
// parked.
func (r *Reader) doRead(fd uintptr) bool {
	b := r.one
	if r.depth > 1 {
		if s := r.state.Load(); s == rHeld || s == rParked && r.state.CompareAndSwap(rParked, rHeld) {
			b = r.b
		}
	}
	r.cur = b
	if b.doRecv(fd) {
		return true
	}
	if b != r.one {
		r.parks.Add(1)
		r.state.Store(rParked)
	}
	return false
}

// The process probe (M5-D15): sendmmsg and recvmmsg on fd −1 run once;
// EBADF from both means the calls are permitted.
var (
	probeOnce sync.Once
	probeOK   bool
)

func batchPermitted() bool {
	probeOnce.Do(func() { probeOK = probeAllows(probeFn()) })
	return probeOK
}

// probeAllows reads the fd −1 probe: the batch calls are permitted only if
// both fail with EBADF (the kernel looked at the descriptor). ENOSYS (no
// such call) and EPERM (a sandbox policy) — and anything else — keep the
// socket plain (M5-D15).
func probeAllows(sendErr, recvErr error) bool {
	return sendErr == syscall.EBADF && recvErr == syscall.EBADF
}

// Test seams: tests replace them; production code never does.
var (
	sendmmsgFn  = sendmmsg
	recvmmsgFn  = recvmmsg
	probeFn     = probe
	batchTarget = accelerated // tests set it on other targets to drive ModeBatch through fake calls
)

func clampBatch(n int) int {
	return min(max(n, 1), MaxMsgs)
}
