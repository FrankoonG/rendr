package lessons1

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Wire taps. Every carrier conn of a fixture is wrapped in a tap on both
// ends: the dialer's (between the factory and rendr) and the passive's
// (between the Link and Listener.Handle). A tap forwards every call to the
// Link's conn and parses the byte stream in both directions — the 40-byte
// PREFACE or PREFACE_ACK, then frames — into a shared, time-stamped frame
// log, so a test can prove which carrier a FIN, ACK, SCHED or RST travelled
// on and when (the stimulus and timing proofs of design §11.1). A tap can
// also inject faults at exact frames: a scripted Read result (L01), and a
// write plan that sees the frames of every batch before it is forwarded and
// may fail or swallow it (L04, L11). The taps never change a forwarded byte.

// side is the end of a session a tap sits on.
type side uint8

const (
	dialerSide  side = 1
	passiveSide side = 2
)

func (s side) String() string {
	if s == dialerSide {
		return "dialer"
	}
	return "passive"
}

// fate is what happened to a frame a side wrote.
type fate uint8

const (
	fateWritten   fate = iota // the conn reported it written
	fateFailed                // the Write carrying it failed by the tap's write plan
	fateSwallowed             // reported written by the tap's write plan, never forwarded
)

// Carrier classes, by the first frame the dialer sent after the PREFACE.
const (
	classUnknown int32 = iota
	classSession
	classProbe
)

// frame is one frame a tap saw.
type frame struct {
	at    time.Time
	tap   *tap
	out   bool // written by the tap's side; false: read by it
	fate  fate // out frames only
	typ   wire.Type
	flags uint8
	fseq  uint32
	n     int    // payload length
	off   uint64 // DATA and FIN: the stream offset
	ack   wire.Ack
	sched wire.Sched
	rst   uint32 // RST code
	ping  uint32 // PING and PONG id
	rx    uint64 // JOIN and JOIN_ACK: rxNext
}

// dataEnd is the stream offset after a DATA frame's bytes.
func (f frame) dataEnd() uint64 { return f.off + uint64(f.n-wire.DataPrefixLen) }

// done reports an ACK carrying DONE.
func (f frame) done() bool { return f.typ == wire.TypeAck && f.flags&wire.FlagAckDone != 0 }

// finDelivered reports an ACK carrying FIN_DELIVERED.
func (f frame) finDelivered() bool {
	return f.typ == wire.TypeAck && f.flags&wire.FlagAckFinDelivered != 0
}

// wireLog collects the frames of every tap of a fixture.
type wireLog struct {
	mu      sync.Mutex
	frames  []frame
	taps    []*tap
	seq     [3]int        // taps created per side
	changed chan struct{} // closed and renewed on every new frame or tap
	hook    atomic.Pointer[func(f frame)]
	onNew   atomic.Pointer[func(tp *tap)]
}

// setOnNew installs fn, called with every tap created afterwards before
// its conn carries any byte (a test arms per-carrier faults there).
func (w *wireLog) setOnNew(fn func(tp *tap)) { w.onNew.Store(&fn) }

func newWireLog() *wireLog { return &wireLog{changed: make(chan struct{})} }

// setHook installs fn, called synchronously (on the conn's reader or
// writer goroutine, no lock held) for every frame logged afterwards; nil
// removes it. fn must not wait for the test; it may delay the goroutine it
// runs on by a fixed virtual time as a stimulus (a Read that returns late).
func (w *wireLog) setHook(fn func(f frame)) {
	if fn == nil {
		w.hook.Store(nil)
		return
	}
	w.hook.Store(&fn)
}

func (w *wireLog) add(f frame) {
	w.mu.Lock()
	w.frames = append(w.frames, f)
	close(w.changed)
	w.changed = make(chan struct{})
	w.mu.Unlock()
	if h := w.hook.Load(); h != nil {
		(*h)(f)
	}
}

// pick returns the logged frames for which keep is true, in log order.
func (w *wireLog) pick(keep func(f frame) bool) []frame {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []frame
	for _, f := range w.frames {
		if keep(f) {
			out = append(out, f)
		}
	}
	return out
}

// count counts the logged frames for which keep is true.
func (w *wireLog) count(keep func(f frame) bool) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, f := range w.frames {
		if keep(f) {
			n++
		}
	}
	return n
}

// wait blocks until some logged frame satisfies keep and returns the first
// one, or false after within (virtual time inside a bubble).
func (w *wireLog) wait(within time.Duration, keep func(f frame) bool) (frame, bool) {
	timer := time.NewTimer(within)
	defer timer.Stop()
	for i := 0; ; {
		w.mu.Lock()
		for ; i < len(w.frames); i++ {
			if keep(w.frames[i]) {
				f := w.frames[i]
				w.mu.Unlock()
				return f, true
			}
		}
		ch := w.changed
		w.mu.Unlock()
		select {
		case <-ch:
		case <-timer.C:
			return frame{}, false
		}
	}
}

// tapsOf returns the taps of side s for which keep is true, in creation order.
func (w *wireLog) tapsOf(s side, keep func(tp *tap) bool) []*tap {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []*tap
	for _, tp := range w.taps {
		if tp.side == s && (keep == nil || keep(tp)) {
			out = append(out, tp)
		}
	}
	return out
}

// sessionTaps returns side s's taps of session carriers on link (all links
// when link is ""), in creation order.
func (w *wireLog) sessionTaps(s side, link string) []*tap {
	return w.tapsOf(s, func(tp *tap) bool {
		return tp.class.Load() == classSession && (link == "" || tp.link == link)
	})
}

// newTap wraps c, the end of a carrier of link on side s.
func (w *wireLog) newTap(link string, s side, c net.Conn) *tap {
	tp := &tap{Conn: c, log: w, link: link, side: s}
	w.mu.Lock()
	w.seq[s]++
	tp.seq = w.seq[s]
	w.taps = append(w.taps, tp)
	close(w.changed)
	w.changed = make(chan struct{})
	w.mu.Unlock()
	if fn := w.onNew.Load(); fn != nil {
		(*fn)(tp)
	}
	return tp
}

// planVerdict is a write plan's decision for one Write.
type planVerdict struct {
	fail    error // non-nil: the Write returns (0, fail) and forwards nothing
	swallow bool  // the Write reports len(p) written and forwards nothing
}

// writePlan sees the frames a Write would complete (in order) and decides.
type writePlan func(tp *tap, fs []frame) planVerdict

// readFault scripts the result of one Read.
type readFault uint8

const (
	faultEOF           readFault = iota + 1 // (0, io.EOF)
	faultUnexpectedEOF                      // (0, io.ErrUnexpectedEOF)
	faultReset                              // (0, a connection-reset *net.OpError)
	faultTimeout                            // (0, a timeout *net.OpError)
	faultZeroNil                            // (0, nil)
	faultPanic                              // panic inside Read
	// faultDataEOF returns real bytes together with io.EOF from the first
	// Read whose bytes complete a DATA frame (earlier Reads pass), so the
	// carrier must apply a known frame before it dies (L01: n before err);
	// the frames that Read completed are kept (eofFrames).
	faultDataEOF
)

var errInjected = errors.New("lessons1: injected carrier write failure")

// tap is a net.Conn wrapper that logs every frame both ways (see wireLog).
type tap struct {
	net.Conn
	log   *wireLog
	link  string
	side  side
	seq   int           // creation order among the taps of its side (1-based)
	cid   atomic.Uint32 // the CarrierID of its PREFACE / PREFACE_ACK
	class atomic.Int32  // classUnknown, classSession, classProbe

	wmu    sync.Mutex
	outp   parser
	plan   atomic.Pointer[writePlan]
	faults atomic.Int64 // write-plan and read faults injected on this tap

	rmu   sync.Mutex
	inp   parser
	fault atomic.Uint32 // a pending readFault (0 = none)
	eof   []frame       // faultDataEOF: the frames its Read completed (rmu)
}

// sever closes the tap's underlying conn: this side's blocked and later
// Reads and Writes on the carrier fail, and the far end reads EOF after the
// bytes already in the Link — a read failure of this one carrier, unlike
// Link.Kill, which ends every carrier of the Link, probe carriers included.
func (tp *tap) sever() { tp.Conn.Close() }

// eofFrames returns the frames completed by the Read that faultDataEOF
// failed (nil before it fired).
func (tp *tap) eofFrames() []frame {
	tp.rmu.Lock()
	defer tp.rmu.Unlock()
	return tp.eof
}

// setPlan installs a write plan (nil removes it).
func (tp *tap) setPlan(p writePlan) {
	if p == nil {
		tp.plan.Store(nil)
		return
	}
	tp.plan.Store(&p)
}

// armRead makes the next Read return f.
func (tp *tap) armRead(f readFault) { tp.fault.Store(uint32(f)) }

// Write forwards p and logs the frames it completes, after consulting the
// write plan.
func (tp *tap) Write(p []byte) (int, error) {
	tp.wmu.Lock()
	defer tp.wmu.Unlock()
	if pl := tp.plan.Load(); pl != nil && len(p) > 0 {
		dry := tp.outp.clone()
		var fs []frame
		dry.feed(p, nil, func(h wire.Header, body []byte) { fs = append(fs, decode(h, body)) })
		switch v := (*pl)(tp, fs); {
		case v.fail != nil:
			tp.faults.Add(1)
			now := time.Now()
			for _, f := range fs {
				f.at, f.tap, f.out, f.fate = now, tp, true, fateFailed
				tp.log.add(f)
			}
			return 0, v.fail
		case v.swallow:
			tp.faults.Add(1)
			tp.parseOut(p, fateSwallowed)
			return len(p), nil
		}
	}
	n, err := tp.Conn.Write(p)
	if k := min(max(n, 0), len(p)); k > 0 {
		tp.parseOut(p[:k], fateWritten)
	}
	return n, err
}

// Read forwards to the conn (or injects the armed fault) and logs the
// frames the bytes complete.
func (tp *tap) Read(p []byte) (int, error) {
	switch f := readFault(tp.fault.Load()); {
	case f == faultDataEOF:
		return tp.readDataEOF(p)
	case f != 0 && tp.fault.CompareAndSwap(uint32(f), 0):
		tp.faults.Add(1)
		switch f {
		case faultEOF:
			return 0, io.EOF
		case faultUnexpectedEOF:
			return 0, io.ErrUnexpectedEOF
		case faultReset:
			return 0, &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
		case faultTimeout:
			return 0, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
		case faultZeroNil:
			return 0, nil
		case faultPanic:
			panic("lessons1: injected panic in a carrier Read")
		}
	}
	n, err := tp.Conn.Read(p)
	if k := min(max(n, 0), len(p)); k > 0 {
		tp.parseIn(p[:k], nil)
	}
	return n, err
}

// readDataEOF serves a Read while faultDataEOF is armed: the conn's real
// bytes, and io.EOF with them once they complete a DATA frame.
func (tp *tap) readDataEOF(p []byte) (int, error) {
	n, err := tp.Conn.Read(p)
	k := min(max(n, 0), len(p))
	if k == 0 {
		return n, err
	}
	var fs []frame
	tp.parseIn(p[:k], &fs)
	data := false
	for _, f := range fs {
		data = data || f.typ == wire.TypeData
	}
	if err != nil || !data || !tp.fault.CompareAndSwap(uint32(faultDataEOF), 0) {
		return n, err
	}
	tp.faults.Add(1)
	tp.rmu.Lock()
	tp.eof = fs
	tp.rmu.Unlock()
	return n, io.EOF
}

// parseOut logs the frames completed by bytes this side wrote (wmu held).
func (tp *tap) parseOut(b []byte, ft fate) {
	tp.outp.feed(b, tp.preface, func(h wire.Header, body []byte) {
		f := decode(h, body)
		f.at, f.tap, f.out, f.fate = time.Now(), tp, true, ft
		if tp.side == dialerSide {
			tp.classify(h.Type)
		}
		tp.log.add(f)
	})
}

// parseIn logs the frames completed by bytes this side read, also appending
// them to keep when it is non-nil.
func (tp *tap) parseIn(b []byte, keep *[]frame) {
	tp.rmu.Lock()
	defer tp.rmu.Unlock()
	tp.inp.feed(b, tp.preface, func(h wire.Header, body []byte) {
		f := decode(h, body)
		f.at, f.tap = time.Now(), tp
		if tp.side == passiveSide {
			tp.classify(h.Type)
		}
		if keep != nil {
			*keep = append(*keep, f)
		}
		tp.log.add(f)
	})
}

// preface records the CarrierID carried by a PREFACE or PREFACE_ACK.
func (tp *tap) preface(b []byte) {
	if id := binary.BigEndian.Uint32(b[32:36]); id != 0 {
		tp.cid.CompareAndSwap(0, id)
	}
}

// classify records the class of the carrier from the dialer's first frame.
func (tp *tap) classify(t wire.Type) {
	c := classUnknown
	switch t {
	case wire.TypeOpen, wire.TypeJoin:
		c = classSession
	case wire.TypePing:
		c = classProbe
	default:
		return
	}
	tp.class.CompareAndSwap(classUnknown, c)
}

// sent returns the frames this tap's side wrote with fate written, of type t.
func (tp *tap) sent(t wire.Type) []frame {
	return tp.log.pick(func(f frame) bool { return f.tap == tp && f.out && f.fate == fateWritten && f.typ == t })
}

// recv returns the frames this tap's side read, of type t.
func (tp *tap) recv(t wire.Type) []frame {
	return tp.log.pick(func(f frame) bool { return f.tap == tp && !f.out && f.typ == t })
}

// parser follows one direction of a carrier: PREFACE (or PREFACE_ACK), then
// frames of HeaderLen + Len + TrailerLen bytes. It keeps only a short
// payload prefix per frame; a length beyond MaxFramePayload stops it.
type parser struct {
	pre  [wire.PrefaceLen]byte
	pn   int
	hdr  [wire.HeaderLen]byte
	hn   int
	h    wire.Header
	in   bool // inside a frame (payload and trailer)
	keep int  // payload bytes to keep
	body []byte
	rest int // payload and trailer bytes still to come
	bad  bool
}

// clone returns a copy that shares no memory with ps.
func (ps *parser) clone() parser {
	c := *ps
	c.body = append([]byte(nil), ps.body...)
	return c
}

// feed parses b: preface (if non-nil) gets the 40 preface bytes once, frame
// gets every completed frame with its kept payload prefix (valid during
// the call).
func (ps *parser) feed(b []byte, preface func([]byte), frame func(h wire.Header, body []byte)) {
	for len(b) > 0 && !ps.bad {
		switch {
		case ps.pn < wire.PrefaceLen:
			k := copy(ps.pre[ps.pn:], b)
			ps.pn += k
			b = b[k:]
			if ps.pn == wire.PrefaceLen && preface != nil {
				preface(ps.pre[:])
			}
		case !ps.in:
			k := copy(ps.hdr[ps.hn:], b)
			ps.hn += k
			b = b[k:]
			if ps.hn < wire.HeaderLen {
				continue
			}
			ps.hn = 0
			h := wire.Header{
				Type:   wire.Type(ps.hdr[0]),
				Flags:  ps.hdr[1],
				Len:    uint32(ps.hdr[2])<<16 | uint32(ps.hdr[3])<<8 | uint32(ps.hdr[4]),
				Fseq:   binary.BigEndian.Uint32(ps.hdr[5:9]),
				Handle: binary.BigEndian.Uint32(ps.hdr[9:13]),
			}
			if h.Len > wire.MaxFramePayload {
				ps.bad = true
				return
			}
			ps.h, ps.in = h, true
			ps.rest = int(h.Len) + wire.TrailerLen
			ps.keep = keepLen(h.Type, int(h.Len))
			ps.body = ps.body[:0]
		default:
			if len(ps.body) < ps.keep {
				k := min(ps.keep-len(ps.body), len(b))
				ps.body = append(ps.body, b[:k]...)
				ps.rest -= k
				b = b[k:]
			} else {
				k := min(ps.rest, len(b))
				ps.rest -= k
				b = b[k:]
			}
			if ps.rest == 0 {
				ps.in = false
				frame(ps.h, ps.body)
			}
		}
	}
}

// keepLen is how much of a frame's payload the parser keeps.
func keepLen(t wire.Type, n int) int {
	switch t {
	case wire.TypeData, wire.TypeFin:
		return min(n, wire.DataPrefixLen)
	case wire.TypeAck:
		return min(n, wire.AckLen)
	case wire.TypePing, wire.TypePong:
		return min(n, 4)
	default:
		return min(n, 512)
	}
}

// decode builds a frame record from a header and its kept payload prefix.
func decode(h wire.Header, body []byte) frame {
	f := frame{typ: h.Type, flags: h.Flags, fseq: h.Fseq, n: int(h.Len)}
	switch h.Type {
	case wire.TypeData, wire.TypeFin:
		if len(body) >= 8 {
			f.off = binary.BigEndian.Uint64(body)
		}
	case wire.TypeAck:
		if a, err := wire.ParseAck(body); err == nil {
			f.ack = a
		}
	case wire.TypeSched:
		if s, err := wire.ParseSched(body); err == nil {
			f.sched = s
		}
	case wire.TypeRst:
		if len(body) >= 4 {
			f.rst = binary.BigEndian.Uint32(body)
		}
	case wire.TypePing, wire.TypePong:
		if len(body) >= 4 {
			f.ping = binary.BigEndian.Uint32(body)
		}
	case wire.TypeJoin:
		if j, err := wire.ParseJoin(body); err == nil {
			f.rx = j.RxNext
		}
	case wire.TypeJoinAck:
		if a, err := wire.ParseJoinAck(body); err == nil {
			f.rx = a.RxNext
		}
	}
	return f
}
