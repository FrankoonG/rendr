package l4u

import (
	"encoding/binary"
	"hash/crc32"
	"math"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The Moonlight-like profile ML-100 (M6 design §B3.1) at 1/20 of its video
// rate, in process: a host (the target applications of the video, audio
// and control ports) and a client (three ingress clients), with the
// profile's frame, audio-block and control judges. Every datagram carries
// F80's 28-byte header — flow tag, seq, frame (or block, or message) id,
// block and shard index, the block's data and parity shard counts, the
// send instant, a CRC-32C over header and payload, the frame's block
// count and a flags byte — so the judges see every loss, duplicate,
// corruption and delay per flow and direction.

// Profile ports (Sunshine's defaults) and flow tags.
const (
	mlVideoPort = 47998
	mlCtlPort   = 47999
	mlAudioPort = 48000

	tagVideo     = 1 // host → client: video shards
	tagAudio     = 2 // host → client: audio shards
	tagCtlUp     = 3 // client → host: reliable messages, IDR requests, keepalives
	tagCtlDown   = 4 // host → client: acks, feedback, keepalives
	tagVideoPing = 5 // client → host on the video port
	tagAudioPing = 6 // client → host on the audio port
)

// Profile parameters (§B3.1 at 1/20: 5 Mbit/s of video).
const (
	mlHdr         = 28
	mlFPS         = 60
	mlInterval    = time.Second / mlFPS
	mlVideoBps    = 5e6
	mlMeanFrame   = mlVideoBps / 8 / mlFPS // 10,416.7 bytes
	mlShard       = 1408                   // a video datagram: 16-byte shard header + 1,392 payload bytes
	mlShardData   = 1392
	mlBlockData   = 212 // data shards per FEC block at most
	mlParity      = 0.2
	mlIDREvery    = 600 // frames
	mlIDRScale    = 4
	mlIDRGap      = 500 * time.Millisecond // no IDR starts within this of another IDR's start
	mlSigma       = 0.25
	mlPing        = 500 * time.Millisecond
	mlAudioBlock  = 20 * time.Millisecond // 4 data + 2 parity shards of 220 bytes: 300 pps
	mlAudioSize   = 220
	mlMsgRate     = 250 // client → host reliable messages per second, 48 bytes
	mlMsgSize     = 48
	mlAckSize     = 40
	mlFeedback    = 100 * time.Millisecond // host → client feedback, 256 bytes
	mlFeedSize    = 256
	mlKeepalive   = 500 * time.Millisecond // 32 bytes each way
	mlKeepSize    = 32
	mlDisconnect  = 10 * time.Second // either side declares "disconnected" after this long without a datagram
	mlRTOInit     = 500 * time.Millisecond
	mlRTOMin      = 100 * time.Millisecond
	mlJudgeTick   = 5 * time.Millisecond
	mlPreDeadline = 50 * time.Millisecond // the frame deadline before Q's latencies set it
)

// Control datagram kinds (mlHead.block on the control flows).
const (
	ctlMsg = iota + 1
	ctlIDR
	ctlKeep
	ctlAck
	ctlFeed
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// mlHead is a profile datagram's header.
type mlHead struct {
	tag                uint16
	seq                uint32
	id                 uint32 // video: frame id; audio: block id; control: message id
	block, shard, d, p uint8  // FEC position and shape; control: the kind in block
	sent               time.Time
	blocks             uint8 // video: the frame's block count; control: the transmission number
	flags              uint8 // video: 1 = IDR
}

// mlPut builds a profile datagram of size bytes (≥ mlHdr) in b.
func mlPut(b []byte, size int, h mlHead) []byte {
	if cap(b) < size {
		b = make([]byte, size)
	}
	b = b[:size]
	binary.BigEndian.PutUint16(b[0:], h.tag)
	binary.BigEndian.PutUint32(b[2:], h.seq)
	binary.BigEndian.PutUint32(b[6:], h.id)
	b[10], b[11], b[12], b[13] = h.block, h.shard, h.d, h.p
	binary.BigEndian.PutUint64(b[14:], uint64(h.sent.UnixNano()))
	clear(b[22:26])
	b[26], b[27] = h.blocks, h.flags
	for i := mlHdr; i < size; i++ {
		b[i] = byte(uint32(i)*7 + h.seq)
	}
	binary.BigEndian.PutUint32(b[22:], crc32.Checksum(b, crcTable))
	return b
}

// mlParse checks b's CRC and returns its header.
func mlParse(b []byte) (mlHead, bool) {
	if len(b) < mlHdr {
		return mlHead{}, false
	}
	want := binary.BigEndian.Uint32(b[22:])
	var zero [4]byte
	crc := crc32.Update(crc32.Update(crc32.Checksum(b[:22], crcTable), crcTable, zero[:]), crcTable, b[26:])
	if crc != want {
		return mlHead{}, false
	}
	return mlHead{tag: binary.BigEndian.Uint16(b[0:]), seq: binary.BigEndian.Uint32(b[2:]), id: binary.BigEndian.Uint32(b[6:]),
		block: b[10], shard: b[11], d: b[12], p: b[13], sent: time.Unix(0, int64(binary.BigEndian.Uint64(b[14:]))),
		blocks: b[26], flags: b[27]}, true
}

// mlFlow is one direction of one profile flow: its ledger and its seq.
type mlFlow struct {
	*ledger
	tag  uint16
	next atomic.Uint32
	bad  atomic.Int64 // datagrams of this flow that failed their CRC or came with another tag
}

func newMLFlow(name string, tag uint16) *mlFlow {
	return &mlFlow{ledger: newLedger(name, uint64(tag)), tag: tag}
}

// send builds and writes the flow's next datagram.
func (f *mlFlow) send(wr interface{ Write([]byte) (int, error) }, buf []byte, size int, h mlHead) {
	h.tag, h.seq, h.sent = f.tag, f.next.Add(1)-1, time.Now()
	f.sentAt(uint64(h.seq), h.sent)
	wr.Write(mlPut(buf, size, h))
}

// recv parses one received datagram of the flow, records its arrival and
// returns its header.
func (f *mlFlow) recv(b []byte, at time.Time) (mlHead, bool) {
	h, ok := mlParse(b)
	if !ok || h.tag != f.tag {
		f.bad.Add(1)
		return h, false
	}
	f.arrivedAt(uint64(h.seq), at)
	return h, true
}

// mlFrame is one video frame as the host sent it.
type mlFrame struct {
	id     uint32
	start  time.Time
	idr    bool
	seq0   uint32  // its first datagram's seq
	blocks []uint8 // each block's data shard count
	shards []int   // each block's shard count (data + parity)
}

// mlMsg is one reliable control message as the client sent it.
type mlMsg struct {
	first, last time.Time // first and latest transmission
	acked       time.Time
	tries       int
	rto         time.Duration
	idr         bool
}

// mlRun is one profile run: the host's and the client's state and the
// flows' ledgers.
type mlRun struct {
	quit <-chan struct{} // the world's
	stop chan struct{}   // closed to end the profile's traffic
	wg   sync.WaitGroup  // every profile goroutine
	rng  *rand.Rand      // frame sizes (the host's video goroutine only)

	vDown, aDown, cDown *mlFlow // host → client
	vUp, aUp, cUp       *mlFlow // client → host

	deadline atomic.Int64 // the frame deadline offset in force (ns)

	mu        sync.Mutex
	frames    []mlFrame
	idrWant   bool      // a requested IDR is pending
	lastIDR   time.Time // the latest IDR's start
	idrReqs   int       // IDR requests the host received
	audio     []mlFrame // audio blocks as sent (one block each)
	msgs      []*mlMsg
	srtt      time.Duration
	rttvar    time.Duration
	haveRTT   bool
	retx      []time.Time // first-send instants of retransmitted messages, one per retransmission
	cliLast   time.Time   // the client's latest control datagram from the host
	hostLast  time.Time
	cliGap    time.Duration
	hostGap   time.Duration
	disc      int // "disconnected" verdicts
	judged    map[uint32]bool
	requested int // IDR requests the client sent

	cMu  sync.Mutex // the control client's writers (messages, retransmissions, IDR requests, keepalives)
	cBuf [512]byte
}

func newMLRun(quit <-chan struct{}) *mlRun {
	m := &mlRun{quit: quit, stop: make(chan struct{}), rng: rand.New(rand.NewPCG(0x4d4c, 100)), judged: map[uint32]bool{},
		vDown: newMLFlow("video host → client", tagVideo), aDown: newMLFlow("audio host → client", tagAudio),
		cDown: newMLFlow("control host → client", tagCtlDown), vUp: newMLFlow("video client → host", tagVideoPing),
		aUp: newMLFlow("audio client → host", tagAudioPing), cUp: newMLFlow("control client → host", tagCtlUp)}
	m.deadline.Store(int64(mlPreDeadline))
	return m
}

// tick waits until at; false when the run is stopping.
func (m *mlRun) tick(at time.Time) bool {
	select {
	case <-m.stop:
		return false
	default:
	}
	d := time.Until(at)
	if d <= 0 {
		return true
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-tm.C:
		return true
	case <-m.stop:
		return false
	case <-m.quit:
		return false
	}
}

// go_ runs f as a profile goroutine.
func (m *mlRun) go_(f func()) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		f()
	}()
}

// end stops the profile's traffic and waits for its goroutines.
func (m *mlRun) end() {
	close(m.stop)
	m.wg.Wait()
}

// Host side.

// hostVideo is the video port's target: it streams frames to the source
// of the port's first datagram (learn-and-stream) once a ping arrived.
func (m *mlRun) hostVideo(e *egress) {
	buf := make([]byte, 2048)
	started := false
	for {
		n, err := e.conn.Read(buf)
		if err != nil {
			return
		}
		if _, ok := m.vUp.recv(buf[:n], time.Now()); ok && !started {
			started = true
			m.go_(func() { m.videoLoop(e) })
		}
	}
}

// videoLoop sends a frame every mlInterval on an absolute schedule.
func (m *mlRun) videoLoop(e *egress) {
	t0 := time.Now()
	buf := make([]byte, mlShard)
	for k := uint32(0); m.tick(t0.Add(time.Duration(k) * mlInterval)); k++ {
		now := time.Now()
		m.mu.Lock()
		idr := k%mlIDREvery == 0
		if !idr && m.idrWant && (m.lastIDR.IsZero() || now.Sub(m.lastIDR) >= mlIDRGap) {
			idr, m.idrWant = true, false
		}
		if idr {
			m.lastIDR = now
		}
		m.mu.Unlock()
		size := mlMeanFrame * math.Exp(mlSigma*m.rng.NormFloat64()-mlSigma*mlSigma/2)
		size = min(max(size, 0.25*mlMeanFrame), 3*mlMeanFrame)
		if idr {
			size = mlIDRScale * mlMeanFrame
		}
		data := int(math.Ceil(size / mlShardData))
		fr := mlFrame{id: k, start: now, idr: idr, seq0: m.vDown.next.Load()}
		for left := data; left > 0; left -= mlBlockData {
			d := min(left, mlBlockData)
			fr.blocks = append(fr.blocks, uint8(d))
			fr.shards = append(fr.shards, d+int(math.Ceil(mlParity*float64(d))))
		}
		m.mu.Lock()
		m.frames = append(m.frames, fr)
		m.mu.Unlock()
		var flags uint8
		if idr {
			flags = 1
		}
		for b, d := range fr.blocks {
			for s := range fr.shards[b] {
				m.vDown.send(e.conn, buf, mlShard, mlHead{id: k, block: uint8(b), shard: uint8(s), d: d,
					p: uint8(fr.shards[b] - int(d)), blocks: uint8(len(fr.blocks)), flags: flags})
			}
		}
	}
}

// hostAudio is the audio port's target: blocks of 4 data and 2 parity
// shards every 20 ms once a ping arrived.
func (m *mlRun) hostAudio(e *egress) {
	buf := make([]byte, 2048)
	started := false
	for {
		n, err := e.conn.Read(buf)
		if err != nil {
			return
		}
		if _, ok := m.aUp.recv(buf[:n], time.Now()); ok && !started {
			started = true
			m.go_(func() {
				t0 := time.Now()
				out := make([]byte, mlAudioSize)
				for k := uint32(0); m.tick(t0.Add(time.Duration(k) * mlAudioBlock)); k++ {
					fr := mlFrame{id: k, start: time.Now(), seq0: m.aDown.next.Load(), blocks: []uint8{4}, shards: []int{6}}
					m.mu.Lock()
					m.audio = append(m.audio, fr)
					m.mu.Unlock()
					for s := range 6 {
						m.aDown.send(e.conn, out, mlAudioSize, mlHead{id: k, shard: uint8(s), d: 4, p: 2, blocks: 1})
					}
				}
			})
		}
	}
}

// hostControl is the control port's target: it acks every message and IDR
// request, takes IDR requests to the video loop (coalesced: one pending at
// a time), sends feedback and keepalives, and watches the client's
// silence.
func (m *mlRun) hostControl(e *egress) {
	buf := make([]byte, 2048)
	out := make([]byte, 512)
	var wmu sync.Mutex // the acks (this goroutine) and the feedback goroutine write e.conn
	started := false
	for {
		n, err := e.conn.Read(buf)
		if err != nil {
			return
		}
		now := time.Now()
		h, ok := m.cUp.recv(buf[:n], now)
		if !ok {
			continue
		}
		m.mu.Lock()
		if !m.hostLast.IsZero() {
			m.hostGap = max(m.hostGap, now.Sub(m.hostLast))
		}
		m.hostLast = now
		if h.block == ctlIDR {
			m.idrReqs++
			m.idrWant = true
		}
		m.mu.Unlock()
		if h.block == ctlMsg || h.block == ctlIDR {
			wmu.Lock()
			m.cDown.send(e.conn, out, mlAckSize, mlHead{id: h.id, block: ctlAck, blocks: h.blocks})
			wmu.Unlock()
		}
		if !started {
			started = true
			m.go_(func() {
				t0 := time.Now()
				o := make([]byte, 512)
				for k := 1; m.tick(t0.Add(time.Duration(k) * mlFeedback)); k++ {
					wmu.Lock()
					m.cDown.send(e.conn, o, mlFeedSize, mlHead{block: ctlFeed})
					if k%int(mlKeepalive/mlFeedback) == 0 {
						m.cDown.send(e.conn, o, mlKeepSize, mlHead{block: ctlKeep})
					}
					wmu.Unlock()
				}
			})
		}
	}
}

// Client side.

// clientPing sends a ping every mlPing on c (the first at once: it rides
// the OPEN) and reads what the host sends into recv.
func (m *mlRun) clientPing(c *rendrtest.DatagramConn, up *mlFlow, recv func(b []byte, at time.Time)) {
	m.go_(func() {
		buf := make([]byte, mlKeepSize)
		t0 := time.Now()
		for k := 0; m.tick(t0.Add(time.Duration(k) * mlPing)); k++ {
			up.send(c, buf, mlKeepSize, mlHead{})
		}
	})
	readAll(c, recv)
}

// readAll reads c until it fails (the kit closes the clients at shutdown)
// and hands each datagram to recv. It is not one of the profile's
// goroutines: it outlives end, so that the last datagrams still arrive.
func readAll(c *rendrtest.DatagramConn, recv func(b []byte, at time.Time)) {
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			recv(buf[:n], time.Now())
		}
	}()
}

// clientVideo runs the video client: pings, shard arrivals, and the frame
// judge's live part — a frame incomplete at its deadline asks the host for
// an IDR (a reliable control message).
func (m *mlRun) clientVideo(c *rendrtest.DatagramConn, ctl *rendrtest.DatagramConn) {
	m.clientPing(c, m.vUp, func(b []byte, at time.Time) { m.vDown.recv(b, at) })
	m.go_(func() {
		t0 := time.Now()
		for k := 1; m.tick(t0.Add(time.Duration(k) * mlJudgeTick)); k++ {
			for range m.lateIncomplete(time.Now()) {
				m.sendMsg(ctl, true)
			}
		}
	})
}

// lateIncomplete returns the frames whose deadline passed at now that the
// client judged for the first time and found incomplete. The client knows
// a frame by its shards; a frame none of whose shards arrived is found by
// the gap in frame ids (the host's schedule is absolute).
func (m *mlRun) lateIncomplete(now time.Time) []uint32 {
	m.mu.Lock()
	frames := m.frames // the host's record stands in for the client's view of frame ids and starts
	var out []uint32
	off := time.Duration(m.deadline.Load())
	for i := len(frames) - 1; i >= 0; i-- {
		fr := frames[i]
		if m.judged[fr.id] {
			break
		}
		if now.Before(fr.start.Add(off)) {
			continue
		}
		m.judged[fr.id] = true
		m.mu.Unlock()
		ok, _ := m.frameDone(fr, fr.start.Add(off))
		m.mu.Lock()
		if !ok {
			out = append(out, fr.id)
		}
	}
	m.mu.Unlock()
	return out
}

// frameDone reports whether every block of fr had at least its data shard
// count of distinct shards by the deadline, and when the last block
// completed.
func (m *mlRun) frameDone(fr mlFrame, deadline time.Time) (bool, time.Time) {
	return blocksDone(m.vDown.ledger, fr, deadline)
}

// blocksDone is frameDone over any flow's ledger.
func blocksDone(l *ledger, fr mlFrame, deadline time.Time) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var done time.Time
	seq := int(fr.seq0)
	for b, d := range fr.blocks {
		var arr []time.Time
		for s := range fr.shards[b] {
			if q := seq + s; q < len(l.arr) && !l.arr[q].IsZero() && !l.arr[q].After(deadline) {
				arr = append(arr, l.arr[q])
			}
		}
		seq += fr.shards[b]
		if len(arr) < int(d) {
			return false, time.Time{}
		}
		slices.SortFunc(arr, func(a, b time.Time) int { return a.Compare(b) })
		done = maxTime(done, arr[d-1])
	}
	return true, done
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// clientAudio runs the audio client.
func (m *mlRun) clientAudio(c *rendrtest.DatagramConn) {
	m.clientPing(c, m.aUp, func(b []byte, at time.Time) { m.aDown.recv(b, at) })
}

// clientControl runs the control client: 250 reliable messages per second
// with ENet's retransmission (RTO = max(srtt + 4·rttvar, 100 ms), 500 ms
// before the first sample, doubling per retry, until acked), a keepalive
// every 500 ms, and the host's acks, feedback and keepalives.
func (m *mlRun) clientControl(c *rendrtest.DatagramConn) {
	m.go_(func() { // messages and keepalives
		t0 := time.Now()
		step := time.Second / mlMsgRate
		for k := 0; m.tick(t0.Add(time.Duration(k) * step)); k++ {
			m.sendMsg(c, false)
			if k%int(mlKeepalive/step) == 0 {
				m.cMu.Lock()
				m.cUp.send(c, m.cBuf[:], mlKeepSize, mlHead{block: ctlKeep})
				m.cMu.Unlock()
			}
		}
	})
	m.go_(func() { // retransmissions
		t0 := time.Now()
		for k := 1; m.tick(t0.Add(time.Duration(k) * 10 * time.Millisecond)); k++ {
			now := time.Now()
			m.mu.Lock()
			var due []uint32
			for id, g := range m.msgs {
				if g.acked.IsZero() && !now.Before(g.last.Add(g.rto)) {
					due = append(due, uint32(id))
					g.tries++
					g.last = now
					g.rto *= 2
					m.retx = append(m.retx, g.first)
				}
			}
			m.mu.Unlock()
			for _, id := range due {
				m.transmit(c, id)
			}
		}
	})
	readAll(c, func(b []byte, now time.Time) { // the host's datagrams
		{
			h, ok := m.cDown.recv(b, now)
			if !ok {
				return
			}
			m.mu.Lock()
			if !m.cliLast.IsZero() {
				m.cliGap = max(m.cliGap, now.Sub(m.cliLast))
			}
			m.cliLast = now
			if h.block == ctlAck && int(h.id) < len(m.msgs) {
				g := m.msgs[h.id]
				if g.acked.IsZero() {
					g.acked = now
					if g.tries == 0 { // Karn: no sample from a retransmitted message
						m.rttSampleLocked(now.Sub(g.first))
					}
				}
			}
			m.mu.Unlock()
		}
	})
}

// sendMsg sends a new reliable message (an IDR request when idr).
func (m *mlRun) sendMsg(c *rendrtest.DatagramConn, idr bool) {
	now := time.Now()
	m.mu.Lock()
	rto := mlRTOInit
	if m.haveRTT {
		rto = max(m.srtt+4*m.rttvar, mlRTOMin)
	}
	m.msgs = append(m.msgs, &mlMsg{first: now, last: now, rto: rto, idr: idr})
	id := uint32(len(m.msgs) - 1)
	if idr {
		m.requested++
	}
	m.mu.Unlock()
	m.transmit(c, id)
}

// transmit sends message id's current transmission.
func (m *mlRun) transmit(c *rendrtest.DatagramConn, id uint32) {
	m.mu.Lock()
	g := m.msgs[id]
	kind, tries := uint8(ctlMsg), g.tries
	if g.idr {
		kind = ctlIDR
	}
	m.mu.Unlock()
	m.cMu.Lock()
	m.cUp.send(c, m.cBuf[:], mlMsgSize, mlHead{id: id, block: kind, blocks: uint8(min(tries, 255))})
	m.cMu.Unlock()
}

// rttSampleLocked folds one RTT sample in (RFC 6298's estimator).
func (m *mlRun) rttSampleLocked(r time.Duration) {
	if !m.haveRTT {
		m.srtt, m.rttvar, m.haveRTT = r, r/2, true
		return
	}
	d := m.srtt - r
	if d < 0 {
		d = -d
	}
	m.rttvar = (3*m.rttvar + d) / 4
	m.srtt = (7*m.srtt + r) / 8
}
