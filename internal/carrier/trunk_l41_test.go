package carrier

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The recorded M2 traces of TestDedicatedWriterBytesUnchanged_L41: the
// SHA-256 of every byte a dedicated carrier wrote and of every delivery its
// endpoint saw in two fixed scripts, recorded with this file on the M2
// carrier code (the M2 merge on v2 and the M3 skeleton, which moved no
// field: both give these values at GOMAXPROCS 1 and 4) before the
// trunk/view split. A change of the writer's bytes or of the reader's
// deliveries on a one-view trunk changes them (149,932 bytes written and
// 2 deliveries in the stream script; 19,233 bytes of length-prefixed
// datagrams and 3 deliveries in the datagram script).
const (
	l41StreamWire = "69aa7f2ab2b4210f77a2eed8a2e5c735829b2a8dda0b2cf1a20c95b4ef25ed0f"
	l41StreamRx   = "a149ad7c129f2c9e911f13d61deefa42b2d21523a8e0de9f81feb1a575ffd91f"
	l41DgramWire  = "05a74636e973b96ca58c26e02efeffc5bcca79401a44ae054061ca52a6cdba6e"
	l41DgramRx    = "59c050993e7bd1db57d1aeed6a76c797444c4dfbc1464e1d5f225d412331c5c6"
)

// l41Salt replaces a carrier's random PING nonce salt, so its PINGs are the
// same in every run.
const l41Salt = 0x5a17_c0de_0b5e_55ed

// l41EP is the scripted endpoint of the trace scripts: Fill places a due
// ACK or PACK, then the offered DATA (stream) or datagrams (packet), then a
// FIN once asked; Data, Datagram and Control append a record of what
// arrived to log and ask for an ACK or PACK. It implements PacketEndpoint
// only through l41PacketEP, so the stream script's carrier sees a stream
// session.
type l41EP struct {
	mu      sync.Mutex
	chunk   *Buf
	next    uint64 // the next stream offset or datagram seq to place
	end     uint64 // offered up to here
	fin     bool   // place a FIN at end once everything was placed
	finSent bool
	ackDue  bool
	rxEnd   uint64 // the end of the highest DATA received (the ACK's Delivered)
	rxN     uint64 // datagrams received (the PACK's Received)
	rxHigh  uint64
	log     []byte
}

func (e *l41EP) Handle() uint32 { return wire.SessionHandle }

func (e *l41EP) Fill(c *Conn, b *Batch) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ackDue {
		if b.Datagram() {
			if !b.AddPack(wire.SessionHandle, 0, &wire.Pack{HighestSeq: e.rxHigh, Received: e.rxN}, false) {
				return
			}
		} else if !b.AddAck(wire.SessionHandle, 0, &wire.Ack{Delivered: e.rxEnd, Window: 1 << 20}) {
			return
		}
		e.ackDue = false
	}
	for e.next < e.end {
		if b.Datagram() {
			n := 200 + int(e.next%7)*100
			if !b.AddDgram(wire.SessionHandle, e.next, e.chunk.B[:n], nil) {
				return
			}
			e.next++
			continue
		}
		in := int(e.next % ChunkSize)
		n := min(1400, int(e.end-e.next), ChunkSize-in, b.Room())
		if n <= 0 || !b.AddData(wire.SessionHandle, e.next, e.chunk.B[in:in+n], e.chunk, false) {
			return
		}
		e.next += uint64(n)
	}
	if e.fin && !e.finSent && !b.Datagram() && b.AddFin(wire.SessionHandle, e.end) {
		e.finSent = true
	}
}

func (e *l41EP) record(kind byte, a, n uint64, byRef bool) {
	var r [18]byte
	r[0] = kind
	binary.BigEndian.PutUint64(r[1:9], a)
	binary.BigEndian.PutUint64(r[9:17], n)
	if byRef {
		r[17] = 1
	}
	e.log = append(e.log, r[:]...)
}

func (e *l41EP) Data(c *Conn, off uint64, p []byte, buf *Buf) error {
	e.mu.Lock()
	e.record('D', off, uint64(len(p)), buf != nil)
	e.rxEnd = max(e.rxEnd, off+uint64(len(p)))
	e.ackDue = true
	e.mu.Unlock()
	buf.Release()
	c.Wake()
	return nil
}

func (e *l41EP) Control(c *Conn, h wire.Header, p []byte) error {
	e.mu.Lock()
	e.record('C', uint64(h.Type), uint64(len(p)), false)
	e.mu.Unlock()
	return nil
}

func (e *l41EP) WriteBlocked(c *Conn) {}

func (e *l41EP) offer(n uint64, fin bool) {
	e.mu.Lock()
	e.end += n
	e.fin = fin
	e.mu.Unlock()
}

func (e *l41EP) rxLog() []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]byte(nil), e.log...)
}

// l41PacketEP is l41EP as a packet session's endpoint.
type l41PacketEP struct{ l41EP }

func (e *l41PacketEP) Datagram(c *Conn, seq uint64, p []byte, buf *Buf) error {
	e.mu.Lock()
	e.record('G', seq, uint64(len(p)), buf != nil)
	e.rxN++
	e.rxHigh = max(e.rxHigh, seq)
	e.ackDue = true
	e.mu.Unlock()
	buf.Release()
	// No Wake here: the script wakes the writer once the whole peer
	// datagram was dispatched. A wake per frame let the writer run between
	// two frames of one datagram under load (an extra PACK), so the trace
	// was not deterministic.
	return nil
}

func l41Hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// l41Stream runs the stream script and returns the bytes the carrier wrote
// and its endpoint's delivery log. A dedicated passive carrier over a
// net.Pipe in a bubble (every step settles before the next, so the trace
// is the same in every run and at every GOMAXPROCS): the first PING at
// Start, answered by the peer 5 ms later (every PING is); 40,000 bytes of
// DATA; 7,000 more bytes that wait for the round the peer's PING wakes
// (its PONG first, then the DATA); the peer's 3,000 and 20,000 bytes (the second read by reference,
// ≥ BigData) acknowledged by the endpoint; a cadence PING while DATA is in
// flight; 100,000 more bytes and a FIN; then a planned retirement whose
// CLOSE the peer answers with its own.
func l41Stream(t *testing.T) (wireBytes, rx []byte) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		var mu sync.Mutex
		var out []byte
		rec := func(nc net.Conn) net.Conn {
			return &hookConn{Conn: nc, onWrite: func(nc net.Conn, p []byte) (int, error) {
				mu.Lock()
				out = append(out, p...)
				mu.Unlock()
				return nc.Write(p)
			}}
		}
		c, p := hPair(t, env, rec)
		c.salt = l41Salt
		p.autoPong(func(uint32) time.Duration { return 5 * time.Millisecond })
		ep := &l41EP{chunk: env.Bufs.Get(ChunkSize, nil)}
		defer ep.chunk.Release()
		for i := range ep.chunk.B {
			ep.chunk.B[i] = byte(i*13 + 5)
		}
		c.Start(ep, &hBell{}, StartOptions{})
		synctest.Wait()
		time.Sleep(time.Millisecond)
		ep.offer(40000, false)
		c.Wake()
		synctest.Wait()
		time.Sleep(3 * time.Millisecond)
		// Endpoint data waits unannounced; the peer's PING wakes the writer,
		// whose round carries the PONG and then the DATA.
		ep.offer(7000, false)
		if err := p.ping(77, true); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(14 * time.Millisecond)
		if err := p.send(wire.TypeData, 0, wire.SessionHandle, dataPayload(0, 3000)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(13 * time.Millisecond)
		if err := p.send(wire.TypeData, 0, wire.SessionHandle, dataPayload(3000, 20000)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(61 * time.Millisecond) // past PingBusy: a cadence PING
		ep.offer(100000, true)
		c.Wake()
		synctest.Wait()
		time.Sleep(29 * time.Millisecond)
		c.Retire(wire.CloseRetire)
		synctest.Wait()
		if err := p.send(wire.TypeClose, 0, 0, []byte{byte(wire.CloseRetire)}); err != nil {
			t.Fatal(err)
		}
		hWait(t, c)
		if _, cause, detail, _ := c.Death(); cause != CauseRetired {
			t.Fatalf("the script ended %v (%s), want retired", cause, detail)
		}
		mu.Lock()
		wireBytes = append([]byte(nil), out...)
		mu.Unlock()
		rx = ep.rxLog()
	})
	return wireBytes, rx
}

// l41Dgram runs the datagram script and returns every datagram the carrier
// wrote (each with its length) and its endpoint's delivery log: a
// dedicated dialer datagram carrier on a lossless in-memory link, a raw
// peer answering each PING with its PONG; 12 datagrams of the endpoint;
// 5 more that wait for the round the peer's PING wakes (its PONG first);
// the peer's DGRAMs acknowledged by PACKs; a cadence PING; 20 more
// datagrams; then a kill.
func l41Dgram(t *testing.T) (wireBytes, rx []byte) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.c.salt = l41Salt
		s.io.setRec(true)
		ep := &l41PacketEP{l41EP{chunk: s.env.Bufs.Get(ChunkSize, nil)}}
		defer ep.chunk.Release()
		for i := range ep.chunk.B {
			ep.chunk.B[i] = byte(i*13 + 5)
		}
		pong := func() {
			for _, d := range p.read() {
				for len(d) > 0 {
					f, n, err := wire.DecodeFrame(d)
					if err != nil {
						t.Fatalf("carrier datagram: %v", err)
					}
					d = d[n:]
					if f.Type != wire.TypePing {
						continue
					}
					pg, err := wire.ParsePing(f.Payload)
					if err != nil {
						t.Fatal(err)
					}
					if pg.ID == 0 {
						continue
					}
					pg.Pad = 0
					p.send(rawFrame{t: wire.TypePong, payload: pingPayload(pg)})
				}
			}
		}
		dgram := func(seq uint64, n int) rawFrame {
			b := make([]byte, wire.DgramPrefixLen+n)
			wire.PutDgramSeq(b, seq)
			for i := range n {
				b[wire.DgramPrefixLen+i] = byte(int(seq) + i)
			}
			return rawFrame{t: wire.TypeDgram, handle: wire.SessionHandle, payload: b}
		}
		s.c.Start(ep, s.bell, StartOptions{})
		synctest.Wait()
		time.Sleep(5 * time.Millisecond)
		pong()
		synctest.Wait()
		time.Sleep(time.Millisecond)
		ep.offer(12, false)
		s.c.Wake()
		synctest.Wait()
		time.Sleep(3 * time.Millisecond)
		// Endpoint datagrams wait unannounced; the peer's PING wakes the
		// writer, whose round carries the PONG and then the DGRAMs.
		ep.offer(5, false)
		p.send(rawFrame{t: wire.TypePing, payload: pingPayload(wire.Ping{ID: 77, Nonce: 99})})
		synctest.Wait()
		time.Sleep(14 * time.Millisecond)
		p.send(dgram(1, 300), dgram(2, 500))
		synctest.Wait()
		s.c.Wake() // one PACK for both (l41PacketEP.Datagram)
		synctest.Wait()
		time.Sleep(13 * time.Millisecond)
		p.send(dgram(3, 1100))
		synctest.Wait()
		s.c.Wake()
		synctest.Wait()
		pong()
		synctest.Wait()
		time.Sleep(61 * time.Millisecond)
		ep.offer(20, false)
		s.c.Wake()
		synctest.Wait()
		time.Sleep(5 * time.Millisecond)
		pong()
		synctest.Wait()
		time.Sleep(29 * time.Millisecond)
		s.c.Kill(CauseLocalClose, "script end")
		hWait(t, s.c)
		for _, w := range s.io.recorded() {
			var n [4]byte
			binary.BigEndian.PutUint32(n[:], uint32(len(w.b)))
			wireBytes = append(wireBytes, n[:]...)
			wireBytes = append(wireBytes, w.b...)
		}
		rx = ep.rxLog()
	})
	return wireBytes, rx
}

// TestDedicatedWriterBytesUnchanged_L41 (WP7, M3 design §A11.1; L41: the
// trunk/view split is behaviour-neutral): a dedicated carrier — a trunk
// with its one view — writes byte for byte the frames M2's carrier wrote
// and delivers the same frames to its endpoint in two fixed scripts, a
// stream carrier (DATA, ACK, PING and PONG, a FIN, the CLOSE exchange; big
// DATA by reference) and a datagram carrier (DGRAM, PACK, PING and PONG).
// Each script runs twice, so a trace that is not
// deterministic fails here rather than against the recording.
func TestDedicatedWriterBytesUnchanged_L41(t *testing.T) {
	scripts := []struct {
		name         string
		run          func(*testing.T) ([]byte, []byte)
		wantW, wantR string
	}{
		{"stream", l41Stream, l41StreamWire, l41StreamRx},
		{"datagram", l41Dgram, l41DgramWire, l41DgramRx},
	}
	for _, sc := range scripts {
		t.Run(sc.name, func(t *testing.T) {
			w1, r1 := sc.run(t)
			w2, r2 := sc.run(t)
			if t.Failed() {
				return
			}
			if l41Hash(w1) != l41Hash(w2) || l41Hash(r1) != l41Hash(r2) {
				t.Fatalf("the script is not deterministic: %d/%d bytes written, %d/%d bytes of deliveries", len(w1), len(w2), len(r1), len(r2))
			}
			if len(w1) == 0 || len(r1) == 0 {
				t.Fatalf("an empty trace: %d bytes written, %d bytes of deliveries", len(w1), len(r1))
			}
			if got := l41Hash(w1); got != sc.wantW {
				t.Errorf("%d bytes written: sha256 %s, the recorded M2 trace is %s", len(w1), got, sc.wantW)
			}
			if got := l41Hash(r1); got != sc.wantR {
				t.Errorf("%d bytes of deliveries: sha256 %s, the recorded M2 trace is %s", len(r1), got, sc.wantR)
			}
		})
	}
}
