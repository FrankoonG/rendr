package rendrtest

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// harness is a link whose far ends are collected by the test.
type harness struct {
	t   *testing.T
	l   *Link
	acc chan net.Conn
}

func newHarness(t *testing.T, cfg LinkConfig) *harness {
	t.Helper()
	h := &harness{t: t, acc: make(chan net.Conn, 64)}
	cfg.Accept = func(c net.Conn) error {
		h.acc <- c
		return nil
	}
	h.l = NewLink(cfg)
	return h
}

// dial creates one carrier and returns the dialer's and the passive's conn.
func (h *harness) dial() (cli, srv net.Conn) {
	h.t.Helper()
	cli, err := h.l.Dial(context.Background())
	if err != nil {
		h.t.Fatalf("Dial: %v", err)
	}
	return cli, <-h.acc
}

// session dials a carrier and completes PREFACE + OPEN / PREFACE_ACK +
// OPEN_ACK, so both directions are past their first frame.
func (h *harness) session() (cli, srv net.Conn) {
	h.t.Helper()
	cli, srv = h.dial()
	write(h.t, cli, append(prefaceBytes(7), frameBytes(FrameOpen, 1, openPayload())...))
	readN(h.t, srv, wire.PrefaceLen)
	readFrame(h.t, srv)
	write(h.t, srv, append(prefaceAckBytes(7), frameBytes(FrameOpenAck, 1, make([]byte, wire.OpenAckFixedLen))...))
	readN(h.t, cli, wire.PrefaceLen)
	readFrame(h.t, cli)
	return cli, srv
}

// probe dials a carrier whose first frames are PING / PONG.
func (h *harness) probe() (cli, srv net.Conn) {
	h.t.Helper()
	cli, srv = h.dial()
	write(h.t, cli, append(prefaceBytes(8), frameBytes(FramePing, 1, pingPayload(1))...))
	readN(h.t, srv, wire.PrefaceLen)
	readFrame(h.t, srv)
	write(h.t, srv, append(prefaceAckBytes(8), frameBytes(FramePong, 1, pingPayload(1))...))
	readN(h.t, cli, wire.PrefaceLen)
	readFrame(h.t, cli)
	return cli, srv
}

var testInstance = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

func prefaceBytes(id uint32) []byte {
	b := make([]byte, wire.PrefaceLen)
	wire.PutPreface(b, &wire.Preface{Kind: wire.KindStream, Instance: testInstance, CarrierID: id})
	return b
}

func prefaceAckBytes(id uint32) []byte {
	b := make([]byte, wire.PrefaceLen)
	wire.PutPrefaceAck(b, &wire.PrefaceAck{Instance: testInstance, CarrierID: id})
	return b
}

// frameBytes encodes one frame with the M1 handle rule.
func frameBytes(t FrameType, fseq uint32, payload []byte) []byte {
	h := wire.Header{Type: wire.Type(t), Fseq: fseq, Handle: wire.SessionHandle}
	if wire.Type(t).CarrierLevel() {
		h.Handle = 0
	}
	return wire.AppendFrame(nil, h, payload)
}

func openPayload() []byte {
	b := make([]byte, wire.OpenFixedLen)
	wire.PutOpen(b, &wire.Open{SID: testInstance, Kind: wire.KindStream, Mode: 1, RetainMs: 34000, Window: 8 << 20})
	return b
}

func pingPayload(id uint32) []byte {
	b := make([]byte, wire.PingFixedLen)
	wire.PutPing(b, &wire.Ping{ID: id, TS: 99, Nonce: 0xfeed ^ uint64(id)})
	return b
}

func dataPayload(off uint64, body []byte) []byte {
	b := make([]byte, wire.DataPrefixLen, wire.DataPrefixLen+len(body))
	wire.PutDataOffset(b, off)
	return append(b, body...)
}

func ackPayload(delivered uint64) []byte {
	b := make([]byte, wire.AckLen)
	wire.PutAck(b, &wire.Ack{Delivered: delivered, Window: 1 << 20})
	return b
}

func write(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if n, err := c.Write(b); err != nil || n != len(b) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(b))
	}
}

func readN(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if k, err := io.ReadFull(r, b); err != nil {
		t.Fatalf("read %d of %d bytes: %v", k, n, err)
	}
	return b
}

// readFrame reads one frame's raw bytes (header through trailer) without
// validating it.
func readFrame(t *testing.T, r io.Reader) []byte {
	t.Helper()
	h := readN(t, r, wire.HeaderLen)
	n := int(h[2])<<16 | int(h[3])<<8 | int(h[4])
	return append(h, readN(t, r, n+wire.TrailerLen)...)
}

// decodeAll splits a frame stream (after the preface) into decoded frames,
// failing on any invalid frame.
func decodeAll(t *testing.T, b []byte) []wire.Frame {
	t.Helper()
	var fs []wire.Frame
	for len(b) > 0 {
		f, n, err := wire.DecodeFrame(b)
		if err != nil {
			t.Fatalf("frame %d: %v", len(fs), err)
		}
		fs = append(fs, f)
		b = b[n:]
	}
	return fs
}

func fseqOf(frame []byte) uint32 { return binary.BigEndian.Uint32(frame[5:9]) }

// goldenFrames returns every frame vector of internal/wire's golden file
// with its header kept except the fseq, renumbered from first: a stream of
// every frame type and size the wire format defines. Vectors that are not
// exactly one frame (datagrams behind a PREFACE, flow headers) are skipped;
// internal/wire's golden test checks them.
func goldenFrames(t *testing.T, first uint32) [][]byte {
	t.Helper()
	f, err := os.Open("../internal/wire/testdata/golden.txt")
	if err != nil {
		t.Fatalf("golden vectors: %v", err)
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		name, hx, ok := strings.Cut(sc.Text(), " ")
		if !ok || strings.HasPrefix(name, "#") || strings.HasPrefix(name, "preface") {
			continue
		}
		b, err := hex.DecodeString(hx)
		if err != nil {
			t.Fatalf("golden %s: %v", name, err)
		}
		fr, n, err := wire.DecodeFrame(b)
		if err != nil || n != len(b) {
			continue
		}
		fr.Fseq = first + uint32(len(out))
		out = append(out, wire.AppendFrame(nil, fr.Header, fr.Payload))
	}
	if err := sc.Err(); err != nil || len(out) < 50 {
		t.Fatalf("golden vectors: %d frames, %v", len(out), err)
	}
	return out
}

// chunked writes b to w in pieces of random size (1..max bytes).
func chunked(t *testing.T, w io.Writer, b []byte, seed uint64, maxPiece int) {
	t.Helper()
	r := rand.New(rand.NewPCG(seed, seed+1))
	for len(b) > 0 {
		n := min(len(b), 1+r.IntN(maxPiece))
		if k, err := w.Write(b[:n]); err != nil || k != n {
			t.Fatalf("Write = (%d, %v), want (%d, nil)", k, err, n)
		}
		b = b[n:]
	}
}

// readAsync reads from r in the background; done is closed when r fails.
type readAsync struct {
	mu   sync.Mutex
	buf  []byte
	at   []time.Time // arrival time of every byte
	err  error
	done chan struct{}
}

func readBackground(r io.Reader) *readAsync {
	a := &readAsync{done: make(chan struct{})}
	go func() {
		defer close(a.done)
		b := make([]byte, 64<<10)
		for {
			n, err := r.Read(b)
			now := time.Now()
			a.mu.Lock()
			a.buf = append(a.buf, b[:max(n, 0)]...)
			for range max(n, 0) {
				a.at = append(a.at, now)
			}
			if err != nil {
				a.err = err
			}
			a.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return a
}

// bytes returns a copy of what arrived so far.
func (a *readAsync) bytes() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.buf)
}

// times returns the arrival time of every byte so far.
func (a *readAsync) times() []time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.at)
}

// result waits for the reader to end and returns what it read and why it
// stopped.
func (a *readAsync) result() ([]byte, error) {
	<-a.done
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.buf, a.err
}
