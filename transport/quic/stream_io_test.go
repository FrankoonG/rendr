package quic

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
)

type recordingQUICStream struct {
	mu       sync.Mutex
	input    bytes.Buffer
	writes   [][]byte
	shortBy  int
	writeErr error
	closed   bool
}

func (s *recordingQUICStream) Read(payload []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.input.Read(payload)
}

func (s *recordingQUICStream) Write(payload []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyOfPayload := append([]byte(nil), payload...)
	s.writes = append(s.writes, copyOfPayload)
	n := len(payload) - s.shortBy
	if n < 0 {
		n = 0
	}
	return n, s.writeErr
}

func (s *recordingQUICStream) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *recordingQUICStream) appendFrames(frames ...[]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, frame := range frames {
		var prefix [LengthPrefixSize]byte
		binary.BigEndian.PutUint16(prefix[:], uint16(len(frame)))
		s.input.Write(prefix[:])
		s.input.Write(frame)
	}
}

func TestStreamWriteUsesOneExactPhysicalWrite(t *testing.T) {
	stream := new(recordingQUICStream)
	path := &PathConn{stream: stream}
	frame := bytes.Repeat([]byte{0x5a}, 1024)
	n, err := path.Write(frame)
	if err != nil || n != len(frame) {
		t.Fatalf("Write=(%d,%v), want (%d,nil)", n, err, len(frame))
	}
	if len(stream.writes) != 1 {
		t.Fatalf("physical writes=%d, want 1", len(stream.writes))
	}
	wire := stream.writes[0]
	if len(wire) != LengthPrefixSize+len(frame) || int(binary.BigEndian.Uint16(wire[:2])) != len(frame) ||
		!bytes.Equal(wire[2:], frame) {
		t.Fatalf("wire framing is not one exact length-prefixed frame")
	}
	firstBuffer := &path.writeBuf[0]
	if _, err := path.Write(frame[:17]); err != nil {
		t.Fatal(err)
	}
	if firstBuffer != &path.writeBuf[0] {
		t.Fatal("smaller write did not reuse the grown frame buffer")
	}
}

func TestStreamWriteShortPhysicalWriteIsTerminal(t *testing.T) {
	stream := &recordingQUICStream{shortBy: 3}
	path := &PathConn{stream: stream}
	n, err := path.Write([]byte("payload"))
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write error=%v, want net.ErrClosed", err)
	}
	if n != len("payload")-3 {
		t.Fatalf("payload bytes=%d, want %d", n, len("payload")-3)
	}
	if !path.dead.Load() || !stream.closed {
		t.Fatalf("short write dead=%v streamClosed=%v", path.dead.Load(), stream.closed)
	}
}

func TestStreamConcurrentWritersPreserveFrameBoundaries(t *testing.T) {
	stream := new(recordingQUICStream)
	path := &PathConn{stream: stream}
	const writers = 64
	var wait sync.WaitGroup
	wait.Add(writers)
	for id := 0; id < writers; id++ {
		go func() {
			defer wait.Done()
			frame := bytes.Repeat([]byte{byte(id + 1)}, 37+id)
			if n, err := path.Write(frame); err != nil || n != len(frame) {
				t.Errorf("writer %d=(%d,%v)", id, n, err)
			}
		}()
	}
	wait.Wait()
	if len(stream.writes) != writers {
		t.Fatalf("physical writes=%d, want %d", len(stream.writes), writers)
	}
	seen := make(map[byte]bool, writers)
	for index, wire := range stream.writes {
		if len(wire) < LengthPrefixSize {
			t.Fatalf("write %d has no prefix", index)
		}
		size := int(binary.BigEndian.Uint16(wire[:LengthPrefixSize]))
		if size != len(wire)-LengthPrefixSize || size == 0 {
			t.Fatalf("write %d prefix=%d payload=%d", index, size, len(wire)-LengthPrefixSize)
		}
		marker := wire[LengthPrefixSize]
		if seen[marker] {
			t.Fatalf("duplicate marker %d", marker)
		}
		seen[marker] = true
		for _, value := range wire[LengthPrefixSize:] {
			if value != marker {
				t.Fatalf("write %d interleaved marker %d with %d", index, marker, value)
			}
		}
	}
}

func TestStreamOwnedFrameReaderAndShortBuffer(t *testing.T) {
	stream := new(recordingQUICStream)
	first := []byte("first immutable frame")
	second := bytes.Repeat([]byte{0x6b}, 64)
	third := []byte("third frame")
	stream.appendFrames(first, second, third)
	path := &PathConn{stream: stream}

	owned, err := path.ReadOwnedFrame()
	if err != nil || !bytes.Equal(owned, first) {
		t.Fatalf("ReadOwnedFrame=(%q,%v)", owned, err)
	}
	short := make([]byte, 9)
	n, err := path.Read(short)
	if !errors.Is(err, io.ErrShortBuffer) || n != len(short) || !bytes.Equal(short, second[:len(short)]) {
		t.Fatalf("short Read=(%d,%v,%x)", n, err, short)
	}
	if !bytes.Equal(owned, first) {
		t.Fatal("later reads mutated the transferred frame allocation")
	}
	last, err := path.ReadOwnedFrame()
	if err != nil || !bytes.Equal(last, third) {
		t.Fatalf("frame after short Read=(%q,%v)", last, err)
	}
}

func TestStreamConcurrentReadersReceiveWholeFrames(t *testing.T) {
	stream := new(recordingQUICStream)
	left := bytes.Repeat([]byte{0x11}, 257)
	right := bytes.Repeat([]byte{0x22}, 513)
	stream.appendFrames(left, right)
	path := &PathConn{stream: stream}
	results := make(chan []byte, 2)
	errorsFound := make(chan error, 2)
	for range 2 {
		go func() {
			frame, err := path.ReadOwnedFrame()
			if err != nil {
				errorsFound <- err
				return
			}
			results <- frame
		}()
	}
	got := [][]byte{<-results, <-results}
	select {
	case err := <-errorsFound:
		t.Fatal(err)
	default:
	}
	if !(bytes.Equal(got[0], left) && bytes.Equal(got[1], right)) &&
		!(bytes.Equal(got[0], right) && bytes.Equal(got[1], left)) {
		t.Fatalf("concurrent frames sizes=%d,%d", len(got[0]), len(got[1]))
	}
}

type discardQUICStream struct{}

func (discardQUICStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (discardQUICStream) Write(p []byte) (int, error) { return len(p), nil }
func (discardQUICStream) Close() error                { return nil }

func BenchmarkStreamPathConnWriteFramed1K(b *testing.B) {
	path := &PathConn{stream: discardQUICStream{}}
	frame := bytes.Repeat([]byte{0x5a}, 1024)
	if _, err := path.Write(frame); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for range b.N {
		if _, err := path.Write(frame); err != nil {
			b.Fatal(err)
		}
	}
}
