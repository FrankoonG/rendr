package tcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

func newPair(t *testing.T) (*PathConn, *PathConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var server *PathConn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		server = Wrap(c)
	}()

	tp := New()
	pc, err := tp.DialPath(context.Background(), transport.PathSpec{Address: ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if server == nil {
		t.Fatal("server side never bound")
	}
	t.Cleanup(func() {
		_ = pc.Close()
		_ = server.Close()
	})
	return pc.(*PathConn), server
}

func TestTCPRoundTrip(t *testing.T) {
	client, server := newPair(t)

	frame := bytes.Repeat([]byte{0xAB}, 100)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, MaxFrameSize)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], frame) {
		t.Fatalf("frame round-trip mismatch: got %x want %x", buf[:n], frame)
	}
}

func TestTCPRejectsOversize(t *testing.T) {
	client, _ := newPair(t)
	huge := make([]byte, MaxFrameSize+1)
	if _, err := client.Write(huge); err == nil {
		t.Fatal("expected error for oversize frame")
	}
}

func TestTCPRejectsEmpty(t *testing.T) {
	client, _ := newPair(t)
	if _, err := client.Write(nil); err == nil {
		t.Fatal("expected error for empty frame")
	}
}

func TestTCPOnDeathOnRemoteClose(t *testing.T) {
	client, server := newPair(t)

	deathCh := make(chan struct {
		cause transport.DeathCause
		err   error
	}, 1)
	client.OnDeath(func(c transport.DeathCause, e error) {
		deathCh <- struct {
			cause transport.DeathCause
			err   error
		}{c, e}
	})

	_ = server.Close()
	// Force the client to observe by attempting a Read.
	buf := make([]byte, 16)
	_, readErr := client.Read(buf)
	if readErr == nil {
		t.Fatal("expected Read error after peer close")
	}

	select {
	case d := <-deathCh:
		// Without BYE, EOF on mid-stream Read is TransportError.
		// (Hard rule #2.)
		if d.cause != transport.CauseTransportError {
			t.Errorf("got cause %v want TransportError", d.cause)
		}
	case <-time.After(time.Second):
		t.Fatal("OnDeath not fired in 1s")
	}
}

func TestTCPOnDeathAfterBye(t *testing.T) {
	client, server := newPair(t)

	deathCh := make(chan transport.DeathCause, 1)
	client.OnDeath(func(c transport.DeathCause, _ error) { deathCh <- c })

	client.MarkByeSeen()
	_ = server.Close()

	buf := make([]byte, 16)
	_, _ = client.Read(buf)

	select {
	case c := <-deathCh:
		if c != transport.CauseCleanClose {
			t.Errorf("after BYE: got cause %v want CleanClose", c)
		}
	case <-time.After(time.Second):
		t.Fatal("OnDeath not fired in 1s")
	}
}

func TestTCPReadReturnsErrClosedNotRaw(t *testing.T) {
	client, server := newPair(t)
	_ = server.Close()
	buf := make([]byte, 16)
	_, err := client.Read(buf)
	if err == nil {
		t.Fatal("expected an error")
	}
	// Hard rule #1: surface must be net.ErrClosed or io.EOF, not the
	// raw "use of closed network connection" or similar.
	if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Fatalf("got raw transport error %v; engine relies on this being masked", err)
	}
}

func TestTCPLengthPrefixWireStability(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	pc := Wrap(a)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = pc.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	}()

	got := make([]byte, 6)
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatal(err)
	}
	want := []byte{0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}
	if !bytes.Equal(got, want) {
		t.Fatalf("framing drift: got %x want %x", got, want)
	}
	<-done
}
