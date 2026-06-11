package quic

import (
	"errors"
	"io"
	"net"
	"testing"
)

func TestStreamSwallowTransportDeathAsNetErrClosed(t *testing.T) {
	p := &PathConn{}
	if err := p.swallow(errors.New("transport died")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("swallow transport error = %v, want net.ErrClosed", err)
	}
}

func TestStreamSwallowByeEOF(t *testing.T) {
	p := &PathConn{}
	p.byeSeen.Store(true)
	if err := p.swallow(io.EOF); !errors.Is(err, io.EOF) {
		t.Fatalf("swallow BYE EOF = %v, want io.EOF", err)
	}
}

func TestStreamDeadWritePrecheckReturnsNetErrClosed(t *testing.T) {
	p := &PathConn{}
	p.dead.Store(true)
	_, err := p.Write([]byte{1})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dead stream Write error = %v, want net.ErrClosed", err)
	}
}

func TestDatagramDeadPrechecksReturnNetErrClosed(t *testing.T) {
	p := &datagramPathConn{}
	p.dead.Store(true)

	if _, err := p.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dead datagram Read error = %v, want net.ErrClosed", err)
	}
	if _, err := p.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dead datagram Write error = %v, want net.ErrClosed", err)
	}
}
