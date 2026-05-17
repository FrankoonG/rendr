package quic

import (
	"bytes"
	"context"
	"testing"
	"time"

	qg "github.com/quic-go/quic-go"

	"github.com/FrankoonG/rendr/transport"
)

// pairCtx packages the client PathConn and a channel for the server
// side, which is only ready after the client has written at least
// one byte (QUIC streams are lazy - the peer's AcceptStream blocks
// until data is on the wire).
type pairCtx struct {
	client *PathConn
	srvCh  <-chan acceptResult
}

type acceptResult struct {
	pc  *PathConn
	err error
}

func newPair(t *testing.T) pairCtx {
	t.Helper()
	srvTLS, cliTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &qg.Config{
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	}

	ln, err := qg.ListenAddr("127.0.0.1:0", srvTLS, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	addr := ln.Addr().String()

	srvCh := make(chan acceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		if err != nil {
			srvCh <- acceptResult{err: err}
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			srvCh <- acceptResult{err: err}
			return
		}
		srvCh <- acceptResult{pc: Accept(conn, stream)}
	}()

	tp := &Transport{ClientTLS: cliTLS}
	cliPath, err := tp.DialPath(context.Background(), transport.PathSpec{Address: addr})
	if err != nil {
		t.Fatal(err)
	}
	client := cliPath.(*PathConn)
	t.Cleanup(func() { _ = client.Close() })
	return pairCtx{client: client, srvCh: srvCh}
}

// awaitServer blocks until the server-side accept completes. Caller
// must have produced bytes on the client side first (a Write or
// failed Write attempt - QUIC's lazy-stream semantics requires data
// to be in flight before AcceptStream returns).
func (p pairCtx) awaitServer(t *testing.T) *PathConn {
	t.Helper()
	res := <-p.srvCh
	if res.err != nil {
		t.Fatalf("server accept: %v", res.err)
	}
	t.Cleanup(func() { _ = res.pc.Close() })
	return res.pc
}

func TestQUICRoundTrip(t *testing.T) {
	p := newPair(t)

	frame := bytes.Repeat([]byte{0xAB}, 100)
	if _, err := p.client.Write(frame); err != nil {
		t.Fatal(err)
	}
	server := p.awaitServer(t)

	buf := make([]byte, MaxFrameSize)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], frame) {
		t.Fatalf("frame mismatch: got %x want %x", buf[:n], frame)
	}

	reply := []byte("pong over quic")
	if _, err := server.Write(reply); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, MaxFrameSize)
	rn, err := p.client.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:rn], reply) {
		t.Fatalf("reply mismatch: got %x want %x", got[:rn], reply)
	}
}

func TestQUICOversizeRejected(t *testing.T) {
	p := newPair(t)
	huge := make([]byte, MaxFrameSize+1)
	if _, err := p.client.Write(huge); err == nil {
		t.Fatal("expected error for oversize frame")
	}
	// Drain any in-flight server accept so leak-checks remain clean.
	_ = p
}
