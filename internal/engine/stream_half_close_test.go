package engine

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

func TestStreamHalfCloseKeepsReverseDirectionAlive(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	defer client.Close()
	defer server.Close()

	clientPath, serverPath := newMemoryPathPair()
	if _, err := client.AttachPath(clientPath, transport.PathSpec{Transport: "memory", Address: "half-close"}); err != nil {
		t.Fatalf("attach client path: %v", err)
	}
	if _, err := server.AttachPath(serverPath, transport.PathSpec{Transport: "memory", Address: "half-close"}); err != nil {
		t.Fatalf("attach server path: %v", err)
	}

	clientConn := &Conn{E: client}
	serverConn := &Conn{E: server}
	request := []byte("request-before-fin")
	if _, err := clientConn.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := clientConn.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	if err := clientConn.CloseWrite(); err != nil {
		t.Fatalf("repeated client CloseWrite: %v", err)
	}
	if _, err := clientConn.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write after CloseWrite = %v, want io.ErrClosedPipe", err)
	}

	if err := serverConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	gotRequest, err := io.ReadAll(serverConn)
	if err != nil {
		t.Fatalf("read request through FIN: %v", err)
	}
	if !bytes.Equal(gotRequest, request) {
		t.Fatalf("request = %q, want %q", gotRequest, request)
	}

	response := []byte("response-after-peer-fin")
	if _, err := serverConn.Write(response); err != nil {
		t.Fatalf("reverse write after peer FIN: %v", err)
	}
	if err := serverConn.CloseWrite(); err != nil {
		t.Fatalf("server CloseWrite: %v", err)
	}
	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	gotResponse, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("read response through reverse FIN: %v", err)
	}
	if !bytes.Equal(gotResponse, response) {
		t.Fatalf("response = %q, want %q", gotResponse, response)
	}
}

func TestStreamHalfCloseRejectsPacketMode(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	defer e.Close()
	e.SetPacketMode()
	if err := e.SendStreamFin(); !errors.Is(err, ErrStreamHalfCloseUnsupported) {
		t.Fatalf("SendStreamFin packet mode = %v, want %v", err, ErrStreamHalfCloseUnsupported)
	}
}
