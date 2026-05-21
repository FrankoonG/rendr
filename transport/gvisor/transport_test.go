package gvisor

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

func TestGVisorTransportRoundTrip(t *testing.T) {
	ln, err := Listen("")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pc, err := ln.Accept(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- pc
	}()

	client, err := New().DialPath(context.Background(), transport.PathSpec{
		Transport: "gvisor",
		Address:   ln.Addr().String(),
	})
	if err != nil {
		t.Fatalf("DialPath: %v", err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	want := []byte("hello over gvisor tcp")
	if _, err := client.Write(want); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGVisorPacketCarrierRoundTrip(t *testing.T) {
	ln, err := ListenPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pc, err := ln.Accept(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- pc
	}()

	client, err := New().DialPath(context.Background(), transport.PathSpec{
		Transport: "gvisor",
		Address:   ln.Addr().String(),
	})
	if err != nil {
		t.Fatalf("DialPath: %v", err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	want := []byte("hello over gvisor udp packet carrier")
	if _, err := client.Write(want); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGVisorAcceptTimeoutDoesNotPoisonListener(t *testing.T) {
	ln, err := Listen("")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := ln.Accept(ctx); err == nil {
		t.Fatal("Accept unexpectedly succeeded without a dial")
	}

	client, err := New().DialPath(context.Background(), transport.PathSpec{
		Transport: "gvisor",
		Address:   ln.Addr().String(),
	})
	if err != nil {
		t.Fatalf("DialPath after timed-out Accept: %v", err)
	}
	defer client.Close()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	server, err := ln.Accept(ctx2)
	if err != nil {
		t.Fatalf("Accept after timeout: %v", err)
	}
	defer server.Close()

	want := []byte("still accepts")
	if _, err := client.Write(want); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
