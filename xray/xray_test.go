package xray

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
)

// TestM9ConfigValidate exercises the structural checks before
// xray-side code burns through a Dial only to fail mid-stream.
func TestM9ConfigValidate(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		ok   bool
	}{
		{"nil", nil, false},
		{"no paths", &Config{}, false},
		{"unknown mode", &Config{Mode: 99, Paths: []PathSpec{{Transport: "tcp", Address: "x:1"}}}, false},
		{"bond not yet", &Config{Mode: ModeBond, Paths: []PathSpec{{Transport: "tcp", Address: "x:1"}}}, false},
		{"missing transport", &Config{Paths: []PathSpec{{Address: "x:1"}}}, false},
		{"missing address", &Config{Paths: []PathSpec{{Transport: "tcp"}}}, false},
		{"valid prime tcp", &Config{Mode: ModePrime, Paths: []PathSpec{{Transport: "tcp", Address: "x:1"}}}, true},
		{"valid race quic", &Config{Mode: ModeRace, Paths: []PathSpec{{Transport: "quic", Address: "x:1"}}}, true},
		{"mode unset defaults", &Config{Paths: []PathSpec{{Transport: "tcp", Address: "x:1"}}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if c.ok && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestM9DialerRoundTrip exercises the end-to-end xray Dialer +
// ListenTCP flow without involving xray-core proper. Confirms the
// xray surface is independently usable.
func TestM9DialerRoundTrip(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptContext(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- c
	}()

	d, err := NewDialer(&Config{
		Mode: ModePrime,
		Paths: []PathSpec{
			{Transport: "tcp", Address: ln.Addr().String()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := d.DialContext(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	want := []byte("rendr/xray says hi")
	if _, err := client.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch")
	}

	// FlowID symmetry should still hold after the xray wrap.
	if cli, ok := client.(rendr.Conn); ok {
		if srv, ok := server.(rendr.Conn); ok {
			if cli.FlowID() != srv.FlowID() {
				t.Fatalf("flow_id mismatch: client=%x server=%x", cli.FlowID(), srv.FlowID())
			}
		}
	}
}
