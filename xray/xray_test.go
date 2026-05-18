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
		{"bond ok now", &Config{Mode: ModeBond, Paths: []PathSpec{{Transport: "tcp", Address: "x:1"}}}, true},
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

// TestM9DialerPacketRoundTrip is the packet-mode analogue of
// TestM9DialerRoundTrip. xray.ListenUDPFlow + Dialer.DialPacketContext
// establish a rendr packet-mode connection without involving xray-core
// proper; each application WriteTo lands as one ReadFrom on the peer
// with byte-identical payload and a stable FlowID through the wrap.
func TestM9DialerPacketRoundTrip(t *testing.T) {
	ln, err := ListenUDPFlow("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptPacketContext(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- c
	}()

	d, err := NewDialer(&Config{
		Mode: ModePrime,
		Paths: []PathSpec{
			{Transport: "udpflow", Address: ln.Addr().String()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := d.DialPacketContext(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// Two distinct packets - boundaries must survive the xray wrap.
	pkts := [][]byte{
		[]byte("hello-packet"),
		[]byte("second one with different length"),
	}
	for _, p := range pkts {
		if _, err := client.WriteTo(p, nil); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}
	buf := make([]byte, 256)
	for i, want := range pkts {
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("packet %d: got %q want %q", i, buf[:n], want)
		}
	}

	// FlowID symmetry survives the xray packet wrap too.
	if cli, ok := client.(rendr.PacketConn); ok {
		if srv, ok := server.(rendr.PacketConn); ok {
			if cli.FlowID() != srv.FlowID() {
				t.Fatalf("flow_id mismatch: client=%x server=%x", cli.FlowID(), srv.FlowID())
			}
		}
	}
}

// TestM9XrayListenerFlowIDs: the xray.Listener / PacketListener
// wrappers must pass-through FlowIDs() so production monitoring can
// enumerate live flow_ids without unwrapping. After a successful
// dial the returned set must contain exactly the dialed flow.
func TestM9XrayListenerFlowIDs(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		if got := len(ln.FlowIDs()); got != 0 {
			t.Errorf("pre-dial FlowIDs: got %d want 0", got)
		}

		accepted := make(chan net.Conn, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := ln.AcceptContext(ctx)
			if err != nil {
				return
			}
			accepted <- c
		}()

		d, err := NewDialer(&Config{
			Mode:  ModePrime,
			Paths: []PathSpec{{Transport: "tcp", Address: ln.Addr().String()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		c, err := d.DialContext(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		srv := <-accepted
		defer srv.Close()

		ids := ln.FlowIDs()
		if len(ids) != 1 {
			t.Fatalf("post-dial FlowIDs: got %d want 1", len(ids))
		}
		want := c.(rendr.Conn).FlowID()
		if ids[0] != want {
			t.Errorf("FlowIDs[0]: got %x want %x", ids[0], want)
		}
	})

	t.Run("packet", func(t *testing.T) {
		ln, err := ListenUDPFlow("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		accepted := make(chan net.PacketConn, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := ln.AcceptPacketContext(ctx)
			if err != nil {
				return
			}
			accepted <- c
		}()

		d, err := NewDialer(&Config{
			Mode:  ModePrime,
			Paths: []PathSpec{{Transport: "udpflow", Address: ln.Addr().String()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		c, err := d.DialPacketContext(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		srv := <-accepted
		defer srv.Close()

		ids := ln.FlowIDs()
		if len(ids) != 1 {
			t.Fatalf("post-dial FlowIDs: got %d want 1", len(ids))
		}
		want := c.(rendr.PacketConn).FlowID()
		if ids[0] != want {
			t.Errorf("FlowIDs[0]: got %x want %x", ids[0], want)
		}
	})
}

// TestM9AdminSurfaceThroughXrayWrap: the net.Conn / net.PacketConn
// values returned by xray.Dialer must still satisfy rendr.AdminConn /
// rendr.AdminPacketConn so embedders can plumb migration metrics and
// path-set control into their xray-side observability without
// reaching past the xray wrapper.
func TestM9AdminSurfaceThroughXrayWrap(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
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
				return
			}
			accepted <- c
		}()

		d, err := NewDialer(&Config{
			Mode:  ModePrime,
			Paths: []PathSpec{{Transport: "tcp", Address: ln.Addr().String()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		c, err := d.DialContext(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		<-accepted

		adm, ok := c.(rendr.AdminConn)
		if !ok {
			t.Fatal("xray-side net.Conn is not rendr.AdminConn")
		}
		if adm.State() != "active" {
			t.Fatalf("State=%q want active", adm.State())
		}
		s := adm.Stats()
		if s.Mode != rendr.ModePrime || len(s.Paths) != 1 {
			t.Fatalf("Stats unexpected: %+v", s)
		}
	})

	t.Run("packet", func(t *testing.T) {
		ln, err := ListenUDPFlow("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		accepted := make(chan net.PacketConn, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := ln.AcceptPacketContext(ctx)
			if err != nil {
				return
			}
			accepted <- c
		}()

		d, err := NewDialer(&Config{
			Mode:  ModePrime,
			Paths: []PathSpec{{Transport: "udpflow", Address: ln.Addr().String()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		c, err := d.DialPacketContext(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		<-accepted

		adm, ok := c.(rendr.AdminPacketConn)
		if !ok {
			t.Fatal("xray-side net.PacketConn is not rendr.AdminPacketConn")
		}
		if adm.State() != "active" {
			t.Fatalf("State=%q want active", adm.State())
		}
		s := adm.Stats()
		if s.Mode != rendr.ModePrime || len(s.Paths) != 1 {
			t.Fatalf("Stats unexpected: %+v", s)
		}
	})
}
