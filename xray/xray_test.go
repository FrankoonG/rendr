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

// TestM9XrayQUICDatagramRoundTrip: parallel to TestM9DialerPacketRoundTrip
// but exercises QUIC DATAGRAM (RFC 9221) as the transport. Client
// uses DialPacketContext with PathSpec.Opts["mode"]="datagram";
// server uses xray.ListenQUICDatagram. Validates that the xray
// PacketListener wrapper composes uniformly over QUIC DATAGRAM and
// udpflow (same surface, swap constructor).
func TestM9XrayQUICDatagramRoundTrip(t *testing.T) {
	ln, err := ListenQUICDatagram("127.0.0.1:0", nil)
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
			t.Errorf("AcceptPacketContext: %v", err)
			return
		}
		accepted <- c
	}()

	d, err := NewDialer(&Config{
		Mode: ModePrime,
		Paths: []PathSpec{{
			Transport: "quic",
			Address:   ln.Addr().String(),
			Opts:      map[string]string{"mode": "datagram"},
		}},
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

	pkts := [][]byte{[]byte("quic-dg-1"), []byte("quic-dg-second-message")}
	for _, p := range pkts {
		if _, err := c.WriteTo(p, nil); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}
	buf := make([]byte, 256)
	for i, want := range pkts {
		n, _, err := srv.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("packet %d: got %q want %q", i, buf[:n], want)
		}
	}

	if cli, ok := c.(rendr.PacketConn); ok {
		if s, ok := srv.(rendr.PacketConn); ok {
			if cli.FlowID() != s.FlowID() {
				t.Fatalf("flow_id mismatch through xray QUIC DATAGRAM wrap")
			}
		}
	}

	// xray-side FlowIDs() pass-through still works for the new
	// constructor.
	if ids := ln.FlowIDs(); len(ids) != 1 {
		t.Fatalf("FlowIDs post-dial: got %d want 1", len(ids))
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

func TestM9XrayMixedTCPQUICListener(t *testing.T) {
	ln, err := Listen(&ListenConfig{
		Paths: []PathSpec{
			{Transport: "tcp", Address: "127.0.0.1:0"},
			{Transport: "quic", Address: "127.0.0.1:0"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addrs := ln.Addrs()
	if len(addrs) != 2 {
		t.Fatalf("Addrs len=%d want 2", len(addrs))
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptContext(ctx)
		if err != nil {
			t.Errorf("AcceptContext: %v", err)
			return
		}
		accepted <- c
	}()

	d, err := NewDialer(&Config{
		Mode: ModePrime,
		Paths: []PathSpec{
			{Transport: "tcp", Address: addrs[0].String()},
			{Transport: "quic", Address: addrs[1].String()},
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

	adm := client.(rendr.AdminConn)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(adm.Paths()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var quicPath uint32
	for _, p := range adm.Paths() {
		if p.Spec.Transport == "quic" {
			quicPath = p.ID
			break
		}
	}
	if quicPath == 0 {
		t.Fatalf("quic path not attached: %+v", adm.Paths())
	}

	if _, err := client.Write([]byte("tcp-half")); err != nil {
		t.Fatal(err)
	}
	if err := adm.Migrate(quicPath); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := client.Write([]byte("quic-half")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("tcp-halfquic-half"))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "tcp-halfquic-half" {
		t.Fatalf("payload got %q", got)
	}
}

// TestM9MigrationUnderLoadThroughXrayWrap drives sustained writes
// while explicitly migrating through the xray-wrapped Conn. The
// contract from CLAUDE.md hard rule #1 (migration never surfaces an
// error to the application) and the framework G1 contract (bytes
// identical after mid-stream migration) must both hold through the
// xray adapter layer - otherwise an xray embedder gets a different
// guarantee than a bare-rendr embedder, which violates the "xray
// surface is just a thin wrap" promise.
func TestM9MigrationUnderLoadThroughXrayWrap(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const chunk = 4096
	const chunks = 256
	total := int64(chunk) * int64(chunks)

	srvErr := make(chan error, 1)
	srvDone := make(chan int64, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s, err := ln.AcceptContext(ctx)
		if err != nil {
			srvErr <- err
			return
		}
		defer s.Close()
		buf := make([]byte, chunk)
		var got int64
		for got < total {
			n, err := io.ReadFull(s, buf)
			if err != nil {
				srvErr <- err
				return
			}
			for i, b := range buf[:n] {
				if b != byte((int64(i)+got)&0xFF) {
					srvErr <- io.ErrUnexpectedEOF
					return
				}
			}
			got += int64(n)
		}
		srvDone <- got
	}()

	d, err := NewDialer(&Config{
		Mode: ModePrime,
		Paths: []PathSpec{
			{Transport: "tcp", Address: ln.Addr().String()},
			{Transport: "tcp", Address: ln.Addr().String()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.DialContext(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	adm, ok := c.(rendr.AdminConn)
	if !ok {
		t.Fatal("xray-side net.Conn is not rendr.AdminConn (migration plumbing unreachable)")
	}
	startMigrations := adm.MigrationCount()

	payload := make([]byte, chunk)
	var sent int64
	for i := 0; i < chunks; i++ {
		for j := range payload {
			payload[j] = byte((int64(j) + sent) & 0xFF)
		}
		if _, err := c.Write(payload); err != nil {
			t.Fatalf("Write chunk %d: %v (migration must not surface as error)", i, err)
		}
		sent += int64(len(payload))

		// Migrate every 32 chunks to a different path id.
		if i > 0 && i%32 == 0 {
			cur := adm.ActivePath()
			for _, p := range adm.Paths() {
				if p.ID != cur {
					if err := adm.Migrate(p.ID); err != nil {
						t.Fatalf("Migrate chunk %d: %v", i, err)
					}
					break
				}
			}
		}
	}

	select {
	case err := <-srvErr:
		t.Fatalf("server side: %v", err)
	case got := <-srvDone:
		if got != total {
			t.Fatalf("server got %d bytes, want %d", got, total)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("server side did not finish in 30s")
	}

	endMigrations := adm.MigrationCount()
	migrated := endMigrations - startMigrations
	if migrated == 0 {
		t.Fatalf("no migrations happened; MigrationCount unchanged at %d", endMigrations)
	}
	t.Logf("xray wrap: %d migrations across %d chunks, %d bytes intact", migrated, chunks, total)
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
