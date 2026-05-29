package rendr

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeLocalDefault(t *testing.T) {
	st, err := ProbeLocal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Caps.Has(CapRendr) {
		t.Fatalf("caps=%v missing %q", st.Caps, CapRendr)
	}
	if !st.Caps.Has(CapL7) {
		t.Fatalf("caps=%v missing %q", st.Caps, CapL7)
	}
}

func TestDialerOptionalPathRetryAttachesAfterForwardingFix(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	native, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	go func() {
		for {
			c, err := native.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("native"))
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan Conn, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err == nil {
			accepted <- c
		}
	}()

	var useNative atomic.Bool
	useNative.Store(true)
	d := &Dialer{
		Root: Selector("root", []Target{
			Path("A", PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
			Path("B", PathSpec{Transport: "switch", Address: "B"}),
		}),
		Retry: RetryPolicy{MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond},
	}
	if err := d.AddStreamPathFactory("switch", func(ctx context.Context, _ string) (net.Conn, error) {
		addr := ln.Addr().String()
		if useNative.Load() {
			addr = native.Addr().String()
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", addr)
	}); err != nil {
		t.Fatal(err)
	}

	client, err := d.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	st := client.Status()
	if len(st.Paths) != 2 || st.Paths[1].State == PathAttached {
		t.Fatalf("before fix paths=%+v want B not attached", st.Paths)
	}

	useNative.Store(false)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st = client.Status()
		if len(st.Paths) == 2 && st.Paths[1].State == PathAttached {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("B did not attach after forwarding fix; status=%+v", client.Status())
}

func TestDialerOptionalPathFailureDoesNotSurfaceToApp(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	bad, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	badAddr := bad.Addr().String()
	_ = bad.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan Conn, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err == nil {
			accepted <- c
		}
	}()

	client, err := (&Dialer{
		Root: Selector("root", []Target{
			Path("A", PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
			Path("B", PathSpec{Transport: "tcp", Address: badAddr}),
		}),
		Retry: RetryPolicy{MinBackoff: 20 * time.Millisecond, MaxBackoff: 20 * time.Millisecond},
	}).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	msg := []byte("ok")
	if _, err := client.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("payload=%q want %q", string(buf), string(msg))
	}
}
