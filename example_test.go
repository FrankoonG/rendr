package rendr_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/FrankoonG/rendr"
)

// ExampleRuntime_Dial demonstrates the smallest useful rendr setup:
// one TCP path between two in-process endpoints. Real deployments
// supply two or more paths so migration has somewhere to go.
func ExampleRuntime_Dial() {
	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		log.Fatal(err)
	}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	ln, err := serverRuntime.Listen(rendr.ListenConfig{Streams: []rendr.StreamSource{{
		Name:     "stream",
		Carrier:  rendr.CarrierTCP,
		Listener: rawListener,
	}}})
	if err != nil {
		_ = rawListener.Close()
		log.Fatal(err)
	}
	defer ln.Close()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		c, err := ln.AcceptStream(context.Background())
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		fmt.Println("server got:", string(buf[:n]))
	}()

	runtime, err := newStreamRuntime()
	if err != nil {
		log.Fatal(err)
	}
	c, err := runtime.Dial(context.Background(), rendr.SessionConfig{
		Root: rendr.Path("tcp", rendr.PathSpec{Transport: "stream", Address: ln.Addr().String()}),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "hello rendr")
	<-srvDone
	// Output: server got: hello rendr
}

// ExampleConnectionObserver shows the optional observation surface.
func ExampleConnectionObserver() {
	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		log.Fatal(err)
	}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	ln, err := serverRuntime.Listen(rendr.ListenConfig{Streams: []rendr.StreamSource{{
		Name:     "stream",
		Carrier:  rendr.CarrierTCP,
		Listener: rawListener,
	}}})
	if err != nil {
		_ = rawListener.Close()
		log.Fatal(err)
	}
	defer ln.Close()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		c, err := ln.AcceptStream(context.Background())
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 8)
		_, _ = io.ReadFull(c, buf)
	}()

	runtime, err := newStreamRuntime()
	if err != nil {
		log.Fatal(err)
	}
	c, err := runtime.Dial(context.Background(), rendr.SessionConfig{
		Root: rendr.Path("tcp", rendr.PathSpec{Transport: "stream", Address: ln.Addr().String()}),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(make([]byte, 8))

	if adm, ok := c.(rendr.ConnectionObserver); ok {
		s := adm.Stats()
		fmt.Println("state:", s.State)
		fmt.Println("effective paths:", len(s.EffectivePaths))
		fmt.Println("paths:", len(s.Paths))
	}
	<-srvDone
	// Output:
	// state: active
	// effective paths: 1
	// paths: 1
}

// ExampleRuntime_DialPacket demonstrates packet-boundary mode over
// opaque UDP. Each WriteTo becomes one frame; each ReadFrom returns
// one frame's payload. Use this for datagram-oriented protocols
// (WireGuard, custom UDP echo) where boundaries must be preserved.
func ExampleRuntime_DialPacket() {
	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		log.Fatal(err)
	}
	rawPacketConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	ln, err := serverRuntime.Listen(rendr.ListenConfig{Packets: []rendr.PacketSource{{
		Name:    "packet",
		Carrier: rendr.CarrierUDP,
		Conn:    rawPacketConn,
	}}})
	if err != nil {
		_ = rawPacketConn.Close()
		log.Fatal(err)
	}
	defer ln.Close()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		c, err := ln.AcceptPacket(context.Background())
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _, _ := c.ReadFrom(buf)
		fmt.Println("server got:", string(buf[:n]))
	}()

	runtime, err := newPacketRuntime()
	if err != nil {
		log.Fatal(err)
	}
	c, err := runtime.DialPacket(context.Background(), rendr.SessionConfig{
		Root: rendr.Path("udp", rendr.PathSpec{Transport: "packet", Address: ln.Addr().String()}),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	_, _ = c.WriteTo([]byte("hello packets"), nil)
	<-srvDone
	// Output: server got: hello packets
}

func newStreamRuntime() (*rendr.Runtime, error) {
	runtime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{}
	if err := runtime.RegisterStreamFactory("stream", rendr.StreamFactory{
		Carrier: rendr.CarrierTCP,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		},
	}); err != nil {
		return nil, err
	}
	return runtime, nil
}

func newPacketRuntime() (*rendr.Runtime, error) {
	runtime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		return nil, err
	}
	listenConfig := &net.ListenConfig{}
	if err := runtime.RegisterPacketFactory("packet", rendr.PacketFactory{
		Carrier: rendr.CarrierUDP,
		Dial: func(ctx context.Context, _ string) (net.PacketConn, error) {
			return listenConfig.ListenPacket(ctx, "udp", "127.0.0.1:0")
		},
	}); err != nil {
		return nil, err
	}
	return runtime, nil
}
