package xray_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/xray"
)

// ExampleDialer demonstrates the shape an xray-style embedder uses:
// build a rendr.xray.Config, hand it to NewDialer, and treat the
// returned *Dialer as the project's own internet.Dialer
// implementation. The net.Conn returned by DialContext already
// implements rendr.AdminConn, so migration metrics / explicit
// Migrate() are reachable without unwrapping the xray adapter.
func ExampleDialer() {
	ln, err := xray.ListenTCP("127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, err := ln.AcceptContext(ctx)
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 32)
		n, _ := c.Read(buf)
		fmt.Println("server got:", string(buf[:n]))
	}()

	d, err := xray.NewDialer(&xray.Config{
		Mode: xray.ModePrime,
		Paths: []xray.PathSpec{
			{Transport: "tcp", Address: ln.Addr().String()},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	c, err := d.DialContext(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "hello xray-shaped")
	<-srvDone
	// Output: server got: hello xray-shaped
}

// ExampleDialer_admin shows the migration-control surface an xray
// embedder reaches via rendr.AdminConn on the net.Conn returned by
// DialContext. The same value is both a net.Conn (for xray's wire
// protocols) and an AdminConn (for migration metrics / path-set
// updates) - no parallel handle is required.
func ExampleDialer_admin() {
	ln, err := xray.ListenTCP("127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, _ := ln.AcceptContext(ctx)
		if c != nil {
			defer c.Close()
			io.ReadFull(c, make([]byte, 4))
		}
	}()

	d, _ := xray.NewDialer(&xray.Config{
		Mode:  xray.ModePrime,
		Paths: []xray.PathSpec{{Transport: "tcp", Address: ln.Addr().String()}},
	})
	c, err := d.DialContext(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("ping"))

	if adm, ok := c.(rendr.AdminConn); ok {
		s := adm.Stats()
		fmt.Println("mode:", s.Mode)
		fmt.Println("paths:", len(s.Paths))
		fmt.Println("state:", s.State)
	}
	<-srvDone
	// Output:
	// mode: prime
	// paths: 1
	// state: active
}

// ExampleListener_FlowIDs shows how a monitoring goroutine can
// enumerate the live flow_ids being served by an xray-side listener
// without unwrapping to the underlying rendr.Listener. The use case
// is a metrics endpoint that reports active rendr connections per
// xray inbound.
func ExampleListener_FlowIDs() {
	ln, err := xray.ListenTCP("127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, _ := ln.AcceptContext(ctx)
		acceptedCh <- c
	}()

	d, _ := xray.NewDialer(&xray.Config{
		Mode:  xray.ModePrime,
		Paths: []xray.PathSpec{{Transport: "tcp", Address: ln.Addr().String()}},
	})
	c, err := d.DialContext(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	s := <-acceptedCh
	defer s.Close()

	fmt.Println("flows:", len(ln.FlowIDs()))
	// Output: flows: 1
}
