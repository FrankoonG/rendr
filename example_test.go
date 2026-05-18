package rendr_test

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/FrankoonG/rendr"
)

// ExampleDialer_Dial demonstrates the smallest useful rendr setup:
// one TCP path between two in-process endpoints. Real deployments
// supply two or more paths so migration has somewhere to go.
func ExampleDialer_Dial() {
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		c, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		fmt.Println("server got:", string(buf[:n]))
	}()

	d := &rendr.Dialer{
		Mode:  rendr.ModePrime,
		Paths: []rendr.PathSpec{{Transport: "tcp", Address: ln.Addr().String()}},
	}
	c, err := d.Dial(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "hello rendr")
	<-srvDone
	// Output: server got: hello rendr
}

// ExampleAdminConn shows the monitoring / control face. After
// Dial, the application can assert to rendr.AdminConn to inspect
// path state, drive migration, or attach a fresh path post-death.
func ExampleAdminConn() {
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		c, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 8)
		_, _ = io.ReadFull(c, buf)
	}()

	d := &rendr.Dialer{
		Mode:  rendr.ModePrime,
		Paths: []rendr.PathSpec{{Transport: "tcp", Address: ln.Addr().String()}},
	}
	c, err := d.Dial(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(make([]byte, 8))

	if adm, ok := c.(rendr.AdminConn); ok {
		s := adm.Stats()
		fmt.Println("state:", s.State)
		fmt.Println("mode:", s.Mode)
		fmt.Println("paths:", len(s.Paths))
	}
	<-srvDone
	// Output:
	// state: active
	// mode: prime
	// paths: 1
}

// ExampleDialer_DialPacket demonstrates packet-boundary mode over
// opaque UDP. Each WriteTo becomes one frame; each ReadFrom returns
// one frame's payload. Use this for datagram-oriented protocols
// (WireGuard, custom UDP echo) where boundaries must be preserved.
func ExampleDialer_DialPacket() {
	ln, err := rendr.ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
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

	d := &rendr.Dialer{
		Mode:  rendr.ModePrime,
		Paths: []rendr.PathSpec{{Transport: "udpflow", Address: ln.Addr().String()}},
	}
	c, err := d.DialPacket(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	_, _ = c.WriteTo([]byte("hello packets"), nil)
	<-srvDone
	// Output: server got: hello packets
}
