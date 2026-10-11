package udp_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
)

// A packet session over the raw-UDP carrier on the loopback address. The
// passive side serves a socket from Listen through rendr.FromPacketConn;
// the dialer's Peer gets one Carrier factory per path. With the default
// MaxDatagram (1232 bytes) an application datagram holds up to 1,198
// bytes. MaxBatch caps the datagrams one sendmmsg or recvmmsg call moves on
// Linux amd64 and arm64; other platforms move one datagram per call.
func ExampleCarrier() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Passive side: a rendr-owned listening socket as a packet source.
	srv, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()
	sock, err := udp.Listen("udp", "127.0.0.1:0", udp.Options{})
	if err != nil {
		log.Fatal(err)
	}
	ln, err := srv.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}})
	if err != nil {
		sock.Close()
		log.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		pp, err := ln.AcceptPacket(ctx)
		if err != nil {
			return
		}
		pc, err := pp.Confirm()
		if err != nil {
			return
		}
		stop := context.AfterFunc(ctx, func() { pc.SetReadDeadline(time.Now()) })
		defer stop()
		buf := make([]byte, pc.MaxPayload())
		for {
			n, _, err := pc.ReadFrom(buf) // io.EOF once the dialer closed
			if err != nil {
				break
			}
			pc.WriteTo(buf[:n], nil) // nil: the session's peer
		}
		pc.Close()
		select {
		case <-pc.Done():
		case <-ctx.Done():
		}
	}()

	// Dialer side: one factory, batching at most 16 datagrams per call.
	cli, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()
	peer, err := cli.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{
		udp.Carrier("loopback", "udp", sock.LocalAddr().String(), udp.Options{MaxBatch: 16}),
	}})
	if err != nil {
		log.Fatal(err)
	}
	pc, err := peer.DialPacket(ctx, rendr.DialOptions{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("max payload:", pc.MaxPayload())
	buf := make([]byte, pc.MaxPayload())
	for {
		if _, err := pc.WriteTo([]byte("ping"), nil); err != nil {
			log.Fatal(err)
		}
		pc.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, _, err := pc.ReadFrom(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) && ctx.Err() == nil {
			continue // a datagram is never retransmitted: send again
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("echo: %s\n", buf[:n])
		break
	}
	pc.Close()
	select {
	case <-pc.Done():
	case <-ctx.Done():
	}
	select {
	case <-served:
	case <-ctx.Done():
		log.Fatal("the passive side did not end")
	}
	// Output:
	// max payload: 1198
	// echo: ping
}
