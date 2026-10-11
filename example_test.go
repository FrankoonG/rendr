package rendr_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
)

// A stream session over the built-in TCP carrier on the loopback address:
// the passive Runtime echoes what it reads, the dialer writes, half-closes
// and reads the echo until io.EOF. Both sides end the session cleanly (read
// until io.EOF, Close, wait for Done) before their Runtimes close.
func ExamplePeer_Dial() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Passive side: a Runtime, a carrier listener and a rendr Listener.
	srv, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()
	raw, err := tcp.Listen("tcp", "127.0.0.1:0", tcp.Options{})
	if err != nil {
		log.Fatal(err)
	}
	ln, err := srv.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(raw)}})
	if err != nil {
		raw.Close()
		log.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		pc, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		conn, err := pc.Confirm()
		if err != nil {
			return
		}
		io.Copy(conn, conn) // echo until the dialer's FIN
		conn.Close()        // this side's FIN
		select {
		case <-conn.Done():
		case <-ctx.Done():
		}
	}()

	// Dialer side: one Peer per destination instance, one factory per path.
	cli, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()
	peer, err := cli.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{
		tcp.Carrier("direct", "tcp", raw.Addr().String(), tcp.Options{}),
	}})
	if err != nil {
		log.Fatal(err)
	}
	conn, err := peer.Dial(ctx, rendr.DialOptions{Mode: rendr.ModeSelector})
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte("hello, rendr")); err != nil {
		log.Fatal(err)
	}
	conn.CloseWrite()              // FIN after the bytes written
	reply, err := io.ReadAll(conn) // until the passive's FIN
	if err != nil {
		log.Fatal(err)
	}
	conn.Close()
	select {
	case <-conn.Done():
	case <-ctx.Done():
	}
	<-served

	fmt.Printf("%s\n", reply)
	fmt.Println("ended:", conn.Status().Err)
	// Output:
	// hello, rendr
	// ended: EOF
}

// A packet session over the built-in raw-UDP carrier on the loopback
// address. A listening socket from carrier/udp is a FromPacketConn source;
// the dialer's Peer gets a carrier/udp factory. Each WriteTo is one
// datagram, delivered at most once and never retransmitted, so the dialer
// sends again when no answer arrives in time.
func ExamplePeer_DialPacket() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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
		pp, err := ln.AcceptPacket(ctx) // Accept returns stream sessions only
		if err != nil {
			return
		}
		pc, err := pp.Confirm()
		if err != nil {
			return
		}
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

	cli, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()
	peer, err := cli.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{
		udp.Carrier("udp", "udp", sock.LocalAddr().String(), udp.Options{}),
	}})
	if err != nil {
		log.Fatal(err)
	}
	pc, err := peer.DialPacket(ctx, rendr.DialOptions{Mode: rendr.ModeSelector})
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, pc.MaxPayload())
	for {
		if _, err := pc.WriteTo([]byte("ping"), nil); err != nil {
			log.Fatal(err)
		}
		pc.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, _, err := pc.ReadFrom(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) && ctx.Err() == nil {
			continue // lost in flight: send again
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s back over a %s session\n", buf[:n], pc.Status().Kind)
		break
	}
	pc.Close()
	select {
	case <-pc.Done():
	case <-ctx.Done():
	}
	<-served
	// Output:
	// ping back over a datagram session
}

// The passive application decides every session: Accept returns a pending
// session with the dialer's OPEN metadata, and Confirm or Reject answers
// it. A rejected Dial returns a *rendr.RejectError with the code and the
// message passed to Reject.
func ExampleListener_Accept() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()
	raw, err := tcp.Listen("tcp", "127.0.0.1:0", tcp.Options{})
	if err != nil {
		log.Fatal(err)
	}
	ln, err := srv.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(raw)}})
	if err != nil {
		raw.Close()
		log.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		for {
			pc, err := ln.Accept(ctx) // net.ErrClosed once the Runtime closes
			if err != nil {
				return
			}
			if string(pc.Metadata()) != "tenant-a" {
				pc.Reject(4001, "unknown tenant") // application codes are at least 256
				continue
			}
			conn, err := pc.Confirm()
			if err != nil {
				continue // the dialer withdrew, or AcceptTimeout answered
			}
			io.Copy(io.Discard, conn) // until the dialer's FIN
			conn.Close()
			select {
			case <-conn.Done():
			case <-ctx.Done():
			}
		}
	}()

	cli, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		log.Fatal(err)
	}
	peer, err := cli.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{
		tcp.Carrier("direct", "tcp", raw.Addr().String(), tcp.Options{}),
	}})
	if err != nil {
		log.Fatal(err)
	}

	_, err = peer.Dial(ctx, rendr.DialOptions{Metadata: []byte("tenant-b")})
	var rej *rendr.RejectError
	if errors.As(err, &rej) {
		fmt.Printf("rejected: code %d, %q\n", rej.Code, rej.Msg)
	}

	conn, err := peer.Dial(ctx, rendr.DialOptions{Metadata: []byte("tenant-a")})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("confirmed, bound to the passive:", conn.PeerInstance() == srv.InstanceID())
	conn.CloseWrite()
	io.Copy(io.Discard, conn) // until the passive's FIN
	conn.Close()
	select {
	case <-conn.Done():
	case <-ctx.Done():
	}
	cli.Close()
	srv.Close() // the Accept loop returns net.ErrClosed
	<-served
	// Output:
	// rejected: code 4001, "unknown tenant"
	// confirmed, bound to the passive: true
}
