package l4_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/l4"
)

// udpEcho starts a UDP echo target on the loopback address; it answers
// every datagram to its source until the socket is closed.
func udpEcho() *net.UDPConn {
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := target.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			target.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return target
}

// udpPassive starts a passive Runtime whose Listener serves a carrier/udp
// socket on the loopback address and runs srv on it until stop is called;
// stop returns Serve's result once every flow it served has ended.
func udpPassive(ctx context.Context, srv *l4.Server) (rt *rendr.Runtime, addr string, stop func() error) {
	rt, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		log.Fatal(err)
	}
	sock, err := udp.Listen("udp", "127.0.0.1:0", udp.Options{})
	if err != nil {
		log.Fatal(err)
	}
	ln, err := rt.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}})
	if err != nil {
		sock.Close()
		log.Fatal(err)
	}
	serveCtx, cancel := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(serveCtx, ln) }()
	return rt, sock.LocalAddr().String(), func() error {
		cancel()
		return <-served
	}
}

// One UDP flow through a rendr packet session to an in-process UDP echo
// target on the loopback address. The passive Runtime runs an l4.Server
// with UDP set, which dials the target named in the OPEN while the session
// is pending. The flow's first datagram rides the OPEN: the Server writes
// it to the target before it confirms the session, so the first answer
// costs no extra round trip. A datagram is never retransmitted, so the
// dialer sends again when no answer arrives in time. A forward of a local
// UDP port uses PortForward instead, which runs DialUDP for every client
// source address.
func ExampleDialUDP() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := udpEcho()
	defer target.Close()

	// Passive side. The Server dials any address the host can reach: give
	// a real one a Dial hook (see the PortForward example).
	server := &l4.Server{UDP: true}
	srv, rendrAddr, stopServe := udpPassive(ctx, server)
	defer srv.Close()

	// Dialer side: a Peer with one carrier/udp factory.
	cli, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()
	peer, err := cli.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{
		udp.Carrier("udp", "udp", rendrAddr, udp.Options{}),
	}})
	if err != nil {
		log.Fatal(err)
	}
	ping := []byte("ping")
	pc, err := l4.DialUDP(ctx, peer, target.LocalAddr().String(), ping, rendr.DialOptions{})
	if err != nil {
		code, _ := l4.CodeOf(err) // the Server's refusal: not allowed, unreachable, ...
		log.Fatal(code, err)
	}
	fmt.Println("largest datagram:", pc.MaxPayload())
	buf := make([]byte, pc.MaxPayload())
	for {
		pc.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, _, err := pc.ReadFrom(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) && ctx.Err() == nil {
			pc.WriteTo(ping, nil) // lost in flight: send again
			continue
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s back from the target\n", buf[:n])
		break
	}
	pc.Close()
	select {
	case <-pc.Done():
	case <-ctx.Done():
	}
	stopServe() // Serve returns once every flow it served has ended
	st := server.Status().UDP
	fmt.Println("flows confirmed:", st.Confirmed, "first datagrams written from the OPEN:", st.FirstSent)
	// Output:
	// largest datagram: 1198
	// ping back from the target
	// flows confirmed: 1 first datagrams written from the OPEN: 1
}

// A local UDP port forwarded through rendr: every client source address
// that sends to the ingress socket is one flow, carried by one packet
// session, like a NAT mapping; replies go back to that address. The
// ingress socket is bound to the loopback address: ServeUDP refuses any
// other unless AllowNonLoopback is set, since whoever reaches the port
// reaches its target. The passive Server forwards UDP flows only to the
// targets of its allowlist, the shape of a forward to one game-streaming
// or VPN host's ports. UDP forwards belong on a Peer with datagram
// carriers only, so that no datagram waits behind a TCP stream.
func ExamplePortForward_ServeUDP() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := udpEcho()
	defer target.Close()

	// Passive side: an allowlist of exact host:port targets (as the
	// metadata spells them: an IP host in canonical form). A hook that
	// allows names or address ranges checks the resolved address in a
	// net.Dialer.Control instead, and turns SO_BROADCAST off there, as the
	// default UDP dialer does.
	allowed := map[string]bool{target.LocalAddr().String(): true}
	server := &l4.Server{
		UDP: true,
		Dial: func(ctx context.Context, r l4.Request) (net.Conn, error) {
			if r.Cmd != l4.CmdUDP || !allowed[r.Addr] {
				return nil, l4.ErrDenied // CodeNotAllowed; TCP is refused too
			}
			var d net.Dialer
			return d.DialContext(ctx, "udp", r.Addr) // a connected UDP socket
		},
	}
	srv, rendrAddr, stopServe := udpPassive(ctx, server)
	defer srv.Close()

	// Dialer side: the ingress.
	cli, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()
	peer, err := cli.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{
		udp.Carrier("udp", "udp", rendrAddr, udp.Options{}),
	}})
	if err != nil {
		log.Fatal(err)
	}
	fwd := &l4.PortForward{Peer: peer}
	ingress, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Fatal(err)
	}
	fwdCtx, stopFwd := context.WithCancel(ctx)
	forwarded := make(chan error, 1)
	go func() { forwarded <- fwd.ServeUDP(fwdCtx, ingress, target.LocalAddr().String()) }()

	// A client application: an ordinary UDP socket sending to the ingress.
	client, err := net.DialUDP("udp", nil, ingress.LocalAddr().(*net.UDPAddr))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	buf := make([]byte, 2048)
	for {
		client.Write([]byte("ping"))
		client.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := client.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) && ctx.Err() == nil {
			continue // lost in flight: send again, as a UDP application does
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s back through the forward\n", buf[:n])
		break
	}
	st := fwd.Status().UDP
	fmt.Println("open flows:", st.Flows, "first datagrams in the OPEN:", st.FirstInOpen)
	stopFwd()
	fmt.Println("ServeUDP:", <-forwarded) // once every flow it started has ended
	stopServe()
	// Output:
	// ping back through the forward
	// open flows: 1 first datagrams in the OPEN: 1
	// ServeUDP: context canceled
}
