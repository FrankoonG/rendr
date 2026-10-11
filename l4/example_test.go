package l4_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/l4"
)

// A TCP connection forwarded through a rendr session to an in-process
// target on the loopback address. The passive Runtime runs an l4.Server,
// which dials the target named in the OPEN while the session is pending and
// confirms it once the target connected; the dialer uses the returned
// *rendr.Conn as its connection to the target. A dialer that serves local
// TCP clients would pass each accepted conn and the session to l4.Forward.
func ExampleDial() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The target: a TCP echo server.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c) // echo until the FIN
		c.Close()
	}()

	// Passive side: an l4.Server on a rendr Listener. The zero Server
	// dials any address the host can reach: give a real one a Dial hook
	// that refuses what must not be reached (l4.ErrDenied).
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
	serveCtx, stop := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() { served <- (&l4.Server{}).Serve(serveCtx, ln) }()

	// Dialer side.
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
	conn, err := l4.Dial(ctx, peer, target.Addr().String(), rendr.DialOptions{})
	if err != nil {
		code, _ := l4.CodeOf(err) // the Server's refusal: refused, timeout, ...
		log.Fatal(code, err)
	}
	conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	conn.CloseWrite()              // the target reads EOF after the request
	reply, err := io.ReadAll(conn) // until the target's FIN
	if err != nil {
		log.Fatal(err)
	}
	conn.Close()
	select {
	case <-conn.Done():
	case <-ctx.Done():
	}
	stop()
	<-served // Serve returns once every connection it served has ended

	fmt.Printf("%q\n", reply)
	// Output:
	// "GET / HTTP/1.0\r\n\r\n"
}
