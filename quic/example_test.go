package quic_test

import (
	"context"
	"crypto/tls"
	"log"

	"github.com/FrankoonG/rendr/quic/v2"
	"github.com/FrankoonG/rendr/v2"
)

// QUIC carriers on both sides. The example compiles but does not run: it
// needs TLS material (a server certificate for the listener, a client
// configuration that verifies it and, for mutual authentication, a client
// certificate). QUIC encrypts, but authenticates only what the tls.Config
// verifies.
func Example() {
	var serverTLS, clientTLS *tls.Config // the embedder's TLS configurations
	ctx := context.Background()

	// Passive side: one QUIC listener hands stream and datagram carriers to
	// a rendr Listener.
	srv, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()
	ln, err := srv.Listen(rendr.ListenConfig{}) // push-only: fed by the QUIC listener
	if err != nil {
		log.Fatal(err)
	}
	ql, err := quic.Listen("udp", "127.0.0.1:7443", quic.Options{TLS: serverTLS})
	if err != nil {
		log.Fatal(err)
	}
	defer ql.Close()
	go ql.Serve(ln)

	// Dialer side: a stream factory for stream sessions and a datagram
	// factory for packet sessions, both to the same rendr instance.
	cli, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()
	sc, err := quic.StreamCarrier("quic-stream", "127.0.0.1:7443", quic.Options{TLS: clientTLS})
	if err != nil {
		log.Fatal(err)
	}
	dc, err := quic.DatagramCarrier("quic-dgram", "127.0.0.1:7443", quic.Options{TLS: clientTLS})
	if err != nil {
		log.Fatal(err)
	}
	peer, err := cli.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{sc, dc}})
	if err != nil {
		log.Fatal(err)
	}
	conn, err := peer.Dial(ctx, rendr.DialOptions{}) // over sc
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	pc, err := peer.DialPacket(ctx, rendr.DialOptions{}) // over dc first
	if err != nil {
		log.Fatal(err)
	}
	defer pc.Close()
}
