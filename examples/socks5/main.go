// Command socks5 is a SOCKS5 front end for rendr's l4 package: the client
// subcommand serves a loopback-only SOCKS5 listener (no authentication,
// CONNECT only) and carries each connection over a rendr stream session to
// the server subcommand, which dials the requested target and forwards.
// The SOCKS reply is written only after the session was confirmed or
// rejected, so a refused target is a SOCKS failure reply, never a dropped
// connection. rendr neither encrypts nor authenticates: the carriers are
// carrier/tcp on loopback unless -carrier-insecure allows other addresses,
// which is only for carriers inside a tunnel that authenticates and
// encrypts (see examples/mtls). Both subcommands stop on SIGINT or
// SIGTERM.
//
// Not implemented yet: this is the M4 skeleton; it parses its flags and
// exits.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch cmd := os.Args[1]; cmd {
	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		listen := fs.String("listen", "127.0.0.1:1080", "SOCKS5 listen address (must be loopback)")
		carrier := fs.String("carrier", "127.0.0.1:7443", "the server's rendr carrier address (carrier/tcp)")
		insecure := fs.Bool("carrier-insecure", false, "allow a non-loopback carrier address: only inside a tunnel that authenticates and encrypts (see examples/mtls)")
		_ = fs.Parse(os.Args[2:])
		_, _, _ = listen, carrier, insecure
	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		carrier := fs.String("carrier", "127.0.0.1:7443", "rendr carrier listen address (carrier/tcp)")
		insecure := fs.Bool("carrier-insecure", false, "allow a non-loopback carrier listen address: only inside a tunnel that authenticates and encrypts (see examples/mtls)")
		_ = fs.Parse(os.Args[2:])
		_, _ = carrier, insecure
	default:
		usage()
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "socks5: not implemented yet")
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: socks5 client [-listen addr] [-carrier addr] [-carrier-insecure]")
	fmt.Fprintln(os.Stderr, "       socks5 server [-carrier addr] [-carrier-insecure]")
}
