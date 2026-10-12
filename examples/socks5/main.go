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
// SIGTERM: they reset the connections they forward, close the rendr
// Runtime, log "<subcommand>: stopped" and exit with status 0.
//
//	socks5 server [-rendr addr] [-carrier-insecure]
//	socks5 client [-listen addr] [-rendr addr]... [-carrier-insecure]
//
// The client's -rendr may be repeated: one carrier factory per address,
// all toward the same server (several paths).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/l4"
)

const (
	defaultRendr  = "127.0.0.1:7443"
	defaultListen = "127.0.0.1:1080"
	insecureHelp  = "allow non-loopback carrier addresses; the carriers are plaintext and unauthenticated: only inside a tunnel that authenticates and encrypts (see examples/mtls)"
)

// errUsage marks a usage error (exit status 2).
var errUsage = errors.New("usage")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stderr)
	stop()
	os.Exit(code)
}

// run runs the subcommand in args until ctx is done and returns the exit
// status: 0 after ctx ended it, 2 for a usage error (a non-loopback
// -listen included), 1 for any other failure.
func run(ctx context.Context, args []string, stderr io.Writer) int {
	logger := log.New(stderr, "socks5: ", log.LstdFlags)
	if len(args) == 0 || (args[0] != "client" && args[0] != "server") {
		usage(stderr)
		return 2
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	var addrs []string
	fs.Func("rendr", "the server's carrier address (client: repeatable) or the carrier listen address (server); default "+defaultRendr, func(s string) error {
		addrs = append(addrs, s)
		return nil
	})
	insecure := fs.Bool("carrier-insecure", false, insecureHelp)
	listen := defaultListen
	if args[0] == "client" {
		fs.StringVar(&listen, "listen", defaultListen, "the SOCKS5 listen address; must be loopback (the front end has no authentication)")
	}
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 || (args[0] == "server" && len(addrs) > 1) {
		usage(stderr)
		return 2
	}
	if len(addrs) == 0 {
		addrs = []string{defaultRendr}
	}
	o := tcp.Options{AllowNonLoopback: *insecure}
	var err error
	if args[0] == "client" {
		err = runClient(ctx, logger, listen, addrs, o)
	} else {
		err = runServer(ctx, logger, addrs[0], o)
	}
	switch {
	case errors.Is(err, errUsage):
		logger.Print(err)
		return 2
	case err != nil:
		logger.Print(err)
		return 1
	}
	logger.Printf("%s: stopped", args[0]) // the Runtime is closed
	return 0
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: socks5 server [-rendr addr] [-carrier-insecure]")
	fmt.Fprintln(w, "       socks5 client [-listen addr] [-rendr addr]... [-carrier-insecure]")
}

// runServer serves l4 sessions arriving on carrier/tcp at addr until ctx
// is done.
func runServer(ctx context.Context, logger *log.Logger, addr string, o tcp.Options) error {
	rt, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		return err
	}
	defer rt.Close()
	nl, err := tcp.Listen("tcp", addr, o)
	if err != nil {
		return err
	}
	ln, err := rt.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(nl)}})
	if err != nil {
		nl.Close()
		return err
	}
	logger.Printf("server: rendr carriers on %s", nl.Addr())
	err = (&l4.Server{}).Serve(ctx, ln)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// runClient serves SOCKS5 on the loopback address listen until ctx is
// done, carrying each CONNECT over a session to the server at addrs.
func runClient(ctx context.Context, logger *log.Logger, listen string, addrs []string, o tcp.Options) error {
	la, err := loopbackAddr(listen)
	if err != nil {
		return err
	}
	rt, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		return err
	}
	defer rt.Close()
	cs := make([]rendr.Carrier, len(addrs))
	for i, a := range addrs {
		cs[i] = tcp.Carrier(fmt.Sprintf("rendr-%d", i), "tcp", a, o)
	}
	peer, err := rt.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		return err
	}
	ln, err := net.ListenTCP("tcp", la)
	if err != nil {
		return err
	}
	logger.Printf("client: SOCKS5 on %s", ln.Addr())
	f := newFront(func(ctx context.Context, addr string) (*rendr.Conn, error) {
		return l4.Dial(ctx, peer, addr, rendr.DialOptions{})
	}, logger.Printf)
	return f.serve(ctx, ln)
}

// loopbackAddr resolves the -listen address, which must be loopback: the
// SOCKS5 front end has no authentication, so it never listens elsewhere.
func loopbackAddr(s string) (*net.TCPAddr, error) {
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		return nil, fmt.Errorf("%w: -listen %q: %v", errUsage, s, err)
	}
	if ip, ok := netip.AddrFromSlice(a.IP); !ok || !ip.Unmap().IsLoopback() {
		return nil, fmt.Errorf("%w: -listen %q is not a loopback address; the SOCKS5 listener has no authentication and listens on loopback only", errUsage, s)
	}
	return a, nil
}
