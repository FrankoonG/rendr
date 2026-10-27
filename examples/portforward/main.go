// Command portforward forwards local TCP and UDP ports through rendr. The
// client subcommand listens on local ports and carries every TCP
// connection as one rendr stream session and every UDP flow (the
// datagrams of one client source address, like a NAT mapping) as one
// packet session to the server subcommand, which dials the target and
// forwards (l4.PortForward, l4.Server). Carrier deaths and migrations are
// invisible to the applications; a UDP flow ends when idle (30 s until it
// was active both ways for 2 s, then 180 s).
//
//	portforward server [-rendr addr]... [-allow host:port]... [-allow-any] [-udp]
//	                   [-max-datagram n] [-carrier-insecure]
//	portforward client [-rendr addr]... -L tcp|udp:<local addr>=<target>...
//	                   [-mode selector|bond|race] [-max-datagram n]
//	                   [-allow-nonloopback] [-carrier-insecure]
//
// The server opens a carrier/tcp listener and a carrier/udp socket on every
// -rendr address (one port for both). Each client -rendr is one path to it:
// a carrier/udp factory for the UDP forwards and a carrier/tcp factory for
// the TCP forwards (two Peers, one PortForward each).
//
// Security: rendr neither encrypts nor authenticates. The server forwards
// only to its -allow targets (host:port as the client names them, in any
// spelling of the address and any case) and UDP only with -udp. A name
// that resolves to a multicast, broadcast or unspecified address is
// refused (a subnet-directed broadcast by the OS), with -allow-any too, as
// by l4's default dialer. -allow-any reaches every address the server host
// can, its loopback services and private networks included: an open relay.
// The carriers are loopback-only unless -carrier-insecure, which is for
// carriers inside a tunnel that authenticates and encrypts (see
// examples/mtls). The client's -L addresses are loopback-only unless
// -allow-nonloopback: whoever reaches an ingress port reaches its target,
// and a host that spoofs source addresses makes a LAN-facing UDP ingress
// reflect the target's replies toward them.
//
// Sizes: a UDP datagram above the path's budget (1,198 bytes by default)
// is dropped and counted, never fragmented. -max-datagram 1472 on both
// ends of a 1500-byte path carries datagrams of up to 1,438 bytes
// (Moonlight video, QUIC Initials, WireGuard with an MTU of at most 1406).
// The UDP sockets ask for buffers sized for keyframe bursts (4 MiB toward
// the target, 8 MiB at the client's ingress); a subcommand logs a warning
// at its start when the OS grants less (on Linux raise net.core.rmem_max
// and net.core.wmem_max).
//
// Every 10 s, and once at the stop, the client logs one status line per
// forward kind ("client: status udp: …", "client: status tcp: …") and the
// server one ("server: status l4: …"): every non-zero field of the
// l4.PortForwardStatus or l4.ServerStatus by its name (Name=n, UDP.Name=n
// for the server's UDP flows, ByCode(<code text>)=n such as
// ByCode(not allowed)=1, LastErr="…"), then CarrierDeaths(<cause>)=n, the
// Runtime's carrier-down events other than local closes and retirements.
// After a client datagram above the path's budget the UDP line ends with
// "; datagrams up to <TooLargeMax> bytes dropped; this path carries
// <MaxPayload> (raise -max-datagram on both ends)".
//
// SIGINT or SIGTERM stops a subcommand within 5 s: it ends its flows and
// connections, waits at most 2.5 s for them, closes its Runtimes (bounded
// by Runtime.Close at about 2.25 s), logs "<subcommand>: stopped" and
// exits with status 0. A usage error, a non-loopback -L without
// -allow-nonloopback included, exits with status 2; any other failure, a
// non-loopback carrier address without -carrier-insecure included, with
// status 1.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

const (
	defaultRendr = "127.0.0.1:7443"
	insecureHelp = "allow non-loopback carrier addresses; the carriers are plaintext and unauthenticated: only inside a tunnel that authenticates and encrypts (see examples/mtls)"
	// stopWait bounds a stop: the serves get stopWait minus closeBound, the
	// Runtimes' Close (closed at once; each joins within about 2.25 s when
	// no embedder code is stuck) the rest.
	stopWait   = 5 * time.Second
	closeBound = 2500 * time.Millisecond
	// The buffers a burst crosses (M6 design §A4.4 item 6): burstBuffer is
	// every packet session's queue per direction, the server's UDP target
	// socket buffers and the carrier/udp write buffers.
	burstBuffer       = 4 << 20
	carrierReadBuffer = 16 << 20 // both ends' carrier/udp sockets
	ingressBuffer     = 8 << 20  // the client's UDP ingress sockets
)

// statusEvery is the status line cadence (tests shorten it).
var statusEvery = 10 * time.Second

// errUsage marks a usage error (exit status 2).
var errUsage = errors.New("usage")

var modes = map[string]rendr.Mode{"selector": rendr.ModeSelector, "bond": rendr.ModeBond, "race": rendr.ModeRace}

// subcommands are the subcommands by name.
var subcommands = map[string]func(context.Context, *log.Logger, options) error{"client": runClient, "server": runServer}

// options are a subcommand's flags.
type options struct {
	rendr, allow, fwd                         []string
	allowAny, udp, allowNonLoopback, insecure bool
	mode                                      rendr.Mode // 0: selector
	maxDatagram                               int
}

func main() {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	os.Exit(run(ctx, os.Args[1:], os.Stderr))
}

// run runs the subcommand in args until ctx is done and returns the exit
// status: 0 after ctx ended it, 2 for a usage error, 1 for any other
// failure.
func run(ctx context.Context, args []string, stderr io.Writer) int {
	logger := log.New(stderr, "portforward: ", log.LstdFlags)
	if len(args) == 0 || subcommands[args[0]] == nil {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	o, err := parseFlags(args[0], args[1:], stderr)
	if err == nil {
		err = subcommands[args[0]](ctx, logger, o)
	}
	if err != nil {
		logger.Print(err)
		if errors.Is(err, errUsage) {
			fmt.Fprint(stderr, usageText)
			return 2
		}
		return 1
	}
	logger.Printf("%s: stopped", args[0]) // the Runtimes are closed
	return 0
}

const usageText = `usage: portforward server [-rendr addr]... [-allow host:port]... [-allow-any] [-udp] [-max-datagram n] [-carrier-insecure]
       portforward client [-rendr addr]... -L tcp|udp:<local addr>=<target>... [-mode selector|bond|race] [-max-datagram n] [-allow-nonloopback] [-carrier-insecure]
`

// parseFlags parses the flags of the subcommand sub.
func parseFlags(sub string, args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Func("rendr", "the server's carrier address, repeatable: one path each (client); a carrier listen address, repeatable (server); default "+defaultRendr, func(s string) error { o.rendr = append(o.rendr, s); return nil })
	fs.IntVar(&o.maxDatagram, "max-datagram", 0, "carrier/udp MaxDatagram, on both ends (0: 1232; 546-65507); a UDP datagram of up to this minus 34 bytes crosses")
	fs.BoolVar(&o.insecure, "carrier-insecure", false, insecureHelp)
	if sub == "client" {
		fs.Func("L", "a forward tcp:<local addr>=<target> or udp:<local addr>=<target>, repeatable; the target is resolved by the server", func(s string) error { o.fwd = append(o.fwd, s); return nil })
		fs.Func("mode", "the sessions' scheduling mode: selector (the default), bond or race", func(s string) error {
			if o.mode = modes[s]; o.mode == 0 {
				return errors.New("want selector, bond or race")
			}
			return nil
		})
		fs.BoolVar(&o.allowNonLoopback, "allow-nonloopback", false, "allow non-loopback -L addresses; a forward has no authentication: whoever reaches the port reaches its target")
	} else {
		fs.Func("allow", "a target host:port the server forwards to, repeatable; without -allow (or -allow-any) every target is refused", func(s string) error { o.allow = append(o.allow, s); return nil })
		fs.BoolVar(&o.allowAny, "allow-any", false, "forward to every target: an open relay to everything the server host reaches, its loopback services and private networks included")
		fs.BoolVar(&o.udp, "udp", false, "serve UDP flows")
	}
	switch err := fs.Parse(args); {
	case err != nil:
		return o, fmt.Errorf("%w: %v", errUsage, err)
	case fs.NArg() > 0:
		return o, fmt.Errorf("%w: unexpected arguments %q", errUsage, fs.Args())
	case o.maxDatagram != 0 && (o.maxDatagram < 546 || o.maxDatagram > 65507):
		return o, fmt.Errorf("%w: -max-datagram %d: want 546-65507", errUsage, o.maxDatagram)
	case sub == "client" && len(o.fwd) == 0:
		return o, fmt.Errorf("%w: the client needs at least one -L", errUsage)
	case len(o.rendr) == 0: // valid flags without -rendr: the default
		o.rendr = []string{defaultRendr}
	}
	return o, nil
}

// runtimeConfig is the Config of every Runtime: packet queues sized for
// keyframe bursts, the carrier deaths counted in d.
func runtimeConfig(d *carrierDeaths) rendr.Config {
	return rendr.Config{Packet: rendr.PacketPolicy{Queue: burstBuffer}, OnEvent: d.event}
}

// supervise runs serves until ctx is done or one of them returns, calling
// report every statusEvery; after the stop it waits at most stopWait minus
// closeBound for them and calls report once more. It returns the error of
// the first serve that ended before the stop.
func supervise(ctx context.Context, report func(), serves []func(context.Context) error) error {
	sctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	for _, s := range serves {
		wg.Go(func() { cancel(s(sctx)) }) // after the stop, the cause is ctx's
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	tick := time.NewTicker(statusEvery)
	defer tick.Stop()
	for sctx.Err() == nil {
		select {
		case <-tick.C:
			report()
		case <-sctx.Done():
		}
	}
	select {
	case <-done:
	case <-time.After(stopWait - closeBound): // closing the Runtimes ends the rest
	}
	report()
	if err := context.Cause(sctx); err != context.Cause(ctx) {
		return err // a serve ended first (a nil return as context.Canceled)
	}
	return nil
}
