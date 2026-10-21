package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/l4"
)

// runServer serves l4 sessions arriving on the carriers of every -rendr
// address until ctx is done.
func runServer(ctx context.Context, logger *log.Logger, o options) error {
	allow := map[string]bool{}
	for _, a := range o.allow {
		// The form Request.Addr takes for a, in lower case: an entry
		// matches every spelling of its address.
		md, err := l4.AppendMetadata(nil, l4.Request{Cmd: l4.CmdConnect, Addr: a})
		if err != nil {
			return fmt.Errorf("%w: -allow %q: %v", errUsage, a, err)
		}
		r, _ := l4.ParseMetadata(md)
		allow[strings.ToLower(r.Addr)] = true
	}
	s := &l4.Server{UDP: o.udp, Dial: allowDial(allow, o.allowAny)}
	if o.udp {
		checkBuffers(logger, "server", "target", burstBuffer)
	}
	var deaths carrierDeaths
	rt, err := rendr.NewRuntime(runtimeConfig(&deaths))
	if err != nil {
		return err
	}
	defer rt.Close() // after the serves: it closes every Listener and its carrier sockets
	// One Listener per address, each owning its carrier sockets from Listen
	// on (a session's carriers may arrive through any of them).
	var serves []func(context.Context) error
	for _, a := range o.rendr {
		tl, ul, err := listenPair(a, o)
		if err != nil {
			return err
		}
		ln, err := rt.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(tl), rendr.FromPacketConn(ul)}})
		if err != nil {
			tl.Close() // a failed Listen leaves them to the caller
			ul.Close()
			return err
		}
		logger.Printf("server: rendr carriers on %s (tcp and udp)", tl.Addr())
		serves = append(serves, func(ctx context.Context) error { return s.Serve(ctx, ln) })
	}
	return supervise(ctx, func() {
		logger.Print("server: status ", string(statusLine("l4", s.Status(), &deaths)))
	}, serves)
}

// listenPair opens a carrier/tcp listener and a carrier/udp socket on one
// address and port (port 0: one free for both, a few tries).
func listenPair(addr string, o options) (net.Listener, net.PacketConn, error) {
	to, uo := carrierOptions(o)
	_, port, _ := net.SplitHostPort(addr)
	for try := 0; ; try++ {
		tl, err := tcp.Listen("tcp", addr, to)
		if err != nil {
			return nil, nil, err
		}
		ul, err := udp.Listen("udp", tl.Addr().String(), uo)
		if err == nil {
			return tl, ul, nil
		}
		tl.Close()
		if port != "0" || try == 9 {
			return nil, nil, err
		}
	}
}

// targetControl is the hook's net.Dialer.Control, run for every resolved
// target address before its connect, as l4's default UDP dialer's
// (M6-D34): a multicast, limited-broadcast or unspecified address is
// refused (a name may resolve to one), and an IPv4 UDP socket gets
// SO_BROADCAST off (Go turns it on), so that the OS refuses a directed
// broadcast; a socket whose SO_BROADCAST stays on is not dialled.
func targetControl(network, address string, c syscall.RawConn) error {
	if a, _ := netip.ParseAddrPort(address); a.Addr().IsMulticast() || a.Addr().IsUnspecified() || a.Addr() == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return fmt.Errorf("%w: resolved to %s", l4.ErrDenied, a.Addr())
	}
	var serr error
	if network == "udp4" {
		c.Control(func(fd uintptr) { serr = clearBroadcast(fd) })
	}
	return serr
}

// allowDial is the server's Dial hook: unless all (-allow-any), a target
// that is not an -allow entry is refused (ErrDenied: CodeNotAllowed); every
// other target is dialled as l4's default dialer does (targetControl), the
// socket buffers of a UDP flow's target sized for keyframe bursts. Both
// modes dial through it, so -allow-any's targets get the same sockets.
func allowDial(allow map[string]bool, all bool) func(context.Context, l4.Request) (net.Conn, error) {
	d := &net.Dialer{Control: targetControl}
	return func(ctx context.Context, r l4.Request) (net.Conn, error) {
		if !all && !allow[strings.ToLower(r.Addr)] {
			return nil, fmt.Errorf("%w: %s is not an -allow target", l4.ErrDenied, r.Addr)
		}
		if r.Cmd != l4.CmdUDP {
			return d.DialContext(ctx, "tcp", r.Addr)
		}
		c, err := d.DialContext(ctx, "udp", r.Addr)
		if u, ok := c.(*net.UDPConn); ok {
			u.SetReadBuffer(burstBuffer)
			u.SetWriteBuffer(burstBuffer)
		}
		return c, err
	}
}
