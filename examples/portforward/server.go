package main

import (
	"context"
	"fmt"
	"io"
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
	var deaths carrierDeaths
	rt, err := newRuntime(&deaths)
	if err != nil {
		return err
	}
	defer rt.Close()
	var srcs []rendr.Source
	var socks []io.Closer
	defer func() {
		for _, c := range socks {
			c.Close() // the Listener closed them already, unless it never started
		}
	}()
	for _, a := range o.rendr {
		tl, ul, err := listenPair(a, o)
		if err != nil {
			return err
		}
		srcs, socks = append(srcs, rendr.FromListener(tl), rendr.FromPacketConn(ul)), append(socks, tl, ul)
		logger.Printf("server: rendr carriers on %s (tcp and udp)", tl.Addr())
	}
	ln, err := rt.Listen(rendr.ListenConfig{Sources: srcs})
	if err != nil {
		return err
	}
	s := &l4.Server{UDP: o.udp, UDPBuffer: burstBuffer}
	if !o.allowAny {
		s.Dial = allowDial(allow)
	}
	return supervise(ctx, func() {
		logger.Print("server: status ", string(statusLine("l4", s.Status(), &deaths)))
	}, []func(context.Context) error{func(ctx context.Context) error { return s.Serve(ctx, ln) }})
}

// listenPair opens a carrier/tcp listener and a carrier/udp socket on one
// address and port (port 0: one free for both, a few tries).
func listenPair(addr string, o options) (net.Listener, net.PacketConn, error) {
	_, port, _ := net.SplitHostPort(addr)
	for try := 0; ; try++ {
		tl, err := tcp.Listen("tcp", addr, tcp.Options{AllowNonLoopback: o.insecure})
		if err != nil {
			return nil, nil, err
		}
		ul, err := udp.Listen("udp", tl.Addr().String(), udpOptions(o))
		if err == nil {
			return tl, ul, nil
		}
		tl.Close()
		if port != "0" || try == 9 {
			return nil, nil, err
		}
	}
}

// allowDial is the Dial hook without -allow-any: a target that is not an
// -allow entry is refused (ErrDenied: CodeNotAllowed); an allowed one is
// dialled as l4's default dialer does, a resolved multicast, limited
// broadcast or unspecified address refused (a name may resolve to one),
// with the socket buffers of a UDP flow's target sized for keyframe bursts.
func allowDial(allow map[string]bool) func(context.Context, l4.Request) (net.Conn, error) {
	d := &net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
		if a, _ := netip.ParseAddrPort(address); a.Addr().IsMulticast() || a.Addr().IsUnspecified() || a.Addr() == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return fmt.Errorf("%w: resolved to %s", l4.ErrDenied, a.Addr())
		}
		return nil
	}}
	return func(ctx context.Context, r l4.Request) (net.Conn, error) {
		if !allow[strings.ToLower(r.Addr)] {
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
