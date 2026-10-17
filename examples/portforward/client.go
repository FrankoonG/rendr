package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/l4"
)

// parseForward parses the -L s, tcp:<local addr>=<target> or
// udp:<local addr>=<target>, into its protocol, its resolved local address
// (whose IP, port and zone serve both protocols) and its target. The local
// address must be loopback unless nonLoopback; the target must be a valid
// l4 target.
func parseForward(s string, nonLoopback bool) (proto string, local *net.TCPAddr, target string, err error) {
	proto, rest, ok1 := strings.Cut(s, ":")
	l, target, ok2 := strings.Cut(rest, "=")
	if !ok1 || !ok2 || (proto != "tcp" && proto != "udp") || l == "" {
		return "", nil, "", fmt.Errorf("%w: -L %q: want tcp:<local addr>=<target> or udp:<local addr>=<target>", errUsage, s)
	}
	if _, err := l4.AppendMetadata(nil, l4.Request{Cmd: l4.CmdConnect, Addr: target}); err != nil {
		return "", nil, "", fmt.Errorf("%w: -L %q: target: %v", errUsage, s, err)
	}
	if local, err = net.ResolveTCPAddr("tcp", l); err != nil {
		return "", nil, "", fmt.Errorf("%w: -L %q: %v", errUsage, s, err)
	}
	if ip, ok := netip.AddrFromSlice(local.IP); !nonLoopback && (!ok || !ip.Unmap().IsLoopback()) {
		return "", nil, "", fmt.Errorf("%w: -L %q: %s is not a loopback address; a forward has no authentication, so a non-loopback one needs -allow-nonloopback", errUsage, s, l)
	}
	return proto, local, target, nil
}

// side is one kind of forward, UDP or TCP: its Runtime, its Peer (datagram
// carriers only for UDP, stream carriers for TCP: M6-D33) and its
// PortForward.
type side struct {
	kind   string
	rt     *rendr.Runtime
	pf     *l4.PortForward
	deaths carrierDeaths
}

func newSide(kind string, o options) (*side, error) {
	s := &side{kind: kind}
	rt, err := newRuntime(&s.deaths)
	if err != nil {
		return nil, err
	}
	cs := make([]rendr.Carrier, len(o.rendr))
	for i, a := range o.rendr {
		if name := fmt.Sprintf("%s-%d", kind, i); kind == "udp" {
			cs[i] = udp.Carrier(name, "udp", a, udpOptions(o))
		} else {
			cs[i] = tcp.Carrier(name, "tcp", a, tcp.Options{AllowNonLoopback: o.insecure})
		}
	}
	peer, err := rt.NewPeer(rendr.PeerConfig{Carriers: cs})
	s.rt, s.pf = rt, &l4.PortForward{Peer: peer, Options: rendr.DialOptions{Mode: o.mode}, AllowNonLoopback: o.allowNonLoopback}
	return s, err // with an error, s only holds the Runtime to close
}

// line is the side's status line.
func (s *side) line() string {
	st := s.pf.Status()
	if s.kind == "tcp" {
		return string(statusLine("tcp", st.TCP, &s.deaths))
	}
	b := statusLine("udp", st.UDP, &s.deaths)
	if u := st.UDP; u.TooLarge > 0 {
		b = fmt.Appendf(b, "; datagrams up to %d bytes dropped; this path carries %d (raise -max-datagram on both ends)", u.TooLargeMax, u.MaxPayload)
	}
	return string(b)
}

// serve binds local and forwards it to target until ctx is done.
func (s *side) serve(ctx context.Context, logger *log.Logger, local *net.TCPAddr, target string) error {
	if s.kind == "tcp" {
		ln, err := net.ListenTCP("tcp", local)
		if err != nil {
			return err
		}
		logger.Printf("client: tcp %s to %s", ln.Addr(), target)
		return s.pf.ServeTCP(ctx, ln, target)
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Port: local.Port, Zone: local.Zone})
	if err != nil {
		return err
	}
	c.SetReadBuffer(ingressBuffer)
	c.SetWriteBuffer(ingressBuffer)
	logger.Printf("client: udp %s to %s", c.LocalAddr(), target)
	return s.pf.ServeUDP(ctx, c, target)
}

// runClient forwards the -L addresses through the server at o.rendr until
// ctx is done.
func runClient(ctx context.Context, logger *log.Logger, o options) error {
	sides := map[string]*side{}
	defer func() {
		for _, s := range sides {
			s.rt.Close()
		}
	}()
	var serves []func(context.Context) error
	for _, spec := range o.fwd {
		proto, local, target, err := parseForward(spec, o.allowNonLoopback)
		if err != nil {
			return err
		}
		s := sides[proto]
		if s == nil {
			if s, err = newSide(proto, o); s != nil {
				sides[proto] = s
			}
			if err != nil {
				return err
			}
		}
		serves = append(serves, func(ctx context.Context) error { return s.serve(ctx, logger, local, target) })
	}
	return supervise(ctx, func() {
		for _, k := range []string{"udp", "tcp"} {
			if s := sides[k]; s != nil {
				logger.Print("client: status ", s.line())
			}
		}
	}, serves)
}
