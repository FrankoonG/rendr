package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"

	qgo "github.com/quic-go/quic-go"
)

// owned is a dialer carrier's connection with its own Transport and UDP
// socket; close ends the three in that order, once, so closing a carrier
// releases its socket (Transport.Close only stops reading a socket it did
// not create).
type owned struct {
	qc   *qgo.Conn
	tr   *qgo.Transport
	udp  *net.UDPConn
	once sync.Once
}

func (w *owned) close(code qgo.ApplicationErrorCode) {
	w.once.Do(func() {
		_ = w.qc.CloseWithError(code, "") // returns once quic-go's run loop exited
		_ = w.tr.Close()
		_ = w.udp.Close()
	})
}

// dial opens one connection to address (its IPv4 address first, as
// net.ResolveUDPAddr) on a socket of its own, bound to Options.LocalAddr,
// else to the loopback address of a loopback peer, else to the unspecified
// address, and verifies the ALPN (L44). ctx bounds the resolution and the
// handshake only: quic-go runs the connection on context.WithoutCancel.
func dial(ctx context.Context, address string, tc *tls.Config, o *Options, datagrams bool) (*owned, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	pn, err := net.DefaultResolver.LookupPort(ctx, "udp", port)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	ip := ips[max(slices.IndexFunc(ips, func(a netip.Addr) bool { return a.Unmap().Is4() }), 0)].Unmap()
	network, laddr := "udp6", &net.UDPAddr{}
	if ip.Is4() {
		network = "udp4"
	}
	if ip.IsLoopback() {
		laddr.IP = ip.AsSlice()
	}
	if o.LocalAddr != "" {
		if laddr, err = net.ResolveUDPAddr(network, o.LocalAddr); err != nil {
			return nil, err
		}
	}
	udp, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}
	tr := &qgo.Transport{Conn: udp, StatelessResetKey: o.StatelessResetKey}
	raddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(pn)))
	qc, err := tr.Dial(ctx, raddr, tc, quicConfig(o.Config, o.IdleTimeout, false, datagrams))
	if err != nil {
		_ = tr.Close()
		_ = udp.Close()
		return nil, err
	}
	w := &owned{qc: qc, tr: tr, udp: udp}
	if p := qc.ConnectionState().TLS.NegotiatedProtocol; p != ALPN {
		w.close(codeBadKind)
		return nil, fmt.Errorf("rendr/quic: negotiated ALPN %q, want %q", p, ALPN)
	}
	return w, nil
}

// dialStream opens a stream carrier: one connection, one client
// bidirectional stream, announced to the passive by the first bytes rendr
// writes (the PREFACE).
func dialStream(ctx context.Context, address string, tc *tls.Config, o *Options) (net.Conn, error) {
	w, err := dial(ctx, address, tc, o, false)
	if err != nil {
		return nil, err
	}
	st, err := w.qc.OpenStreamSync(ctx)
	if err != nil {
		w.close(codeClosed)
		return nil, err
	}
	return newStreamConn(w.qc, st, w.close), nil
}

// dialDatagram opens a datagram carrier whose DATAGRAM limit, probed at
// once, reaches DatagramBudget (L37).
func dialDatagram(ctx context.Context, address string, tc *tls.Config, o *Options) (net.PacketConn, net.Addr, error) {
	w, err := dial(ctx, address, tc, o, true)
	if err != nil {
		return nil, nil, err
	}
	n, err := probeLimit(w.qc)
	if err == nil && n < DatagramBudget {
		err = fmt.Errorf("rendr/quic: DATAGRAM limit %d is below the %d-byte budget", n, DatagramBudget)
	}
	if err != nil {
		w.close(codeBudget)
		return nil, nil, err
	}
	d := newDgramConn(w.qc, nil, n, w.close, o, nil)
	return d, d.peer, nil
}
