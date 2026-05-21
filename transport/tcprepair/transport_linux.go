//go:build linux

package tcprepair

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/FrankoonG/rendr/transport"
	basetcp "github.com/FrankoonG/rendr/transport/tcp"
)

// Transport is the TCP_REPAIR-capable TCP adapter. Stage 2 engine
// integration still needs an explicit migration hook, but exposing a
// real transport lets embedders select it via PathSpec.Transport and
// gets capability detection into the normal dial path.
type Transport struct{}

// New returns a TCP_REPAIR transport.
func New() *Transport { return &Transport{} }

func init() {
	if err := transport.Default.Register(New()); err != nil {
		panic(err)
	}
}

// Name implements transport.Transport.
func (*Transport) Name() string { return "tcprepair" }

// Available probes whether TCP_REPAIR is usable in this process. EPERM
// is reported with an explicit CAP_NET_ADMIN hint so embedders can
// fall back to gvisor cleanly.
func Available() error {
	if err := requireTCPRepairWindowKernel(); err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("tcprepair: probe socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := setInt(fd, tcpRepair, 1); err != nil {
		if errors.Is(err, syscall.EPERM) {
			return errors.New("tcprepair: CAP_NET_ADMIN required, use gvisor fallback")
		}
		return fmt.Errorf("tcprepair: enable TCP_REPAIR: %w", err)
	}
	_ = setInt(fd, tcpRepair, 0)
	return nil
}

// DialPath dials a TCP socket and wraps it in a TCP_REPAIR-capable
// PathConn. The adapter currently shares the same steady-state data
// path as transport/tcp; stage 2's migration dance will type-assert to
// *tcprepair.PathConn to access the underlying *net.TCPConn.
func (*Transport) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	if err := Available(); err != nil {
		return nil, err
	}
	d := net.Dialer{KeepAlive: -1}
	if spec.Local != "" {
		la, err := net.ResolveTCPAddr("tcp", spec.Local)
		if err != nil {
			return nil, fmt.Errorf("tcprepair: bad local %q: %w", spec.Local, err)
		}
		d.LocalAddr = la
	}
	c, err := d.DialContext(ctx, "tcp", spec.Address)
	if err != nil {
		return nil, fmt.Errorf("tcprepair: dial %s: %w", spec.Address, err)
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		_ = c.Close()
		return nil, errors.New("tcprepair: dial did not return *net.TCPConn")
	}
	_ = tc.SetKeepAlive(false)
	return Wrap(tc), nil
}

// Probe matches transport/tcp: dial, time the handshake, then close.
func (t *Transport) Probe(ctx context.Context, spec transport.PathSpec) (transport.PathQuality, error) {
	start := time.Now()
	pc, err := t.DialPath(ctx, spec)
	if err != nil {
		return transport.PathQuality{}, err
	}
	rtt := time.Since(start)
	_ = pc.Close()
	return transport.PathQuality{RTT: rtt, At: time.Now()}, nil
}

// PathConn is the steady-state framed TCP path plus access to the
// underlying *net.TCPConn for future TCP_REPAIR migration hooks.
type PathConn struct {
	base *basetcp.PathConn
	tcp  *net.TCPConn
}

// Wrap promotes an established TCP socket into a TCP_REPAIR-capable
// PathConn.
func Wrap(c *net.TCPConn) *PathConn {
	return &PathConn{
		base: basetcp.Wrap(c),
		tcp:  c,
	}
}

// TCPConn exposes the underlying socket for migration routines.
func (p *PathConn) TCPConn() *net.TCPConn { return p.tcp }

// Snapshot captures the current TCP_REPAIR state of the underlying
// socket. The caller still owns the migration window sequencing.
func (p *PathConn) Snapshot() (*State, error) { return Snapshot(p.tcp) }

// MigratePathLocalAddr rebuilds the underlying TCP socket via
// TCP_REPAIR and returns a fresh PathConn. v0.1.0 supports only the
// same local 4-tuple rebuild shape validated by the stage-1 POC; a
// different local address still needs the broader coordination
// protocol described in docs/handoff-2026-05-20.md.
func (p *PathConn) MigratePathLocalAddr(newLocal string) (transport.PathConn, error) {
	curLocal := p.tcp.LocalAddr().String()
	if newLocal != "" && newLocal != curLocal {
		return nil, fmt.Errorf("tcprepair: changing local addr from %s to %s not yet supported", curLocal, newLocal)
	}

	snap, err := Snapshot(p.tcp)
	if err != nil {
		return nil, err
	}
	cleanup, err := installDropRules(snap.LocalAddr, snap.RemoteAddr)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	_ = p.base.Close()
	fd, err := Restore(snap)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "tcprepair-restored")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("tcprepair: FileConn: %w", err)
	}
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("tcprepair: restored socket is not *net.TCPConn")
	}
	_ = tc.SetKeepAlive(false)
	return Wrap(tc), nil
}

func (p *PathConn) Read(buf []byte) (int, error)                           { return p.base.Read(buf) }
func (p *PathConn) Write(frame []byte) (int, error)                        { return p.base.Write(frame) }
func (p *PathConn) Close() error                                           { return p.base.Close() }
func (p *PathConn) CloseWrite() error                                      { return p.base.CloseWrite() }
func (p *PathConn) Quality() transport.PathQuality                         { return p.base.Quality() }
func (p *PathConn) OnDeath(fn func(cause transport.DeathCause, err error)) { p.base.OnDeath(fn) }
func (p *PathConn) LocalAddr() string                                      { return p.base.LocalAddr() }
func (p *PathConn) RemoteAddr() string                                     { return p.base.RemoteAddr() }
func (p *PathConn) SetQuality(q transport.PathQuality)                     { p.base.SetQuality(q) }
func (p *PathConn) MarkByeSeen()                                           { p.base.MarkByeSeen() }
func (p *PathConn) MarkQuiesced()                                          { p.base.MarkQuiesced() }
func (p *PathConn) Writes() uint64                                         { return p.base.Writes() }
func (p *PathConn) Reads() uint64                                          { return p.base.Reads() }
