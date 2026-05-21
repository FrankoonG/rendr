package udprelay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/FrankoonG/rendr"
)

const defaultBufferSize = 64 << 10

// Config describes one UDP relay endpoint.
//
// PacketConn is the rendr packet-mode connection used as the migrated
// carrier. It is required for now; callers can create one with
// Dialer.DialPacket or PacketListener.AcceptPacket.
//
// LocalAddr is the UDP address exposed to the application or used as
// the source socket for target traffic. Empty means "127.0.0.1:0".
//
// TargetAddr selects server-side mode: packets received from rendr
// are written to this UDP target, and replies from the target are
// forwarded back over rendr. When empty, client-side mode learns the
// most recent UDP sender and writes rendr replies back to it.
type Config struct {
	PacketConn rendr.PacketConn
	LocalAddr  string
	TargetAddr string
	BufferSize int
}

// DialConfig creates a client-side relay and dials the rendr
// packet-mode carrier for it.
type DialConfig struct {
	Dialer     *rendr.Dialer
	LocalAddr  string
	BufferSize int
}

// ServeConfig creates a server-side relay from an accepted rendr
// packet-mode carrier.
type ServeConfig struct {
	Listener   rendr.PacketListener
	LocalAddr  string
	TargetAddr string
	BufferSize int
}

// Relay bridges one local UDP socket to one rendr PacketConn.
type Relay struct {
	pc     rendr.PacketConn
	udp    net.PacketConn
	target net.Addr

	closeOnce sync.Once
	done      chan struct{}

	peerMu sync.RWMutex
	peer   net.Addr
}

// Dial dials a rendr PacketConn and starts a client-side local UDP
// relay for a self-managed UDP application.
func Dial(ctx context.Context, cfg DialConfig) (*Relay, error) {
	if cfg.Dialer == nil {
		return nil, errors.New("udprelay: Dialer is required")
	}
	pc, err := cfg.Dialer.DialPacket(ctx)
	if err != nil {
		return nil, fmt.Errorf("udprelay: dial packet carrier: %w", err)
	}
	r, err := Start(ctx, Config{
		PacketConn: pc,
		LocalAddr:  cfg.LocalAddr,
		BufferSize: cfg.BufferSize,
	})
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return r, nil
}

// Serve accepts one rendr PacketConn and starts a server-side UDP
// relay to TargetAddr. Call Serve once per accepted remote relay.
func Serve(ctx context.Context, cfg ServeConfig) (*Relay, error) {
	if cfg.Listener == nil {
		return nil, errors.New("udprelay: Listener is required")
	}
	if cfg.TargetAddr == "" {
		return nil, errors.New("udprelay: TargetAddr is required")
	}
	pc, err := cfg.Listener.AcceptPacket(ctx)
	if err != nil {
		return nil, fmt.Errorf("udprelay: accept packet carrier: %w", err)
	}
	r, err := Start(ctx, Config{
		PacketConn: pc,
		LocalAddr:  cfg.LocalAddr,
		TargetAddr: cfg.TargetAddr,
		BufferSize: cfg.BufferSize,
	})
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return r, nil
}

// Start creates and starts a UDP relay endpoint.
func Start(ctx context.Context, cfg Config) (*Relay, error) {
	if cfg.PacketConn == nil {
		return nil, errors.New("udprelay: PacketConn is required")
	}
	local := cfg.LocalAddr
	if local == "" {
		local = "127.0.0.1:0"
	}
	udp, err := net.ListenPacket("udp", local)
	if err != nil {
		return nil, fmt.Errorf("udprelay: listen udp %s: %w", local, err)
	}

	var target net.Addr
	if cfg.TargetAddr != "" {
		target, err = net.ResolveUDPAddr("udp", cfg.TargetAddr)
		if err != nil {
			_ = udp.Close()
			return nil, fmt.Errorf("udprelay: resolve target %s: %w", cfg.TargetAddr, err)
		}
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = defaultBufferSize
	}

	r := &Relay{
		pc:     cfg.PacketConn,
		udp:    udp,
		target: target,
		done:   make(chan struct{}),
	}
	go r.closeOnContext(ctx)
	go r.udpToRendr(cfg.BufferSize)
	go r.rendrToUDP(cfg.BufferSize)
	return r, nil
}

// LocalAddr returns the UDP socket address applications should use.
func (r *Relay) LocalAddr() net.Addr { return r.udp.LocalAddr() }

// PacketConn returns the underlying rendr carrier. Callers may
// type-assert it to rendr.AdminPacketConn to add paths or trigger
// explicit migrations.
func (r *Relay) PacketConn() rendr.PacketConn { return r.pc }

// Close stops the relay and closes both the UDP socket and rendr
// PacketConn.
func (r *Relay) Close() error {
	var err error
	r.closeOnce.Do(func() {
		close(r.done)
		if e := r.udp.Close(); e != nil {
			err = e
		}
		if e := r.pc.Close(); err == nil && e != nil {
			err = e
		}
	})
	return err
}

func (r *Relay) closeOnContext(ctx context.Context) {
	select {
	case <-ctx.Done():
		_ = r.Close()
	case <-r.done:
	}
}

func (r *Relay) udpToRendr(bufSize int) {
	buf := make([]byte, bufSize)
	for {
		n, addr, err := r.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		if r.target == nil {
			r.peerMu.Lock()
			r.peer = addr
			r.peerMu.Unlock()
		}
		if _, err := r.pc.WriteTo(buf[:n], nil); err != nil {
			return
		}
	}
}

func (r *Relay) rendrToUDP(bufSize int) {
	buf := make([]byte, bufSize)
	for {
		n, _, err := r.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		dst := r.target
		if dst == nil {
			r.peerMu.RLock()
			dst = r.peer
			r.peerMu.RUnlock()
		}
		if dst == nil {
			continue
		}
		if _, err := r.udp.WriteTo(buf[:n], dst); err != nil {
			return
		}
	}
}
