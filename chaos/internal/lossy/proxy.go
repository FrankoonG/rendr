// Package lossy is a userspace TCP forwarder that drops a
// configurable fraction of rendr frames per direction.
//
// It is frame-aware: rendr's TCP transport prepends a 2-byte
// big-endian length to every frame, so the proxy reads
// length-then-frame and either forwards both halves or silently
// consumes them. Dropping at the frame boundary keeps the rest of
// the stream parseable by the peer.
//
// Intended for race-mode chaos tests where we want path A to
// pretend it loses 30 percent of frames while path B is intact.
package lossy

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const lengthPrefix = 2

// Proxy forwards TCP byte streams that carry length-prefixed rendr
// frames. Each direction can drop a percentage of frames and add a
// fixed per-frame delay.
type Proxy struct {
	UpstreamAddr   string
	DropPctForward int           // 0..100, drops frames from client toward server
	DropPctReverse int           // 0..100, drops frames from server toward client
	LatencyForward time.Duration // sleep before forwarding each frame, client -> server
	LatencyReverse time.Duration // sleep before forwarding each frame, server -> client
	Seed           int64

	ln net.Listener

	forwarded atomic.Uint64
	dropped   atomic.Uint64
}

// Listen binds the proxy to a loopback port. Use Addr() to get the
// chosen address. Serve runs the accept loop.
func (p *Proxy) Listen() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	p.ln = ln
	return nil
}

// Addr is the listening address.
func (p *Proxy) Addr() string {
	if p.ln == nil {
		return ""
	}
	return p.ln.Addr().String()
}

// Forwarded / Dropped expose proxy counters for the chaos report.
func (p *Proxy) Forwarded() uint64 { return p.forwarded.Load() }
func (p *Proxy) Dropped() uint64   { return p.dropped.Load() }

// Close shuts the proxy listener.
func (p *Proxy) Close() error {
	if p.ln == nil {
		return nil
	}
	return p.ln.Close()
}

// Serve loops Accept. Each inbound connection spawns a forwarder.
func (p *Proxy) Serve() error {
	if p.ln == nil {
		return fmt.Errorf("lossy: not listening")
	}
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return err
		}
		go p.handle(client)
	}
}

func (p *Proxy) handle(client net.Conn) {
	defer client.Close()
	server, err := net.Dial("tcp", p.UpstreamAddr)
	if err != nil {
		return
	}
	defer server.Close()

	// Per-direction RNGs so each side picks its own drops.
	src := rand.NewSource(p.Seed)
	rng := rand.New(src)
	var rngMu sync.Mutex

	pump := func(dir string, in net.Conn, out net.Conn, dropPct int, latency time.Duration) {
		defer in.Close()
		defer out.Close()
		buf := make([]byte, 1<<16)
		for {
			lp := make([]byte, lengthPrefix)
			if _, err := io.ReadFull(in, lp); err != nil {
				return
			}
			n := binary.BigEndian.Uint16(lp)
			if int(n) > len(buf) {
				return
			}
			if _, err := io.ReadFull(in, buf[:n]); err != nil {
				return
			}
			// Never drop control frames - BRIDGE_TAG, HELLO, BYE,
			// PATH_PROBE all carry setup / liveness state that race
			// mode does not duplicate at the engine level. Without
			// this guard a dropped BRIDGE_TAG would prevent the
			// chaos path from ever attaching on the server side.
			isCtrl := false
			if int(n) >= 1 {
				// proto header byte 0 layout: VER(2) T(1) F(1) FLAGS(4)
				// T bit is bit 5 of byte 0 (mask 0x20).
				isCtrl = (buf[0] & 0x20) != 0
			}
			drop := false
			if dropPct > 0 && !isCtrl {
				rngMu.Lock()
				drop = rng.Intn(100) < dropPct
				rngMu.Unlock()
			}
			if drop {
				p.dropped.Add(1)
				_ = dir
				continue
			}
			if latency > 0 {
				time.Sleep(latency)
			}
			if _, err := out.Write(lp); err != nil {
				return
			}
			if _, err := out.Write(buf[:n]); err != nil {
				return
			}
			p.forwarded.Add(1)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pump("c->s", client, server, p.DropPctForward, p.LatencyForward) }()
	go func() { defer wg.Done(); pump("s->c", server, client, p.DropPctReverse, p.LatencyReverse) }()
	wg.Wait()
}
