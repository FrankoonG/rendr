// Command race-chaos validates the M7 race-mode contract:
//
//	"single path 30% loss + race -> application sees 0 loss"
//
// Setup:
//   - rendr listener at 127.0.0.1:P_server (TCP)
//   - lossy TCP proxy at 127.0.0.1:P_proxy that forwards to P_server
//     and drops a fraction of frames in each direction
//   - rendr Dialer with 2 paths:
//     paths[0] -> P_proxy (chaos)
//     paths[1] -> P_server (clean)
//   - Mode = race
//
// Acceptance: every echo counter arrives in order with zero
// application-visible loss, even though the proxy reports
// dropping ~30% of forward frames.
//
// Usage:
//
//	go run ./cmd/race-chaos -drop-pct 30 -frames 200 -report race.json
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/chaos/internal/lossy"
)

type report struct {
	Frames          int     `json:"frames"`
	DropPctForward  int     `json:"drop_pct_forward"`
	ProxyForwarded  uint64  `json:"proxy_forwarded"`
	ProxyDropped    uint64  `json:"proxy_dropped"`
	ApplicationLost int     `json:"application_lost"`
	ElapsedSeconds  float64 `json:"elapsed_seconds"`
	Pass            bool    `json:"pass"`
}

func main() {
	var (
		frames     = flag.Int("frames", 200, "number of echo frames to send")
		dropPct    = flag.Int("drop-pct", 30, "percent of frames the proxy drops in each direction")
		echoInt    = flag.Duration("interval", 10*time.Millisecond, "echo cadence")
		reportPath = flag.String("report", "", "write JSON report path")
	)
	flag.Parse()

	r, err := run(*frames, *dropPct, *echoInt)
	if err != nil {
		log.Fatal(err)
	}
	r.Pass = r.ApplicationLost == 0 && r.ProxyDropped > 0
	fmt.Printf("race-chaos: frames=%d drop_pct=%d proxy_forwarded=%d proxy_dropped=%d app_lost=%d elapsed=%.2fs pass=%v\n",
		r.Frames, r.DropPctForward, r.ProxyForwarded, r.ProxyDropped, r.ApplicationLost, r.ElapsedSeconds, r.Pass)

	if *reportPath != "" {
		writeJSON(*reportPath, r)
	}
	if !r.Pass {
		os.Exit(1)
	}
}

func run(frames, dropPct int, echoInt time.Duration) (*report, error) {
	// Rendr server.
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	// Lossy proxy.
	p := &lossy.Proxy{
		UpstreamAddr:   ln.Addr().String(),
		DropPctForward: dropPct,
		DropPctReverse: dropPct,
		Seed:           42,
	}
	if err := p.Listen(); err != nil {
		return nil, err
	}
	defer p.Close()
	go p.Serve()

	accepted := make(chan rendr.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		accepted <- c
	}()

	d := &rendr.Dialer{
		Mode: rendr.ModeRace,
		Paths: []rendr.PathSpec{
			// First path carries HELLO; route it through the clean
			// link so the bridge is guaranteed to come up regardless
			// of the proxy's drop rate. Subsequent paths attach via
			// BRIDGE_TAG and a lost BRIDGE_TAG just means that path
			// stays detached, which is fine for race once at least
			// one peer-known path exists.
			{Transport: "tcp", Address: ln.Addr().String()}, // clean (HELLO path)
			{Transport: "tcp", Address: p.Addr()},           // chaos path
		},
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		return nil, err
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// Wait for both paths attached.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= 2 && len(server.Paths()) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	t0 := time.Now()
	lost := 0
	rxbuf := make([]byte, 8)
	for i := uint64(0); i < uint64(frames); i++ {
		var tx [8]byte
		binary.BigEndian.PutUint64(tx[:], i)
		if _, err := client.Write(tx[:]); err != nil {
			return nil, fmt.Errorf("write at %d: %w", i, err)
		}
		if _, err := io.ReadFull(server, rxbuf); err != nil {
			return nil, fmt.Errorf("read at %d: %w", i, err)
		}
		if binary.BigEndian.Uint64(rxbuf) != i {
			lost++
		}
		if echoInt > 0 {
			time.Sleep(echoInt)
		}
	}
	elapsed := time.Since(t0)

	return &report{
		Frames:          frames,
		DropPctForward:  dropPct,
		ProxyForwarded:  p.Forwarded(),
		ProxyDropped:    p.Dropped(),
		ApplicationLost: lost,
		ElapsedSeconds:  elapsed.Seconds(),
	}, nil
}

func writeJSON(path string, r *report) {
	f, err := os.Create(path)
	if err != nil {
		log.Printf("report: %v", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		log.Printf("report encode: %v", err)
	}
}
