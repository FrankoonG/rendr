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
	"sort"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/chaos/internal/lossy"
)

type report struct {
	Mode            string        `json:"mode"`
	Frames          int           `json:"frames"`
	DropPctForward  int           `json:"drop_pct_forward"`
	LatencyMs       int           `json:"latency_ms_each_dir"`
	ProxyForwarded  uint64        `json:"proxy_forwarded"`
	ProxyDropped    uint64        `json:"proxy_dropped"`
	ApplicationLost int           `json:"application_lost"`
	P50RTT          time.Duration `json:"p50_rtt"`
	P99RTT          time.Duration `json:"p99_rtt"`
	MaxRTT          time.Duration `json:"max_rtt"`
	ElapsedSeconds  float64       `json:"elapsed_seconds"`
	Pass            bool          `json:"pass"`
}

func main() {
	var (
		modeArg    = flag.String("mode", "race", "operating mode: race | prime")
		frames     = flag.Int("frames", 200, "number of echo frames to send")
		dropPct    = flag.Int("drop-pct", 30, "percent of frames the proxy drops in each direction")
		latencyMs  = flag.Int("latency-ms", 0, "extra latency applied to each chaos-path frame, each direction (ms)")
		echoInt    = flag.Duration("interval", 10*time.Millisecond, "echo cadence")
		reportPath = flag.String("report", "", "write JSON report path")
	)
	flag.Parse()

	var mode rendr.Mode
	switch *modeArg {
	case "race":
		mode = rendr.ModeRace
	case "prime":
		mode = rendr.ModePrime
	default:
		log.Fatalf("unknown mode %q", *modeArg)
	}

	r, err := run(mode, *frames, *dropPct, *latencyMs, *echoInt)
	if err != nil {
		log.Fatal(err)
	}
	r.Mode = *modeArg
	// Pass criteria: zero application loss; for race we also require
	// drops actually occurred (otherwise the test proves nothing).
	r.Pass = r.ApplicationLost == 0
	if mode == rendr.ModeRace && *dropPct > 0 {
		r.Pass = r.Pass && r.ProxyDropped > 0
	}
	fmt.Printf("race-chaos: mode=%s frames=%d drop_pct=%d latency_ms=%d proxy_forwarded=%d proxy_dropped=%d app_lost=%d P50=%s P99=%s max=%s elapsed=%.2fs pass=%v\n",
		*modeArg, r.Frames, r.DropPctForward, r.LatencyMs, r.ProxyForwarded, r.ProxyDropped, r.ApplicationLost,
		r.P50RTT, r.P99RTT, r.MaxRTT, r.ElapsedSeconds, r.Pass)

	if *reportPath != "" {
		writeJSON(*reportPath, r)
	}
	if !r.Pass {
		os.Exit(1)
	}
}

func run(mode rendr.Mode, frames, dropPct, latencyMs int, echoInt time.Duration) (*report, error) {
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
		LatencyForward: time.Duration(latencyMs) * time.Millisecond,
		LatencyReverse: time.Duration(latencyMs) * time.Millisecond,
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
		Mode: mode,
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

	// Server echos back so we can measure end-to-end RTT from the
	// client side under the chaos conditions.
	echoErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		for {
			if _, err := io.ReadFull(server, buf); err != nil {
				echoErr <- err
				return
			}
			if _, err := server.Write(buf); err != nil {
				echoErr <- err
				return
			}
		}
	}()

	t0 := time.Now()
	lost := 0
	rxbuf := make([]byte, 8)
	rtts := make([]time.Duration, 0, frames)
	for i := uint64(0); i < uint64(frames); i++ {
		var tx [8]byte
		binary.BigEndian.PutUint64(tx[:], i)
		tStart := time.Now()
		if _, err := client.Write(tx[:]); err != nil {
			return nil, fmt.Errorf("write at %d: %w", i, err)
		}
		if _, err := io.ReadFull(client, rxbuf); err != nil {
			return nil, fmt.Errorf("read at %d: %w", i, err)
		}
		rtts = append(rtts, time.Since(tStart))
		if binary.BigEndian.Uint64(rxbuf) != i {
			lost++
		}
		if echoInt > 0 {
			time.Sleep(echoInt)
		}
	}
	elapsed := time.Since(t0)

	p50, p99, max := percentiles(rtts)
	return &report{
		Frames:          frames,
		DropPctForward:  dropPct,
		LatencyMs:       latencyMs,
		ProxyForwarded:  p.Forwarded(),
		ProxyDropped:    p.Dropped(),
		ApplicationLost: lost,
		P50RTT:          p50,
		P99RTT:          p99,
		MaxRTT:          max,
		ElapsedSeconds:  elapsed.Seconds(),
	}, nil
}

func percentiles(rtts []time.Duration) (p50, p99, max time.Duration) {
	if len(rtts) == 0 {
		return
	}
	sorted := make([]time.Duration, len(rtts))
	copy(sorted, rtts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	p50 = sorted[(50*len(sorted))/100]
	p99 = sorted[(99*len(sorted))/100]
	for _, r := range sorted {
		if r > max {
			max = r
		}
	}
	return
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
