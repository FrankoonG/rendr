// Command g2 runs G2 at configurable scale.
//
// G2 contract (docs/success-criteria.md):
//   - long-lived echo between two rendr Conns, 100 ms interval
//   - random migrations sprinkled across the run
//   - 0 echo loss (every counter received)
//   - P99 RTT < baseline x 2; P99.9 < 1 s
//   - fd unchanged (Go: same Conn pointer throughout)
//
// Usage:
//
//	go run ./cmd/g2 -duration 30m -migrations 30 -paths 4 -report g2.json
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"sort"
	"time"

	"github.com/FrankoonG/rendr"
)

type report struct {
	DurationSeconds float64       `json:"duration_seconds"`
	Echoes          int           `json:"echoes"`
	Migrations      int           `json:"migrations"`
	Paths           int           `json:"paths"`
	P50RTT          time.Duration `json:"p50_rtt"`
	P99RTT          time.Duration `json:"p99_rtt"`
	P999RTT         time.Duration `json:"p999_rtt"`
	MaxRTT          time.Duration `json:"max_rtt"`
	Lost            int           `json:"lost"`
	Pass            bool          `json:"pass"`
}

func main() {
	var (
		duration      = flag.Duration("duration", 30*time.Second, "echo run length")
		migrations    = flag.Int("migrations", 10, "approximate number of migrations to trigger")
		paths         = flag.Int("paths", 4, "number of TCP paths to attach")
		echoInterval  = flag.Duration("interval", 100*time.Millisecond, "echo cadence")
		reportPath    = flag.String("report", "", "write JSON report to this path")
		p99CeilingMs  = flag.Int("p99-ms-ceiling", 200, "fail if P99 RTT exceeds this (ms)")
		lossTolerated = flag.Int("loss-tolerated", 0, "max acceptable lost echoes")
		failOnNoMigs  = flag.Bool("require-migrations", true, "fail if 0 migrations actually fired")
	)
	flag.Parse()

	if *paths < 2 {
		log.Fatalf("g2 needs paths >= 2 for migrations to be possible")
	}

	r, err := run(*duration, *migrations, *paths, *echoInterval)
	if err != nil {
		log.Fatal(err)
	}

	r.Pass = r.Lost <= *lossTolerated &&
		r.P99RTT.Milliseconds() <= int64(*p99CeilingMs) &&
		(!*failOnNoMigs || r.Migrations > 0)

	fmt.Printf("G2: duration=%s, echoes=%d, migrations=%d, P50=%s P99=%s max=%s, lost=%d, pass=%v\n",
		*duration, r.Echoes, r.Migrations, r.P50RTT, r.P99RTT, r.MaxRTT, r.Lost, r.Pass)

	if *reportPath != "" {
		if err := writeJSON(*reportPath, r); err != nil {
			log.Fatalf("report: %v", err)
		}
	}
	if !r.Pass {
		os.Exit(1)
	}
}

func run(duration time.Duration, migrations, paths int, echoInterval time.Duration) (*report, error) {
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		accepted <- c
	}()

	specs := make([]rendr.PathSpec, paths)
	for i := range specs {
		specs[i] = rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}
	}
	d := &rendr.Dialer{Mode: rendr.ModePrime, Paths: specs}
	client, err := d.Dial(context.Background())
	if err != nil {
		return nil, err
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// Wait for all paths.
	wait := time.Now().Add(5 * time.Second)
	for time.Now().Before(wait) {
		if len(client.Paths()) >= paths && len(server.Paths()) >= paths {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(client.Paths()) < paths {
		return nil, fmt.Errorf("only %d paths attached on client", len(client.Paths()))
	}

	// Server-side echo loop.
	echoDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		for {
			if _, err := io.ReadFull(server, buf); err != nil {
				echoDone <- err
				return
			}
			if _, err := server.Write(buf); err != nil {
				echoDone <- err
				return
			}
		}
	}()

	admin, ok := client.(rendr.AdminConn)
	if !ok {
		return nil, fmt.Errorf("client does not implement AdminConn")
	}

	// Migration driver.
	migCount := 0
	if migrations > 0 {
		gap := duration / time.Duration(migrations+1)
		if gap < 50*time.Millisecond {
			gap = 50 * time.Millisecond
		}
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			t := time.NewTicker(gap)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					cur := admin.ActivePath()
					ps := client.Paths()
					if len(ps) < 2 {
						continue
					}
					idx := rand.Intn(len(ps))
					if ps[idx].ID == cur {
						idx = (idx + 1) % len(ps)
					}
					if err := admin.Migrate(ps[idx].ID); err == nil {
						migCount++
					}
				}
			}
		}()
	}

	rtts := make([]time.Duration, 0, int(duration/echoInterval)+1)
	rxbuf := make([]byte, 8)
	endAt := time.Now().Add(duration)
	lost := 0
	var counter uint64
	for time.Now().Before(endAt) {
		var tx [8]byte
		binary.BigEndian.PutUint64(tx[:], counter)
		t0 := time.Now()
		if _, err := client.Write(tx[:]); err != nil {
			return nil, fmt.Errorf("write at counter=%d: %w", counter, err)
		}
		if _, err := io.ReadFull(client, rxbuf); err != nil {
			return nil, fmt.Errorf("read at counter=%d: %w", counter, err)
		}
		rtt := time.Since(t0)
		if got := binary.BigEndian.Uint64(rxbuf); got != counter {
			lost++
		}
		rtts = append(rtts, rtt)
		counter++
		time.Sleep(echoInterval)
	}

	pct := percentiles(rtts)
	max := time.Duration(0)
	for _, r := range rtts {
		if r > max {
			max = r
		}
	}

	r := &report{
		DurationSeconds: duration.Seconds(),
		Echoes:          len(rtts),
		Migrations:      migCount,
		Paths:           paths,
		P50RTT:          pct[50],
		P99RTT:          pct[99],
		P999RTT:         pct[999],
		MaxRTT:          max,
		Lost:            lost,
	}
	return r, nil
}

func percentiles(rtts []time.Duration) map[int]time.Duration {
	if len(rtts) == 0 {
		return map[int]time.Duration{50: 0, 99: 0, 999: 0}
	}
	sorted := make([]time.Duration, len(rtts))
	copy(sorted, rtts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pick := func(p int) time.Duration {
		idx := (p * len(sorted)) / 1000
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		return sorted[idx]
	}
	return map[int]time.Duration{
		50:  pick(500),
		99:  pick(990),
		999: pick(999),
	}
}

func writeJSON(path string, r *report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
