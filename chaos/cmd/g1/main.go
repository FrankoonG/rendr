// Command g1 runs G1 at configurable scale.
//
// G1 contract (docs/success-criteria.md):
//   - ≥1 GiB transfer between two rendr Conns
//   - planned migration at 30 / 50 / 70 percent
//   - zero application-visible interruption
//   - SHA-256 of received bytes equals SHA-256 of sent bytes
//   - total time relative to no-migration baseline < +10 percent
//
// Usage:
//
//	go run ./cmd/g1 -size 1GiB -migrations 3 -paths 2 -report g1.json
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/FrankoonG/rendr"
)

type report struct {
	Transport      string        `json:"transport"`
	Size           int64         `json:"size"`
	Migrations     int           `json:"migrations"`
	Paths          int           `json:"paths"`
	ElapsedSeconds float64       `json:"elapsed_seconds"`
	ThroughputMBs  float64       `json:"throughput_mb_s"`
	SHA256Sent     string        `json:"sha256_sent"`
	SHA256Recv     string        `json:"sha256_recv"`
	Pass           bool          `json:"pass"`
	BaselineRatio  float64       `json:"baseline_ratio,omitempty"`
	WallClock      time.Duration `json:"-"`
}

func main() {
	var (
		sizeArg      = flag.String("size", "1GiB", "transfer size, e.g. 256MiB, 1GiB, 4GiB")
		migrations   = flag.Int("migrations", 3, "number of planned migrations")
		paths        = flag.Int("paths", 2, "number of paths to attach")
		transportArg = flag.String("transport", "tcp", "transport for all paths: tcp | quic")
		reportPath   = flag.String("report", "", "write JSON report to this path (optional)")
		baselineSecs = flag.Float64("baseline-seconds", 0, "if >0, fail when elapsed > baseline*1.1")
	)
	flag.Parse()

	size, err := parseSize(*sizeArg)
	if err != nil {
		log.Fatalf("bad -size: %v", err)
	}
	if size <= 0 {
		log.Fatalf("size must be positive")
	}
	if *paths < 1 {
		log.Fatalf("paths must be >= 1")
	}
	if *migrations > 0 && *paths < 2 {
		log.Fatalf("migrations require paths >= 2")
	}

	r, err := run(size, *migrations, *paths, *transportArg)
	if err != nil {
		log.Fatal(err)
	}
	if *baselineSecs > 0 {
		r.BaselineRatio = r.ElapsedSeconds / *baselineSecs
		if r.BaselineRatio > 1.1 {
			r.Pass = false
		}
	}

	fmt.Printf("G1: transport=%s, size=%s, paths=%d, migrations=%d, elapsed=%.2fs (%.1f MB/s), sha256_ok=%v, pass=%v\n",
		*transportArg, *sizeArg, *paths, *migrations, r.ElapsedSeconds, r.ThroughputMBs,
		r.SHA256Sent == r.SHA256Recv, r.Pass)

	if *reportPath != "" {
		if err := writeJSON(*reportPath, r); err != nil {
			log.Fatalf("report: %v", err)
		}
	}
	if !r.Pass {
		os.Exit(1)
	}
}

func run(size int64, migrations, paths int, transportName string) (*report, error) {
	var ln rendr.Listener
	var err error
	switch transportName {
	case "tcp":
		ln, err = rendr.ListenTCP("127.0.0.1:0")
	case "quic":
		ln, err = rendr.ListenQUIC("127.0.0.1:0", nil)
	default:
		return nil, fmt.Errorf("unknown transport %q", transportName)
	}
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
		specs[i] = rendr.PathSpec{Transport: transportName, Address: ln.Addr().String()}
	}
	d := &rendr.Dialer{Mode: rendr.ModePrime, Paths: specs}
	client, err := d.Dial(context.Background())
	if err != nil {
		return nil, err
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	// Wait for all paths to attach.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= paths && len(server.Paths()) >= paths {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Generate deterministic payload.
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i*17 + 3)
	}
	hSent := sha256.Sum256(payload)

	hRecv := sha256.New()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 256*1024)
		got := int64(0)
		for got < size {
			n, err := server.Read(buf)
			if err != nil {
				done <- err
				return
			}
			hRecv.Write(buf[:n])
			got += int64(n)
		}
		done <- nil
	}()

	// Compute migration points along the byte stream.
	migPts := make([]int64, migrations)
	for i := 0; i < migrations; i++ {
		migPts[i] = size * int64(i+1) / int64(migrations+1)
	}

	admin, ok := client.(rendr.AdminConn)
	if !ok {
		return nil, fmt.Errorf("client conn does not implement rendr.AdminConn")
	}
	t0 := time.Now()
	written := int64(0)
	migIdx := 0
	chunk := int64(256 * 1024)
	for written < size {
		end := written + chunk
		if end > size {
			end = size
		}
		n, err := client.Write(payload[written:end])
		if err != nil {
			return nil, fmt.Errorf("write at %d: %w", written, err)
		}
		written += int64(n)
		for migIdx < len(migPts) && written >= migPts[migIdx] {
			cur := admin.ActivePath()
			var other uint32
			for _, p := range client.Paths() {
				if p.ID != cur {
					other = p.ID
					break
				}
			}
			if other != 0 {
				if err := admin.Migrate(other); err != nil {
					return nil, fmt.Errorf("migrate %d: %w", migIdx, err)
				}
			}
			migIdx++
		}
	}
	if err := <-done; err != nil {
		return nil, fmt.Errorf("recv: %w", err)
	}
	elapsed := time.Since(t0)

	sentHex := fmt.Sprintf("%x", hSent[:])
	recvHex := fmt.Sprintf("%x", hRecv.Sum(nil))

	r := &report{
		Transport:      transportName,
		Size:           size,
		Migrations:     migrations,
		Paths:          paths,
		ElapsedSeconds: elapsed.Seconds(),
		ThroughputMBs:  float64(size) / elapsed.Seconds() / 1e6,
		SHA256Sent:     sentHex,
		SHA256Recv:     recvHex,
		Pass:           sentHex == recvHex,
		WallClock:      elapsed,
	}
	return r, nil
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

// parseSize accepts decimal byte counts ("4194304") or human-friendly
// suffixes ("256MiB", "1GiB").
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "GiB"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "GiB")
	case strings.HasSuffix(s, "MiB"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "MiB")
	case strings.HasSuffix(s, "KiB"):
		mult = 1 << 10
		s = strings.TrimSuffix(s, "KiB")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}
