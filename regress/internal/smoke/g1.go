package smoke

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr"
)

// G1Opts configures one G1-smoke run. Defaults (30 MiB / 3 migrations /
// 2 paths / tcp) match docs/regression-suite.md §6.
type G1Opts struct {
	Size       int64  // bytes; default 30 MiB
	Migrations int    // forced migrations; default 3
	Paths      int    // number of paths; default 2
	Transport  string // "tcp" | "quic"; default "tcp"
	Transports []string
}

func (o *G1Opts) withDefaults() {
	if o.Size <= 0 {
		o.Size = 30 << 20
	}
	if o.Migrations < 0 {
		o.Migrations = 0
	}
	if o.Paths < 1 {
		o.Paths = 2
	}
	if o.Transport == "" {
		o.Transport = "tcp"
	}
	if len(o.Transports) == 0 {
		o.Transports = make([]string, o.Paths)
		for i := range o.Transports {
			o.Transports[i] = o.Transport
		}
	} else {
		o.Paths = len(o.Transports)
	}
}

// RunG1 drives one G1-smoke case: deterministic payload from client
// to server with `Migrations` forced rendr.Migrate calls evenly
// spaced across the byte stream. Asserts SHA-256 sent == received
// AND MigrationCount() >= Migrations. Detail keys:
//
//	elapsed_seconds   float64
//	throughput_mb_s   float64
//	migrations_done   uint64
//	sha256_match      bool
func RunG1(ctx context.Context, opts G1Opts) Result {
	opts.withDefaults()
	t0 := time.Now()
	name := fmt.Sprintf("G1-smoke (%s, %dMiB, %d paths, %d migrations)",
		transportDesc(opts.Transports), opts.Size>>20, opts.Paths, opts.Migrations)

	ln, specs, err := listenAndSpecsForTransports(opts.Transports)
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("listen: %w", err))
	}
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		c, err := ln.Accept(actx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	client, err := (&rendr.Dialer{Mode: rendr.ModePrime, Paths: specs}).Dial(ctx)
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("dial: %w", err))
	}
	defer client.Close()

	var server rendr.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		return FromError(name, time.Since(t0), fmt.Errorf("accept: %w", err))
	case <-time.After(15 * time.Second):
		return FromError(name, time.Since(t0), fmt.Errorf("accept timeout"))
	}
	defer server.Close()

	// Wait briefly for all paths to attach so migration has somewhere
	// to go from the very first chunk.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= opts.Paths && len(server.Paths()) >= opts.Paths {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	recvErr := make(chan error, 1)
	hRecv := sha256.New()
	go func() {
		buf := make([]byte, 256*1024)
		var got int64
		for got < opts.Size {
			n, err := server.Read(buf)
			if err != nil {
				recvErr <- err
				return
			}
			hRecv.Write(buf[:n])
			got += int64(n)
		}
		recvErr <- nil
	}()

	migPts := make([]int64, opts.Migrations)
	for i := 0; i < opts.Migrations; i++ {
		migPts[i] = opts.Size * int64(i+1) / int64(opts.Migrations+1)
	}

	admin, ok := client.(rendr.AdminConn)
	if !ok {
		return FromError(name, time.Since(t0), fmt.Errorf("client conn is not rendr.AdminConn"))
	}

	const chunk = int64(256 * 1024)
	sendBuf := make([]byte, chunk)
	hSent := sha256.New()
	var written int64
	var migIdx int
	for written < opts.Size {
		end := written + chunk
		if end > opts.Size {
			end = opts.Size
		}
		fillG1Pattern(sendBuf[:end-written], written)
		n, err := client.Write(sendBuf[:end-written])
		if err != nil {
			// Capture per-path state at the failure boundary so the
			// regress report has something to bisect on. Particularly
			// useful for chaos-baseline failures where we want to see
			// whether the paths are "all dead" or "one alive, one dying".
			var pathDbg string
			for _, p := range client.Paths() {
				ra := time.Since(p.LastRecvAt).Round(time.Millisecond)
				sa := time.Since(p.LastSendAt).Round(time.Millisecond)
				pathDbg += fmt.Sprintf(" p%d{r=%d w=%d recvAgo=%s sendAgo=%s rtt=%s}",
					p.ID, p.Reads, p.Writes, ra, sa,
					p.Quality.RTT.Round(time.Millisecond))
			}
			return FromError(name, time.Since(t0),
				fmt.Errorf("write at %d: %w | active=%d paths:%s",
					written, err, admin.ActivePath(), pathDbg))
		}
		hSent.Write(sendBuf[:n])
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
					return FromError(name, time.Since(t0), fmt.Errorf("migrate %d: %w", migIdx, err))
				}
			}
			migIdx++
		}
	}
	if err := <-recvErr; err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("recv: %w", err))
	}

	elapsed := time.Since(t0)
	sentHex := fmt.Sprintf("%x", hSent.Sum(nil))
	recvHex := fmt.Sprintf("%x", hRecv.Sum(nil))
	migCount := admin.MigrationCount()

	r := Result{
		Name:     name,
		Duration: elapsed,
		Detail: map[string]any{
			"elapsed_seconds": elapsed.Seconds(),
			"throughput_mb_s": float64(opts.Size) / elapsed.Seconds() / 1e6,
			"migrations_done": migCount,
			"sha256_match":    sentHex == recvHex,
		},
	}
	if sentHex != recvHex {
		r.Failure = fmt.Sprintf("SHA-256 mismatch: sent=%s recv=%s", sentHex, recvHex)
		return r
	}
	if opts.Migrations > 0 && migCount < uint64(opts.Migrations) {
		r.Failure = fmt.Sprintf("MigrationCount=%d, want >= %d", migCount, opts.Migrations)
		return r
	}
	return r
}

func fillG1Pattern(buf []byte, offset int64) {
	for i := range buf {
		buf[i] = byte((offset+int64(i))*17 + 3)
	}
}

func listenForTransport(name string) (rendr.Listener, error) {
	switch name {
	case "tcp":
		return rendr.ListenTCP("127.0.0.1:0")
	case "gvisor":
		return rendr.ListenGVisor("")
	case "gvisor-packet":
		return rendr.ListenGVisorPacket("127.0.0.1:0")
	case "quic":
		return rendr.ListenQUIC("127.0.0.1:0", nil)
	default:
		return nil, fmt.Errorf("unknown transport %q", name)
	}
}

func dialTransportName(name string) string {
	if name == "gvisor-packet" {
		return "gvisor"
	}
	return name
}

func listenAndSpecsForTransports(transports []string) (rendr.Listener, []rendr.PathSpec, error) {
	if len(transports) == 0 {
		return nil, nil, fmt.Errorf("no transports")
	}
	allSame := true
	for _, t := range transports[1:] {
		if t != transports[0] {
			allSame = false
			break
		}
	}
	if allSame {
		ln, err := listenForTransport(transports[0])
		if err != nil {
			return nil, nil, err
		}
		specs := make([]rendr.PathSpec, len(transports))
		for i := range specs {
			specs[i] = rendr.PathSpec{Transport: dialTransportName(transports[0]), Address: ln.Addr().String()}
		}
		return ln, specs, nil
	}

	listenSpecs := make([]rendr.ListenSpec, len(transports))
	for i, name := range transports {
		listenSpecs[i] = rendr.ListenSpec{Transport: name, Address: "127.0.0.1:0"}
	}
	ln, err := rendr.Listen(listenSpecs...)
	if err != nil {
		return nil, nil, err
	}
	addrs := ln.Addrs()
	specs := make([]rendr.PathSpec, len(transports))
	for i, name := range transports {
		specs[i] = rendr.PathSpec{Transport: dialTransportName(name), Address: addrs[i].String()}
	}
	return ln, specs, nil
}

func transportDesc(transports []string) string {
	if len(transports) == 0 {
		return ""
	}
	s := transports[0]
	for _, t := range transports[1:] {
		s += "+" + t
	}
	return s
}
