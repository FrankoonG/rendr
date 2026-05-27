package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/transport/tcprepair"
)

type benchCase struct {
	Scheme string
	Mode   rendr.Mode
}

type result struct {
	Scheme          string  `json:"scheme"`
	Mode            string  `json:"mode"`
	Repeat          int     `json:"repeat"`
	SizeBytes       int64   `json:"size_bytes"`
	KillAtBytes     int64   `json:"kill_at_bytes"`
	ElapsedMS       int64   `json:"elapsed_ms"`
	ThroughputMiBps float64 `json:"throughput_mib_s"`
	RecvGapP50MS    int64   `json:"recv_gap_p50_ms"`
	RecvGapP95MS    int64   `json:"recv_gap_p95_ms"`
	RecvGapP99MS    int64   `json:"recv_gap_p99_ms"`
	MaxRecvGapMS    int64   `json:"max_recv_gap_ms"`
	UserCPUMS       int64   `json:"user_cpu_ms,omitempty"`
	SysCPUMS        int64   `json:"sys_cpu_ms,omitempty"`
	CPUPct          float64 `json:"cpu_pct,omitempty"`
	AllocMiB        float64 `json:"alloc_mib"`
	Mallocs         uint64  `json:"mallocs"`
	Migrations      uint64  `json:"migrations"`
	RecvDups        uint64  `json:"recv_dups"`
	RecvQueueHWM    int     `json:"recv_queue_hwm"`
	BondStuckSkips  uint64  `json:"bond_stuck_skips"`
	PathsAfterKill  int     `json:"paths_after_kill"`
	SHA256Match     bool    `json:"sha256_match"`
	Error           string  `json:"error,omitempty"`
}

func main() {
	var (
		sizeMiB = flag.Int("size-mib", 256, "payload size per run")
		repeats = flag.Int("repeats", 1, "repeats per scheme/mode")
		schemes = flag.String("schemes", "tcprepair,gvisor,mixed", "comma-separated schemes: tcprepair,gvisor,mixed")
		modes   = flag.String("modes", "prime,race,bond", "comma-separated modes: prime,race,bond")
		killPct = flag.Float64("kill-pct", 30, "percentage of bytes after which to kill one path")
		timeout = flag.Duration("timeout", 5*time.Minute, "timeout per run")
		jsonl   = flag.Bool("jsonl", true, "print one JSON object per run")
	)
	flag.Parse()

	cases, err := expandCases(*schemes, *modes)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	var results []result
	for _, c := range cases {
		for i := 1; i <= *repeats; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), *timeout)
			r := run(ctx, c, i, int64(*sizeMiB)<<20, *killPct/100)
			cancel()
			results = append(results, r)
			if *jsonl {
				_ = json.NewEncoder(os.Stdout).Encode(r)
			}
			if r.Error != "" {
				os.Exit(1)
			}
		}
	}
	printTable(results)
}

func expandCases(schemesCSV, modesCSV string) ([]benchCase, error) {
	var schemes []string
	for _, s := range strings.Split(schemesCSV, ",") {
		s = strings.TrimSpace(strings.ToLower(s))
		if s != "" {
			if s != "tcprepair" && s != "gvisor" && s != "mixed" {
				return nil, fmt.Errorf("unknown scheme %q", s)
			}
			schemes = append(schemes, s)
		}
	}
	var modes []rendr.Mode
	for _, s := range strings.Split(modesCSV, ",") {
		switch strings.TrimSpace(strings.ToLower(s)) {
		case "":
		case "prime":
			modes = append(modes, rendr.ModePrime)
		case "race":
			modes = append(modes, rendr.ModeRace)
		case "bond":
			modes = append(modes, rendr.ModeBond)
		default:
			return nil, fmt.Errorf("unknown mode %q", s)
		}
	}
	if len(schemes) == 0 || len(modes) == 0 {
		return nil, fmt.Errorf("need at least one scheme and mode")
	}
	out := make([]benchCase, 0, len(schemes)*len(modes))
	for _, scheme := range schemes {
		for _, mode := range modes {
			out = append(out, benchCase{Scheme: scheme, Mode: mode})
		}
	}
	return out, nil
}

func run(ctx context.Context, c benchCase, repeat int, size int64, killFrac float64) result {
	r := result{
		Scheme:      c.Scheme,
		Mode:        c.Mode.String(),
		Repeat:      repeat,
		SizeBytes:   size,
		KillAtBytes: int64(float64(size) * killFrac),
	}
	if r.KillAtBytes <= 0 || r.KillAtBytes >= size {
		r.KillAtBytes = size / 3
	}

	ln, specs, err := listen(c.Scheme)
	if err != nil {
		r.Error = "listen: " + err.Error()
		return r
	}
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := (&rendr.Dialer{
		Mode:            c.Mode,
		Paths:           specs,
		MigrationBudget: 10 * time.Second,
	}).Dial(ctx)
	if err != nil {
		r.Error = "dial: " + err.Error()
		return r
	}
	defer client.Close()

	var server rendr.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		r.Error = "accept: " + err.Error()
		return r
	case <-ctx.Done():
		r.Error = "accept: " + ctx.Err().Error()
		return r
	}
	defer server.Close()

	if err := waitPaths(ctx, client, server, len(specs)); err != nil {
		r.Error = err.Error()
		return r
	}

	admin := client.(rendr.AdminConn)
	if c.Mode != rendr.ModePrime {
		if err := client.SetMode(c.Mode); err != nil {
			r.Error = "set mode: " + err.Error()
			return r
		}
	}
	if c.Scheme == "mixed" {
		if tcpID := findPath(client, "tcp"); tcpID != 0 && c.Mode == rendr.ModePrime && admin.ActivePath() != tcpID {
			if err := admin.Migrate(tcpID); err != nil {
				r.Error = "prime tcp path: " + err.Error()
				return r
			}
		}
	}

	recv := &recvMeter{last: time.Now()}
	var wg sync.WaitGroup
	wg.Add(1)
	recvHash := sha256.New()
	recvErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 256<<10)
		var got int64
		for got < size {
			n, err := server.Read(buf)
			if n > 0 {
				recvHash.Write(buf[:n])
				got += int64(n)
				recv.note()
			}
			if err != nil {
				recvErr <- err
				return
			}
		}
		recvErr <- nil
	}()

	sendHash := sha256.New()
	buf := make([]byte, 256<<10)
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	usageBefore, usageOK := readProcessUsage()
	start := time.Now()
	recv.reset(start)
	var sent int64
	killed := false
	for sent < size {
		n := int64(len(buf))
		if rem := size - sent; rem < n {
			n = rem
		}
		fill(buf[:n], sent)
		w, err := client.Write(buf[:n])
		if w > 0 {
			sendHash.Write(buf[:w])
			sent += int64(w)
		}
		if err != nil {
			r.Error = fmt.Sprintf("write at %d: %v", sent, err)
			return r
		}
		if !killed && sent >= r.KillAtBytes {
			id := pathToKill(c.Scheme, client, admin)
			if id == 0 {
				r.Error = "no path to kill"
				return r
			}
			killer := client.(interface{ ForceKillPathForTest(uint32) error })
			if err := killer.ForceKillPathForTest(id); err != nil {
				r.Error = "kill path: " + err.Error()
				return r
			}
			killed = true
		}
	}

	select {
	case err := <-recvErr:
		if err != nil && err != io.EOF {
			r.Error = "recv: " + err.Error()
			return r
		}
	case <-ctx.Done():
		r.Error = "recv: " + ctx.Err().Error()
		return r
	}
	wg.Wait()
	elapsed := time.Since(start)
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	usageAfter, usageAfterOK := readProcessUsage()

	clientStats := admin.Stats()
	serverStats := clientStats
	if serverAdmin, ok := server.(rendr.AdminConn); ok {
		serverStats = serverAdmin.Stats()
	}
	r.ElapsedMS = elapsed.Milliseconds()
	r.ThroughputMiBps = float64(size) / elapsed.Seconds() / (1 << 20)
	p50, p95, p99, maxGap := recv.summary()
	r.RecvGapP50MS = p50.Milliseconds()
	r.RecvGapP95MS = p95.Milliseconds()
	r.RecvGapP99MS = p99.Milliseconds()
	r.MaxRecvGapMS = maxGap.Milliseconds()
	if usageOK && usageAfterOK {
		cpu := usageAfter.sub(usageBefore)
		r.UserCPUMS = cpu.User.Milliseconds()
		r.SysCPUMS = cpu.Sys.Milliseconds()
		if elapsed > 0 {
			r.CPUPct = float64(cpu.User+cpu.Sys) / float64(elapsed) * 100
		}
	}
	if memAfter.TotalAlloc >= memBefore.TotalAlloc {
		r.AllocMiB = float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / (1 << 20)
	}
	if memAfter.Mallocs >= memBefore.Mallocs {
		r.Mallocs = memAfter.Mallocs - memBefore.Mallocs
	}
	r.Migrations = clientStats.MigrationCount
	r.RecvDups = serverStats.RecvDups
	r.RecvQueueHWM = serverStats.RecvQueueHWM
	r.BondStuckSkips = clientStats.BondStuckSkips
	r.PathsAfterKill = len(clientStats.Paths)
	r.SHA256Match = fmt.Sprintf("%x", sendHash.Sum(nil)) == fmt.Sprintf("%x", recvHash.Sum(nil))
	if !r.SHA256Match {
		r.Error = "sha256 mismatch"
	}
	return r
}

func listen(scheme string) (rendr.Listener, []rendr.PathSpec, error) {
	switch scheme {
	case "tcprepair":
		if err := tcprepair.Available(); err != nil {
			return nil, nil, err
		}
		ln, err := rendr.ListenTCP("127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		specs := []rendr.PathSpec{
			{Transport: "tcprepair", Address: ln.Addr().String()},
			{Transport: "tcprepair", Address: ln.Addr().String()},
		}
		return ln, specs, nil
	case "gvisor":
		ln, err := rendr.ListenGVisor("")
		if err != nil {
			return nil, nil, err
		}
		specs := []rendr.PathSpec{
			{Transport: "gvisor", Address: ln.Addr().String()},
			{Transport: "gvisor", Address: ln.Addr().String()},
		}
		return ln, specs, nil
	case "mixed":
		ln, err := rendr.Listen(
			rendr.ListenSpec{Transport: "tcp", Address: "127.0.0.1:0"},
			rendr.ListenSpec{Transport: "quic", Address: "127.0.0.1:0"},
		)
		if err != nil {
			return nil, nil, err
		}
		addrs := ln.Addrs()
		specs := []rendr.PathSpec{
			{Transport: "tcp", Address: addrs[0].String()},
			{Transport: "quic", Address: addrs[1].String()},
		}
		return ln, specs, nil
	default:
		return nil, nil, fmt.Errorf("unknown scheme %q", scheme)
	}
}

func waitPaths(ctx context.Context, client, server rendr.Conn, want int) error {
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	for {
		if len(client.Paths()) >= want && len(server.Paths()) >= want {
			return nil
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-t.C:
			return fmt.Errorf("path attach timeout: client=%d server=%d want=%d", len(client.Paths()), len(server.Paths()), want)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func pathToKill(scheme string, client rendr.Conn, admin rendr.AdminConn) uint32 {
	if scheme == "mixed" {
		if id := findPath(client, "tcp"); id != 0 {
			return id
		}
	}
	if id := admin.ActivePath(); id != 0 {
		return id
	}
	paths := client.Paths()
	if len(paths) == 0 {
		return 0
	}
	return paths[0].ID
}

func findPath(c rendr.Conn, transport string) uint32 {
	for _, p := range c.Paths() {
		if p.Spec.Transport == transport {
			return p.ID
		}
	}
	return 0
}

func fill(buf []byte, offset int64) {
	for i := range buf {
		buf[i] = byte((offset+int64(i))*31 + 7)
	}
}

type recvMeter struct {
	mu   sync.Mutex
	last time.Time
	gaps []time.Duration
}

func (m *recvMeter) reset(t time.Time) {
	m.mu.Lock()
	m.last = t
	m.gaps = m.gaps[:0]
	m.mu.Unlock()
}

func (m *recvMeter) note() {
	now := time.Now()
	m.mu.Lock()
	if !m.last.IsZero() {
		m.gaps = append(m.gaps, now.Sub(m.last))
	}
	m.last = now
	m.mu.Unlock()
}

func (m *recvMeter) summary() (p50, p95, p99, max time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.gaps) == 0 {
		return 0, 0, 0, 0
	}
	gaps := append([]time.Duration(nil), m.gaps...)
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	return percentile(gaps, 0.50), percentile(gaps, 0.95), percentile(gaps, 0.99), gaps[len(gaps)-1]
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func printTable(results []result) {
	fmt.Println()
	fmt.Println("raw results")
	fmt.Println("scheme    mode   rep  ok  elapsed_ms  MiB/s   gap_p95  gap_p99  gap_max  cpu%   allocMiB  mig  dups  hwm  stuck")
	for _, r := range results {
		ok := "yes"
		if r.Error != "" || !r.SHA256Match {
			ok = "no"
		}
		fmt.Printf("%-9s %-6s %-4d %-3s %-11d %-7.1f %-8d %-8d %-8d %-6.1f %-9.1f %-4d %-5d %-4d %-5d\n",
			r.Scheme, r.Mode, r.Repeat, ok, r.ElapsedMS, r.ThroughputMiBps,
			r.RecvGapP95MS, r.RecvGapP99MS, r.MaxRecvGapMS, r.CPUPct, r.AllocMiB,
			r.Migrations, r.RecvDups, r.RecvQueueHWM, r.BondStuckSkips)
	}

	avgs := averageBySchemeMode(results)
	fmt.Println()
	fmt.Println("averages and overhead vs tcprepair baseline in same mode")
	fmt.Println("scheme    mode   runs  MiB/s   speed_overhead%  gap_p95_ms  latency_overhead%  cpu%   allocMiB")
	for _, mode := range []string{"prime", "race", "bond"} {
		base, hasBase := avgs[avgKey{scheme: "tcprepair", mode: mode}]
		for _, scheme := range []string{"tcprepair", "gvisor", "mixed"} {
			a, ok := avgs[avgKey{scheme: scheme, mode: mode}]
			if !ok {
				continue
			}
			speedOverhead := 0.0
			latencyOverhead := 0.0
			if hasBase && a.throughput > 0 {
				speedOverhead = (base.throughput/a.throughput - 1) * 100
			}
			if hasBase && base.gapP95 > 0 {
				latencyOverhead = (a.gapP95/base.gapP95 - 1) * 100
			}
			fmt.Printf("%-9s %-6s %-5d %-7.1f %-15.1f %-10.1f %-17.1f %-6.1f %-8.1f\n",
				scheme, mode, a.n, a.throughput, speedOverhead, a.gapP95,
				latencyOverhead, a.cpuPct, a.allocMiB)
		}
	}
}

type avgKey struct {
	scheme string
	mode   string
}

type avgVal struct {
	n          int
	throughput float64
	gapP95     float64
	cpuPct     float64
	allocMiB   float64
}

func averageBySchemeMode(results []result) map[avgKey]avgVal {
	out := map[avgKey]avgVal{}
	for _, r := range results {
		if r.Error != "" || !r.SHA256Match {
			continue
		}
		k := avgKey{scheme: r.Scheme, mode: r.Mode}
		v := out[k]
		v.n++
		v.throughput += r.ThroughputMiBps
		v.gapP95 += float64(r.RecvGapP95MS)
		v.cpuPct += r.CPUPct
		v.allocMiB += r.AllocMiB
		out[k] = v
	}
	for k, v := range out {
		if v.n > 0 {
			div := float64(v.n)
			v.throughput /= div
			v.gapP95 /= div
			v.cpuPct /= div
			v.allocMiB /= div
			out[k] = v
		}
	}
	return out
}
