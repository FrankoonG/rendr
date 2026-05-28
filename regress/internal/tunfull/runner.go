// Package tunfull defines the TUN translation of the existing full
// regression surface.
package tunfull

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/l3session"
	"github.com/FrankoonG/rendr/regress/internal/chaos"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/transport/tcprepair"
)

// Options filters the TUN full baseline matrix.
type Options struct {
	Case string
}

// Planned cases mirror the non-TUN full surface that must eventually
// run through TUN ingress. They intentionally fail until their real
// TUN-backed implementations land; this preserves the hard guard that
// --tun-full must not report a false green.
var plannedCases = []string{
	"TUN-full.G1-smoke",
	"TUN-full.G2-smoke",
	"TUN-full.G3-smoke",
	"TUN-full.G4-path-death",
	"TUN-full.G5-path-recovery",
	"TUN-full.T3-xray-matrix",
	"TUN-full.T4-G1-1GiB-tcp",
	"TUN-full.T4-G2-30m-prime",
	"TUN-full.T4-G3-100k-pps",
	"TUN-full.T5-fallback",
	"TUN-full.T6-selector",
}

// Run records the TUN full baseline status. Implemented cases run as real
// TUN/per-flow baselines; remaining planned cases stay as explicit guard
// failures so --tun-full cannot report a false green.
func Run(ctx context.Context, suite *report.Suite, rendrRoot string, opts Options) {
	if opts.Case == "TUN-full.T3-xray-stream-smoke" {
		suite.Add(runT3XrayStreamSmoke(ctx, rendrRoot, opts.Case))
		return
	}
	if opts.Case == "TUN-full.T4-long-run" {
		for _, name := range t4LongRunCases {
			suite.Add(runPlannedCase(ctx, rendrRoot, name))
		}
		return
	}
	matched := false
	for _, name := range plannedCases {
		if !caseMatches(opts.Case, name) {
			continue
		}
		matched = true
		suite.Add(runPlannedCase(ctx, rendrRoot, name))
	}
	if opts.Case != "" && !matched {
		suite.Add(report.Case{
			Name:    "TUN-full-case-filter",
			Tier:    "T7",
			Failure: fmt.Sprintf("no TUN full case matched %q", opts.Case),
		})
		return
	}
}

func runPlannedCase(ctx context.Context, rendrRoot, name string) report.Case {
	switch name {
	case "TUN-full.G1-smoke":
		return runG1Smoke(ctx, g1SmokeOptions{
			name:       name,
			size:       30 << 20,
			paths:      2,
			migrations: 3,
		})
	case "TUN-full.G2-smoke":
		return runG2Smoke(ctx, g2SmokeOptions{
			name:       name,
			duration:   30 * time.Second,
			interval:   100 * time.Millisecond,
			paths:      2,
			migrations: 5,
		})
	case "TUN-full.G3-smoke":
		return runG3Smoke(ctx, g3Options{
			name:       name,
			duration:   5 * time.Second,
			pps:        5000,
			payloadLen: 1024,
			paths:      4,
			migrations: 3,
			lossPct:    0.5,
			p95Ceiling: 50 * time.Millisecond,
		})
	case "TUN-full.G4-path-death":
		return runG4PathDeath(ctx, g4Options{
			name:     name,
			duration: 6 * time.Second,
			killAt:   2 * time.Second,
			echoInt:  10 * time.Millisecond,
			paths:    2,
			budget:   5 * time.Second,
		})
	case "TUN-full.G5-path-recovery":
		return runG5PathRecovery(ctx, g5Options{
			name:         name,
			paths:        2,
			postAddBytes: 256 << 10,
		})
	case "TUN-full.T3-xray-stream-smoke":
		return runT3XrayStreamSmoke(ctx, rendrRoot, name)
	case "TUN-full.T3-xray-matrix":
		return runT3XrayMatrix(ctx, rendrRoot, name)
	case "TUN-full.T4-G1-1GiB-tcp":
		return runT4WithBudget(ctx, name, 7*time.Minute, chaos.Realistic50M, func(c context.Context) report.Case {
			return runG1Smoke(c, g1SmokeOptions{
				name:       name,
				size:       1 << 30,
				paths:      2,
				migrations: 10,
			})
		})
	case "TUN-full.T4-G2-30m-prime":
		return runT4WithBudget(ctx, name, 33*time.Minute, chaos.Realistic50M, func(c context.Context) report.Case {
			return runG2Smoke(c, g2SmokeOptions{
				name:       name,
				duration:   30 * time.Minute,
				interval:   100 * time.Millisecond,
				paths:      2,
				migrations: 30,
			})
		})
	case "TUN-full.T4-G3-100k-pps":
		return runT4WithBudget(ctx, name, 8*time.Minute, chaos.Profile{}, func(c context.Context) report.Case {
			return runG3Smoke(c, g3Options{
				name:       name,
				duration:   5 * time.Minute,
				pps:        100_000,
				payloadLen: 1024,
				paths:      8,
				migrations: 10,
				lossPct:    -1,
				p95Ceiling: 20 * time.Millisecond,
			})
		})
	case "TUN-full.T5-fallback":
		return runT5Fallback(ctx, t5FallbackOptions{
			name: name,
		})
	case "TUN-full.T6-selector":
		return runT6Selector(ctx, t6SelectorOptions{
			name: name,
		})
	default:
		return UnimplementedCase(name)
	}
}

var t4LongRunCases = []string{
	"TUN-full.T4-G1-1GiB-tcp",
	"TUN-full.T4-G2-30m-prime",
	"TUN-full.T4-G3-100k-pps",
}

// UnimplementedCase returns the explicit guard case used until real
// TUN full baseline cases are implemented.
func UnimplementedCase(name string) report.Case {
	if name == "" {
		name = "TUN-full-not-implemented"
	}
	return report.Case{
		Name:     name,
		Tier:     "T7",
		Duration: 0 * time.Second,
		Failure:  "--tun-full baseline is not implemented yet; T7 feature tests are not a full TUN regression",
	}
}

func caseMatches(filter, name string) bool {
	return filter == "" || filter == name
}

func runT4WithBudget(ctx context.Context, name string, budget time.Duration, prof chaos.Profile, fn func(context.Context) report.Case) report.Case {
	start := time.Now()
	cleanup, err := chaos.Apply(prof)
	if err != nil {
		return failedCase(name, start, fmt.Errorf("chaos.Apply: %w", err))
	}
	defer func() {
		if cleanup != nil {
			_ = cleanup()
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	done := make(chan report.Case, 1)
	go func() {
		done <- fn(cctx)
	}()
	select {
	case c := <-done:
		if c.Name == "" {
			c.Name = name
		}
		if c.Tier == "" {
			c.Tier = "T7"
		}
		if c.Duration == 0 {
			c.Duration = time.Since(start)
		}
		return c
	case <-cctx.Done():
		return failedCase(name, start, fmt.Errorf("case exceeded T4 budget %s: %w", budget, cctx.Err()))
	}
}

type g1SmokeOptions struct {
	name       string
	size       int64
	paths      int
	migrations int
}

type g2SmokeOptions struct {
	name       string
	duration   time.Duration
	interval   time.Duration
	paths      int
	migrations int
}

type g4Options struct {
	name     string
	duration time.Duration
	killAt   time.Duration
	echoInt  time.Duration
	paths    int
	budget   time.Duration
}

type g5Options struct {
	name         string
	paths        int
	postAddBytes int64
}

type g3Options struct {
	name       string
	duration   time.Duration
	pps        int
	payloadLen int
	paths      int
	migrations int
	lossPct    float64
	p95Ceiling time.Duration
}

type t6SelectorOptions struct {
	name           string
	bulkWarmWrites int
	bulkBondWrites int
}

type t5FallbackOptions struct {
	name       string
	size       int64
	migrations int
}

func runT3XrayStreamSmoke(ctx context.Context, rendrRoot, name string) report.Case {
	return runT3XrayGoTest(ctx, rendrRoot, name, "^TestTUNT3(SS2022StreamOverTUN|VMessStreamOverTUN|VLESSVisionTLSStreamOverTUN|MixedSS2022VMessStreamOverTUN)$", 8*time.Minute, "6m")
}

func runT3XrayMatrix(ctx context.Context, rendrRoot, name string) report.Case {
	return runT3XrayGoTest(ctx, rendrRoot, name, "^TestTUNT3", 12*time.Minute, "10m")
}

func runT3XrayGoTest(ctx context.Context, rendrRoot, name, pattern string, budget time.Duration, testTimeout string) report.Case {
	start := time.Now()
	if name == "" {
		name = "TUN-full.T3-xray-go-test"
	}
	if _, err := os.Stat(rendrRoot); err != nil {
		return failedCase(name, start, fmt.Errorf("bad rendr root: %w", err))
	}
	regressDir := filepath.Join(rendrRoot, "regress")
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	cmd := exec.CommandContext(
		cctx,
		"go",
		"test",
		"./internal/matrix",
		"-run",
		pattern,
		"-count=1",
		"-timeout",
		testTimeout,
	)
	cmd.Dir = regressDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		} else {
			msg = fmt.Sprintf("%v (%s)", err, msg)
		}
		return report.Case{Name: name, Tier: "T7", Duration: time.Since(start), Failure: msg}
	}
	return report.Case{Name: name, Tier: "T7", Duration: time.Since(start)}
}

func runG1Smoke(ctx context.Context, opts g1SmokeOptions) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = "TUN-full.G1-smoke"
	}
	if opts.size <= 0 {
		opts.size = 30 << 20
	}
	if opts.paths < 2 {
		opts.paths = 2
	}
	if opts.migrations < 0 {
		opts.migrations = 0
	}
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("listen: %w", err))
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

	id := g1Identity()
	root := g1Root(ln.Addr().String(), opts.paths)
	manager := &l3session.Manager{}
	relay := &l3session.TCPRelay{Manager: manager}
	app, endpoint := net.Pipe()
	defer app.Close()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- relay.Serve(ctx, g1Event(id, root), endpoint)
	}()

	var server rendr.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		return failedCase(opts.name, start, fmt.Errorf("accept: %w", err))
	case <-time.After(15 * time.Second):
		return failedCase(opts.name, start, fmt.Errorf("accept timeout"))
	}
	defer server.Close()

	sess, err := waitStreamSession(ctx, manager, id)
	if err != nil {
		return failedCase(opts.name, start, err)
	}
	admin, ok := sess.Conn.(rendr.AdminConn)
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("session conn is not rendr.AdminConn"))
	}
	waitPaths(ctx, admin, opts.paths)

	recvErr := make(chan error, 1)
	hRecv := sha256.New()
	go func() {
		buf := make([]byte, 256*1024)
		var got int64
		for got < opts.size {
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

	migPts := make([]int64, opts.migrations)
	for i := 0; i < opts.migrations; i++ {
		migPts[i] = opts.size * int64(i+1) / int64(opts.migrations+1)
	}
	hSent := sha256.New()
	buf := make([]byte, 256*1024)
	var written int64
	var migIdx int
	for written < opts.size {
		end := written + int64(len(buf))
		if end > opts.size {
			end = opts.size
		}
		chunk := buf[:end-written]
		fillPattern(chunk, written)
		if err := writeAll(app, chunk); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("write at %d: %w", written, err))
		}
		hSent.Write(chunk)
		written += int64(len(chunk))
		for migIdx < len(migPts) && written >= migPts[migIdx] {
			next := nextPath(admin)
			if next != 0 {
				if err := admin.Migrate(next); err != nil {
					return failedCase(opts.name, start, fmt.Errorf("migrate %d: %w", migIdx, err))
				}
			}
			migIdx++
		}
	}

	if err := <-recvErr; err != nil {
		return failedCase(opts.name, start, fmt.Errorf("recv: %w", err))
	}
	_ = app.Close()
	select {
	case err := <-relayErr:
		if err != nil {
			return failedCase(opts.name, start, fmt.Errorf("relay: %w", err))
		}
	case <-time.After(5 * time.Second):
		return failedCase(opts.name, start, fmt.Errorf("relay shutdown timeout"))
	}

	sentHex := fmt.Sprintf("%x", hSent.Sum(nil))
	recvHex := fmt.Sprintf("%x", hRecv.Sum(nil))
	if sentHex != recvHex {
		return failedCase(opts.name, start, fmt.Errorf("SHA-256 mismatch: sent=%s recv=%s", sentHex, recvHex))
	}
	if opts.migrations > 0 && admin.MigrationCount() < uint64(opts.migrations) {
		return failedCase(opts.name, start, fmt.Errorf("MigrationCount=%d, want >= %d", admin.MigrationCount(), opts.migrations))
	}
	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

func failedCase(name string, start time.Time, err error) report.Case {
	return report.Case{Name: name, Tier: "T7", Duration: time.Since(start), Failure: err.Error()}
}

func g1Identity() l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.20"),
		DstPort: 443,
	}
}

func g1Root(addr string, paths int) rendr.Target {
	children := make([]rendr.Target, 0, paths)
	for i := 0; i < paths; i++ {
		name := fmt.Sprintf("tun-g1-%d", i+1)
		children = append(children, rendr.Path(name, rendr.PathSpec{Transport: "tcp", Address: addr}))
	}
	return rendr.Selector("tun-full-g1", children)
}

func g1Event(id l3ingress.L3Identity, root rendr.Target) l3ingress.PacketEvent {
	return l3ingress.PacketEvent{
		Meta: l3ingress.PacketMeta{Identity: id},
		Flow: l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
		Decision: l3ingress.FlowDecision{
			Peer:   "peer-a",
			Root:   root,
			Egress: "direct",
		},
		Decided: true,
	}
}

func waitStreamSession(ctx context.Context, manager *l3session.Manager, id l3ingress.L3Identity) (*l3session.Session, error) {
	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if sess, ok := manager.Session(id); ok && sess.Conn != nil {
			return sess, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return nil, fmt.Errorf("stream session timeout")
		case <-tick.C:
		}
	}
}

func waitPaths(ctx context.Context, admin rendr.AdminConn, want int) {
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for len(admin.Paths()) < want {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			return
		case <-tick.C:
		}
	}
}

func nextPath(admin rendr.AdminConn) uint32 {
	cur := admin.ActivePath()
	for _, p := range admin.Paths() {
		if p.ID != cur {
			return p.ID
		}
	}
	return 0
}

func fillPattern(buf []byte, offset int64) {
	for i := range buf {
		buf[i] = byte((offset+int64(i))*17 + 3)
	}
}

func writeAll(w net.Conn, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("short write")
		}
		buf = buf[n:]
	}
	return nil
}

func runG2Smoke(ctx context.Context, opts g2SmokeOptions) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = "TUN-full.G2-smoke"
	}
	if opts.duration <= 0 {
		opts.duration = 30 * time.Second
	}
	if opts.interval <= 0 {
		opts.interval = 100 * time.Millisecond
	}
	if opts.paths < 2 {
		opts.paths = 2
	}
	if opts.migrations < 0 {
		opts.migrations = 0
	}

	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("listen: %w", err))
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

	id := g1Identity()
	root := g1Root(ln.Addr().String(), opts.paths)
	manager := &l3session.Manager{}
	relay := &l3session.TCPRelay{Manager: manager}
	app, endpoint := net.Pipe()
	defer app.Close()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- relay.Serve(ctx, g1Event(id, root), endpoint)
	}()

	var server rendr.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		return failedCase(opts.name, start, fmt.Errorf("accept: %w", err))
	case <-time.After(15 * time.Second):
		return failedCase(opts.name, start, fmt.Errorf("accept timeout"))
	}
	defer server.Close()

	sess, err := waitStreamSession(ctx, manager, id)
	if err != nil {
		return failedCase(opts.name, start, err)
	}
	admin, ok := sess.Conn.(rendr.AdminConn)
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("session conn is not rendr.AdminConn"))
	}
	waitPaths(ctx, admin, opts.paths)

	echoErr := make(chan error, 1)
	go func() {
		var msg [8]byte
		for {
			if err := readAll(server, msg[:]); err != nil {
				echoErr <- err
				return
			}
			if err := writeAll(server, msg[:]); err != nil {
				echoErr <- err
				return
			}
		}
	}()

	deadline := time.Now().Add(opts.duration)
	nextMig := make([]time.Time, opts.migrations)
	for i := range nextMig {
		nextMig[i] = start.Add(opts.duration * time.Duration(i+1) / time.Duration(opts.migrations+1))
	}
	var migIdx int
	var seq uint64
	rtts := make([]time.Duration, 0, int(opts.duration/opts.interval)+1)
	ticker := time.NewTicker(opts.interval)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return failedCase(opts.name, start, ctx.Err())
		case <-ticker.C:
		}
		var msg [8]byte
		binary.BigEndian.PutUint64(msg[:], seq)
		sentAt := time.Now()
		if err := writeAll(app, msg[:]); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("write seq %d: %w", seq, err))
		}
		var got [8]byte
		if err := readAll(app, got[:]); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("read seq %d: %w", seq, err))
		}
		if binary.BigEndian.Uint64(got[:]) != seq {
			return failedCase(opts.name, start, fmt.Errorf("echo seq mismatch: got %d want %d", binary.BigEndian.Uint64(got[:]), seq))
		}
		rtts = append(rtts, time.Since(sentAt))
		seq++
		for migIdx < len(nextMig) && time.Now().After(nextMig[migIdx]) {
			next := nextPath(admin)
			if next != 0 {
				if err := admin.Migrate(next); err != nil {
					return failedCase(opts.name, start, fmt.Errorf("migrate %d: %w", migIdx, err))
				}
			}
			migIdx++
		}
	}
	if len(rtts) == 0 {
		return failedCase(opts.name, start, fmt.Errorf("no echoes completed"))
	}
	if opts.migrations > 0 && admin.MigrationCount() < uint64(opts.migrations) {
		return failedCase(opts.name, start, fmt.Errorf("MigrationCount=%d, want >= %d", admin.MigrationCount(), opts.migrations))
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	if p99 := percentile(rtts, 0.99); p99 > time.Second {
		return failedCase(opts.name, start, fmt.Errorf("P99 RTT %s exceeds 1s", p99))
	}

	_ = app.Close()
	select {
	case err := <-relayErr:
		if err != nil {
			return failedCase(opts.name, start, fmt.Errorf("relay: %w", err))
		}
	case <-time.After(5 * time.Second):
		return failedCase(opts.name, start, fmt.Errorf("relay shutdown timeout"))
	}
	select {
	case err := <-echoErr:
		if err != nil && !isClosedRelayErr(err) {
			return failedCase(opts.name, start, fmt.Errorf("echo: %w", err))
		}
	default:
	}
	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

func readAll(r net.Conn, buf []byte) error {
	for len(buf) > 0 {
		n, err := r.Read(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("short read")
		}
		buf = buf[n:]
	}
	return nil
}

func percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * q)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func isClosedRelayErr(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

func runG4PathDeath(ctx context.Context, opts g4Options) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = "TUN-full.G4-path-death"
	}
	if opts.duration <= 0 {
		opts.duration = 6 * time.Second
	}
	if opts.killAt <= 0 {
		opts.killAt = 2 * time.Second
	}
	if opts.echoInt <= 0 {
		opts.echoInt = 10 * time.Millisecond
	}
	if opts.paths < 2 {
		opts.paths = 2
	}
	if opts.budget <= 0 {
		opts.budget = 5 * time.Second
	}

	env, err := startTUNStream(ctx, opts.paths)
	if err != nil {
		return failedCase(opts.name, start, err)
	}
	defer env.close()

	killer, ok := env.admin.(interface {
		ForceKillPathForTest(id uint32) error
	})
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("session conn lacks ForceKillPathForTest test hook"))
	}
	echoErr := startStreamEcho(env.server, 8)

	killDone := make(chan time.Time, 1)
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(opts.killAt):
		}
		cur := env.admin.ActivePath()
		if cur != 0 {
			_ = killer.ForceKillPathForTest(cur)
		}
		killDone <- time.Now()
	}()

	endAt := time.Now().Add(opts.duration)
	var seq uint64
	var lost int
	var maxRTT time.Duration
	var killStamp time.Time
	var firstPostKill time.Time
	for time.Now().Before(endAt) {
		var tx [8]byte
		binary.BigEndian.PutUint64(tx[:], seq)
		echoStart := time.Now()
		if err := writeAll(env.app, tx[:]); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("write seq %d: %w", seq, err))
		}
		var rx [8]byte
		if err := readAll(env.app, rx[:]); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("read seq %d: %w", seq, err))
		}
		if binary.BigEndian.Uint64(rx[:]) != seq {
			lost++
		}
		if rtt := time.Since(echoStart); rtt > maxRTT {
			maxRTT = rtt
		}
		select {
		case s := <-killDone:
			killStamp = s
			killDone = nil
		default:
		}
		if !killStamp.IsZero() && firstPostKill.IsZero() && time.Now().After(killStamp) {
			firstPostKill = time.Now()
		}
		seq++
		select {
		case <-ctx.Done():
			return failedCase(opts.name, start, ctx.Err())
		case <-time.After(opts.echoInt):
		}
	}

	if lost > 0 {
		return failedCase(opts.name, start, fmt.Errorf("application-visible echo loss: %d", lost))
	}
	if killStamp.IsZero() {
		return failedCase(opts.name, start, fmt.Errorf("path kill did not run"))
	}
	if firstPostKill.IsZero() {
		return failedCase(opts.name, start, fmt.Errorf("no echo completed after path kill"))
	}
	if failover := firstPostKill.Sub(killStamp); failover > opts.budget {
		return failedCase(opts.name, start, fmt.Errorf("failover %s exceeds %s budget", failover, opts.budget))
	}
	_ = env.app.Close()
	if err := env.waitRelay(5 * time.Second); err != nil {
		return failedCase(opts.name, start, err)
	}
	select {
	case err := <-echoErr:
		if err != nil && !isClosedRelayErr(err) {
			return failedCase(opts.name, start, fmt.Errorf("echo: %w", err))
		}
	default:
	}
	_ = maxRTT
	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

func runG5PathRecovery(ctx context.Context, opts g5Options) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = "TUN-full.G5-path-recovery"
	}
	if opts.paths < 2 {
		opts.paths = 2
	}
	if opts.postAddBytes <= 0 {
		opts.postAddBytes = 256 << 10
	}

	env, err := startTUNStream(ctx, opts.paths)
	if err != nil {
		return failedCase(opts.name, start, err)
	}
	defer env.close()

	killer, ok := env.admin.(interface {
		ForceKillPathForTest(id uint32) error
	})
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("session conn lacks ForceKillPathForTest test hook"))
	}
	cur := env.admin.ActivePath()
	if cur == 0 {
		return failedCase(opts.name, start, fmt.Errorf("no active path"))
	}
	if err := killer.ForceKillPathForTest(cur); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("kill active: %w", err))
	}
	echoErr := startStreamEcho(env.server, 4096)
	time.Sleep(300 * time.Millisecond)

	newID, err := env.admin.AddPath(rendr.PathSpec{Transport: "tcp", Address: env.addr})
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("AddPath: %w", err))
	}
	if newID == 0 {
		return failedCase(opts.name, start, fmt.Errorf("AddPath returned id=0"))
	}

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	rx := make([]byte, 4096)
	var written int64
	for written < opts.postAddBytes {
		toWrite := opts.postAddBytes - written
		if toWrite > int64(len(payload)) {
			toWrite = int64(len(payload))
		}
		chunk := payload[:toWrite]
		if err := writeAll(env.app, chunk); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("post-add write: %w", err))
		}
		got := int64(0)
		for got < toWrite {
			n, err := env.app.Read(rx[got:toWrite])
			if err != nil {
				return failedCase(opts.name, start, fmt.Errorf("post-add read: %w", err))
			}
			got += int64(n)
		}
		if string(rx[:toWrite]) != string(chunk) {
			return failedCase(opts.name, start, fmt.Errorf("post-add payload mismatch at byte %d", written))
		}
		written += toWrite
	}
	if stats := env.admin.Stats(); stats.RecvDups > 0 {
		return failedCase(opts.name, start, fmt.Errorf("RecvDups=%d after path re-add (expected 0)", stats.RecvDups))
	}

	_ = env.app.Close()
	if err := env.waitRelay(5 * time.Second); err != nil {
		return failedCase(opts.name, start, err)
	}
	select {
	case err := <-echoErr:
		if err != nil && !isClosedRelayErr(err) {
			return failedCase(opts.name, start, fmt.Errorf("echo: %w", err))
		}
	default:
	}
	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

func runT5Fallback(ctx context.Context, opts t5FallbackOptions) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = "TUN-full.T5-fallback"
	}
	if opts.size <= 0 {
		opts.size = 8 << 20
	}
	if opts.migrations <= 0 {
		opts.migrations = 2
	}

	if err := tcprepair.Available(); err == nil {
		ln, err := rendr.ListenTCP("127.0.0.1:0")
		if err != nil {
			return failedCase(opts.name, start, fmt.Errorf("tcprepair listen: %w", err))
		}
		if err := runTUNStreamTransfer(ctx, ln, t5Root(ln.Addr().String(), "tcprepair", "tun-t5-tcprepair", 2), t5Identity(44000), opts.size, 1); err != nil {
			_ = ln.Close()
			return failedCase(opts.name, start, fmt.Errorf("tcprepair path: %w", err))
		}
		_ = ln.Close()
	} else if !strings.Contains(err.Error(), "gvisor fallback") {
		return failedCase(opts.name, start, fmt.Errorf("tcprepair unavailable error does not name gvisor fallback: %w", err))
	}

	ln, err := rendr.ListenGVisor("")
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("gvisor listen: %w", err))
	}
	if err := runTUNStreamTransfer(ctx, ln, t5Root(ln.Addr().String(), "gvisor", "tun-t5-gvisor", 2), t5Identity(45000), opts.size, opts.migrations); err != nil {
		_ = ln.Close()
		return failedCase(opts.name, start, fmt.Errorf("gvisor path: %w", err))
	}
	_ = ln.Close()

	packetLn, err := rendr.ListenGVisorPacket("127.0.0.1:0")
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("gvisor packet listen: %w", err))
	}
	if err := runTUNStreamTransfer(ctx, packetLn, t5Root(packetLn.Addr().String(), "gvisor", "tun-t5-gvisor-packet", 2), t5Identity(46000), opts.size, opts.migrations); err != nil {
		_ = packetLn.Close()
		return failedCase(opts.name, start, fmt.Errorf("gvisor packet path: %w", err))
	}
	_ = packetLn.Close()

	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

func runT6Selector(ctx context.Context, opts t6SelectorOptions) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = "TUN-full.T6-selector"
	}
	if opts.bulkWarmWrites <= 0 {
		opts.bulkWarmWrites = 36
	}
	if opts.bulkBondWrites <= 0 {
		opts.bulkBondWrites = 24
	}

	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("listen: %w", err))
	}
	defer ln.Close()

	addr := ln.Addr().String()
	interactiveID := t6Identity(42000, 22)
	bulkID := t6Identity(43000, 443)
	interactiveRoot := t6SelectorRoot(addr, "tun-t6-int")
	bulkRoot := t6SelectorRoot(addr, "tun-t6-bulk")
	table := l3ingress.NewFlowTable(func(_ context.Context, flow l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
		switch flow.L3Identity {
		case interactiveID:
			return l3ingress.FlowDecision{
				Peer:   "peer-low",
				Root:   interactiveRoot,
				Egress: "direct",
				Labels: map[string]string{"class": "interactive"},
			}, nil
		case bulkID:
			return l3ingress.FlowDecision{
				Peer:   "peer-bulk",
				Root:   bulkRoot,
				Egress: "bond",
				Labels: map[string]string{"class": "bulk"},
			}, nil
		default:
			return l3ingress.FlowDecision{}, fmt.Errorf("unexpected flow identity: %+v", flow.L3Identity)
		}
	}, l3ingress.FlowTableOptions{})
	manager := &l3session.Manager{
		FlowTable: table,
		Starter: l3session.Starter{Options: []l3session.DialerOption{
			func(_ l3ingress.SessionRequest, d *rendr.Dialer) error {
				d.ProbeInterval = time.Hour
				return nil
			},
		}},
	}
	relay := &l3session.TCPRelay{Manager: manager, BufferSize: 64 << 10}

	intApp, intEndpoint := net.Pipe()
	defer intApp.Close()
	intRelayErr := make(chan error, 1)
	if err := startT6Flow(ctx, table, relay, interactiveID, intEndpoint, intRelayErr); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("interactive flow: %w", err))
	}
	intServer, err := acceptOneStream(ctx, ln)
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("accept interactive: %w", err))
	}
	defer intServer.Close()
	intEchoErr := startStreamEcho(intServer, 1024)
	intSess, err := waitStreamSession(ctx, manager, interactiveID)
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("interactive session: %w", err))
	}
	intAdmin, ok := intSess.Conn.(rendr.AdminConn)
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("interactive session conn is not rendr.AdminConn"))
	}
	waitPaths(ctx, intAdmin, 3)
	intIDs := idsByPathName(intAdmin.Paths())
	if intIDs["tun-t6-int-A"] == 0 || intIDs["tun-t6-int-B"] == 0 || intIDs["tun-t6-int-C"] == 0 {
		return failedCase(opts.name, start, fmt.Errorf("interactive path names missing: %v", intIDs))
	}

	bulkApp, bulkEndpoint := net.Pipe()
	defer bulkApp.Close()
	bulkRelayErr := make(chan error, 1)
	if err := startT6Flow(ctx, table, relay, bulkID, bulkEndpoint, bulkRelayErr); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("bulk flow: %w", err))
	}
	bulkServer, err := acceptOneStream(ctx, ln)
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("accept bulk: %w", err))
	}
	defer bulkServer.Close()
	bulkDrainErr := startStreamDrain(bulkServer)
	bulkSess, err := waitStreamSession(ctx, manager, bulkID)
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("bulk session: %w", err))
	}
	bulkAdmin, ok := bulkSess.Conn.(rendr.AdminConn)
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("bulk session conn is not rendr.AdminConn"))
	}
	waitPaths(ctx, bulkAdmin, 3)
	bulkIDs := idsByPathName(bulkAdmin.Paths())
	if bulkIDs["tun-t6-bulk-A"] == 0 || bulkIDs["tun-t6-bulk-B"] == 0 || bulkIDs["tun-t6-bulk-C"] == 0 {
		return failedCase(opts.name, start, fmt.Errorf("bulk path names missing: %v", bulkIDs))
	}

	for i := 0; i < 8; i++ {
		var msg [8]byte
		binary.BigEndian.PutUint64(msg[:], uint64(i))
		if err := writeAll(intApp, msg[:]); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("interactive write: %w", err))
		}
		var got [8]byte
		if err := readAll(intApp, got[:]); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("interactive read: %w", err))
		}
		if got != msg {
			return failedCase(opts.name, start, fmt.Errorf("interactive echo mismatch"))
		}
	}
	if got := intAdmin.Mode(); got != rendr.ModePrime {
		return failedCase(opts.name, start, fmt.Errorf("interactive mode=%v want prime", got))
	}
	if got := intAdmin.ActivePath(); got != intIDs["tun-t6-int-A"] {
		return failedCase(opts.name, start, fmt.Errorf("interactive active=%d want A=%d", got, intIDs["tun-t6-int-A"]))
	}

	chunk := make([]byte, 32<<10)
	for i := 0; i < opts.bulkWarmWrites; i++ {
		fillPattern(chunk, int64(i*len(chunk)))
		if err := writeAll(bulkApp, chunk); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("bulk warm write %d: %w", i, err))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := waitForAdminMode(bulkAdmin, rendr.ModeBond, 3*time.Second); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("bulk peak transfer: %w", err))
	}
	before := writesByPathName(bulkAdmin.Paths())
	for i := 0; i < opts.bulkBondWrites; i++ {
		fillPattern(chunk, int64((opts.bulkWarmWrites+i)*len(chunk)))
		if err := writeAll(bulkApp, chunk); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("bulk bond write %d: %w", i, err))
		}
	}
	after := writesByPathName(bulkAdmin.Paths())
	if after["tun-t6-bulk-B"] <= before["tun-t6-bulk-B"] || after["tun-t6-bulk-C"] <= before["tun-t6-bulk-C"] {
		return failedCase(opts.name, start, fmt.Errorf("bulk bond did not use both peak paths: before=%v after=%v", before, after))
	}

	if snap, ok := table.Snapshot(interactiveID); !ok {
		return failedCase(opts.name, start, fmt.Errorf("missing interactive flow snapshot"))
	} else if snap.MigrationCount != 0 || snap.Decision.Labels["class"] != "interactive" {
		return failedCase(opts.name, start, fmt.Errorf("interactive flow was polluted by bulk selector: %+v", snap))
	}
	if snap, ok := table.Snapshot(bulkID); !ok {
		return failedCase(opts.name, start, fmt.Errorf("missing bulk flow snapshot"))
	} else if snap.MigrationCount == 0 || snap.Decision.Labels["class"] != "bulk" {
		return failedCase(opts.name, start, fmt.Errorf("bulk flow did not record selector migration: %+v", snap))
	}

	_ = intApp.Close()
	_ = bulkApp.Close()
	if err := waitRelayErr(intRelayErr, 5*time.Second); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("interactive relay: %w", err))
	}
	if err := waitRelayErr(bulkRelayErr, 5*time.Second); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("bulk relay: %w", err))
	}
	select {
	case err := <-intEchoErr:
		if err != nil && !isClosedRelayErr(err) {
			return failedCase(opts.name, start, fmt.Errorf("interactive echo: %w", err))
		}
	default:
	}
	select {
	case err := <-bulkDrainErr:
		if err != nil && !isClosedRelayErr(err) {
			return failedCase(opts.name, start, fmt.Errorf("bulk drain: %w", err))
		}
	default:
	}
	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

type tunStreamEnv struct {
	ln       rendr.Listener
	server   rendr.Conn
	app      net.Conn
	admin    rendr.AdminConn
	addr     string
	relayErr chan error
}

func startTUNStream(ctx context.Context, paths int) (*tunStreamEnv, error) {
	if paths < 2 {
		paths = 2
	}
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

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

	id := g1Identity()
	root := g1Root(ln.Addr().String(), paths)
	manager := &l3session.Manager{}
	relay := &l3session.TCPRelay{Manager: manager}
	app, endpoint := net.Pipe()
	relayErr := make(chan error, 1)
	go func() {
		relayErr <- relay.Serve(ctx, g1Event(id, root), endpoint)
	}()

	var server rendr.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		_ = app.Close()
		_ = ln.Close()
		return nil, fmt.Errorf("accept: %w", err)
	case <-time.After(15 * time.Second):
		_ = app.Close()
		_ = ln.Close()
		return nil, fmt.Errorf("accept timeout")
	}

	sess, err := waitStreamSession(ctx, manager, id)
	if err != nil {
		_ = app.Close()
		_ = server.Close()
		_ = ln.Close()
		return nil, err
	}
	admin, ok := sess.Conn.(rendr.AdminConn)
	if !ok {
		_ = app.Close()
		_ = server.Close()
		_ = ln.Close()
		return nil, fmt.Errorf("session conn is not rendr.AdminConn")
	}
	waitPaths(ctx, admin, paths)
	return &tunStreamEnv{
		ln:       ln,
		server:   server,
		app:      app,
		admin:    admin,
		addr:     ln.Addr().String(),
		relayErr: relayErr,
	}, nil
}

func (e *tunStreamEnv) close() {
	if e == nil {
		return
	}
	if e.app != nil {
		_ = e.app.Close()
	}
	if e.server != nil {
		_ = e.server.Close()
	}
	if e.ln != nil {
		_ = e.ln.Close()
	}
}

func (e *tunStreamEnv) waitRelay(timeout time.Duration) error {
	if e == nil || e.relayErr == nil {
		return nil
	}
	select {
	case err := <-e.relayErr:
		if err != nil {
			return fmt.Errorf("relay: %w", err)
		}
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("relay shutdown timeout")
	}
}

func startStreamEcho(c net.Conn, bufferSize int) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		if bufferSize <= 0 {
			bufferSize = 4096
		}
		buf := make([]byte, bufferSize)
		for {
			n, err := c.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if err := writeAll(c, buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()
	return errCh
}

func runTUNStreamTransfer(ctx context.Context, ln rendr.Listener, root rendr.Target, id l3ingress.L3Identity, size int64, migrations int) error {
	if size <= 0 {
		size = 8 << 20
	}
	if migrations < 0 {
		migrations = 0
	}
	manager := &l3session.Manager{}
	relay := &l3session.TCPRelay{Manager: manager, BufferSize: 64 << 10}
	app, endpoint := net.Pipe()
	defer app.Close()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- relay.Serve(ctx, g1Event(id, root), endpoint)
	}()

	server, err := acceptOneStream(ctx, ln)
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	defer server.Close()

	sess, err := waitStreamSession(ctx, manager, id)
	if err != nil {
		return err
	}
	admin, ok := sess.Conn.(rendr.AdminConn)
	if !ok {
		return fmt.Errorf("session conn is not rendr.AdminConn")
	}
	waitPaths(ctx, admin, 2)

	recvErr := make(chan error, 1)
	hRecv := sha256.New()
	go func() {
		buf := make([]byte, 128*1024)
		var got int64
		for got < size {
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

	migPts := make([]int64, migrations)
	for i := 0; i < migrations; i++ {
		migPts[i] = size * int64(i+1) / int64(migrations+1)
	}
	hSent := sha256.New()
	buf := make([]byte, 128*1024)
	var written int64
	var migIdx int
	for written < size {
		end := written + int64(len(buf))
		if end > size {
			end = size
		}
		chunk := buf[:end-written]
		fillPattern(chunk, written)
		if err := writeAll(app, chunk); err != nil {
			return fmt.Errorf("write at %d: %w", written, err)
		}
		hSent.Write(chunk)
		written += int64(len(chunk))
		for migIdx < len(migPts) && written >= migPts[migIdx] {
			next := nextPath(admin)
			if next != 0 {
				if err := admin.Migrate(next); err != nil {
					return fmt.Errorf("migrate %d: %w", migIdx, err)
				}
			}
			migIdx++
		}
	}
	if err := <-recvErr; err != nil {
		return fmt.Errorf("recv: %w", err)
	}
	if sentHex, recvHex := fmt.Sprintf("%x", hSent.Sum(nil)), fmt.Sprintf("%x", hRecv.Sum(nil)); sentHex != recvHex {
		return fmt.Errorf("SHA-256 mismatch: sent=%s recv=%s", sentHex, recvHex)
	}
	if migrations > 0 && admin.MigrationCount() < uint64(migrations) {
		return fmt.Errorf("MigrationCount=%d, want >= %d", admin.MigrationCount(), migrations)
	}
	_ = app.Close()
	if err := waitRelayErr(relayErr, 5*time.Second); err != nil {
		return err
	}
	return nil
}

func t5Root(addr, transportName, prefix string, paths int) rendr.Target {
	children := make([]rendr.Target, 0, paths)
	for i := 0; i < paths; i++ {
		name := fmt.Sprintf("%s-%d", prefix, i+1)
		children = append(children, rendr.Path(name, rendr.PathSpec{
			Transport: transportName,
			Address:   addr,
			Opts:      map[string]string{"name": name},
		}))
	}
	return rendr.Selector(prefix+"-root", children)
}

func t5Identity(srcPort uint16) l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: srcPort,
		DstIP:   netip.MustParseAddr("198.51.100.50"),
		DstPort: 443,
	}
}

func startStreamDrain(c net.Conn) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, c)
		errCh <- err
	}()
	return errCh
}

func startT6Flow(ctx context.Context, table *l3ingress.FlowTable, relay *l3session.TCPRelay, id l3ingress.L3Identity, endpoint net.Conn, relayErr chan<- error) error {
	decision, _, _, err := table.Resolve(ctx, l3ingress.FlowMeta{
		L3Identity: id,
		Direction:  l3ingress.DirectionIngress,
	}, 1)
	if err != nil {
		_ = endpoint.Close()
		return err
	}
	ev := l3ingress.PacketEvent{
		Meta: l3ingress.PacketMeta{Identity: id},
		Flow: l3ingress.FlowMeta{
			L3Identity: id,
			Direction:  l3ingress.DirectionIngress,
		},
		Decision: decision,
		Decided:  true,
	}
	go func() {
		relayErr <- relay.Serve(ctx, ev, endpoint)
	}()
	return nil
}

func acceptOneStream(ctx context.Context, ln rendr.Listener) (rendr.Conn, error) {
	actx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return ln.Accept(actx)
}

func t6Identity(srcPort, dstPort uint16) l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: srcPort,
		DstIP:   netip.MustParseAddr("198.51.100.60"),
		DstPort: dstPort,
	}
}

func t6SelectorRoot(addr, prefix string) rendr.Target {
	spec := func(name string) rendr.PathSpec {
		return rendr.PathSpec{
			Transport: "tcp",
			Address:   addr,
			Opts:      map[string]string{"name": name},
		}
	}
	bulk := rendr.Bond(prefix+"-bulk", []rendr.Target{
		rendr.Path(prefix+"-B", spec(prefix+"-B")),
		rendr.Path(prefix+"-C", spec(prefix+"-C")),
	})
	return rendr.Selector(prefix+"-root", []rendr.Target{
		rendr.Path(prefix+"-A", spec(prefix+"-A")),
		bulk,
	}, rendr.PeakTransfer{
		Targets:         []string{prefix + "-bulk"},
		SaturationFor:   200 * time.Millisecond,
		ReturnFor:       2 * time.Second,
		SaturationRatio: 0.8,
		ReturnRatio:     0.2,
	})
}

func idsByPathName(paths []rendr.PathInfo) map[string]uint32 {
	out := make(map[string]uint32, len(paths))
	for _, p := range paths {
		if name := pathInfoName(p); name != "" {
			out[name] = p.ID
		}
	}
	return out
}

func writesByPathName(paths []rendr.PathInfo) map[string]uint64 {
	out := make(map[string]uint64, len(paths))
	for _, p := range paths {
		if name := pathInfoName(p); name != "" {
			out[name] = p.Writes
		}
	}
	return out
}

func pathInfoName(p rendr.PathInfo) string {
	if p.Spec.Opts == nil {
		return ""
	}
	return p.Spec.Opts["name"]
}

func waitForAdminMode(admin rendr.AdminConn, want rendr.Mode, within time.Duration) error {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if admin.Mode() == want {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("mode=%v want %v", admin.Mode(), want)
}

func waitRelayErr(ch <-chan error, timeout time.Duration) error {
	select {
	case err := <-ch:
		if err != nil && !isClosedRelayErr(err) {
			return err
		}
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("relay shutdown timeout")
	}
}

func runG3Smoke(ctx context.Context, opts g3Options) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = "TUN-full.G3-smoke"
	}
	if opts.duration <= 0 {
		opts.duration = 5 * time.Second
	}
	if opts.pps <= 0 {
		opts.pps = 5000
	}
	if opts.payloadLen <= 16 {
		opts.payloadLen = 1024
	}
	if opts.paths < 1 {
		opts.paths = 4
	}
	if opts.migrations < 0 {
		opts.migrations = 0
	}
	if opts.migrations == 0 {
		opts.migrations = 3
	}
	if opts.lossPct < 0 {
		opts.lossPct = 0
	} else if opts.lossPct == 0 {
		opts.lossPct = 0.5
	}
	if opts.p95Ceiling <= 0 {
		opts.p95Ceiling = 50 * time.Millisecond
	}

	ln, err := rendr.ListenQUICDatagram("127.0.0.1:0", nil)
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("ListenQUICDatagram: %w", err))
	}
	defer ln.Close()

	accepted := make(chan rendr.PacketConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		pc, err := ln.AcceptPacket(actx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- pc
	}()

	id := l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.53"),
		DstPort: 53,
	}
	root := g3Root(ln.Addr().String(), opts.paths)
	manager := &l3session.Manager{}
	dev := &captureDevice{}
	relay := &l3session.UDPRelay{Device: dev, Manager: manager, BufferSize: opts.payloadLen + 64}
	defer relay.Close()

	payload := make([]byte, opts.payloadLen)
	binary.BigEndian.PutUint64(payload[:8], 0)
	binary.BigEndian.PutUint64(payload[8:16], uint64(time.Now().UnixNano()))
	packet, meta, err := udpPacketEventParts(id, payload)
	if err != nil {
		return failedCase(opts.name, start, err)
	}
	event := l3ingress.PacketEvent{
		Packet: packet,
		Meta:   meta,
		Flow:   l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
		Decision: l3ingress.FlowDecision{
			Peer:   "peer-a",
			Root:   root,
			Egress: "direct",
		},
		Decided: true,
	}
	if err := relay.HandlePacket(ctx, l3ingress.PacketEvent{
		Packet: event.Packet,
		Meta:   event.Meta,
		Flow:   event.Flow,
		Decision: l3ingress.FlowDecision{
			Peer:   event.Decision.Peer,
			Root:   event.Decision.Root,
			Egress: event.Decision.Egress,
		},
		Decided: event.Decided,
	}); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("start relay: %w", err))
	}

	var server rendr.PacketConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		return failedCase(opts.name, start, fmt.Errorf("accept: %w", err))
	case <-time.After(15 * time.Second):
		return failedCase(opts.name, start, fmt.Errorf("accept timeout"))
	}
	defer server.Close()

	sess, ok := manager.Session(id)
	if !ok || sess.PacketConn == nil {
		return failedCase(opts.name, start, fmt.Errorf("missing packet session"))
	}
	admin, ok := sess.PacketConn.(rendr.AdminPacketConn)
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("session packet conn is not rendr.AdminPacketConn"))
	}
	waitPacketPaths(ctx, admin, opts.paths)

	expected := int(float64(opts.pps)*opts.duration.Seconds()) + opts.pps
	recvBmp := make([]uint8, expected+opts.pps)
	latencies := make([]time.Duration, 0, expected/100+1)
	recvDone := make(chan struct{})
	sendDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		buf := make([]byte, opts.payloadLen+64)
		_ = server.SetReadDeadline(time.Now().Add(opts.duration + 5*time.Second))
		var rx int
		sendDoneC := sendDone
		for {
			n, _, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case <-sendDoneC:
				sendDoneC = nil
				_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
			default:
			}
			if n < 16 {
				continue
			}
			seq := binary.BigEndian.Uint64(buf[:8])
			if seq < uint64(len(recvBmp)) {
				recvBmp[seq] = 1
			}
			if rx%100 == 0 {
				sentNS := int64(binary.BigEndian.Uint64(buf[8:16]))
				latencies = append(latencies, time.Since(time.Unix(0, sentNS)))
			}
			rx++
		}
	}()

	startMig := admin.MigrationCount()
	migInterval := opts.duration / time.Duration(opts.migrations+1)
	migTicker := time.NewTicker(migInterval)
	defer migTicker.Stop()
	packetInterval := time.Second / time.Duration(opts.pps)
	nextTick := time.Now()
	endAt := time.Now().Add(opts.duration)
	var sent int64 = 1
	payloadOffset := meta.PayloadOffset + 8
	for time.Now().Before(endAt) {
		select {
		case <-ctx.Done():
			return failedCase(opts.name, start, ctx.Err())
		case <-migTicker.C:
			next := nextPacketPath(admin)
			if next != 0 {
				_ = admin.Migrate(next)
			}
		default:
		}
		paceUntil(nextTick)
		nextTick = nextTick.Add(packetInterval)
		binary.BigEndian.PutUint64(payload[:8], uint64(sent))
		binary.BigEndian.PutUint64(payload[8:16], uint64(time.Now().UnixNano()))
		copy(packet[payloadOffset:payloadOffset+len(payload)], payload)
		if err := relay.HandlePacket(ctx, event); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("send seq %d: %w", sent, err))
		}
		sent++
	}
	close(sendDone)
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	<-recvDone
	relay.CloseFlow(id)

	lost := int64(0)
	limit := sent
	if limit > int64(len(recvBmp)) {
		limit = int64(len(recvBmp))
	}
	for seq := int64(0); seq < limit; seq++ {
		if recvBmp[seq] == 0 {
			lost++
		}
	}
	if sent > int64(len(recvBmp)) {
		lost += sent - int64(len(recvBmp))
	}
	lossPct := float64(lost) / float64(sent) * 100
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p95 := percentile(latencies, 0.95)
	migrations := admin.MigrationCount() - startMig
	if lossPct > opts.lossPct {
		return failedCase(opts.name, start, fmt.Errorf("loss %.3f%% exceeds budget %.3f%%", lossPct, opts.lossPct))
	}
	if p95 > opts.p95Ceiling {
		return failedCase(opts.name, start, fmt.Errorf("P95 %s exceeds ceiling %s", p95, opts.p95Ceiling))
	}
	if migrations < uint64(opts.migrations) {
		return failedCase(opts.name, start, fmt.Errorf("MigrationCount=%d, want >= %d", migrations, opts.migrations))
	}
	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

func g3Root(addr string, paths int) rendr.Target {
	children := make([]rendr.Target, 0, paths)
	for i := 0; i < paths; i++ {
		children = append(children, rendr.Path(fmt.Sprintf("tun-g3-%d", i+1), rendr.PathSpec{
			Transport: "quic",
			Address:   addr,
			Opts:      map[string]string{"mode": "datagram"},
		}))
	}
	return rendr.Bond("tun-full-g3", children)
}

func udpPacketEventParts(id l3ingress.L3Identity, payload []byte) ([]byte, l3ingress.PacketMeta, error) {
	packet, err := l3ingress.BuildUDPPacket(id, payload)
	if err != nil {
		return nil, l3ingress.PacketMeta{}, fmt.Errorf("build UDP packet: %w", err)
	}
	meta, err := l3ingress.ParsePacket(packet)
	if err != nil {
		return nil, l3ingress.PacketMeta{}, fmt.Errorf("parse UDP packet: %w", err)
	}
	return packet, meta, nil
}

func waitPacketPaths(ctx context.Context, admin rendr.AdminPacketConn, want int) {
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for len(admin.Paths()) < want {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			return
		case <-tick.C:
		}
	}
}

func nextPacketPath(admin rendr.AdminPacketConn) uint32 {
	cur := admin.ActivePath()
	for _, p := range admin.Paths() {
		if p.ID != cur {
			return p.ID
		}
	}
	return 0
}

func startPacketEcho(pc rendr.PacketConn, bufferSize int) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		if bufferSize <= 0 {
			bufferSize = 2048
		}
		buf := make([]byte, bufferSize)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				errCh <- err
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				errCh <- err
				return
			}
		}
	}()
	return errCh
}

type captureDevice struct {
	writes  chan []byte
	onWrite func([]byte)
}

func (d *captureDevice) Read([]byte) (int, error) { return 0, io.EOF }
func (d *captureDevice) Write(p []byte) (int, error) {
	if d.onWrite != nil {
		d.onWrite(p)
		return len(p), nil
	}
	if d.writes != nil {
		d.writes <- append([]byte(nil), p...)
	}
	return len(p), nil
}
func (d *captureDevice) Close() error { return nil }
func (d *captureDevice) Name() string { return "tun-full-capture0" }
func (d *captureDevice) MTU() int     { return 1500 }

func paceUntil(target time.Time) {
	for {
		now := time.Now()
		if !now.Before(target) {
			return
		}
		remaining := target.Sub(now)
		switch {
		case remaining > 250*time.Microsecond:
			time.Sleep(remaining - 100*time.Microsecond)
		case remaining > 50*time.Microsecond:
			runtime.Gosched()
		default:
		}
	}
}
