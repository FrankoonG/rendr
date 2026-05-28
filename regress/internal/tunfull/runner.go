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
	"sort"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/l3session"
	"github.com/FrankoonG/rendr/regress/internal/report"
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
	"TUN-full.T4-long-run",
	"TUN-full.T5-fallback",
	"TUN-full.T6-selector",
}

// Run records the TUN full baseline status. Implemented cases run as real
// TUN/per-flow baselines; remaining planned cases stay as explicit guard
// failures so --tun-full cannot report a false green.
func Run(ctx context.Context, suite *report.Suite, _ string, opts Options) {
	matched := false
	for _, name := range plannedCases {
		if !caseMatches(opts.Case, name) {
			continue
		}
		matched = true
		suite.Add(runPlannedCase(ctx, name))
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

func runPlannedCase(ctx context.Context, name string) report.Case {
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
	default:
		return UnimplementedCase(name)
	}
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
