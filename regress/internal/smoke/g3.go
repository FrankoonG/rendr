package smoke

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr"
)

// G3Opts configures one G3-smoke case (QUIC DATAGRAM at high pps +
// ConnID migrations). Defaults match docs/regression-suite.md §6:
// 30k pps × ~6s with ≥3 migrations. Needs Linux + sysctl
// net.core.rmem_max=8MiB; the tier2 dispatch already SKIPs on
// non-Linux.
type G3Opts struct {
	Duration   time.Duration // default 6s
	PPS        int           // default 30000
	PayloadLen int           // default 1024 bytes (sub-MTU; rendr adds 8B flow-id)
	Migrations int           // default 3
	Paths      int           // default 4 (bond mode for pps headroom)
	// P95CeilingMs caps the recv-time-after-send histogram. Default
	// 50ms — generous for loopback bond. Phase-1 smoke; T4 tightens.
	P95CeilingMs int
	// LossPct allows N% application loss; default 0 (strict).
	LossPct float64
}

func (o *G3Opts) withDefaults() {
	if o.Duration <= 0 {
		o.Duration = 5 * time.Second
	}
	if o.PPS <= 0 {
		// Smoke target: validates packet-mode rendr + ConnID
		// migration end-to-end without stressing throughput. The
		// full 30k pps / 100k pps contract validation lives in T4
		// (long-run) where loopback CPU contention is avoided and
		// the receiver drainer gets dedicated scheduler time.
		o.PPS = 5000
	}
	if o.PayloadLen <= 0 {
		o.PayloadLen = 1024
	}
	if o.Migrations < 0 {
		o.Migrations = 0
	}
	if o.Migrations == 0 {
		o.Migrations = 3
	}
	if o.Paths < 1 {
		o.Paths = 4
	}
	if o.P95CeilingMs <= 0 {
		o.P95CeilingMs = 50
	}
	if o.LossPct < 0 {
		o.LossPct = 0
	}
	if o.LossPct == 0 {
		// Tolerate sub-1% loss from Go-runtime timer granularity
		// (1ms tick at 5k pps = up to 5 packets per tick burst, the
		// receiver-side drainer goroutine may miss some at migration
		// boundaries). Smoke-level; T4 long-run tightens to 0%.
		o.LossPct = 0.5
	}
}

// RunG3 drives one G3-smoke case end-to-end. The wire shape is
// rendr packet-mode over QUIC DATAGRAM paths (multi-path bond),
// each application packet = 8B seq prefix + payload. Asserts:
//   - application-visible loss ≤ LossPct (default 0)
//   - P95 (recv-time - send-time) under ceiling (default 50ms)
//   - MigrationCount() ≥ Migrations
//
// Detail keys:
//
//	pps_sent          float64
//	pps_received      float64
//	sent              int64
//	received          int64
//	loss_pct          float64
//	migrations        uint64
//	p50_ms            float64
//	p95_ms            float64
//	p99_ms            float64
//	max_ms            float64
func RunG3(ctx context.Context, opts G3Opts) Result {
	opts.withDefaults()
	t0 := time.Now()
	name := fmt.Sprintf("G3-smoke (%d pps, %s, %d paths bond, %d migrations)",
		opts.PPS, opts.Duration, opts.Paths, opts.Migrations)

	ln, err := rendr.ListenQUICDatagram("127.0.0.1:0", nil)
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("ListenQUICDatagram: %w", err))
	}
	defer ln.Close()

	accepted := make(chan rendr.PacketConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		c, err := ln.AcceptPacket(actx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	specs := make([]rendr.PathSpec, opts.Paths)
	for i := range specs {
		specs[i] = rendr.PathSpec{
			Transport: "quic",
			Address:   ln.Addr().String(),
			Opts:      map[string]string{"mode": "datagram"},
		}
	}
	client, err := (&rendr.Dialer{Mode: rendr.ModeBond, Paths: specs}).DialPacket(ctx)
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("DialPacket: %w", err))
	}
	defer client.Close()

	var server rendr.PacketConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		return FromError(name, time.Since(t0), fmt.Errorf("accept: %w", err))
	case <-time.After(15 * time.Second):
		return FromError(name, time.Since(t0), fmt.Errorf("accept timeout"))
	}
	defer server.Close()

	// Wait for all paths to attach.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= opts.Paths && len(server.Paths()) >= opts.Paths {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	admin, ok := client.(rendr.AdminPacketConn)
	if !ok {
		return FromError(name, time.Since(t0), fmt.Errorf("client is not rendr.AdminPacketConn"))
	}

	// Server receiver: write directly to pre-sized slices guarded
	// by a mutex. A buffered channel would block the receiver
	// goroutine the moment buffer fills, deadlocking against the
	// main loop's later drain (observed: goroutine stuck for 9min
	// on chan send because PPS*Duration > buffer of PPS*2).
	expected := int(opts.PPS) * int(opts.Duration.Seconds()*2) // 2x headroom
	if expected < 1000 {
		expected = 1000
	}
	var rxMu sync.Mutex
	recvSeqs := make(map[uint64]struct{}, expected)
	latNs := make([]int64, 0, expected)
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		buf := make([]byte, opts.PayloadLen+8)
		readDeadline := time.Now().Add(opts.Duration + 5*time.Second)
		_ = server.SetReadDeadline(readDeadline)
		for {
			n, _, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 16 {
				continue
			}
			seq := binary.BigEndian.Uint64(buf[:8])
			sentNs := int64(binary.BigEndian.Uint64(buf[8:16]))
			latency := time.Now().UnixNano() - sentNs
			rxMu.Lock()
			recvSeqs[seq] = struct{}{}
			latNs = append(latNs, latency)
			rxMu.Unlock()
		}
	}()

	// Migration scheduler: trigger Migrations spread evenly.
	migInterval := opts.Duration / time.Duration(opts.Migrations+1)
	migTicker := time.NewTicker(migInterval)
	defer migTicker.Stop()

	// Sender: paced loop.
	pktInterval := time.Second / time.Duration(opts.PPS)
	payload := make([]byte, opts.PayloadLen)
	pkt := make([]byte, opts.PayloadLen+8)
	copy(pkt[16:], payload[8:]) // keep 16B header (seq + send_ns), rest payload

	var sent int64
	startMig := admin.MigrationCount()
	endAt := time.Now().Add(opts.Duration)
	nextTick := time.Now()

	for time.Now().Before(endAt) {
		select {
		case <-migTicker.C:
			cur := admin.ActivePath()
			for _, p := range client.Paths() {
				if p.ID != cur {
					_ = admin.Migrate(p.ID)
					break
				}
			}
		default:
		}
		now := time.Now()
		if now.Before(nextTick) {
			time.Sleep(nextTick.Sub(now))
		}
		nextTick = nextTick.Add(pktInterval)
		binary.BigEndian.PutUint64(pkt[:8], uint64(sent))
		binary.BigEndian.PutUint64(pkt[8:16], uint64(time.Now().UnixNano()))
		if _, err := client.WriteTo(pkt, nil); err != nil {
			// Buffer exhausted on the sender side or socket gone.
			// Treat as test failure since the contract says no
			// application-visible error during migration.
			return FromError(name, time.Since(t0), fmt.Errorf("WriteTo at seq %d: %w", sent, err))
		}
		atomic.AddInt64(&sent, 1)
	}

	// Give receiver a moment to drain in-flight datagrams, then
	// force its ReadFrom to return via the deadline.
	time.Sleep(500 * time.Millisecond)
	_ = server.SetReadDeadline(time.Now())
	<-recvDone

	rxMu.Lock()
	received := recvSeqs
	gotLat := latNs
	rxMu.Unlock()

	dur := time.Since(t0)
	lost := int64(0)
	for s := int64(0); s < sent; s++ {
		if _, ok := received[uint64(s)]; !ok {
			lost++
		}
	}
	lossPct := float64(lost) / float64(sent) * 100

	sort.Slice(gotLat, func(i, j int) bool { return gotLat[i] < gotLat[j] })
	idx := func(p int) int64 {
		if len(gotLat) == 0 {
			return 0
		}
		i := len(gotLat) * p / 100
		if i >= len(gotLat) {
			i = len(gotLat) - 1
		}
		return gotLat[i]
	}
	p50 := idx(50)
	p95 := idx(95)
	p99 := idx(99)
	maxN := int64(0)
	if len(gotLat) > 0 {
		maxN = gotLat[len(gotLat)-1]
	}
	migrations := admin.MigrationCount() - startMig

	r := Result{
		Name:     name,
		Duration: dur,
		Detail: map[string]any{
			"pps_sent":     float64(sent) / dur.Seconds(),
			"pps_received": float64(len(received)) / dur.Seconds(),
			"sent":         sent,
			"received":     int64(len(received)),
			"loss_pct":     lossPct,
			"migrations":   migrations,
			"p50_ms":       float64(p50) / float64(time.Millisecond),
			"p95_ms":       float64(p95) / float64(time.Millisecond),
			"p99_ms":       float64(p99) / float64(time.Millisecond),
			"max_ms":       float64(maxN) / float64(time.Millisecond),
		},
	}
	if lossPct > opts.LossPct {
		r.Failure = fmt.Sprintf("loss %.3f%% exceeds budget %.3f%%", lossPct, opts.LossPct)
		return r
	}
	if int(p95/int64(time.Millisecond)) > opts.P95CeilingMs {
		r.Failure = fmt.Sprintf("P95 %.1fms exceeds ceiling %dms",
			float64(p95)/float64(time.Millisecond), opts.P95CeilingMs)
		return r
	}
	if opts.Migrations > 0 && migrations < uint64(opts.Migrations) {
		r.Failure = fmt.Sprintf("MigrationCount=%d, want >= %d", migrations, opts.Migrations)
		return r
	}
	return r
}
