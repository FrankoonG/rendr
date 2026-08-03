package smoke

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"runtime"
	"sort"
	"time"

	"github.com/FrankoonG/rendr"
)

// G3Opts configures one G3-smoke case (QUIC DATAGRAM at high pps plus
// rendr packet-path transitions). This smoke does not prove RFC 9000
// Connection ID or NAT rebinding; the release Gold case needs an external
// packet-capture oracle for that. Defaults match docs/regression-suite.md §6:
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

const (
	g3LatencySampleEvery  = 100
	g3MinimumSamples      = 20
	g3MinimumOfferedRatio = 0.95
	g3PacketIntegrityMask = uint64(0xd6e8feb86659fd93)
	g3MaximumPackets      = 100_000_000
)

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
	if o.Migrations == 0 {
		o.Migrations = 3
	} else if o.Migrations < 0 {
		o.Migrations = 0
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
}

type g3Measurements struct {
	sent               int64
	received           int64
	sendElapsed        time.Duration
	latencySamples     int
	p95                time.Duration
	migrationAttempts  int
	migrationErrors    int
	migrationsObserved uint64
	malformedPackets   int64
	corruptPackets     int64
	duplicatePackets   int64
	outOfRangePackets  int64
	pathWriters        int
	wireWrites         uint64
}

type g3ReceiveOutcome struct {
	latencies         []int64
	uniquePackets     int64
	malformedPackets  int64
	corruptPackets    int64
	duplicatePackets  int64
	outOfRangePackets int64
	err               error
}

// validateG3Measurements separates invalid harness evidence from observed
// product failures. A mandatory case fails closed for either outcome, but the
// distinction prevents an underpowered sender from being reported as a fast,
// lossless transport.
func validateG3Measurements(opts G3Opts, m g3Measurements) (invalidReason, failure string) {
	if m.sent <= 0 {
		return "sender produced no packets", ""
	}
	if m.sendElapsed <= 0 {
		return fmt.Sprintf("sender elapsed=%s, want >0", m.sendElapsed), ""
	}
	offered := float64(m.sent) / m.sendElapsed.Seconds()
	if math.IsNaN(offered) || math.IsInf(offered, 0) {
		return fmt.Sprintf("offered pps is not finite: %v", offered), ""
	}
	if ratio := offered / float64(opts.PPS); ratio < g3MinimumOfferedRatio {
		return fmt.Sprintf("offered load %.0fpps is %.1f%% of %dpps target; want >=%.0f%%",
			offered, ratio*100, opts.PPS, g3MinimumOfferedRatio*100), ""
	}
	if m.received < 0 || m.received > m.sent {
		return fmt.Sprintf("invalid delivery counters: sent=%d received=%d", m.sent, m.received), ""
	}
	minimumSamples := g3MinimumSamples
	if expected := int(m.received / g3LatencySampleEvery); expected > minimumSamples {
		minimumSamples = expected * 9 / 10
	}
	if m.latencySamples < minimumSamples {
		return fmt.Sprintf("latency samples=%d, want >=%d", m.latencySamples, minimumSamples), ""
	}
	if m.migrationAttempts != opts.Migrations {
		return fmt.Sprintf("migration stimulus attempts=%d, want exactly %d", m.migrationAttempts, opts.Migrations), ""
	}
	if opts.Paths > 1 && m.pathWriters < 2 {
		return fmt.Sprintf("paths carrying frames=%d, want >=2", m.pathWriters), ""
	}
	if m.wireWrites < uint64(m.sent) {
		return fmt.Sprintf("wire write delta=%d is below application packets=%d", m.wireWrites, m.sent), ""
	}
	if m.migrationErrors > 0 {
		return "", fmt.Sprintf("migration requests rejected=%d", m.migrationErrors)
	}
	if opts.Migrations > 0 && m.migrationsObserved < uint64(opts.Migrations) {
		return "", fmt.Sprintf("MigrationCount=%d, want >=%d", m.migrationsObserved, opts.Migrations)
	}
	if m.malformedPackets > 0 || m.corruptPackets > 0 || m.outOfRangePackets > 0 {
		return "", fmt.Sprintf("packet integrity failures: malformed=%d corrupt=%d out_of_range=%d",
			m.malformedPackets, m.corruptPackets, m.outOfRangePackets)
	}
	if m.duplicatePackets > 0 {
		return "", fmt.Sprintf("duplicate application packets=%d", m.duplicatePackets)
	}
	lost := m.sent - m.received
	lossPct := float64(lost) / float64(m.sent) * 100
	if math.IsNaN(lossPct) || math.IsInf(lossPct, 0) {
		return fmt.Sprintf("loss percentage is not finite: %v", lossPct), ""
	}
	if lossPct > opts.LossPct {
		return "", fmt.Sprintf("loss %.3f%% exceeds budget %.3f%%", lossPct, opts.LossPct)
	}
	if m.p95 < 0 {
		return fmt.Sprintf("P95 latency=%s, want >=0", m.p95), ""
	}
	if m.p95 > time.Duration(opts.P95CeilingMs)*time.Millisecond {
		return "", fmt.Sprintf("P95 %.1fms exceeds ceiling %dms",
			float64(m.p95)/float64(time.Millisecond), opts.P95CeilingMs)
	}
	return "", ""
}

func invalidG3Result(name string, started time.Time, reason string, detail map[string]any) Result {
	if detail == nil {
		detail = map[string]any{}
	}
	return Result{
		Name:          name,
		Duration:      time.Since(started),
		InvalidReason: reason,
		Detail:        detail,
	}
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// RunG3 drives one packet-mode smoke case end-to-end. The wire shape is
// rendr packet-mode over independent QUIC DATAGRAM paths (multi-path bond),
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
	udpStatsBefore, udpStatsBeforeAvailable, udpStatsBeforeErr := readG3HostUDPStats()
	name := fmt.Sprintf("G3-smoke (%d pps, %s, %d paths bond, %d migrations)",
		opts.PPS, opts.Duration, opts.Paths, opts.Migrations)
	targetPacketsFloat := float64(opts.PPS) * opts.Duration.Seconds()
	if targetPacketsFloat < 1 || targetPacketsFloat > g3MaximumPackets {
		return invalidG3Result(name, t0,
			fmt.Sprintf("target packet count %.0f outside [1,%d]", targetPacketsFloat, g3MaximumPackets), nil)
	}
	if opts.PayloadLen+8 < 24 {
		return invalidG3Result(name, t0,
			fmt.Sprintf("wire packet length=%d, want >=24 for sequence, timestamp, and integrity marker", opts.PayloadLen+8), nil)
	}

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
	if gotClient, gotServer := len(client.Paths()), len(server.Paths()); gotClient < opts.Paths || gotServer < opts.Paths {
		return invalidG3Result(name, t0,
			fmt.Sprintf("path attach incomplete: client=%d server=%d want=%d", gotClient, gotServer, opts.Paths),
			map[string]any{"client_paths": gotClient, "server_paths": gotServer})
	}

	admin, ok := client.(rendr.AdminPacketConn)
	if !ok {
		return FromError(name, time.Since(t0), fmt.Errorf("client is not rendr.AdminPacketConn"))
	}
	pathWritesBefore := make(map[uint32]uint64, opts.Paths)
	for _, path := range admin.Stats().Paths {
		pathWritesBefore[path.ID] = path.Writes
	}

	// The receiver is single-writer and uses a bounded presence bitmap.
	// It sends one immutable outcome after the sender closes; the channel
	// handoff is the happens-before barrier for bitmap and latency reads.
	expected := int(math.Ceil(targetPacketsFloat*1.25)) + 1
	if expected < 1000 {
		expected = 1000
	}
	recvBmp := make([]uint8, expected)
	sendEpoch := time.Now()
	recvOutcome := make(chan g3ReceiveOutcome, 1)
	sendDone := make(chan struct{})
	go func() {
		outcome := g3ReceiveOutcome{
			latencies: make([]int64, 0, expected/g3LatencySampleEvery+8),
		}
		defer func() { recvOutcome <- outcome }()
		buf := make([]byte, opts.PayloadLen+8)
		_ = server.SetReadDeadline(time.Now().Add(opts.Duration + 10*time.Second))
		draining := false
		for {
			n, _, err := server.ReadFrom(buf)
			if err != nil {
				select {
				case <-sendDone:
					if !isTimeoutError(err) {
						outcome.err = err
					}
				default:
					outcome.err = err
				}
				return
			}
			if !draining {
				select {
				case <-sendDone:
					draining = true
					// Keep one fixed tail window. Re-extending it on every
					// packet could let stray traffic keep the case alive forever.
					_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
				default:
				}
			}
			if n != len(buf) {
				outcome.malformedPackets++
				continue
			}
			seq := binary.BigEndian.Uint64(buf[:8])
			if seq >= uint64(len(recvBmp)) {
				outcome.outOfRangePackets++
				continue
			}
			if marker := binary.BigEndian.Uint64(buf[n-8:]); marker != seq^g3PacketIntegrityMask {
				outcome.corruptPackets++
				continue
			}
			if recvBmp[seq] != 0 {
				outcome.duplicatePackets++
				continue
			}
			recvBmp[seq] = 1
			if outcome.uniquePackets%g3LatencySampleEvery == 0 {
				sentElapsed := time.Duration(binary.BigEndian.Uint64(buf[8:16]))
				latency := time.Since(sendEpoch) - sentElapsed
				if latency < 0 {
					outcome.corruptPackets++
				} else {
					outcome.latencies = append(outcome.latencies, int64(latency))
				}
			}
			outcome.uniquePackets++
		}
	}()

	// Sender: paced loop. Migration points are tied to produced packets,
	// so an underpowered sender cannot claim it exercised every transition.
	pktInterval := time.Second / time.Duration(opts.PPS)
	pkt := make([]byte, opts.PayloadLen+8)
	var sent int64
	startMig := admin.MigrationCount()
	migrationAttempts := 0
	migrationErrors := 0
	migrationSequences := make([]int64, 0, opts.Migrations)
	nextMigration := 1
	targetPackets := int64(math.Ceil(targetPacketsFloat))
	sendStarted := time.Now()
	endAt := sendStarted.Add(opts.Duration)
	nextTick := sendStarted
	writeFailure := ""

sendLoop:
	for {
		if err := ctx.Err(); err != nil {
			writeFailure = "sender context: " + err.Error()
			break
		}
		if !time.Now().Before(endAt) {
			break
		}
		for nextMigration <= opts.Migrations && sent >= targetPackets*int64(nextMigration)/int64(opts.Migrations+1) {
			migrationAttempts++
			migrationSequences = append(migrationSequences, sent)
			cur := admin.ActivePath()
			migrated := false
			for _, path := range client.Paths() {
				if path.ID == cur {
					continue
				}
				if err := admin.Migrate(path.ID); err != nil {
					migrationErrors++
				}
				migrated = true
				break
			}
			if !migrated {
				migrationErrors++
			}
			nextMigration++
		}
		paceUntil(nextTick)
		if !time.Now().Before(endAt) {
			break
		}
		nextTick = nextTick.Add(pktInterval)
		seq := uint64(sent)
		binary.BigEndian.PutUint64(pkt[:8], seq)
		binary.BigEndian.PutUint64(pkt[8:16], uint64(time.Since(sendEpoch)))
		binary.BigEndian.PutUint64(pkt[len(pkt)-8:], seq^g3PacketIntegrityMask)
		n, err := client.WriteTo(pkt, nil)
		if err != nil {
			writeFailure = fmt.Sprintf("WriteTo at seq %d: %v", sent, err)
			break sendLoop
		}
		if n != len(pkt) {
			writeFailure = fmt.Sprintf("short WriteTo at seq %d: wrote %d of %d", sent, n, len(pkt))
			break sendLoop
		}
		sent++
	}
	sendElapsed := time.Since(sendStarted)
	close(sendDone)
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	receivedOutcome := <-recvOutcome
	udpStatsAfter, udpStatsAfterAvailable, udpStatsAfterErr := readG3HostUDPStats()
	gotLat := receivedOutcome.latencies

	dur := time.Since(t0)
	received := receivedOutcome.uniquePackets
	lost := sent - received
	lossPct := math.NaN()
	if sent > 0 {
		lossPct = float64(lost) / float64(sent) * 100
	}

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
	pathWriters := 0
	var wireWrites uint64
	for _, path := range admin.Stats().Paths {
		before := pathWritesBefore[path.ID]
		if path.Writes <= before {
			continue
		}
		delta := path.Writes - before
		pathWriters++
		wireWrites += delta
	}
	ppsSent := float64(0)
	ppsReceived := float64(0)
	if sendElapsed > 0 {
		ppsSent = float64(sent) / sendElapsed.Seconds()
		ppsReceived = float64(received) / sendElapsed.Seconds()
	}
	missing := summarizeG3Missing(recvBmp, sent, migrationSequences, opts.PPS)

	detail := map[string]any{
		"target_pps":                     opts.PPS,
		"pps_sent":                       ppsSent,
		"pps_received":                   ppsReceived,
		"send_elapsed_ms":                float64(sendElapsed) / float64(time.Millisecond),
		"sent":                           sent,
		"received":                       received,
		"loss_pct":                       lossPct,
		"loss_budget_pct":                opts.LossPct,
		"migration_attempts":             migrationAttempts,
		"migration_errors":               migrationErrors,
		"migration_sequences":            formatG3Sequences(migrationSequences),
		"migrations":                     migrations,
		"latency_samples":                len(gotLat),
		"p50_ms":                         float64(p50) / float64(time.Millisecond),
		"p95_ms":                         float64(p95) / float64(time.Millisecond),
		"p99_ms":                         float64(p99) / float64(time.Millisecond),
		"max_ms":                         float64(maxN) / float64(time.Millisecond),
		"malformed_packets":              receivedOutcome.malformedPackets,
		"corrupt_packets":                receivedOutcome.corruptPackets,
		"duplicate_packets":              receivedOutcome.duplicatePackets,
		"out_of_range_packets":           receivedOutcome.outOfRangePackets,
		"path_writers":                   pathWriters,
		"wire_writes":                    wireWrites,
		"missing_packets":                missing.Count,
		"missing_range_count":            missing.RangeCount,
		"missing_range_sample":           missing.RangeSample,
		"missing_range_sample_truncated": missing.SampleTruncated,
		"missing_nearest_migration_distance_packets": missing.NearestMigrationDistancePackets,
		"missing_near_migration_packets":             missing.NearMigrationPackets,
		"missing_near_migration_window_packets":      missing.NearMigrationWindowPackets,
	}
	addG3UDPStatsEvidence(detail, udpStatsBefore, udpStatsBeforeAvailable, udpStatsBeforeErr,
		udpStatsAfter, udpStatsAfterAvailable, udpStatsAfterErr)
	r := Result{
		Name:     name,
		Duration: dur,
		Detail:   detail,
	}
	if writeFailure != "" {
		r.Failure = writeFailure
		return r
	}
	if receivedOutcome.err != nil {
		r.Failure = "receiver: " + receivedOutcome.err.Error()
		return r
	}
	r.InvalidReason, r.Failure = validateG3Measurements(opts, g3Measurements{
		sent:               sent,
		received:           received,
		sendElapsed:        sendElapsed,
		latencySamples:     len(gotLat),
		p95:                time.Duration(p95),
		migrationAttempts:  migrationAttempts,
		migrationErrors:    migrationErrors,
		migrationsObserved: migrations,
		malformedPackets:   receivedOutcome.malformedPackets,
		corruptPackets:     receivedOutcome.corruptPackets,
		duplicatePackets:   receivedOutcome.duplicatePackets,
		outOfRangePackets:  receivedOutcome.outOfRangePackets,
		pathWriters:        pathWriters,
		wireWrites:         wireWrites,
	})
	return r
}

// paceUntil smooths the sender cadence for sub-millisecond packet
// rates. A raw time.Sleep(10µs) loop tends to wake in scheduler-sized
// bursts, which injects artificial microbursts into G3 and causes a
// handful of real DATAGRAM drops that then stall the strict reorder
// window behind one missing SEQ. Sleep the coarse part, then yield/
// spin for the final slice to keep pacing closer to the target PPS.
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
