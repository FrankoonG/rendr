package tunfull

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	tunG3LatencySampleEvery  = 100
	tunG3MinimumSamples      = 20
	tunG3MinimumOfferedRatio = 0.95
	tunG3PacketIntegrityMask = uint64(0xd6e8feb86659fd93)
	tunG3MaximumPackets      = 100_000_000
)

type tunG3Measurements struct {
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
	perPathWrites      map[uint32]uint64
	wireWrites         uint64
}

type tunG3ReceiveOutcome struct {
	latencies         []time.Duration
	uniquePackets     int64
	malformedPackets  int64
	corruptPackets    int64
	duplicatePackets  int64
	outOfRangePackets int64
	err               error
}

// validateTUNG3Measurements distinguishes an invalid test stimulus from an
// observed product failure. Both fail a mandatory row, but INVALID prevents a
// weak sender or missing path activity from being reported as transport proof.
func validateTUNG3Measurements(opts g3Options, m tunG3Measurements) (invalidReason, failure string) {
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
	if ratio := offered / float64(opts.pps); ratio < tunG3MinimumOfferedRatio {
		return fmt.Sprintf("offered load %.0fpps is %.1f%% of %dpps target; want >=%.0f%%",
			offered, ratio*100, opts.pps, tunG3MinimumOfferedRatio*100), ""
	}
	if m.received < 0 || m.received > m.sent {
		return fmt.Sprintf("invalid delivery counters: sent=%d received=%d", m.sent, m.received), ""
	}
	minimumSamples := tunG3MinimumSamples
	if expected := int(m.sent / tunG3LatencySampleEvery); expected > minimumSamples {
		minimumSamples = expected * 9 / 10
	}
	if m.latencySamples < minimumSamples {
		return fmt.Sprintf("latency samples=%d, want >=%d", m.latencySamples, minimumSamples), ""
	}
	if m.migrationAttempts != opts.migrations {
		return fmt.Sprintf("migration stimulus attempts=%d, want exactly %d", m.migrationAttempts, opts.migrations), ""
	}
	if len(m.perPathWrites) != opts.paths {
		return fmt.Sprintf("per-path wire evidence covers %d paths, want exactly %d", len(m.perPathWrites), opts.paths), ""
	}
	minimumPathWrites := uint64(m.sent) / uint64(opts.paths*4)
	if minimumPathWrites == 0 {
		minimumPathWrites = 1
	}
	missing := make([]uint32, 0)
	for id, writes := range m.perPathWrites {
		if writes < minimumPathWrites {
			missing = append(missing, id)
		}
	}
	if len(missing) != 0 {
		sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })
		return fmt.Sprintf("paths below minimum measured wire writes=%d: %v", minimumPathWrites, missing), ""
	}
	if m.wireWrites < uint64(m.sent) {
		return fmt.Sprintf("wire write delta=%d is below application packets=%d", m.wireWrites, m.sent), ""
	}
	if m.migrationErrors != 0 {
		return "", fmt.Sprintf("migration requests rejected=%d", m.migrationErrors)
	}
	if m.migrationsObserved != uint64(opts.migrations) {
		return "", fmt.Sprintf("MigrationCount=%d, want exactly %d", m.migrationsObserved, opts.migrations)
	}
	if m.malformedPackets != 0 || m.corruptPackets != 0 || m.outOfRangePackets != 0 {
		return "", fmt.Sprintf("packet integrity failures: malformed=%d corrupt=%d out_of_range=%d",
			m.malformedPackets, m.corruptPackets, m.outOfRangePackets)
	}
	if m.duplicatePackets != 0 {
		return "", fmt.Sprintf("duplicate application packets=%d", m.duplicatePackets)
	}
	lost := m.sent - m.received
	lossPct := float64(lost) / float64(m.sent) * 100
	if math.IsNaN(lossPct) || math.IsInf(lossPct, 0) {
		return fmt.Sprintf("loss percentage is not finite: %v", lossPct), ""
	}
	if lossPct > opts.lossPct {
		return "", fmt.Sprintf("loss %.3f%% exceeds budget %.3f%%", lossPct, opts.lossPct)
	}
	if m.p95 < 0 {
		return fmt.Sprintf("P95 latency=%s, want >=0", m.p95), ""
	}
	if m.p95 > opts.p95Ceiling {
		return "", fmt.Sprintf("P95 %s exceeds ceiling %s", m.p95, opts.p95Ceiling)
	}
	return "", ""
}

func formatTUNG3PathWrites(writes map[uint32]uint64) string {
	ids := make([]uint32, 0, len(writes))
	for id := range writes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("%d:%d", id, writes[id]))
	}
	return strings.Join(parts, ",")
}
