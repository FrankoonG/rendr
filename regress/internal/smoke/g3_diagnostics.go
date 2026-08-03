package smoke

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const g3MissingRangeSampleLimit = 32

type g3MissingSummary struct {
	Count                           int64
	RangeCount                      int
	RangeSample                     string
	SampleTruncated                 bool
	NearestMigrationDistancePackets int64
	NearMigrationPackets            int64
	NearMigrationWindowPackets      int64
}

func summarizeG3Missing(bitmap []uint8, sent int64, migrationSequences []int64, pps int) g3MissingSummary {
	summary := g3MissingSummary{NearestMigrationDistancePackets: -1}
	if sent <= 0 {
		return summary
	}
	window := int64(1)
	if pps > 100 {
		window = int64(pps / 100) // 10 ms at the configured packet rate.
	}
	summary.NearMigrationWindowPackets = window

	ranges := make([]string, 0, g3MissingRangeSampleLimit)
	for seq := int64(0); seq < sent; {
		if seq < int64(len(bitmap)) && bitmap[seq] != 0 {
			seq++
			continue
		}
		start := seq
		for seq < sent && (seq >= int64(len(bitmap)) || bitmap[seq] == 0) {
			summary.Count++
			if distance, ok := nearestG3MigrationDistance(seq, migrationSequences); ok {
				if summary.NearestMigrationDistancePackets < 0 || distance < summary.NearestMigrationDistancePackets {
					summary.NearestMigrationDistancePackets = distance
				}
				if distance <= window {
					summary.NearMigrationPackets++
				}
			}
			seq++
		}
		end := seq - 1
		summary.RangeCount++
		if len(ranges) < g3MissingRangeSampleLimit {
			if start == end {
				ranges = append(ranges, strconv.FormatInt(start, 10))
			} else {
				ranges = append(ranges, fmt.Sprintf("%d-%d", start, end))
			}
		} else {
			summary.SampleTruncated = true
		}
	}
	summary.RangeSample = strings.Join(ranges, ",")
	return summary
}

func nearestG3MigrationDistance(seq int64, migrations []int64) (int64, bool) {
	var nearest int64
	for i, migration := range migrations {
		distance := seq - migration
		if distance < 0 {
			distance = -distance
		}
		if i == 0 || distance < nearest {
			nearest = distance
		}
	}
	return nearest, len(migrations) > 0
}

func formatG3Sequences(sequences []int64) string {
	parts := make([]string, len(sequences))
	for i, seq := range sequences {
		parts[i] = strconv.FormatInt(seq, 10)
	}
	return strings.Join(parts, ",")
}

type g3HostUDPStats struct {
	InDatagrams  uint64
	NoPorts      uint64
	InErrors     uint64
	OutDatagrams uint64
	RcvbufErrors uint64
	SndbufErrors uint64
	InCsumErrors uint64
	IgnoredMulti uint64
	MemErrors    uint64
}

func parseG3HostUDPStats(r io.Reader) (g3HostUDPStats, error) {
	scanner := bufio.NewScanner(r)
	var header []string
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] != "Udp:" {
			continue
		}
		if header == nil {
			header = fields[1:]
			continue
		}
		values := fields[1:]
		if len(values) != len(header) {
			return g3HostUDPStats{}, fmt.Errorf("/proc/net/snmp UDP columns=%d values=%d", len(header), len(values))
		}
		parsed := make(map[string]uint64, len(header))
		for i, name := range header {
			value, err := strconv.ParseUint(values[i], 10, 64)
			if err != nil {
				return g3HostUDPStats{}, fmt.Errorf("/proc/net/snmp UDP %s=%q: %w", name, values[i], err)
			}
			parsed[name] = value
		}
		return g3HostUDPStats{
			InDatagrams:  parsed["InDatagrams"],
			NoPorts:      parsed["NoPorts"],
			InErrors:     parsed["InErrors"],
			OutDatagrams: parsed["OutDatagrams"],
			RcvbufErrors: parsed["RcvbufErrors"],
			SndbufErrors: parsed["SndbufErrors"],
			InCsumErrors: parsed["InCsumErrors"],
			IgnoredMulti: parsed["IgnoredMulti"],
			MemErrors:    parsed["MemErrors"],
		}, nil
	}
	if err := scanner.Err(); err != nil {
		return g3HostUDPStats{}, fmt.Errorf("read /proc/net/snmp: %w", err)
	}
	return g3HostUDPStats{}, fmt.Errorf("/proc/net/snmp has no UDP header/value pair")
}

func deltaG3HostUDPStats(before, after g3HostUDPStats) (g3HostUDPStats, error) {
	if after.InDatagrams < before.InDatagrams || after.NoPorts < before.NoPorts ||
		after.InErrors < before.InErrors || after.OutDatagrams < before.OutDatagrams ||
		after.RcvbufErrors < before.RcvbufErrors || after.SndbufErrors < before.SndbufErrors ||
		after.InCsumErrors < before.InCsumErrors || after.IgnoredMulti < before.IgnoredMulti ||
		after.MemErrors < before.MemErrors {
		return g3HostUDPStats{}, fmt.Errorf("host UDP counters decreased during case")
	}
	return g3HostUDPStats{
		InDatagrams:  after.InDatagrams - before.InDatagrams,
		NoPorts:      after.NoPorts - before.NoPorts,
		InErrors:     after.InErrors - before.InErrors,
		OutDatagrams: after.OutDatagrams - before.OutDatagrams,
		RcvbufErrors: after.RcvbufErrors - before.RcvbufErrors,
		SndbufErrors: after.SndbufErrors - before.SndbufErrors,
		InCsumErrors: after.InCsumErrors - before.InCsumErrors,
		IgnoredMulti: after.IgnoredMulti - before.IgnoredMulti,
		MemErrors:    after.MemErrors - before.MemErrors,
	}, nil
}

func addG3UDPStatsEvidence(detail map[string]any,
	before g3HostUDPStats, beforeAvailable bool, beforeErr error,
	after g3HostUDPStats, afterAvailable bool, afterErr error,
) {
	statsAvailable := beforeAvailable && afterAvailable && beforeErr == nil && afterErr == nil
	detail["host_udp_stats_available"] = statsAvailable
	detail["host_udp_stats_scope"] = "host_wide"
	if beforeErr != nil {
		detail["host_udp_stats_before_error"] = beforeErr.Error()
	}
	if afterErr != nil {
		detail["host_udp_stats_after_error"] = afterErr.Error()
	}
	if !statsAvailable {
		return
	}
	delta, err := deltaG3HostUDPStats(before, after)
	if err != nil {
		detail["host_udp_stats_delta_error"] = err.Error()
		return
	}
	detail["host_udp_in_datagrams_delta"] = delta.InDatagrams
	detail["host_udp_out_datagrams_delta"] = delta.OutDatagrams
	detail["host_udp_in_errors_delta"] = delta.InErrors
	detail["host_udp_rcvbuf_errors_delta"] = delta.RcvbufErrors
	detail["host_udp_sndbuf_errors_delta"] = delta.SndbufErrors
	detail["host_udp_no_ports_delta"] = delta.NoPorts
	detail["host_udp_checksum_errors_delta"] = delta.InCsumErrors
	detail["host_udp_memory_errors_delta"] = delta.MemErrors
}
