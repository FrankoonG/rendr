package smoke

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	g3MissingRangeEdgeLimit = 16
	g3MigrationWindowMillis = 200

	g3UDPStatsOK           = "ok"
	g3UDPStatsUnsupported  = "unsupported"
	g3UDPStatsReadError    = "read_error"
	g3UDPStatsParseError   = "parse_error"
	g3UDPStatsCounterReset = "counter_reset"
)

type g3MissingSummary struct {
	Count                           int64
	RangeCount                      int
	RangeSample                     string
	OmittedRanges                   int
	NearestMigrationDistancePackets int64
	NearestMigrationOffsetPackets   int64
	BeforeMigrationWindowPackets    int64
	AfterMigrationWindowPackets     int64
	MigrationNominalWindowPackets   int64
}

func summarizeG3Missing(bitmap []uint8, sent int64, migrationSequences []int64, pps int) g3MissingSummary {
	summary := g3MissingSummary{
		NearestMigrationDistancePackets: -1,
		NearestMigrationOffsetPackets:   -1,
	}
	if sent <= 0 {
		return summary
	}
	window := int64(1)
	if pps >= 5 {
		window = int64(pps) * g3MigrationWindowMillis / 1000
	}
	summary.MigrationNominalWindowPackets = window

	firstRanges := make([]string, 0, g3MissingRangeEdgeLimit)
	lastRanges := make([]string, 0, g3MissingRangeEdgeLimit)
	for seq := int64(0); seq < sent; {
		if seq < int64(len(bitmap)) && bitmap[seq] != 0 {
			seq++
			continue
		}
		start := seq
		for seq < sent && (seq >= int64(len(bitmap)) || bitmap[seq] == 0) {
			summary.Count++
			if offset, ok := nearestG3MigrationOffset(seq, migrationSequences); ok {
				distance := offset
				if distance < 0 {
					distance = -distance
				}
				if summary.NearestMigrationDistancePackets < 0 || distance < summary.NearestMigrationDistancePackets {
					summary.NearestMigrationDistancePackets = distance
					summary.NearestMigrationOffsetPackets = offset
				}
				if distance <= window {
					if offset < 0 {
						summary.BeforeMigrationWindowPackets++
					} else {
						summary.AfterMigrationWindowPackets++
					}
				}
			}
			seq++
		}
		end := seq - 1
		rangeText := formatG3SequenceRange(start, end)
		summary.RangeCount++
		if len(firstRanges) < g3MissingRangeEdgeLimit {
			firstRanges = append(firstRanges, rangeText)
		} else if len(lastRanges) < g3MissingRangeEdgeLimit {
			lastRanges = append(lastRanges, rangeText)
		} else {
			copy(lastRanges, lastRanges[1:])
			lastRanges[len(lastRanges)-1] = rangeText
		}
	}

	parts := append([]string(nil), firstRanges...)
	if summary.RangeCount > len(firstRanges)+len(lastRanges) {
		summary.OmittedRanges = summary.RangeCount - len(firstRanges) - len(lastRanges)
		parts = append(parts, fmt.Sprintf("...(%d omitted)...", summary.OmittedRanges))
	}
	parts = append(parts, lastRanges...)
	summary.RangeSample = strings.Join(parts, ",")
	return summary
}

func formatG3SequenceRange(start, end int64) string {
	if start == end {
		return strconv.FormatInt(start, 10)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func nearestG3MigrationOffset(seq int64, migrations []int64) (int64, bool) {
	var nearestOffset int64
	var nearestDistance int64
	for i, migration := range migrations {
		offset := seq - migration
		distance := offset
		if distance < 0 {
			distance = -distance
		}
		if i == 0 || distance < nearestDistance {
			nearestOffset = offset
			nearestDistance = distance
		}
	}
	return nearestOffset, len(migrations) > 0
}

func formatG3Sequences(sequences []int64) string {
	parts := make([]string, len(sequences))
	for i, seq := range sequences {
		parts[i] = strconv.FormatInt(seq, 10)
	}
	return strings.Join(parts, ",")
}

type g3HostUDPStats struct {
	InDatagrams      uint64
	NoPorts          uint64
	InErrors         uint64
	OutDatagrams     uint64
	RcvbufErrors     uint64
	SndbufErrors     uint64
	InCsumErrors     uint64
	IgnoredMulti     uint64
	MemErrors        uint64
	MemErrorsPresent bool
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
		required := []string{
			"InDatagrams", "NoPorts", "InErrors", "OutDatagrams",
			"RcvbufErrors", "SndbufErrors", "InCsumErrors", "IgnoredMulti",
		}
		for _, name := range required {
			if _, ok := parsed[name]; !ok {
				return g3HostUDPStats{}, fmt.Errorf("/proc/net/snmp UDP missing required column %s", name)
			}
		}
		memErrors, memErrorsPresent := parsed["MemErrors"]
		return g3HostUDPStats{
			InDatagrams:      parsed["InDatagrams"],
			NoPorts:          parsed["NoPorts"],
			InErrors:         parsed["InErrors"],
			OutDatagrams:     parsed["OutDatagrams"],
			RcvbufErrors:     parsed["RcvbufErrors"],
			SndbufErrors:     parsed["SndbufErrors"],
			InCsumErrors:     parsed["InCsumErrors"],
			IgnoredMulti:     parsed["IgnoredMulti"],
			MemErrors:        memErrors,
			MemErrorsPresent: memErrorsPresent,
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
		(before.MemErrorsPresent && after.MemErrorsPresent && after.MemErrors < before.MemErrors) {
		return g3HostUDPStats{}, fmt.Errorf("network namespace UDP counters decreased during case")
	}
	delta := g3HostUDPStats{
		InDatagrams:  after.InDatagrams - before.InDatagrams,
		NoPorts:      after.NoPorts - before.NoPorts,
		InErrors:     after.InErrors - before.InErrors,
		OutDatagrams: after.OutDatagrams - before.OutDatagrams,
		RcvbufErrors: after.RcvbufErrors - before.RcvbufErrors,
		SndbufErrors: after.SndbufErrors - before.SndbufErrors,
		InCsumErrors: after.InCsumErrors - before.InCsumErrors,
		IgnoredMulti: after.IgnoredMulti - before.IgnoredMulti,
	}
	if before.MemErrorsPresent && after.MemErrorsPresent {
		delta.MemErrors = after.MemErrors - before.MemErrors
		delta.MemErrorsPresent = true
	}
	return delta, nil
}

func addG3UDPStatsEvidence(detail map[string]any,
	before g3HostUDPStats, beforeStatus string, beforeErr error,
	after g3HostUDPStats, afterStatus string, afterErr error,
) {
	detail["udp_snmp_scope"] = "network_namespace"
	status := beforeStatus
	if status == g3UDPStatsOK {
		status = afterStatus
	}
	if beforeErr != nil {
		detail["udp_snmp_before_error"] = beforeErr.Error()
	}
	if afterErr != nil {
		detail["udp_snmp_after_error"] = afterErr.Error()
	}
	if status != g3UDPStatsOK {
		detail["udp_snmp_status"] = status
		return
	}
	delta, err := deltaG3HostUDPStats(before, after)
	if err != nil {
		detail["udp_snmp_status"] = g3UDPStatsCounterReset
		detail["udp_snmp_delta_error"] = err.Error()
		return
	}
	detail["udp_snmp_status"] = g3UDPStatsOK
	detail["udp_in_datagrams_delta"] = delta.InDatagrams
	detail["udp_out_datagrams_delta"] = delta.OutDatagrams
	detail["udp_in_errors_delta"] = delta.InErrors
	detail["udp_rcvbuf_errors_delta"] = delta.RcvbufErrors
	detail["udp_sndbuf_errors_delta"] = delta.SndbufErrors
	detail["udp_no_ports_delta"] = delta.NoPorts
	detail["udp_checksum_errors_delta"] = delta.InCsumErrors
	if delta.MemErrorsPresent {
		detail["udp_memory_errors_delta"] = delta.MemErrors
	}
}
