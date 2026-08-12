package tcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

const (
	kernel5TCPEstablishedState      uint8  = 1
	kernel5TCPTimestampOptionMask   uint8  = 1 << 0
	kernel5TCPSACKOptionMask        uint8  = 1 << 1
	kernel5TCPWindowScaleOptionMask uint8  = 1 << 2
	kernel5TCPSupportedOptionsMask         = kernel5TCPTimestampOptionMask | kernel5TCPSACKOptionMask | kernel5TCPWindowScaleOptionMask
	kernel5TCPMaximumQueueBytes     uint32 = 64 << 20

	kernel5TCPSourceSocketPhase      = "tcp_repair_capture"
	kernel5TCPReplacementSocketPhase = "leaf_mobility_committed"
)

var kernel5TCPInspectionComponentNames = [...]string{
	"tuple",
	"established_state",
	"receive_queue_bytes",
	"send_queue_bytes",
	"unsent_bytes",
	"options_mask",
	"mss_clamp",
	"send_buffer_bytes",
	"receive_buffer_bytes",
	"send_scale",
	"receive_scale",
	"receive_sequence",
	"send_sequence",
	"send_window_last_sequence",
	"send_window",
	"max_window",
	"receive_window",
	"receive_window_update",
	"timestamp",
}

type kernel5TCPMeasuredUint8Evidence struct {
	Observed bool  `json:"observed"`
	Value    uint8 `json:"value"`
}

type kernel5TCPMeasuredUint32Evidence struct {
	Observed bool   `json:"observed"`
	Value    uint32 `json:"value"`
}

type kernel5TCPMeasuredUint64Evidence struct {
	Observed bool   `json:"observed"`
	Value    uint64 `json:"value"`
}

type kernel5TCPMeasuredTimestampEvidence struct {
	Observed  bool   `json:"observed"`
	Available bool   `json:"available"`
	Value     uint32 `json:"value"`
}

type kernel5TCPInspectionTupleEvidence struct {
	Local  string `json:"local"`
	Remote string `json:"remote"`
}

type kernel5TCPInspectionEvidence struct {
	Tuple                  kernel5TCPInspectionTupleEvidence   `json:"tuple"`
	EstablishedState       kernel5TCPMeasuredUint8Evidence     `json:"established_state"`
	ReceiveQueueBytes      kernel5TCPMeasuredUint32Evidence    `json:"receive_queue_bytes"`
	SendQueueBytes         kernel5TCPMeasuredUint32Evidence    `json:"send_queue_bytes"`
	UnsentBytes            kernel5TCPMeasuredUint32Evidence    `json:"unsent_bytes"`
	OptionsMask            kernel5TCPMeasuredUint8Evidence     `json:"options_mask"`
	MSSClamp               kernel5TCPMeasuredUint32Evidence    `json:"mss_clamp"`
	SendBufferBytes        kernel5TCPMeasuredUint32Evidence    `json:"send_buffer_bytes"`
	ReceiveBufferBytes     kernel5TCPMeasuredUint32Evidence    `json:"receive_buffer_bytes"`
	SendScale              kernel5TCPMeasuredUint8Evidence     `json:"send_scale"`
	ReceiveScale           kernel5TCPMeasuredUint8Evidence     `json:"receive_scale"`
	ReceiveSequence        kernel5TCPMeasuredUint32Evidence    `json:"receive_sequence"`
	SendSequence           kernel5TCPMeasuredUint32Evidence    `json:"send_sequence"`
	SendWindowLastSequence kernel5TCPMeasuredUint32Evidence    `json:"send_window_last_sequence"`
	SendWindow             kernel5TCPMeasuredUint32Evidence    `json:"send_window"`
	MaxWindow              kernel5TCPMeasuredUint32Evidence    `json:"max_window"`
	ReceiveWindow          kernel5TCPMeasuredUint32Evidence    `json:"receive_window"`
	ReceiveWindowUpdate    kernel5TCPMeasuredUint32Evidence    `json:"receive_window_update"`
	Timestamp              kernel5TCPMeasuredTimestampEvidence `json:"timestamp"`
}

type kernel5TCPStateComponentsEvidence struct {
	Inventory    []string `json:"inventory"`
	DigestSHA256 string   `json:"digest_sha256"`
}

type kernel5TCPSocketIncarnationEvidence struct {
	SourceCookie                  uint64 `json:"source_cookie"`
	ReplacementCookie             uint64 `json:"replacement_cookie"`
	SourcePhase                   string `json:"source_phase"`
	ReplacementPhase              string `json:"replacement_phase"`
	TransactionID                 string `json:"transaction_id"`
	SourceEndpointGeneration      uint64 `json:"source_endpoint_generation"`
	ReplacementEndpointGeneration uint64 `json:"replacement_endpoint_generation"`
	CanonicalTuple                string `json:"canonical_tuple"`
}

type kernel5TCPCaptureStatisticsEvidence struct {
	Captured         kernel5TCPMeasuredUint64Evidence `json:"captured"`
	ReceivedByFilter kernel5TCPMeasuredUint64Evidence `json:"received_by_filter"`
	DroppedByKernel  kernel5TCPMeasuredUint64Evidence `json:"dropped_by_kernel"`
}

type kernel5TCPCaptureEvidence struct {
	Packets          int                                 `json:"packets"`
	RSTPackets       int                                 `json:"rst_packets"`
	KernelStatistics kernel5TCPCaptureStatisticsEvidence `json:"kernel_statistics"`
}

func kernel5TCPObservedUint8(value uint8) kernel5TCPMeasuredUint8Evidence {
	return kernel5TCPMeasuredUint8Evidence{Observed: true, Value: value}
}

func kernel5TCPObservedUint32(value uint32) kernel5TCPMeasuredUint32Evidence {
	return kernel5TCPMeasuredUint32Evidence{Observed: true, Value: value}
}

func kernel5TCPObservedUint64(value uint64) kernel5TCPMeasuredUint64Evidence {
	return kernel5TCPMeasuredUint64Evidence{Observed: true, Value: value}
}

func validateKernel5TCPSocketIncarnation(
	incarnation kernel5TCPSocketIncarnationEvidence,
	transactionID, canonicalTuple string,
	sourceGeneration, replacementGeneration uint64,
) error {
	if incarnation.SourceCookie == 0 || incarnation.ReplacementCookie == 0 ||
		incarnation.SourceCookie == incarnation.ReplacementCookie {
		return fmt.Errorf("source/replacement socket cookies do not prove a new kernel incarnation: %+v", incarnation)
	}
	if incarnation.SourcePhase != kernel5TCPSourceSocketPhase ||
		incarnation.ReplacementPhase != kernel5TCPReplacementSocketPhase {
		return fmt.Errorf("socket incarnation phases are invalid: %+v", incarnation)
	}
	if err := validateKernel5TCPTransactionID(incarnation.TransactionID); err != nil {
		return fmt.Errorf("socket incarnation transaction: %w", err)
	}
	if incarnation.TransactionID != transactionID {
		return fmt.Errorf("socket incarnation transaction does not match commit")
	}
	if sourceGeneration == 0 || replacementGeneration == 0 || sourceGeneration == replacementGeneration ||
		incarnation.SourceEndpointGeneration != sourceGeneration ||
		incarnation.ReplacementEndpointGeneration != replacementGeneration {
		return fmt.Errorf("socket incarnation generations do not match capture/commit: %+v", incarnation)
	}
	if canonicalTuple == "" || incarnation.CanonicalTuple != canonicalTuple {
		return fmt.Errorf("socket incarnation tuple does not match preserved tuple")
	}
	return nil
}

func parseKernel5TCPCaptureStatistics(stderr string) (kernel5TCPCaptureStatisticsEvidence, error) {
	var statistics kernel5TCPCaptureStatisticsEvidence
	for _, line := range strings.Split(stderr, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		var destination *kernel5TCPMeasuredUint64Evidence
		switch strings.Join(fields[1:], " ") {
		case "packet captured", "packets captured":
			destination = &statistics.Captured
		case "packet received by filter", "packets received by filter":
			destination = &statistics.ReceivedByFilter
		case "packet dropped by kernel", "packets dropped by kernel":
			destination = &statistics.DroppedByKernel
		default:
			continue
		}
		if destination.Observed {
			return kernel5TCPCaptureStatisticsEvidence{}, fmt.Errorf("tcpdump reported duplicate counter %q", strings.Join(fields[1:], " "))
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != fields[0] {
			return kernel5TCPCaptureStatisticsEvidence{}, fmt.Errorf("tcpdump counter %q is not a canonical uint64", fields[0])
		}
		*destination = kernel5TCPObservedUint64(value)
	}
	for name, measurement := range map[string]kernel5TCPMeasuredUint64Evidence{
		"captured":           statistics.Captured,
		"received_by_filter": statistics.ReceivedByFilter,
		"dropped_by_kernel":  statistics.DroppedByKernel,
	} {
		if !measurement.Observed {
			return kernel5TCPCaptureStatisticsEvidence{}, fmt.Errorf("tcpdump did not report %s", name)
		}
	}
	return statistics, nil
}

func validateKernel5TCPCaptureEvidence(capture kernel5TCPCaptureEvidence) error {
	if capture.Packets < 20 || capture.RSTPackets != 0 {
		return fmt.Errorf("decoded capture packets are invalid: %+v", capture)
	}
	statistics := capture.KernelStatistics
	for name, measurement := range map[string]kernel5TCPMeasuredUint64Evidence{
		"captured":           statistics.Captured,
		"received_by_filter": statistics.ReceivedByFilter,
		"dropped_by_kernel":  statistics.DroppedByKernel,
	} {
		if !measurement.Observed {
			return fmt.Errorf("tcpdump %s counter was not observed", name)
		}
	}
	if statistics.Captured.Value != uint64(capture.Packets) {
		return fmt.Errorf("tcpdump captured=%d decoded=%d", statistics.Captured.Value, capture.Packets)
	}
	if statistics.ReceivedByFilter.Value < statistics.Captured.Value {
		return fmt.Errorf("tcpdump received-by-filter=%d captured=%d", statistics.ReceivedByFilter.Value, statistics.Captured.Value)
	}
	if statistics.DroppedByKernel.Value != 0 {
		return fmt.Errorf("tcpdump reported %d packets dropped by kernel", statistics.DroppedByKernel.Value)
	}
	return nil
}

func kernel5TCPRequiredStateComponentInventory() []string {
	inventory := make([]string, 0, len(kernel5TCPInspectionComponentNames)*2)
	for _, phase := range []string{"pre", "post"} {
		for _, component := range kernel5TCPInspectionComponentNames {
			inventory = append(inventory, phase+"."+component)
		}
	}
	return inventory
}

func newKernel5TCPStateComponentsEvidence(
	pre, post kernel5TCPInspectionEvidence,
) kernel5TCPStateComponentsEvidence {
	inventory := kernel5TCPRequiredStateComponentInventory()
	return kernel5TCPStateComponentsEvidence{
		Inventory:    inventory,
		DigestSHA256: kernel5TCPStateComponentDigest(inventory, pre, post),
	}
}

func kernel5TCPStateComponentDigest(
	inventory []string,
	pre, post kernel5TCPInspectionEvidence,
) string {
	encoded, err := json.Marshal(struct {
		Inventory []string                     `json:"inventory"`
		Pre       kernel5TCPInspectionEvidence `json:"pre"`
		Post      kernel5TCPInspectionEvidence `json:"post"`
	}{Inventory: inventory, Pre: pre, Post: post})
	if err != nil {
		panic(fmt.Sprintf("encode fixed TCP state components: %v", err))
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("kernel5-tcprepair-state-components-v2\x00"))
	_, _ = hash.Write(encoded)
	return hex.EncodeToString(hash.Sum(nil))
}

func validateKernel5TCPStateComponents(
	components kernel5TCPStateComponentsEvidence,
	pre, post kernel5TCPInspectionEvidence,
) error {
	required := kernel5TCPRequiredStateComponentInventory()
	if len(components.Inventory) != len(required) {
		return fmt.Errorf("state component inventory length=%d want=%d", len(components.Inventory), len(required))
	}
	for index := range required {
		if components.Inventory[index] != required[index] {
			return fmt.Errorf("state component inventory[%d]=%q want=%q", index, components.Inventory[index], required[index])
		}
	}
	if err := validateKernel5TCPInspectionEvidence("pre", pre); err != nil {
		return err
	}
	if err := validateKernel5TCPInspectionEvidence("post", post); err != nil {
		return err
	}
	if pre.Tuple != post.Tuple {
		return fmt.Errorf("pre/post inspection tuple changed: pre=%+v post=%+v", pre.Tuple, post.Tuple)
	}
	if pre.OptionsMask.Value != post.OptionsMask.Value || pre.MSSClamp.Value != post.MSSClamp.Value ||
		pre.SendBufferBytes.Value != post.SendBufferBytes.Value || pre.ReceiveBufferBytes.Value != post.ReceiveBufferBytes.Value ||
		pre.SendScale.Value != post.SendScale.Value || pre.ReceiveScale.Value != post.ReceiveScale.Value {
		return fmt.Errorf("pre/post TCP options changed")
	}
	if pre.SendSequence.Value == post.SendSequence.Value || pre.ReceiveSequence.Value == post.ReceiveSequence.Value {
		return fmt.Errorf(
			"pre/post TCP sequences did not advance: send=%d/%d receive=%d/%d",
			pre.SendSequence.Value, post.SendSequence.Value,
			pre.ReceiveSequence.Value, post.ReceiveSequence.Value,
		)
	}
	if err := validateKernel5TCPFixedLowerHex("state_components.digest_sha256", components.DigestSHA256, sha256.Size); err != nil {
		return err
	}
	wantDigest := kernel5TCPStateComponentDigest(components.Inventory, pre, post)
	if components.DigestSHA256 != wantDigest {
		return fmt.Errorf("state component digest mismatch")
	}
	return nil
}

func validateKernel5TCPInspectionEvidence(phase string, inspection kernel5TCPInspectionEvidence) error {
	local, localErr := netip.ParseAddrPort(inspection.Tuple.Local)
	remote, remoteErr := netip.ParseAddrPort(inspection.Tuple.Remote)
	if localErr != nil || remoteErr != nil || !local.Addr().Is4() || !remote.Addr().Is4() ||
		local.Port() == 0 || remote.Port() == 0 {
		return fmt.Errorf("%s.tuple is not an established IPv4 tuple: %+v", phase, inspection.Tuple)
	}
	if !inspection.EstablishedState.Observed || inspection.EstablishedState.Value != kernel5TCPEstablishedState {
		return fmt.Errorf("%s.established_state is not measured established state: %+v", phase, inspection.EstablishedState)
	}
	for name, measurement := range map[string]kernel5TCPMeasuredUint32Evidence{
		"receive_queue_bytes":       inspection.ReceiveQueueBytes,
		"send_queue_bytes":          inspection.SendQueueBytes,
		"unsent_bytes":              inspection.UnsentBytes,
		"receive_sequence":          inspection.ReceiveSequence,
		"send_sequence":             inspection.SendSequence,
		"send_window_last_sequence": inspection.SendWindowLastSequence,
		"send_window":               inspection.SendWindow,
		"max_window":                inspection.MaxWindow,
		"receive_window":            inspection.ReceiveWindow,
		"receive_window_update":     inspection.ReceiveWindowUpdate,
	} {
		if !measurement.Observed {
			return fmt.Errorf("%s.%s was not observed", phase, name)
		}
	}
	if inspection.ReceiveQueueBytes.Value > kernel5TCPMaximumQueueBytes ||
		inspection.SendQueueBytes.Value > kernel5TCPMaximumQueueBytes ||
		inspection.UnsentBytes.Value > inspection.SendQueueBytes.Value {
		return fmt.Errorf("%s queue measurements are invalid", phase)
	}
	if !inspection.OptionsMask.Observed || inspection.OptionsMask.Value&^kernel5TCPSupportedOptionsMask != 0 {
		return fmt.Errorf("%s.options_mask is invalid: %+v", phase, inspection.OptionsMask)
	}
	for name, measurement := range map[string]kernel5TCPMeasuredUint32Evidence{
		"mss_clamp":            inspection.MSSClamp,
		"send_buffer_bytes":    inspection.SendBufferBytes,
		"receive_buffer_bytes": inspection.ReceiveBufferBytes,
	} {
		if !measurement.Observed || measurement.Value == 0 {
			return fmt.Errorf("%s.%s is not a positive measurement: %+v", phase, name, measurement)
		}
	}
	if !inspection.SendScale.Observed || !inspection.ReceiveScale.Observed ||
		inspection.SendScale.Value > 14 || inspection.ReceiveScale.Value > 14 {
		return fmt.Errorf("%s window scales are invalid", phase)
	}
	if inspection.OptionsMask.Value&kernel5TCPWindowScaleOptionMask == 0 &&
		(inspection.SendScale.Value != 0 || inspection.ReceiveScale.Value != 0) {
		return fmt.Errorf("%s window scales exist without the option mask", phase)
	}
	if !inspection.Timestamp.Observed {
		return fmt.Errorf("%s.timestamp availability was not observed", phase)
	}
	wantTimestamp := inspection.OptionsMask.Value&kernel5TCPTimestampOptionMask != 0
	if inspection.Timestamp.Available != wantTimestamp || !inspection.Timestamp.Available && inspection.Timestamp.Value != 0 {
		return fmt.Errorf("%s timestamp measurement disagrees with options mask", phase)
	}
	return nil
}

func validateKernel5TCPFixedLowerHex(field, value string, encodedBytes int) error {
	if encodedBytes <= 0 || len(value) != encodedBytes*2 {
		return fmt.Errorf("%s must contain exactly %d lowercase hexadecimal characters", field, encodedBytes*2)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != encodedBytes || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("%s must be canonical lowercase hexadecimal", field)
	}
	return nil
}

func validateKernel5TCPTransactionID(value string) error {
	if err := validateKernel5TCPFixedLowerHex("commit.transaction_id", value, 16); err != nil {
		return err
	}
	if strings.Trim(value, "0") == "" {
		return fmt.Errorf("commit.transaction_id must be nonzero")
	}
	return nil
}

func validateKernel5TCPSourceAddress(value, actorLocal string) error {
	source, err := netip.ParseAddr(value)
	if err != nil || !source.Is4() {
		return fmt.Errorf("source_loss.source_address %q must be canonical IPv4", value)
	}
	endpoint, err := netip.ParseAddrPort(actorLocal)
	if err != nil || endpoint.Addr() != source {
		return fmt.Errorf("source_loss.source_address %q does not match actor-local endpoint %q", value, actorLocal)
	}
	return nil
}

func validateKernel5TCPNetworkNamespaceFormat(value string) error {
	device, inode, found := strings.Cut(value, ":")
	if !found || device == "" || inode == "" || strings.Contains(inode, ":") {
		return fmt.Errorf("network_namespace %q must contain exactly two decimal components", value)
	}
	for name, component := range map[string]string{"device": device, "inode": inode} {
		parsed, err := strconv.ParseUint(component, 10, 64)
		if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != component {
			return fmt.Errorf("network_namespace %s component %q must be a nonzero canonical decimal uint64", name, component)
		}
	}
	return nil
}

func TestKernel5TCPFixedLowerHexValidation(t *testing.T) {
	tests := []struct {
		name         string
		field        string
		value        string
		encodedBytes int
		wantError    bool
	}{
		{name: "payload hash", field: "payload_sha256", value: strings.Repeat("a", 64), encodedBytes: 32},
		{name: "transaction ID", field: "transaction_id", value: strings.Repeat("b", 32), encodedBytes: 16},
		{name: "short hash", field: "payload_sha256", value: strings.Repeat("a", 63), encodedBytes: 32, wantError: true},
		{name: "long hash", field: "payload_sha256", value: strings.Repeat("a", 65), encodedBytes: 32, wantError: true},
		{name: "uppercase hash", field: "payload_sha256", value: strings.Repeat("A", 64), encodedBytes: 32, wantError: true},
		{name: "non-hex hash", field: "payload_sha256", value: strings.Repeat("g", 64), encodedBytes: 32, wantError: true},
		{name: "short transaction ID", field: "transaction_id", value: strings.Repeat("b", 31), encodedBytes: 16, wantError: true},
		{name: "uppercase transaction ID", field: "transaction_id", value: strings.Repeat("B", 32), encodedBytes: 16, wantError: true},
		{name: "non-hex transaction ID", field: "transaction_id", value: strings.Repeat("z", 32), encodedBytes: 16, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateKernel5TCPFixedLowerHex(test.field, test.value, test.encodedBytes)
			if (err != nil) != test.wantError {
				t.Fatalf("validation error=%v wantError=%t", err, test.wantError)
			}
		})
	}
}

func TestKernel5TCPNetworkNamespaceFormatValidation(t *testing.T) {
	tests := []struct {
		value     string
		wantError bool
	}{
		{value: "4:5"},
		{value: "18446744073709551615:18446744073709551615"},
		{value: "", wantError: true},
		{value: "4", wantError: true},
		{value: "4:5:6", wantError: true},
		{value: "0:5", wantError: true},
		{value: "4:0", wantError: true},
		{value: "-4:5", wantError: true},
		{value: "+4:5", wantError: true},
		{value: "04:5", wantError: true},
		{value: "4:05", wantError: true},
		{value: "4:not-decimal", wantError: true},
		{value: "18446744073709551616:5", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			err := validateKernel5TCPNetworkNamespaceFormat(test.value)
			if (err != nil) != test.wantError {
				t.Fatalf("validation error=%v wantError=%t", err, test.wantError)
			}
		})
	}
}

func TestKernel5TCPTransactionIDValidation(t *testing.T) {
	for _, test := range []struct {
		name      string
		value     string
		wantError bool
	}{
		{name: "valid", value: strings.Repeat("a", 32)},
		{name: "zero", value: strings.Repeat("0", 32), wantError: true},
		{name: "short", value: strings.Repeat("a", 31), wantError: true},
		{name: "uppercase", value: strings.Repeat("A", 32), wantError: true},
		{name: "non-hex", value: strings.Repeat("z", 32), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateKernel5TCPTransactionID(test.value)
			if (err != nil) != test.wantError {
				t.Fatalf("validation error=%v wantError=%t", err, test.wantError)
			}
		})
	}
}

func TestKernel5TCPSourceAddressValidation(t *testing.T) {
	for _, test := range []struct {
		name       string
		value      string
		actorLocal string
		wantError  bool
	}{
		{name: "valid", value: "192.0.2.1", actorLocal: "192.0.2.1:1000"},
		{name: "malformed", value: "not-an-address", actorLocal: "192.0.2.1:1000", wantError: true},
		{name: "IPv6", value: "2001:db8::1", actorLocal: "[2001:db8::1]:1000", wantError: true},
		{name: "tuple mismatch", value: "192.0.2.2", actorLocal: "192.0.2.1:1000", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateKernel5TCPSourceAddress(test.value, test.actorLocal)
			if (err != nil) != test.wantError {
				t.Fatalf("validation error=%v wantError=%t", err, test.wantError)
			}
		})
	}
}

func TestKernel5TCPSocketIncarnationRejectsEveryBindingMutation(t *testing.T) {
	transactionID := strings.Repeat("d", 32)
	canonicalTuple := "192.0.2.1:1000<->192.0.2.2:2000"
	valid := kernel5TCPSocketIncarnationEvidence{
		SourceCookie: 11, ReplacementCookie: 12,
		SourcePhase: kernel5TCPSourceSocketPhase, ReplacementPhase: kernel5TCPReplacementSocketPhase,
		TransactionID: transactionID, SourceEndpointGeneration: 1, ReplacementEndpointGeneration: 2,
		CanonicalTuple: canonicalTuple,
	}
	if err := validateKernel5TCPSocketIncarnation(valid, transactionID, canonicalTuple, 1, 2); err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*kernel5TCPSocketIncarnationEvidence)
	}{
		{name: "source_cookie", mutate: func(value *kernel5TCPSocketIncarnationEvidence) { value.SourceCookie = 0 }},
		{name: "replacement_cookie", mutate: func(value *kernel5TCPSocketIncarnationEvidence) { value.ReplacementCookie = 0 }},
		{name: "distinct_cookie", mutate: func(value *kernel5TCPSocketIncarnationEvidence) { value.ReplacementCookie = value.SourceCookie }},
		{name: "source_phase", mutate: func(value *kernel5TCPSocketIncarnationEvidence) { value.SourcePhase = "" }},
		{name: "replacement_phase", mutate: func(value *kernel5TCPSocketIncarnationEvidence) { value.ReplacementPhase = "" }},
		{name: "transaction_id", mutate: func(value *kernel5TCPSocketIncarnationEvidence) { value.TransactionID = strings.Repeat("e", 32) }},
		{name: "source_endpoint_generation", mutate: func(value *kernel5TCPSocketIncarnationEvidence) { value.SourceEndpointGeneration = 0 }},
		{name: "replacement_endpoint_generation", mutate: func(value *kernel5TCPSocketIncarnationEvidence) { value.ReplacementEndpointGeneration = 0 }},
		{name: "canonical_tuple", mutate: func(value *kernel5TCPSocketIncarnationEvidence) { value.CanonicalTuple = "" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := valid
			mutation.mutate(&mutated)
			if err := validateKernel5TCPSocketIncarnation(mutated, transactionID, canonicalTuple, 1, 2); err == nil {
				t.Fatalf("socket incarnation validator accepted mutated %s", mutation.name)
			}
		})
	}
}

func TestKernel5TCPCaptureStatisticsParserRequiresEveryCounter(t *testing.T) {
	valid := "tcpdump: listening on lo\n20 packets captured\n40 packets received by filter\n0 packets dropped by kernel\n"
	statistics, err := parseKernel5TCPCaptureStatistics(valid)
	if err != nil {
		t.Fatal(err)
	}
	if statistics.Captured != kernel5TCPObservedUint64(20) ||
		statistics.ReceivedByFilter != kernel5TCPObservedUint64(40) ||
		statistics.DroppedByKernel != kernel5TCPObservedUint64(0) {
		t.Fatalf("parsed tcpdump statistics=%+v", statistics)
	}
	if singular, err := parseKernel5TCPCaptureStatistics(
		"1 packet captured\n1 packet received by filter\n0 packets dropped by kernel\n",
	); err != nil || singular.Captured.Value != 1 || singular.ReceivedByFilter.Value != 1 {
		t.Fatalf("parse singular tcpdump statistics=%+v err=%v", singular, err)
	}
	invalid := []struct {
		name   string
		stderr string
	}{
		{name: "missing_captured", stderr: "40 packets received by filter\n0 packets dropped by kernel\n"},
		{name: "missing_received", stderr: "20 packets captured\n0 packets dropped by kernel\n"},
		{name: "missing_dropped", stderr: "20 packets captured\n40 packets received by filter\n"},
		{name: "duplicate_captured", stderr: valid + "20 packets captured\n"},
		{name: "duplicate_received", stderr: valid + "40 packets received by filter\n"},
		{name: "duplicate_dropped", stderr: valid + "0 packets dropped by kernel\n"},
		{name: "negative", stderr: "-1 packets captured\n40 packets received by filter\n0 packets dropped by kernel\n"},
		{name: "non_decimal", stderr: "many packets captured\n40 packets received by filter\n0 packets dropped by kernel\n"},
		{name: "leading_zero", stderr: "020 packets captured\n40 packets received by filter\n0 packets dropped by kernel\n"},
		{name: "overflow", stderr: "18446744073709551616 packets captured\n40 packets received by filter\n0 packets dropped by kernel\n"},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseKernel5TCPCaptureStatistics(test.stderr); err == nil {
				t.Fatal("tcpdump statistics parser accepted malformed or incomplete counters")
			}
		})
	}
}

func TestKernel5TCPCaptureEvidenceRejectsEveryCounterMutation(t *testing.T) {
	valid := kernel5TCPCaptureEvidence{
		Packets: 20,
		KernelStatistics: kernel5TCPCaptureStatisticsEvidence{
			Captured: kernel5TCPObservedUint64(20), ReceivedByFilter: kernel5TCPObservedUint64(40),
			DroppedByKernel: kernel5TCPObservedUint64(0),
		},
	}
	if err := validateKernel5TCPCaptureEvidence(valid); err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*kernel5TCPCaptureEvidence)
	}{
		{name: "decoded_packets", mutate: func(value *kernel5TCPCaptureEvidence) { value.Packets = 0 }},
		{name: "rst_packets", mutate: func(value *kernel5TCPCaptureEvidence) { value.RSTPackets = 1 }},
		{name: "captured_missing", mutate: func(value *kernel5TCPCaptureEvidence) {
			value.KernelStatistics.Captured = kernel5TCPMeasuredUint64Evidence{}
		}},
		{name: "captured_mismatch", mutate: func(value *kernel5TCPCaptureEvidence) { value.KernelStatistics.Captured.Value++ }},
		{name: "received_missing", mutate: func(value *kernel5TCPCaptureEvidence) {
			value.KernelStatistics.ReceivedByFilter = kernel5TCPMeasuredUint64Evidence{}
		}},
		{name: "received_less_than_captured", mutate: func(value *kernel5TCPCaptureEvidence) { value.KernelStatistics.ReceivedByFilter.Value = 19 }},
		{name: "dropped_missing", mutate: func(value *kernel5TCPCaptureEvidence) {
			value.KernelStatistics.DroppedByKernel = kernel5TCPMeasuredUint64Evidence{}
		}},
		{name: "dropped_nonzero", mutate: func(value *kernel5TCPCaptureEvidence) { value.KernelStatistics.DroppedByKernel.Value = 1 }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := valid
			mutation.mutate(&mutated)
			if err := validateKernel5TCPCaptureEvidence(mutated); err == nil {
				t.Fatalf("capture evidence validator accepted mutated %s", mutation.name)
			}
		})
	}
}

func TestKernel5TCPStateComponentInventoryRejectsEveryRemoval(t *testing.T) {
	pre, post := validKernel5TCPInspectionsForTest()
	required := kernel5TCPRequiredStateComponentInventory()
	for index, component := range required {
		t.Run(component, func(t *testing.T) {
			inventory := append([]string(nil), required[:index]...)
			inventory = append(inventory, required[index+1:]...)
			binding := kernel5TCPStateComponentsEvidence{
				Inventory:    inventory,
				DigestSHA256: kernel5TCPStateComponentDigest(inventory, pre, post),
			}
			if err := validateKernel5TCPStateComponents(binding, pre, post); err == nil {
				t.Fatalf("state component inventory accepted removal of %q", component)
			}
		})
	}
}

func TestKernel5TCPInspectionRejectsEveryZeroedComponent(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*kernel5TCPInspectionEvidence)
	}{
		{name: "tuple", mutate: func(value *kernel5TCPInspectionEvidence) { value.Tuple = kernel5TCPInspectionTupleEvidence{} }},
		{name: "established_state", mutate: func(value *kernel5TCPInspectionEvidence) { value.EstablishedState = kernel5TCPMeasuredUint8Evidence{} }},
		{name: "receive_queue_bytes", mutate: func(value *kernel5TCPInspectionEvidence) {
			value.ReceiveQueueBytes = kernel5TCPMeasuredUint32Evidence{}
		}},
		{name: "send_queue_bytes", mutate: func(value *kernel5TCPInspectionEvidence) { value.SendQueueBytes = kernel5TCPMeasuredUint32Evidence{} }},
		{name: "unsent_bytes", mutate: func(value *kernel5TCPInspectionEvidence) { value.UnsentBytes = kernel5TCPMeasuredUint32Evidence{} }},
		{name: "options_mask", mutate: func(value *kernel5TCPInspectionEvidence) { value.OptionsMask = kernel5TCPMeasuredUint8Evidence{} }},
		{name: "mss_clamp", mutate: func(value *kernel5TCPInspectionEvidence) { value.MSSClamp = kernel5TCPMeasuredUint32Evidence{} }},
		{name: "send_buffer_bytes", mutate: func(value *kernel5TCPInspectionEvidence) { value.SendBufferBytes = kernel5TCPMeasuredUint32Evidence{} }},
		{name: "receive_buffer_bytes", mutate: func(value *kernel5TCPInspectionEvidence) {
			value.ReceiveBufferBytes = kernel5TCPMeasuredUint32Evidence{}
		}},
		{name: "send_scale", mutate: func(value *kernel5TCPInspectionEvidence) { value.SendScale = kernel5TCPMeasuredUint8Evidence{} }},
		{name: "receive_scale", mutate: func(value *kernel5TCPInspectionEvidence) { value.ReceiveScale = kernel5TCPMeasuredUint8Evidence{} }},
		{name: "receive_sequence", mutate: func(value *kernel5TCPInspectionEvidence) { value.ReceiveSequence = kernel5TCPMeasuredUint32Evidence{} }},
		{name: "send_sequence", mutate: func(value *kernel5TCPInspectionEvidence) { value.SendSequence = kernel5TCPMeasuredUint32Evidence{} }},
		{name: "send_window_last_sequence", mutate: func(value *kernel5TCPInspectionEvidence) {
			value.SendWindowLastSequence = kernel5TCPMeasuredUint32Evidence{}
		}},
		{name: "send_window", mutate: func(value *kernel5TCPInspectionEvidence) { value.SendWindow = kernel5TCPMeasuredUint32Evidence{} }},
		{name: "max_window", mutate: func(value *kernel5TCPInspectionEvidence) { value.MaxWindow = kernel5TCPMeasuredUint32Evidence{} }},
		{name: "receive_window", mutate: func(value *kernel5TCPInspectionEvidence) { value.ReceiveWindow = kernel5TCPMeasuredUint32Evidence{} }},
		{name: "receive_window_update", mutate: func(value *kernel5TCPInspectionEvidence) {
			value.ReceiveWindowUpdate = kernel5TCPMeasuredUint32Evidence{}
		}},
		{name: "timestamp", mutate: func(value *kernel5TCPInspectionEvidence) { value.Timestamp = kernel5TCPMeasuredTimestampEvidence{} }},
	}
	for _, phase := range []string{"pre", "post"} {
		for _, mutation := range mutations {
			t.Run(phase+"."+mutation.name, func(t *testing.T) {
				pre, post := validKernel5TCPInspectionsForTest()
				target := &pre
				if phase == "post" {
					target = &post
				}
				mutation.mutate(target)
				binding := newKernel5TCPStateComponentsEvidence(pre, post)
				if err := validateKernel5TCPStateComponents(binding, pre, post); err == nil {
					t.Fatalf("state component validator accepted zeroed %s.%s", phase, mutation.name)
				}
			})
		}
	}
}

func TestKernel5TCPStateComponentDigestBindsMeasurements(t *testing.T) {
	pre, post := validKernel5TCPInspectionsForTest()
	binding := newKernel5TCPStateComponentsEvidence(pre, post)
	if err := validateKernel5TCPStateComponents(binding, pre, post); err != nil {
		t.Fatal(err)
	}
	post.SendSequence.Value++
	if err := validateKernel5TCPStateComponents(binding, pre, post); err == nil {
		t.Fatal("state component validator accepted a measurement with a stale digest")
	}
	binding = newKernel5TCPStateComponentsEvidence(pre, post)
	binding.DigestSHA256 = strings.ToUpper(binding.DigestSHA256)
	if err := validateKernel5TCPStateComponents(binding, pre, post); err == nil {
		t.Fatal("state component validator accepted an uppercase digest")
	}
}

func validKernel5TCPInspectionsForTest() (kernel5TCPInspectionEvidence, kernel5TCPInspectionEvidence) {
	pre := kernel5TCPInspectionEvidence{
		Tuple:                  kernel5TCPInspectionTupleEvidence{Local: "192.0.2.1:1000", Remote: "192.0.2.2:2000"},
		EstablishedState:       kernel5TCPObservedUint8(kernel5TCPEstablishedState),
		ReceiveQueueBytes:      kernel5TCPObservedUint32(0),
		SendQueueBytes:         kernel5TCPObservedUint32(16),
		UnsentBytes:            kernel5TCPObservedUint32(4),
		OptionsMask:            kernel5TCPObservedUint8(kernel5TCPSupportedOptionsMask),
		MSSClamp:               kernel5TCPObservedUint32(1460),
		SendBufferBytes:        kernel5TCPObservedUint32(262144),
		ReceiveBufferBytes:     kernel5TCPObservedUint32(262144),
		SendScale:              kernel5TCPObservedUint8(7),
		ReceiveScale:           kernel5TCPObservedUint8(7),
		ReceiveSequence:        kernel5TCPObservedUint32(100),
		SendSequence:           kernel5TCPObservedUint32(200),
		SendWindowLastSequence: kernel5TCPObservedUint32(201),
		SendWindow:             kernel5TCPObservedUint32(65535),
		MaxWindow:              kernel5TCPObservedUint32(65535),
		ReceiveWindow:          kernel5TCPObservedUint32(65535),
		ReceiveWindowUpdate:    kernel5TCPObservedUint32(101),
		Timestamp:              kernel5TCPMeasuredTimestampEvidence{Observed: true, Available: true, Value: 300},
	}
	post := pre
	post.ReceiveQueueBytes = kernel5TCPObservedUint32(0)
	post.SendQueueBytes = kernel5TCPObservedUint32(0)
	post.UnsentBytes = kernel5TCPObservedUint32(0)
	post.ReceiveSequence = kernel5TCPObservedUint32(140)
	post.SendSequence = kernel5TCPObservedUint32(260)
	post.SendWindowLastSequence = kernel5TCPObservedUint32(261)
	post.ReceiveWindowUpdate = kernel5TCPObservedUint32(141)
	post.Timestamp = kernel5TCPMeasuredTimestampEvidence{Observed: true, Available: true, Value: 301}
	return pre, post
}
