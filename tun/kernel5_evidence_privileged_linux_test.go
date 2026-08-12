//go:build linux

package tun

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	kernel5TUNEvidenceDirectoryEnvironment = "RENDR_KERNEL5_TUN_EVIDENCE_DIR"
	kernel5TUNInvocationNonceEnvironment   = "RENDR_KERNEL5_INVOCATION_NONCE"
	kernel5TUNNetworkNamespaceEnvironment  = "RENDR_KERNEL5_NETNS_ID"

	kernel5TUNEvidenceSchema = "kernel5-tun-real-io-v2"

	kernel5TUNRecordRealIO     = "real_io"
	kernel5TUNRecordMultiQueue = "multiqueue"
	kernel5TUNRecordLifecycle  = "lifecycle"

	kernel5TUNRealIOFile     = "real-io.json"
	kernel5TUNMultiQueueFile = "multiqueue.json"
	kernel5TUNLifecycleFile  = "lifecycle.json"
)

var kernel5TUNRecordFiles = map[string]string{
	kernel5TUNRecordRealIO:     kernel5TUNRealIOFile,
	kernel5TUNRecordMultiQueue: kernel5TUNMultiQueueFile,
	kernel5TUNRecordLifecycle:  kernel5TUNLifecycleFile,
}

type kernel5TUNDeviceEvidence struct {
	Name    string `json:"name"`
	IfIndex int    `json:"ifindex"`
	MTU     int    `json:"mtu"`
	Queues  int    `json:"queues"`
}

type kernel5TUNDirectionEvidence struct {
	OfferedPackets       int    `json:"offered_packets"`
	ObservedPackets      int    `json:"observed_packets"`
	OfferedPayloadBytes  int    `json:"offered_payload_bytes"`
	ObservedPayloadBytes int    `json:"observed_payload_bytes"`
	OfferedSHA256        string `json:"offered_sha256"`
	ObservedSHA256       string `json:"observed_sha256"`
}

type kernel5TUNDirectionsEvidence struct {
	KernelToTUN kernel5TUNDirectionEvidence `json:"kernel_to_tun"`
	TUNToKernel kernel5TUNDirectionEvidence `json:"tun_to_kernel"`
}

type kernel5TUNBoundaryEvidence struct {
	ExactMTUPacketBytes  []int  `json:"exact_mtu_packet_bytes"`
	OversizeRejections   int    `json:"oversize_rejections"`
	ShortBufferSignals   int    `json:"short_buffer_signals"`
	ReplayedPacketBytes  []int  `json:"replayed_packet_bytes"`
	SequenceFirst        uint32 `json:"sequence_first"`
	SequenceLast         uint32 `json:"sequence_last"`
	SequenceCount        int    `json:"sequence_count"`
	SequenceDuplicates   int    `json:"sequence_duplicates"`
	PacketBoundaryErrors int    `json:"packet_boundary_errors"`
}

type kernel5TUNResourceEvidence struct {
	OpenFDs        int    `json:"open_fds"`
	Goroutines     int    `json:"goroutines"`
	HeapInuseBytes uint64 `json:"heap_inuse_bytes"`
	RSSBytes       uint64 `json:"rss_bytes"`
}

type kernel5TUNLifecycleEvidence struct {
	CyclesRequested     int                        `json:"cycles_requested"`
	CyclesCompleted     int                        `json:"cycles_completed"`
	InterfacesRemoved   int                        `json:"interfaces_removed"`
	CanceledReads       int                        `json:"canceled_reads"`
	CloseUnblockedReads int                        `json:"close_unblocked_reads"`
	Before              kernel5TUNResourceEvidence `json:"before"`
	After               kernel5TUNResourceEvidence `json:"after"`
}

type kernel5TUNEvidence struct {
	Schema                string                       `json:"schema"`
	RecordType            string                       `json:"record_type"`
	InvocationNonce       string                       `json:"invocation_nonce"`
	NetworkNamespace      string                       `json:"network_namespace"`
	TestName              string                       `json:"test_name"`
	RecordSet             []string                     `json:"record_set"`
	Devices               []kernel5TUNDeviceEvidence   `json:"devices"`
	Directions            kernel5TUNDirectionsEvidence `json:"directions"`
	Boundaries            kernel5TUNBoundaryEvidence   `json:"boundaries"`
	QueuePacketCounts     []int                        `json:"queue_packet_counts"`
	QueueDeviceCycles     []int                        `json:"queue_device_cycles"`
	PublicWriteQueueCalls []int                        `json:"public_write_queue_calls"`
	Lifecycle             kernel5TUNLifecycleEvidence  `json:"lifecycle"`
	CounterDigestSHA256   string                       `json:"counter_digest_sha256"`
}

type kernel5TUNEvidenceBinding struct {
	directory string
	nonce     string
	netns     string
}

type tunPayloadTransfer struct {
	offered     []byte
	observed    []byte
	packetBytes int
}

type tunPayloadBatch struct {
	offered  [][]byte
	observed [][]byte
}

type tunPayloadAccumulator struct {
	offeredHash   hash.Hash
	observedHash  hash.Hash
	offeredCount  int
	observedCount int
	offeredBytes  int
	observedBytes int
}

func newTUNPayloadAccumulator() *tunPayloadAccumulator {
	return &tunPayloadAccumulator{offeredHash: sha256.New(), observedHash: sha256.New()}
}

func (accumulator *tunPayloadAccumulator) addTransfer(transfer tunPayloadTransfer) {
	accumulator.addOffered(transfer.offered)
	accumulator.addObserved(transfer.observed)
}

func (accumulator *tunPayloadAccumulator) addBatch(batch tunPayloadBatch) {
	for _, payload := range batch.offered {
		accumulator.addOffered(payload)
	}
	for _, payload := range batch.observed {
		accumulator.addObserved(payload)
	}
}

func (accumulator *tunPayloadAccumulator) addOffered(payload []byte) {
	writeTUNPayloadHash(accumulator.offeredHash, payload)
	accumulator.offeredCount++
	accumulator.offeredBytes += len(payload)
}

func (accumulator *tunPayloadAccumulator) addObserved(payload []byte) {
	writeTUNPayloadHash(accumulator.observedHash, payload)
	accumulator.observedCount++
	accumulator.observedBytes += len(payload)
}

func (accumulator *tunPayloadAccumulator) evidence() kernel5TUNDirectionEvidence {
	return kernel5TUNDirectionEvidence{
		OfferedPackets: accumulator.offeredCount, ObservedPackets: accumulator.observedCount,
		OfferedPayloadBytes: accumulator.offeredBytes, ObservedPayloadBytes: accumulator.observedBytes,
		OfferedSHA256:  hex.EncodeToString(accumulator.offeredHash.Sum(nil)),
		ObservedSHA256: hex.EncodeToString(accumulator.observedHash.Sum(nil)),
	}
}

func writeTUNPayloadHash(destination hash.Hash, payload []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(payload)))
	_, _ = destination.Write(length[:])
	_, _ = destination.Write(payload)
}

func TestMain(m *testing.M) {
	binding, enabled, err := kernel5TUNEvidenceBindingFromEnvironment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "kernel5 TUN evidence setup: %v\n", err)
		os.Exit(2)
	}
	if enabled {
		if err := prepareKernel5TUNEvidenceDirectory(binding.directory); err != nil {
			fmt.Fprintf(os.Stderr, "kernel5 TUN evidence setup: %v\n", err)
			os.Exit(2)
		}
	}
	code := m.Run()
	if enabled {
		if err := verifyKernel5TUNEvidenceSet(binding); err != nil {
			fmt.Fprintf(os.Stderr, "kernel5 TUN evidence set: %v\n", err)
			if code == 0 {
				code = 1
			}
		}
	}
	os.Exit(code)
}

func emitKernel5TUNEvidence(t testing.TB, evidence kernel5TUNEvidence) {
	t.Helper()
	binding, enabled, err := kernel5TUNEvidenceBindingFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		return
	}
	evidence.Schema = kernel5TUNEvidenceSchema
	evidence.InvocationNonce = binding.nonce
	evidence.NetworkNamespace = binding.netns
	evidence.RecordSet = expectedKernel5TUNRecordNames()
	evidence.CounterDigestSHA256 = kernel5TUNCounterDigest(evidence)
	if err := validateKernel5TUNEvidence(evidence); err != nil {
		t.Fatalf("TUN evidence is invalid: %v", err)
	}
	filename, ok := kernel5TUNRecordFiles[evidence.RecordType]
	if !ok {
		t.Fatalf("unknown TUN evidence record type %q", evidence.RecordType)
	}
	path := filepath.Join(binding.directory, filename)
	if err := writeKernel5TUNStrictJSON(path, evidence); err != nil {
		t.Fatalf("write TUN evidence %s: %v", filename, err)
	}
}

func kernel5TUNEvidenceBindingFromEnvironment() (kernel5TUNEvidenceBinding, bool, error) {
	directory := os.Getenv(kernel5TUNEvidenceDirectoryEnvironment)
	if directory == "" {
		return kernel5TUNEvidenceBinding{}, false, nil
	}
	if strings.TrimSpace(directory) != directory || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return kernel5TUNEvidenceBinding{}, false, fmt.Errorf("%s must be a clean absolute directory",
			kernel5TUNEvidenceDirectoryEnvironment)
	}
	nonce := os.Getenv(kernel5TUNInvocationNonceEnvironment)
	if err := validateKernel5TUNNonce(nonce); err != nil {
		return kernel5TUNEvidenceBinding{}, false, err
	}
	netns, err := kernel5TUNNetworkNamespaceIdentity()
	if err != nil {
		return kernel5TUNEvidenceBinding{}, false, err
	}
	expected := os.Getenv(kernel5TUNNetworkNamespaceEnvironment)
	if expected == "" || expected != netns {
		return kernel5TUNEvidenceBinding{}, false, fmt.Errorf("%s=%q does not bind current network namespace %q",
			kernel5TUNNetworkNamespaceEnvironment, expected, netns)
	}
	return kernel5TUNEvidenceBinding{directory: directory, nonce: nonce, netns: netns}, true, nil
}

func validateKernel5TUNNonce(nonce string) error {
	return validateKernel5TUNFixedLowerHex(kernel5TUNInvocationNonceEnvironment, nonce, 32)
}

func kernel5TUNNetworkNamespaceIdentity() (string, error) {
	info, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return "", fmt.Errorf("stat current network namespace: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		return "", errors.New("current network namespace has no device/inode identity")
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), nil
}

func prepareKernel5TUNEvidenceDirectory(directory string) error {
	info, err := os.Stat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("TUN evidence path is not a directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("TUN evidence directory is not initially empty: %v", directoryEntryNames(entries))
	}
	return nil
}

func verifyKernel5TUNEvidenceSet(binding kernel5TUNEvidenceBinding) error {
	entries, err := os.ReadDir(binding.directory)
	if err != nil {
		return err
	}
	actual := directoryEntryNames(entries)
	expected := expectedKernel5TUNRecordNames()
	if !equalStrings(actual, expected) {
		return fmt.Errorf("record files=%v want exact set %v", actual, expected)
	}
	seenTypes := make(map[string]bool, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return fmt.Errorf("record %s mode=%s want regular 0600", entry.Name(), info.Mode())
		}
		data, err := os.ReadFile(filepath.Join(binding.directory, entry.Name()))
		if err != nil {
			return err
		}
		var evidence kernel5TUNEvidence
		if err := decodeKernel5TUNStrictJSON(data, &evidence); err != nil {
			return fmt.Errorf("decode %s: %w", entry.Name(), err)
		}
		if err := validateKernel5TUNEvidence(evidence); err != nil {
			return fmt.Errorf("validate %s: %w", entry.Name(), err)
		}
		if kernel5TUNRecordFiles[evidence.RecordType] != entry.Name() || evidence.InvocationNonce != binding.nonce ||
			evidence.NetworkNamespace != binding.netns || seenTypes[evidence.RecordType] {
			return fmt.Errorf("record binding mismatch in %s", entry.Name())
		}
		seenTypes[evidence.RecordType] = true
	}
	return nil
}

func expectedKernel5TUNRecordNames() []string {
	return []string{kernel5TUNLifecycleFile, kernel5TUNMultiQueueFile, kernel5TUNRealIOFile}
}

func directoryEntryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func captureKernel5TUNDevice(t testing.TB, device *Device) kernel5TUNDeviceEvidence {
	t.Helper()
	if device == nil {
		t.Fatal("capture TUN device evidence: nil device")
	}
	iface, err := net.InterfaceByName(device.Name())
	if err != nil {
		t.Fatalf("capture TUN device evidence: %v", err)
	}
	if iface.Index <= 0 || iface.MTU != device.MTU() || device.QueueCount() <= 0 {
		t.Fatalf("capture TUN device evidence: interface=%+v device mtu/queues=%d/%d", iface, device.MTU(), device.QueueCount())
	}
	return kernel5TUNDeviceEvidence{Name: device.Name(), IfIndex: iface.Index, MTU: iface.MTU, Queues: device.QueueCount()}
}

func sampleKernel5TUNResources(t testing.TB) kernel5TUNResourceEvidence {
	t.Helper()
	runtime.GC()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return kernel5TUNResourceEvidence{
		OpenFDs: countOpenFDs(t), Goroutines: runtime.NumGoroutine(),
		HeapInuseBytes: memory.HeapInuse, RSSBytes: kernel5TUNRSSBytes(t),
	}
}

func kernel5TUNRSSBytes(t testing.TB) uint64 {
	t.Helper()
	content, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "VmRSS:" {
			kilobytes, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return kilobytes * 1024
		}
	}
	t.Fatal("/proc/self/status has no VmRSS")
	return 0
}

func validateKernel5TUNEvidence(evidence kernel5TUNEvidence) error {
	filename, known := kernel5TUNRecordFiles[evidence.RecordType]
	if evidence.Schema != kernel5TUNEvidenceSchema || !known || filename == "" || evidence.TestName == "" {
		return fmt.Errorf("schema/type/test=%q/%q/%q", evidence.Schema, evidence.RecordType, evidence.TestName)
	}
	if err := validateKernel5TUNNonce(evidence.InvocationNonce); err != nil {
		return err
	}
	if err := validateKernel5TUNNetworkNamespaceFormat(evidence.NetworkNamespace); err != nil {
		return err
	}
	if !equalStrings(evidence.RecordSet, expectedKernel5TUNRecordNames()) {
		return errors.New("exact record set is invalid")
	}
	if err := validateKernel5TUNFixedLowerHex("counter_digest_sha256", evidence.CounterDigestSHA256, sha256.Size); err != nil {
		return err
	}
	if evidence.CounterDigestSHA256 != kernel5TUNCounterDigest(evidence) {
		return errors.New("counter digest is not bound to the measured TUN counters")
	}
	if len(evidence.Devices) == 0 {
		return errors.New("device inventory is empty")
	}
	for index, device := range evidence.Devices {
		if device.Name == "" || device.IfIndex <= 0 || device.MTU <= 0 || device.Queues <= 0 {
			return fmt.Errorf("device %d is invalid: %+v", index, device)
		}
	}
	if err := validateKernel5TUNDirection(evidence.Directions.KernelToTUN); err != nil {
		return fmt.Errorf("kernel-to-TUN: %w", err)
	}
	if err := validateKernel5TUNDirection(evidence.Directions.TUNToKernel); err != nil {
		return fmt.Errorf("TUN-to-kernel: %w", err)
	}
	if evidence.Boundaries.PacketBoundaryErrors != 0 || evidence.Boundaries.SequenceDuplicates != 0 {
		return fmt.Errorf("packet boundary evidence reports errors: %+v", evidence.Boundaries)
	}
	lifecycle := evidence.Lifecycle
	if lifecycle.CyclesRequested <= 0 || lifecycle.CyclesCompleted != lifecycle.CyclesRequested ||
		lifecycle.InterfacesRemoved != lifecycle.CyclesCompleted {
		return fmt.Errorf("lifecycle evidence is incomplete: %+v", lifecycle)
	}
	for name, resources := range map[string]kernel5TUNResourceEvidence{"before": lifecycle.Before, "after": lifecycle.After} {
		if resources.OpenFDs <= 0 || resources.Goroutines <= 0 || resources.HeapInuseBytes == 0 || resources.RSSBytes == 0 {
			return fmt.Errorf("%s resources are incomplete: %+v", name, resources)
		}
	}
	if lifecycle.After.OpenFDs > lifecycle.Before.OpenFDs+2 || lifecycle.After.Goroutines > lifecycle.Before.Goroutines+2 {
		return fmt.Errorf("lifecycle resource slope exceeded: before=%+v after=%+v", lifecycle.Before, lifecycle.After)
	}
	switch evidence.RecordType {
	case kernel5TUNRecordRealIO:
		if evidence.TestName != "TestPrivilegedTUNRealIPv4IPv6IO" || len(evidence.Devices) != 1 ||
			evidence.Devices[0].MTU != 1280 || evidence.Devices[0].Queues != 1 ||
			evidence.Directions.KernelToTUN.ObservedPackets != 5 || evidence.Directions.TUNToKernel.ObservedPackets != 2 ||
			!equalInts(evidence.Boundaries.ExactMTUPacketBytes, []int{1280, 1280}) ||
			evidence.Boundaries.OversizeRejections != 3 || evidence.Boundaries.ShortBufferSignals != 2 ||
			!equalInts(evidence.Boundaries.ReplayedPacketBytes, []int{1400}) || len(evidence.QueueDeviceCycles) != 0 ||
			lifecycle.CyclesRequested != 1 {
			return fmt.Errorf("real-I/O evidence does not match its measured contract: %+v", evidence)
		}
	case kernel5TUNRecordMultiQueue:
		if evidence.TestName != "TestPrivilegedTUNMultiQueueDistributesRealPackets" || len(evidence.Devices) != 1 ||
			evidence.Devices[0].MTU != 1400 || evidence.Devices[0].Queues != 2 ||
			evidence.Directions.KernelToTUN.ObservedPackets != 259 || evidence.Directions.TUNToKernel.ObservedPackets != 34 ||
			evidence.Boundaries.SequenceFirst != 0 || evidence.Boundaries.SequenceLast != 255 ||
			evidence.Boundaries.SequenceCount != 256 || len(evidence.QueuePacketCounts) != 2 ||
			evidence.QueuePacketCounts[0] == 0 || evidence.QueuePacketCounts[1] == 0 ||
			evidence.QueuePacketCounts[0]+evidence.QueuePacketCounts[1] != 256 ||
			len(evidence.PublicWriteQueueCalls) != 2 || evidence.PublicWriteQueueCalls[0] == 0 ||
			evidence.PublicWriteQueueCalls[1] == 0 || evidence.PublicWriteQueueCalls[0]+evidence.PublicWriteQueueCalls[1] != 32 ||
			len(evidence.QueueDeviceCycles) != 0 || lifecycle.CyclesRequested != 1 {
			return fmt.Errorf("multiqueue evidence does not match its measured contract: %+v", evidence)
		}
	case kernel5TUNRecordLifecycle:
		if evidence.TestName != "TestPrivilegedTUNDeviceLifecycleIsBounded" || len(evidence.Devices) != 100 ||
			evidence.Directions.KernelToTUN.ObservedPackets != 0 || evidence.Directions.TUNToKernel.ObservedPackets != 0 ||
			lifecycle.CyclesRequested != 100 || lifecycle.CanceledReads != 1 || lifecycle.CloseUnblockedReads != 1 ||
			len(evidence.QueuePacketCounts) != 0 || !equalInts(evidence.QueueDeviceCycles, []int{50, 50}) ||
			len(evidence.PublicWriteQueueCalls) != 0 {
			return fmt.Errorf("lifecycle evidence does not match its measured contract: %+v", evidence)
		}
	}
	return nil
}

func validateKernel5TUNDirection(direction kernel5TUNDirectionEvidence) error {
	if direction.OfferedPackets < 0 || direction.ObservedPackets != direction.OfferedPackets ||
		direction.OfferedPayloadBytes < 0 || direction.ObservedPayloadBytes != direction.OfferedPayloadBytes ||
		direction.ObservedSHA256 != direction.OfferedSHA256 {
		return fmt.Errorf("packet/byte/hash mismatch: %+v", direction)
	}
	if err := validateKernel5TUNFixedLowerHex("offered_sha256", direction.OfferedSHA256, 32); err != nil {
		return err
	}
	if err := validateKernel5TUNFixedLowerHex("observed_sha256", direction.ObservedSHA256, 32); err != nil {
		return err
	}
	return nil
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func kernel5TUNCounterDigest(evidence kernel5TUNEvidence) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("KTNC2"))
	writeKernel5TUNCounterString(hash, evidence.RecordType)
	writeKernel5TUNCounterInt(hash, len(evidence.Devices))
	for _, device := range evidence.Devices {
		writeKernel5TUNCounterString(hash, device.Name)
		writeKernel5TUNCounterInt(hash, device.IfIndex)
		writeKernel5TUNCounterInt(hash, device.MTU)
		writeKernel5TUNCounterInt(hash, device.Queues)
	}
	for _, direction := range []kernel5TUNDirectionEvidence{
		evidence.Directions.KernelToTUN, evidence.Directions.TUNToKernel,
	} {
		writeKernel5TUNCounterInt(hash, direction.OfferedPackets)
		writeKernel5TUNCounterInt(hash, direction.ObservedPackets)
		writeKernel5TUNCounterInt(hash, direction.OfferedPayloadBytes)
		writeKernel5TUNCounterInt(hash, direction.ObservedPayloadBytes)
	}
	boundary := evidence.Boundaries
	writeKernel5TUNCounterInts(hash, boundary.ExactMTUPacketBytes)
	writeKernel5TUNCounterInt(hash, boundary.OversizeRejections)
	writeKernel5TUNCounterInt(hash, boundary.ShortBufferSignals)
	writeKernel5TUNCounterInts(hash, boundary.ReplayedPacketBytes)
	writeKernel5TUNCounterInt(hash, int(boundary.SequenceFirst))
	writeKernel5TUNCounterInt(hash, int(boundary.SequenceLast))
	writeKernel5TUNCounterInt(hash, boundary.SequenceCount)
	writeKernel5TUNCounterInt(hash, boundary.SequenceDuplicates)
	writeKernel5TUNCounterInt(hash, boundary.PacketBoundaryErrors)
	writeKernel5TUNCounterInts(hash, evidence.QueuePacketCounts)
	writeKernel5TUNCounterInts(hash, evidence.QueueDeviceCycles)
	writeKernel5TUNCounterInts(hash, evidence.PublicWriteQueueCalls)
	lifecycle := evidence.Lifecycle
	writeKernel5TUNCounterInt(hash, lifecycle.CyclesRequested)
	writeKernel5TUNCounterInt(hash, lifecycle.CyclesCompleted)
	writeKernel5TUNCounterInt(hash, lifecycle.InterfacesRemoved)
	writeKernel5TUNCounterInt(hash, lifecycle.CanceledReads)
	writeKernel5TUNCounterInt(hash, lifecycle.CloseUnblockedReads)
	for _, resources := range []kernel5TUNResourceEvidence{lifecycle.Before, lifecycle.After} {
		writeKernel5TUNCounterInt(hash, resources.OpenFDs)
		writeKernel5TUNCounterInt(hash, resources.Goroutines)
		writeKernel5TUNCounterUint64(hash, resources.HeapInuseBytes)
		writeKernel5TUNCounterUint64(hash, resources.RSSBytes)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func writeKernel5TUNCounterString(destination hash.Hash, value string) {
	writeKernel5TUNCounterUint64(destination, uint64(len(value)))
	_, _ = destination.Write([]byte(value))
}

func writeKernel5TUNCounterInts(destination hash.Hash, values []int) {
	writeKernel5TUNCounterInt(destination, len(values))
	for _, value := range values {
		writeKernel5TUNCounterInt(destination, value)
	}
}

func writeKernel5TUNCounterInt(destination hash.Hash, value int) {
	writeKernel5TUNCounterUint64(destination, uint64(int64(value)))
}

func writeKernel5TUNCounterUint64(destination hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = destination.Write(encoded[:])
}

func writeKernel5TUNStrictJSON(path string, evidence kernel5TUNEvidence) error {
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	var decoded kernel5TUNEvidence
	if err := decodeKernel5TUNStrictJSON(encoded, &decoded); err != nil {
		return err
	}
	if err := validateKernel5TUNEvidence(decoded); err != nil {
		return err
	}
	return writeKernel5TUNAtomicNoReplace(path, encoded)
}

func decodeKernel5TUNStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON evidence contains a trailing value")
		}
		return err
	}
	return nil
}

func writeKernel5TUNAtomicNoReplace(path string, data []byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("TUN evidence path is not clean and absolute")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, temporaryName, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

func TestKernel5TUNEvidenceStrictJSONAndAtomicNoReplace(t *testing.T) {
	evidence := validKernel5TUNEvidenceForTest(kernel5TUNRecordRealIO)
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var decoded kernel5TUNEvidence
	if err := decodeKernel5TUNStrictJSON(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := validateKernel5TUNEvidence(decoded); err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unknown":true}`)...)
	if err := decodeKernel5TUNStrictJSON(unknown, &decoded); err == nil {
		t.Fatal("strict TUN evidence decoder accepted an unknown field")
	}
	if err := decodeKernel5TUNStrictJSON(append(encoded, []byte(` {}`)...), &decoded); err == nil {
		t.Fatal("strict TUN evidence decoder accepted a trailing value")
	}
	target := filepath.Join(t.TempDir(), kernel5TUNRealIOFile)
	if err := writeKernel5TUNAtomicNoReplace(target, encoded); err != nil {
		t.Fatal(err)
	}
	if err := writeKernel5TUNAtomicNoReplace(target, encoded); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("second TUN evidence write error=%v want EEXIST", err)
	}
}

func TestKernel5TUNEvidenceRejectsMalformedFixedFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*kernel5TUNEvidence)
	}{
		{name: "short payload hash", mutate: func(evidence *kernel5TUNEvidence) {
			evidence.Directions.KernelToTUN.OfferedSHA256 = strings.Repeat("a", 62)
			evidence.Directions.KernelToTUN.ObservedSHA256 = evidence.Directions.KernelToTUN.OfferedSHA256
		}},
		{name: "uppercase payload hash", mutate: func(evidence *kernel5TUNEvidence) {
			evidence.Directions.TUNToKernel.OfferedSHA256 = strings.Repeat("A", 64)
			evidence.Directions.TUNToKernel.ObservedSHA256 = evidence.Directions.TUNToKernel.OfferedSHA256
		}},
		{name: "counter digest drift", mutate: func(evidence *kernel5TUNEvidence) {
			evidence.CounterDigestSHA256 = strings.Repeat("c", 64)
		}},
		{name: "zero namespace inode", mutate: func(evidence *kernel5TUNEvidence) {
			evidence.NetworkNamespace = "4:0"
		}},
		{name: "overflow namespace device", mutate: func(evidence *kernel5TUNEvidence) {
			evidence.NetworkNamespace = "18446744073709551616:5"
		}},
		{name: "extra namespace component", mutate: func(evidence *kernel5TUNEvidence) {
			evidence.NetworkNamespace = "4:5:6"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := validKernel5TUNEvidenceForTest(kernel5TUNRecordRealIO)
			test.mutate(&evidence)
			if err := validateKernel5TUNEvidence(evidence); err == nil {
				t.Fatal("TUN evidence validator accepted malformed fixed-format evidence")
			}
		})
	}
}

func TestKernel5TUNEvidenceVerifierRequiresExactRecordSet(t *testing.T) {
	directory := t.TempDir()
	binding := kernel5TUNEvidenceBinding{directory: directory, nonce: strings.Repeat("a", 64), netns: "4:5"}
	for recordType, filename := range kernel5TUNRecordFiles {
		evidence := validKernel5TUNEvidenceForTest(recordType)
		encoded, err := json.Marshal(evidence)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, filename), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyKernel5TUNEvidenceSet(binding); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "extra.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyKernel5TUNEvidenceSet(binding); err == nil {
		t.Fatal("TUN evidence verifier accepted an extra record")
	}
}

func validKernel5TUNEvidenceForTest(recordType string) kernel5TUNEvidence {
	empty := newTUNPayloadAccumulator().evidence()
	resources := kernel5TUNResourceEvidence{OpenFDs: 1, Goroutines: 1, HeapInuseBytes: 1, RSSBytes: 1}
	record := kernel5TUNEvidence{
		Schema: kernel5TUNEvidenceSchema, RecordType: recordType,
		InvocationNonce: strings.Repeat("a", 64), NetworkNamespace: "4:5",
		RecordSet:         expectedKernel5TUNRecordNames(),
		Directions:        kernel5TUNDirectionsEvidence{KernelToTUN: empty, TUNToKernel: empty},
		Boundaries:        kernel5TUNBoundaryEvidence{ExactMTUPacketBytes: []int{}, ReplayedPacketBytes: []int{}},
		QueuePacketCounts: []int{}, QueueDeviceCycles: []int{}, PublicWriteQueueCalls: []int{},
		Lifecycle: kernel5TUNLifecycleEvidence{
			CyclesRequested: 1, CyclesCompleted: 1, InterfacesRemoved: 1, Before: resources, After: resources,
		},
	}
	switch recordType {
	case kernel5TUNRecordRealIO:
		record.TestName = "TestPrivilegedTUNRealIPv4IPv6IO"
		record.Devices = []kernel5TUNDeviceEvidence{{Name: "tun0", IfIndex: 1, MTU: 1280, Queues: 1}}
		record.Directions.KernelToTUN = validKernel5TUNDirectionForTest(5)
		record.Directions.TUNToKernel = validKernel5TUNDirectionForTest(2)
		record.Boundaries.ExactMTUPacketBytes = []int{1280, 1280}
		record.Boundaries.OversizeRejections = 3
		record.Boundaries.ShortBufferSignals = 2
		record.Boundaries.ReplayedPacketBytes = []int{1400}
	case kernel5TUNRecordMultiQueue:
		record.TestName = "TestPrivilegedTUNMultiQueueDistributesRealPackets"
		record.Devices = []kernel5TUNDeviceEvidence{{Name: "tun0", IfIndex: 1, MTU: 1400, Queues: 2}}
		record.Directions.KernelToTUN = validKernel5TUNDirectionForTest(259)
		record.Directions.TUNToKernel = validKernel5TUNDirectionForTest(34)
		record.Boundaries.SequenceLast = 255
		record.Boundaries.SequenceCount = 256
		record.QueuePacketCounts = []int{128, 128}
		record.PublicWriteQueueCalls = []int{16, 16}
	case kernel5TUNRecordLifecycle:
		record.TestName = "TestPrivilegedTUNDeviceLifecycleIsBounded"
		record.Devices = make([]kernel5TUNDeviceEvidence, 100)
		for index := range record.Devices {
			record.Devices[index] = kernel5TUNDeviceEvidence{Name: fmt.Sprintf("tun%d", index), IfIndex: index + 1, MTU: 1400, Queues: 1 + index%2}
		}
		record.QueueDeviceCycles = []int{50, 50}
		record.Lifecycle = kernel5TUNLifecycleEvidence{
			CyclesRequested: 100, CyclesCompleted: 100, InterfacesRemoved: 100,
			CanceledReads: 1, CloseUnblockedReads: 1, Before: resources, After: resources,
		}
	}
	record.CounterDigestSHA256 = kernel5TUNCounterDigest(record)
	return record
}

func validKernel5TUNDirectionForTest(packets int) kernel5TUNDirectionEvidence {
	digest := strings.Repeat("b", 64)
	return kernel5TUNDirectionEvidence{
		OfferedPackets: packets, ObservedPackets: packets,
		OfferedPayloadBytes: packets, ObservedPayloadBytes: packets,
		OfferedSHA256: digest, ObservedSHA256: digest,
	}
}
