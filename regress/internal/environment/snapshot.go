// Package environment captures deterministic host provenance for regression
// invocations without recording interface addresses.
package environment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
)

const (
	SnapshotSchemaVersion = 1
	VMRoleEnv             = "RENDR_REGRESS_VM_ROLE"
	CPUGroupEnv           = "RENDR_REGRESS_CPU_GROUP"
)

var mandatoryLinuxSysctls = []string{
	"net.core.rmem_default",
	"net.core.rmem_max",
	"net.core.wmem_default",
	"net.core.wmem_max",
	"net.ipv4.tcp_congestion_control",
	"net.ipv4.tcp_mtu_probing",
	"net.ipv4.tcp_rmem",
	"net.ipv4.tcp_wmem",
	"net.ipv4.udp_rmem_min",
	"net.ipv4.udp_wmem_min",
}

// Runtime identifies the Go binary and target platform executing the suite.
type Runtime struct {
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
}

// Interface records only topology-safe interface facts. It intentionally has
// no address or hardware-address field.
type Interface struct {
	Name string `json:"name"`
	MTU  int    `json:"mtu"`
}

// Sysctl is one normalized socket-related Linux sysctl value.
type Sysctl struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// QDisc records canonical tc JSON and a digest used to prove restoration.
type QDisc struct {
	Supported bool            `json:"supported"`
	State     json.RawMessage `json:"state,omitempty"`
	Digest    string          `json:"digest,omitempty"`
}

// Metadata is optional orchestrator-provided VM placement context.
type Metadata struct {
	VMRole   string `json:"vm_role,omitempty"`
	CPUGroup string `json:"cpu_group,omitempty"`
}

// CPU records kernel-observed placement facts independently of optional
// orchestrator metadata.
type CPU struct {
	Models         []string `json:"models"`
	OnlineSet      string   `json:"online_set,omitempty"`
	ProcessAllowed string   `json:"process_allowed,omitempty"`
}

// Snapshot is the deterministic environment provenance bound to an invocation.
type Snapshot struct {
	SchemaVersion    int         `json:"schema_version"`
	Runtime          Runtime     `json:"runtime"`
	Hostname         string      `json:"hostname"`
	KernelRelease    string      `json:"kernel_release,omitempty"`
	BootID           string      `json:"boot_id,omitempty"`
	NumCPU           int         `json:"num_cpu"`
	CPU              CPU         `json:"cpu"`
	TotalMemoryBytes uint64      `json:"total_memory_bytes,omitempty"`
	Clocksource      string      `json:"clocksource,omitempty"`
	Interfaces       []Interface `json:"interfaces"`
	SocketSysctls    []Sysctl    `json:"socket_sysctls"`
	QDisc            QDisc       `json:"qdisc"`
	Metadata         Metadata    `json:"metadata"`
	IdentityDigest   string      `json:"identity_digest"`
}

// Capture reads the current host provenance. Linux platform capture fails when
// any mandatory kernel, memory, clocksource, sysctl, or qdisc source is absent.
func Capture(ctx context.Context) (Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	hostname, err := os.Hostname()
	if err != nil {
		return Snapshot{}, fmt.Errorf("read hostname: %w", err)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return Snapshot{}, fmt.Errorf("list interfaces: %w", err)
	}

	snapshot := Snapshot{
		SchemaVersion: SnapshotSchemaVersion,
		Runtime: Runtime{
			GoVersion: runtime.Version(),
			GOOS:      runtime.GOOS,
			GOARCH:    runtime.GOARCH,
		},
		Hostname: hostname,
		NumCPU:   runtime.NumCPU(),
		Metadata: captureMetadata(),
	}
	for _, iface := range ifaces {
		snapshot.Interfaces = append(snapshot.Interfaces, Interface{Name: iface.Name, MTU: iface.MTU})
	}
	if err := capturePlatform(ctx, &snapshot); err != nil {
		return Snapshot{}, err
	}
	return Seal(snapshot)
}

// Seal normalizes a snapshot, computes its digests, and validates completeness.
func Seal(snapshot Snapshot) (Snapshot, error) {
	snapshot.Runtime.GoVersion = strings.TrimSpace(snapshot.Runtime.GoVersion)
	snapshot.Runtime.GOOS = strings.TrimSpace(snapshot.Runtime.GOOS)
	snapshot.Runtime.GOARCH = strings.TrimSpace(snapshot.Runtime.GOARCH)
	snapshot.Hostname = strings.TrimSpace(snapshot.Hostname)
	snapshot.KernelRelease = strings.TrimSpace(snapshot.KernelRelease)
	snapshot.BootID = strings.TrimSpace(snapshot.BootID)
	snapshot.Clocksource = strings.TrimSpace(snapshot.Clocksource)
	snapshot.CPU.OnlineSet = normalizeValue(snapshot.CPU.OnlineSet)
	snapshot.CPU.ProcessAllowed = normalizeValue(snapshot.CPU.ProcessAllowed)
	for i := range snapshot.CPU.Models {
		snapshot.CPU.Models[i] = normalizeValue(snapshot.CPU.Models[i])
	}
	sort.Strings(snapshot.CPU.Models)
	snapshot.Metadata.VMRole = strings.TrimSpace(snapshot.Metadata.VMRole)
	snapshot.Metadata.CPUGroup = strings.TrimSpace(snapshot.Metadata.CPUGroup)

	for i := range snapshot.Interfaces {
		snapshot.Interfaces[i].Name = strings.TrimSpace(snapshot.Interfaces[i].Name)
	}
	sort.Slice(snapshot.Interfaces, func(i, j int) bool {
		if snapshot.Interfaces[i].Name == snapshot.Interfaces[j].Name {
			return snapshot.Interfaces[i].MTU < snapshot.Interfaces[j].MTU
		}
		return snapshot.Interfaces[i].Name < snapshot.Interfaces[j].Name
	})
	for i := range snapshot.SocketSysctls {
		snapshot.SocketSysctls[i].Name = strings.TrimSpace(snapshot.SocketSysctls[i].Name)
		snapshot.SocketSysctls[i].Value = normalizeValue(snapshot.SocketSysctls[i].Value)
	}
	sort.Slice(snapshot.SocketSysctls, func(i, j int) bool {
		return snapshot.SocketSysctls[i].Name < snapshot.SocketSysctls[j].Name
	})

	if snapshot.QDisc.Supported {
		state, err := canonicalQDisc(snapshot.QDisc.State)
		if err != nil {
			return Snapshot{}, fmt.Errorf("normalize qdisc state: %w", err)
		}
		snapshot.QDisc.State = state
		snapshot.QDisc.Digest = digest(state)
	} else {
		snapshot.QDisc.State = nil
		snapshot.QDisc.Digest = ""
	}
	identityDigest, err := computeIdentityDigest(snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.IdentityDigest = identityDigest
	if err := Validate(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// Validate checks snapshot schema, deterministic ordering, digests, and all
// mandatory Linux fields.
func Validate(snapshot Snapshot) error {
	var reasons []string
	if snapshot.SchemaVersion != SnapshotSchemaVersion {
		reasons = append(reasons, fmt.Sprintf("snapshot schema=%d want %d", snapshot.SchemaVersion, SnapshotSchemaVersion))
	}
	if snapshot.Runtime.GoVersion == "" {
		reasons = append(reasons, "runtime Go version is missing")
	}
	if snapshot.Runtime.GOOS == "" {
		reasons = append(reasons, "runtime GOOS is missing")
	}
	if snapshot.Runtime.GOARCH == "" {
		reasons = append(reasons, "runtime GOARCH is missing")
	}
	if snapshot.Hostname == "" {
		reasons = append(reasons, "hostname is missing")
	}
	if snapshot.NumCPU <= 0 {
		reasons = append(reasons, "NumCPU is missing")
	}
	if !sort.StringsAreSorted(snapshot.CPU.Models) {
		reasons = append(reasons, "CPU model inventory is not deterministic")
	}
	seenModels := make(map[string]bool, len(snapshot.CPU.Models))
	for _, model := range snapshot.CPU.Models {
		if model == "" {
			reasons = append(reasons, "CPU model inventory contains an empty entry")
		}
		if seenModels[model] {
			reasons = append(reasons, fmt.Sprintf("CPU model %q is duplicated", model))
		}
		seenModels[model] = true
	}
	if len(snapshot.Interfaces) == 0 {
		reasons = append(reasons, "interface inventory is empty")
	}
	if !sort.SliceIsSorted(snapshot.Interfaces, func(i, j int) bool {
		if snapshot.Interfaces[i].Name == snapshot.Interfaces[j].Name {
			return snapshot.Interfaces[i].MTU < snapshot.Interfaces[j].MTU
		}
		return snapshot.Interfaces[i].Name < snapshot.Interfaces[j].Name
	}) {
		reasons = append(reasons, "interface inventory is not deterministic")
	}
	seenInterfaces := make(map[string]bool, len(snapshot.Interfaces))
	for _, iface := range snapshot.Interfaces {
		if iface.Name == "" || (snapshot.Runtime.GOOS == "linux" && iface.MTU <= 0) {
			reasons = append(reasons, "interface inventory contains an incomplete entry")
		}
		if seenInterfaces[iface.Name] {
			reasons = append(reasons, fmt.Sprintf("interface %q is duplicated", iface.Name))
		}
		seenInterfaces[iface.Name] = true
	}

	if snapshot.Runtime.GOOS == "linux" {
		if snapshot.KernelRelease == "" {
			reasons = append(reasons, "kernel release is missing")
		}
		if snapshot.BootID == "" {
			reasons = append(reasons, "boot ID is missing")
		}
		if len(snapshot.CPU.Models) == 0 {
			reasons = append(reasons, "CPU model inventory is missing")
		}
		if snapshot.CPU.OnlineSet == "" {
			reasons = append(reasons, "online CPU set is missing")
		}
		if snapshot.CPU.ProcessAllowed == "" {
			reasons = append(reasons, "process allowed CPU list is missing")
		}
		if snapshot.TotalMemoryBytes == 0 {
			reasons = append(reasons, "total memory is missing")
		}
		if snapshot.Clocksource == "" {
			reasons = append(reasons, "clocksource is missing")
		}
		reasons = append(reasons, validateLinuxSysctls(snapshot.SocketSysctls)...)
		if !snapshot.QDisc.Supported {
			reasons = append(reasons, "qdisc capture is unsupported")
		}
	}
	if snapshot.QDisc.Supported {
		canonical, err := canonicalQDisc(snapshot.QDisc.State)
		if err != nil {
			reasons = append(reasons, "qdisc state is invalid: "+err.Error())
		} else {
			if !bytes.Equal(canonical, snapshot.QDisc.State) {
				reasons = append(reasons, "qdisc state is not canonical")
			}
			if snapshot.QDisc.Digest != digest(canonical) {
				reasons = append(reasons, "qdisc digest is missing or does not match state")
			}
		}
	} else if len(snapshot.QDisc.State) != 0 || snapshot.QDisc.Digest != "" {
		reasons = append(reasons, "unsupported qdisc capture contains state")
	}

	identityDigest, err := computeIdentityDigest(snapshot)
	if err != nil {
		reasons = append(reasons, "compute identity digest: "+err.Error())
	} else if snapshot.IdentityDigest != identityDigest {
		reasons = append(reasons, "identity digest is missing or does not match stable fields")
	}
	return errors.Join(stringErrors(reasons)...)
}

// ValidatePair requires stable host identity and exact qdisc restoration.
func ValidatePair(start, end Snapshot) error {
	var pairErrors []error
	if err := Validate(start); err != nil {
		pairErrors = append(pairErrors, fmt.Errorf("start snapshot: %w", err))
	}
	if err := Validate(end); err != nil {
		pairErrors = append(pairErrors, fmt.Errorf("end snapshot: %w", err))
	}
	if start.IdentityDigest != "" && end.IdentityDigest != "" && start.IdentityDigest != end.IdentityDigest {
		pairErrors = append(pairErrors, fmt.Errorf(
			"stable environment identity changed: start=%s end=%s",
			start.IdentityDigest, end.IdentityDigest,
		))
	}
	if start.QDisc.Supported != end.QDisc.Supported || start.QDisc.Digest != end.QDisc.Digest {
		pairErrors = append(pairErrors, fmt.Errorf(
			"qdisc state was not restored: start=%s end=%s",
			start.QDisc.Digest, end.QDisc.Digest,
		))
	}
	return errors.Join(pairErrors...)
}

// Marshal returns the deterministic JSON representation persisted in reports.
func Marshal(snapshot Snapshot) (string, error) {
	b, err := json.Marshal(snapshot)
	if err != nil {
		return "", fmt.Errorf("marshal environment snapshot: %w", err)
	}
	return string(b), nil
}

// IsZero reports whether no environment snapshot has been captured.
func (snapshot Snapshot) IsZero() bool {
	return snapshot.SchemaVersion == 0
}

func validateLinuxSysctls(sysctls []Sysctl) []string {
	var reasons []string
	if !sort.SliceIsSorted(sysctls, func(i, j int) bool { return sysctls[i].Name < sysctls[j].Name }) {
		reasons = append(reasons, "socket sysctls are not deterministic")
	}
	want := make(map[string]bool, len(mandatoryLinuxSysctls))
	for _, name := range mandatoryLinuxSysctls {
		want[name] = true
	}
	seen := make(map[string]bool, len(sysctls))
	for _, sysctl := range sysctls {
		if sysctl.Name == "" || sysctl.Value == "" {
			reasons = append(reasons, "socket sysctls contain an incomplete entry")
		}
		if seen[sysctl.Name] {
			reasons = append(reasons, fmt.Sprintf("socket sysctl %q is duplicated", sysctl.Name))
		}
		seen[sysctl.Name] = true
		if !want[sysctl.Name] {
			reasons = append(reasons, fmt.Sprintf("unexpected socket sysctl %q", sysctl.Name))
		}
	}
	for _, name := range mandatoryLinuxSysctls {
		if !seen[name] {
			reasons = append(reasons, fmt.Sprintf("mandatory socket sysctl %q is missing", name))
		}
	}
	return reasons
}

func computeIdentityDigest(snapshot Snapshot) (string, error) {
	identity := struct {
		SchemaVersion    int         `json:"schema_version"`
		Runtime          Runtime     `json:"runtime"`
		Hostname         string      `json:"hostname"`
		KernelRelease    string      `json:"kernel_release,omitempty"`
		BootID           string      `json:"boot_id,omitempty"`
		NumCPU           int         `json:"num_cpu"`
		CPU              CPU         `json:"cpu"`
		TotalMemoryBytes uint64      `json:"total_memory_bytes,omitempty"`
		Clocksource      string      `json:"clocksource,omitempty"`
		Interfaces       []Interface `json:"interfaces"`
		SocketSysctls    []Sysctl    `json:"socket_sysctls"`
		QDiscSupported   bool        `json:"qdisc_supported"`
		Metadata         Metadata    `json:"metadata"`
	}{
		SchemaVersion:    snapshot.SchemaVersion,
		Runtime:          snapshot.Runtime,
		Hostname:         snapshot.Hostname,
		KernelRelease:    snapshot.KernelRelease,
		BootID:           snapshot.BootID,
		NumCPU:           snapshot.NumCPU,
		CPU:              snapshot.CPU,
		TotalMemoryBytes: snapshot.TotalMemoryBytes,
		Clocksource:      snapshot.Clocksource,
		Interfaces:       snapshot.Interfaces,
		SocketSysctls:    snapshot.SocketSysctls,
		QDiscSupported:   snapshot.QDisc.Supported,
		Metadata:         snapshot.Metadata,
	}
	b, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("marshal stable environment identity: %w", err)
	}
	return digest(b), nil
}

func canonicalQDisc(raw []byte) (json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil, errors.New("qdisc state must be a JSON array")
	}
	var entries []any
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	canonicalEntries := make([]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		encoded, err := json.Marshal(entry)
		if err != nil {
			return nil, err
		}
		canonicalEntries = append(canonicalEntries, encoded)
	}
	sort.Slice(canonicalEntries, func(i, j int) bool {
		return bytes.Compare(canonicalEntries[i], canonicalEntries[j]) < 0
	})
	encoded, err := json.Marshal(canonicalEntries)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func normalizeValue(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func captureMetadata() Metadata {
	return Metadata{
		VMRole:   os.Getenv(VMRoleEnv),
		CPUGroup: os.Getenv(CPUGroupEnv),
	}
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return fmt.Sprintf("sha256:%x", sum[:])
}

func stringErrors(reasons []string) []error {
	errs := make([]error, 0, len(reasons))
	for _, reason := range reasons {
		errs = append(errs, errors.New(reason))
	}
	return errs
}
