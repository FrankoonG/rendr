package tunfull

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/FrankoonG/rendr/virtualif"
)

const (
	kernelTUNProbeSchema = 1

	kernelTUNProbePositive = "positive-packet-io"
	kernelTUNProbeNegative = "negative-no-cap-net-admin"

	kernelTUNHelperArgPrefix  = "--rendr-tunfull-kernel-probe="
	kernelTUNHelperModeEnv    = "RENDR_TUNFULL_KERNEL_PROBE_MODE"
	kernelTUNHelperNonceEnv   = "RENDR_TUNFULL_KERNEL_PROBE_NONCE"
	kernelTUNHelperLinePrefix = "RENDR_TUNFULL_KERNEL_PROBE_V1 "

	kernelTUNPositiveLimit = 8 * time.Second
	kernelTUNNegativeLimit = 4 * time.Second
)

type kernelTUNProbeResult struct {
	Schema int    `json:"schema"`
	Mode   string `json:"mode"`
	Nonce  string `json:"nonce"`

	Completed bool `json:"completed"`
	// Bounded, TimedOut, ProcessError, and CleanupVerified are parent-owned;
	// the helper cannot self-attest the controls that make its result valid.
	Bounded      bool   `json:"-"`
	TimedOut     bool   `json:"-"`
	ProcessError string `json:"-"`

	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Stage     string `json:"stage,omitempty"`
	Detail    string `json:"detail,omitempty"`

	DeviceOpened        bool   `json:"device_opened,omitempty"`
	InterfaceCreated    bool   `json:"interface_created,omitempty"`
	InterfaceName       string `json:"interface_name,omitempty"`
	KernelPacketRead    bool   `json:"kernel_packet_read,omitempty"`
	KernelPacketWrite   bool   `json:"kernel_packet_write,omitempty"`
	PacketIntegrity     bool   `json:"packet_integrity,omitempty"`
	ReadBytes           int    `json:"read_bytes,omitempty"`
	WriteBytes          int    `json:"write_bytes,omitempty"`
	CleanupAttempted    bool   `json:"cleanup_attempted,omitempty"`
	CleanupCloseOK      bool   `json:"cleanup_close_ok,omitempty"`
	CleanupVerified     bool   `json:"-"`
	CapabilitiesDropped bool   `json:"capabilities_dropped,omitempty"`
	CAPNetAdminPresent  bool   `json:"cap_net_admin_present,omitempty"`
	DurationMillis      int64  `json:"duration_ms"`
}

type kernelTUNGateResult struct {
	Positive kernelTUNProbeResult
	Negative kernelTUNProbeResult
}

var executeKernelTUNProbe = executeKernelTUNProbePlatform

func init() {
	mode, nonce, ok := kernelTUNHelperInvocation(os.Args, os.Getenv)
	if !ok {
		return
	}

	started := time.Now()
	result := runKernelTUNProbeHelper(mode, nonce)
	result.Schema = kernelTUNProbeSchema
	result.Mode = mode
	result.Nonce = nonce
	result.DurationMillis = time.Since(started).Milliseconds()
	encoded, err := json.Marshal(result)
	if err != nil {
		os.Exit(125)
	}
	if _, err := fmt.Fprintf(os.Stdout, "%s%s\n", kernelTUNHelperLinePrefix, encoded); err != nil {
		os.Exit(125)
	}
	os.Exit(0)
}

func kernelTUNHelperInvocation(args []string, getenv func(string) string) (mode, nonce string, ok bool) {
	if len(args) != 2 || !strings.HasPrefix(args[1], kernelTUNHelperArgPrefix) {
		return "", "", false
	}
	nonce = strings.TrimPrefix(args[1], kernelTUNHelperArgPrefix)
	if nonce == "" || nonce != getenv(kernelTUNHelperNonceEnv) {
		return "", "", false
	}
	mode = getenv(kernelTUNHelperModeEnv)
	if mode != kernelTUNProbePositive && mode != kernelTUNProbeNegative {
		return "", "", false
	}
	return mode, nonce, true
}

func runKernelTUNGate(ctx context.Context) kernelTUNGateResult {
	positiveCtx, cancelPositive := context.WithTimeout(ctx, kernelTUNPositiveLimit)
	positive := executeKernelTUNProbe(positiveCtx, kernelTUNProbePositive)
	cancelPositive()

	negativeCtx, cancelNegative := context.WithTimeout(ctx, kernelTUNNegativeLimit)
	negative := executeKernelTUNProbe(negativeCtx, kernelTUNProbeNegative)
	cancelNegative()

	return kernelTUNGateResult{Positive: positive, Negative: negative}
}

func validateKernelTUNGate(result kernelTUNGateResult) string {
	positive := result.Positive
	if !positive.Bounded {
		return "positive kernel TUN packet probe had no execution bound"
	}
	if positive.TimedOut {
		return fmt.Sprintf("positive kernel TUN packet probe exceeded %s", kernelTUNPositiveLimit)
	}
	if positive.ProcessError != "" {
		return "positive kernel TUN packet probe process failed: " + positive.ProcessError
	}
	if !positive.Completed {
		return "positive kernel TUN packet probe returned no completed result"
	}
	if !positive.Available {
		return probeUnavailableReason("kernel TUN positive probe unavailable", positive)
	}
	if !positive.DeviceOpened {
		return "kernel TUN positive probe did not prove /dev/net/tun open"
	}
	if !positive.InterfaceCreated {
		return "kernel TUN positive probe did not prove TUNSETIFF interface creation"
	}
	if !positive.KernelPacketRead {
		return "kernel TUN positive probe did not observe a kernel-emitted packet on the TUN fd"
	}
	if !positive.KernelPacketWrite {
		return "kernel TUN positive probe did not observe an injected TUN packet at a kernel UDP socket"
	}
	if !positive.PacketIntegrity || positive.ReadBytes <= 0 || positive.WriteBytes <= 0 {
		return "kernel TUN positive probe did not establish bidirectional packet integrity"
	}
	if !positive.CleanupAttempted || !positive.CleanupCloseOK || !positive.CleanupVerified {
		return "kernel TUN positive probe could not verify deterministic interface cleanup"
	}

	negative := result.Negative
	if !negative.Bounded {
		return "negative kernel TUN capability control had no execution bound"
	}
	if negative.TimedOut {
		return fmt.Sprintf("negative kernel TUN capability control exceeded %s", kernelTUNNegativeLimit)
	}
	if negative.ProcessError != "" {
		return "negative kernel TUN capability control process failed: " + negative.ProcessError
	}
	if !negative.Completed {
		return "negative kernel TUN capability control returned no completed result"
	}
	if !negative.CapabilitiesDropped || negative.CAPNetAdminPresent {
		return "negative kernel TUN capability control did not prove CAP_NET_ADMIN was absent"
	}
	if negative.Available {
		return "negative kernel TUN capability control false-green: TUN creation succeeded without CAP_NET_ADMIN"
	}
	if negative.Reason != string(virtualif.ReasonTUNPermissionDenied) {
		return probeUnavailableReason("negative kernel TUN capability control did not observe permission denial", negative)
	}
	return ""
}

func kernelTUNGateEvidence(result kernelTUNGateResult) map[string]string {
	positive := result.Positive
	negative := result.Negative
	gatePassed := validateKernelTUNGate(result) == ""
	return map[string]string{
		"kernel_tun_available":                  strconv.FormatBool(positive.Available),
		"kernel_tun_environment_gate_pass":      strconv.FormatBool(gatePassed),
		"kernel_tun_packet_io":                  strconv.FormatBool(kernelTUNPacketIOObserved(positive)),
		"kernel_tun_probe_completed":            strconv.FormatBool(positive.Completed),
		"kernel_tun_reason":                     positive.Reason,
		"kernel_tun_probe_stage":                positive.Stage,
		"kernel_tun_probe_detail":               boundedKernelTUNDetail(positive.Detail),
		"kernel_tun_probe_bounded":              strconv.FormatBool(positive.Bounded),
		"kernel_tun_probe_timed_out":            strconv.FormatBool(positive.TimedOut),
		"kernel_tun_probe_timeout_ms":           strconv.FormatInt(kernelTUNPositiveLimit.Milliseconds(), 10),
		"kernel_tun_probe_duration_ms":          strconv.FormatInt(positive.DurationMillis, 10),
		"kernel_tun_device_open":                strconv.FormatBool(positive.DeviceOpened),
		"kernel_tun_interface_created":          strconv.FormatBool(positive.InterfaceCreated),
		"kernel_tun_interface":                  positive.InterfaceName,
		"kernel_tun_fd_read_from_kernel":        strconv.FormatBool(positive.KernelPacketRead),
		"kernel_tun_fd_write_to_kernel":         strconv.FormatBool(positive.KernelPacketWrite),
		"kernel_tun_packet_integrity":           strconv.FormatBool(positive.PacketIntegrity),
		"kernel_tun_read_bytes":                 strconv.Itoa(positive.ReadBytes),
		"kernel_tun_write_bytes":                strconv.Itoa(positive.WriteBytes),
		"kernel_tun_cleanup_attempted":          strconv.FormatBool(positive.CleanupAttempted),
		"kernel_tun_cleanup_close_ok":           strconv.FormatBool(positive.CleanupCloseOK),
		"kernel_tun_cleanup_verified":           strconv.FormatBool(positive.CleanupVerified),
		"kernel_tun_negative_bounded":           strconv.FormatBool(negative.Bounded),
		"kernel_tun_negative_completed":         strconv.FormatBool(negative.Completed),
		"kernel_tun_negative_timed_out":         strconv.FormatBool(negative.TimedOut),
		"kernel_tun_negative_timeout_ms":        strconv.FormatInt(kernelTUNNegativeLimit.Milliseconds(), 10),
		"kernel_tun_negative_duration_ms":       strconv.FormatInt(negative.DurationMillis, 10),
		"kernel_tun_negative_caps_dropped":      strconv.FormatBool(negative.CapabilitiesDropped),
		"kernel_tun_negative_cap_net_admin":     strconv.FormatBool(negative.CAPNetAdminPresent),
		"kernel_tun_negative_available":         strconv.FormatBool(negative.Available),
		"kernel_tun_negative_reason":            negative.Reason,
		"kernel_tun_negative_detail":            boundedKernelTUNDetail(negative.Detail),
		"kernel_tun_negative_cleanup_attempted": strconv.FormatBool(negative.CleanupAttempted),
		"kernel_tun_negative_cleanup_close_ok":  strconv.FormatBool(negative.CleanupCloseOK),
		"kernel_tun_negative_cleanup_verified":  strconv.FormatBool(negative.CleanupVerified),
		"kernel_tun_negative_control_pass":      strconv.FormatBool(kernelTUNNegativeControlPassed(negative)),
	}
}

func kernelTUNNegativeControlPassed(result kernelTUNProbeResult) bool {
	return result.Bounded && !result.TimedOut && result.ProcessError == "" && result.Completed &&
		result.CapabilitiesDropped && !result.CAPNetAdminPresent && !result.Available &&
		result.Reason == string(virtualif.ReasonTUNPermissionDenied)
}

func kernelTUNPacketIOObserved(result kernelTUNProbeResult) bool {
	return result.Completed && result.Available && result.DeviceOpened && result.InterfaceCreated &&
		result.KernelPacketRead && result.KernelPacketWrite && result.PacketIntegrity &&
		result.ReadBytes > 0 && result.WriteBytes > 0
}

func probeUnavailableReason(prefix string, result kernelTUNProbeResult) string {
	parts := make([]string, 0, 3)
	if result.Stage != "" {
		parts = append(parts, result.Stage)
	}
	if result.Reason != "" {
		parts = append(parts, result.Reason)
	}
	if result.Detail != "" {
		parts = append(parts, result.Detail)
	}
	if len(parts) == 0 {
		parts = append(parts, "no machine-readable reason")
	}
	return prefix + ": " + strings.Join(parts, ": ")
}

func newKernelTUNProbeNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func parseKernelTUNHelperOutput(output []byte, mode, nonce string) (kernelTUNProbeResult, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var encoded string
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, kernelTUNHelperLinePrefix) {
			continue
		}
		if found {
			return kernelTUNProbeResult{}, fmt.Errorf("multiple structured probe results")
		}
		found = true
		encoded = strings.TrimPrefix(line, kernelTUNHelperLinePrefix)
	}
	if err := scanner.Err(); err != nil {
		return kernelTUNProbeResult{}, fmt.Errorf("scan probe result: %w", err)
	}
	if !found || encoded == "" {
		return kernelTUNProbeResult{}, fmt.Errorf("structured probe result missing")
	}

	var result kernelTUNProbeResult
	if err := json.Unmarshal([]byte(encoded), &result); err != nil {
		return kernelTUNProbeResult{}, fmt.Errorf("decode probe result: %w", err)
	}
	if result.Schema != kernelTUNProbeSchema {
		return kernelTUNProbeResult{}, fmt.Errorf("probe schema=%d, want %d", result.Schema, kernelTUNProbeSchema)
	}
	if result.Mode != mode {
		return kernelTUNProbeResult{}, fmt.Errorf("probe mode=%q, want %q", result.Mode, mode)
	}
	if result.Nonce != nonce {
		return kernelTUNProbeResult{}, fmt.Errorf("probe nonce mismatch")
	}
	return result, nil
}

func boundedKernelTUNDetail(detail string) string {
	const limit = 512
	detail = strings.TrimSpace(detail)
	if len(detail) <= limit {
		return detail
	}
	return detail[:limit] + " [truncated]"
}
