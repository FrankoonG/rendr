//go:build linux

package tier5

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
	"github.com/FrankoonG/rendr/transport/gvisor"
	"github.com/FrankoonG/rendr/transport/tcprepair"
)

func TestTier5TCPRepairUnprivilegedPreflight(t *testing.T) {
	const caseID = "T5.3-tcprepair-unprivileged"
	evidence := newLinuxProbeEvidence(caseID)
	defer emitLinuxProbeEvidence(t, evidence)

	evidence["behavior"] = "tcp_repair_preflight_capability_probe"
	evidence["fallback_outcome"] = "not_exercised"
	evidence["gvisor_involved"] = "false"
	evidence["kernel_tcp_to_gvisor_conversion"] = "false"
	if !captureUnprivilegedCapabilityEvidence(evidence) {
		return
	}

	err := tcprepair.Available()
	class, typed := classifyTCPRepairError(err)
	evidence["tcp_repair_preflight"] = class
	evidence["preflight_error_typed_eperm"] = strconv.FormatBool(typed)
	evidence["preflight_error_mentions_gvisor"] = strconv.FormatBool(errorMentionsGVisor(err))
	if err == nil {
		t.Error("TCP_REPAIR preflight unexpectedly succeeded without CAP_NET_ADMIN")
		return
	}
	if class != "permission_denied" {
		invalidateProbePrerequisite(evidence, "TCP_REPAIR permission-denial stimulus unavailable")
	}
}

func TestTier5GVisorOwnedSessionUnprivileged(t *testing.T) {
	const caseID = "T5.4-gvisor-unprivileged"
	evidence := newLinuxProbeEvidence(caseID)
	defer emitLinuxProbeEvidence(t, evidence)

	evidence["behavior"] = "gvisor_owned_process_local_session"
	evidence["fallback_relation"] = "independent_gvisor_session"
	evidence["group_executor"] = "legacy_prime"
	evidence["gvisor_endpoint_owner"] = "gvisor_from_session_start"
	evidence["gvisor_packet_link_rebind_observed"] = "false"
	evidence["kernel_tcp_to_gvisor_conversion"] = "false"
	evidence["leaf_mobility"] = "framed_path_switch"
	evidence["outer_carrier"] = "process_local_veth"
	evidence["session_protocol"] = fmt.Sprintf("framed_stream_v%d", proto.Version)
	if !captureUnprivilegedCapabilityEvidence(evidence) {
		return
	}
	runGVisorOwnedSessionSmoke(t, evidence, "gvisor")
}

func TestTier5TCPRepairFailureRequiresNegotiatedFallback(t *testing.T) {
	const caseID = "T5.5-tcprepair-gvisor-fallback-unprivileged"
	evidence := newLinuxProbeEvidence(caseID)
	defer emitLinuxProbeEvidence(t, evidence)

	evidence["attach_negotiation"] = "not_attempted"
	evidence["behavior"] = "tcp_repair_failure_to_same_session_redial_attach"
	evidence["fallback_outcome"] = "not_attempted"
	evidence["fallback_selection"] = "regression_orchestrated_after_failure"
	evidence["group_executor"] = "legacy_prime"
	evidence["gvisor_involved"] = "false"
	evidence["kernel_tcp_to_gvisor_conversion"] = "false"
	evidence["leaf_mobility"] = "not_selected"
	evidence["original_socket_usable_after_preflight"] = "false"
	evidence["original_socket_usable_after_prepare_failure"] = "false"
	evidence["post_fallback_payload_ok"] = "false"
	evidence["product_mobility_plan_observable"] = "false"
	evidence["same_session_flow_id_stable"] = "false"
	evidence["session_protocol"] = fmt.Sprintf("framed_stream_v%d", proto.Version)
	evidence["typed_failure_observed"] = "false"
	if !captureUnprivilegedCapabilityEvidence(evidence) {
		return
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	listener, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan tier5AcceptResult, 1)
	go func() {
		conn, acceptErr := listener.Accept(ctx)
		accepted <- tier5AcceptResult{conn: conn, err: acceptErr}
	}()

	const factoryName = "tier5-generic-tcp-redial"
	tracker := &tier5TCPFactoryTracker{}
	spec := rendr.PathSpec{Transport: factoryName, Address: listener.Addr().String()}
	dialer := &rendr.Dialer{
		Mode:  rendr.ModePrime,
		Paths: []rendr.PathSpec{spec},
		Dwell: time.Hour,
	}
	if err := dialer.AddStreamPathFactory(factoryName, tracker.dial); err != nil {
		t.Fatalf("register stream factory: %v", err)
	}
	client, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatalf("dial initial session: %v", err)
	}
	defer client.Close()

	var server rendr.Conn
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatalf("accept initial session: %v", result.err)
		}
		server = result.conn
	case <-ctx.Done():
		t.Fatalf("accept initial session: %v", ctx.Err())
	}
	defer server.Close()

	admin, ok := client.(rendr.AdminConn)
	if !ok {
		t.Fatal("client does not implement rendr.AdminConn")
	}
	initialFlowID := client.FlowID()
	if initialFlowID == ([16]byte{}) || server.FlowID() != initialFlowID {
		t.Fatal("initial client/server flow identity was not negotiated")
	}
	evidence["same_session_flow_id_stable"] = "true"
	initialPathID := admin.ActivePath()
	initialTCP := tracker.conn(0)
	if initialTCP == nil {
		t.Fatal("stream factory did not retain the initial TCP socket")
	}

	if err := tier5StreamRoundTrip(client, server, "before-tcp-repair-probes"); err != nil {
		t.Fatalf("initial payload round trip: %v", err)
	}
	preflightErr := tcprepair.Available()
	preflightClass, preflightTyped := classifyTCPRepairError(preflightErr)
	evidence["tcp_repair_preflight"] = preflightClass
	evidence["preflight_error_typed_eperm"] = strconv.FormatBool(preflightTyped)
	if preflightErr == nil {
		t.Error("TCP_REPAIR preflight unexpectedly succeeded without CAP_NET_ADMIN")
		return
	}
	if preflightClass != "permission_denied" {
		invalidateProbePrerequisite(evidence, "TCP_REPAIR preflight permission-denial stimulus unavailable")
		return
	}
	if err := tier5StreamRoundTrip(client, server, "after-tcp-repair-preflight"); err != nil {
		t.Fatalf("original socket unusable after preflight failure: %v", err)
	}
	evidence["original_socket_usable_after_preflight"] = "true"

	_, prepareErr := tcprepair.Snapshot(initialTCP)
	prepareClass, prepareTyped := classifyTCPRepairError(prepareErr)
	evidence["tcp_repair_prepare"] = prepareClass
	evidence["prepare_error_typed_eperm"] = strconv.FormatBool(prepareTyped)
	if prepareErr == nil {
		t.Error("TCP_REPAIR prepare unexpectedly succeeded without CAP_NET_ADMIN")
		return
	}
	if prepareClass != "permission_denied" {
		invalidateProbePrerequisite(evidence, "TCP_REPAIR prepare permission-denial stimulus unavailable")
		return
	}
	if admin.ActivePath() != initialPathID {
		t.Fatalf("active path changed during failed prepare: got %d want %d", admin.ActivePath(), initialPathID)
	}
	if err := tier5StreamRoundTrip(client, server, "after-tcp-repair-prepare-failure"); err != nil {
		t.Fatalf("original socket unusable after prepare failure: %v", err)
	}
	evidence["original_socket_usable_after_prepare_failure"] = "true"

	migrationsBefore := admin.MigrationCount()
	newPathID, err := admin.AddPath(spec)
	if err != nil {
		evidence["fallback_outcome"] = "manual_redial_attach_failed"
		t.Fatalf("regression-orchestrated redial/attach failed: %v", err)
	}

	if !waitForTier5PathCounts(ctx, client, server, 2) {
		t.Fatalf("redialed path did not attach: client=%d server=%d", len(client.Paths()), len(server.Paths()))
	}
	evidence["client_path_count"] = strconv.Itoa(len(client.Paths()))
	evidence["server_path_count"] = strconv.Itoa(len(server.Paths()))
	evidence["factory_dials"] = strconv.Itoa(tracker.count())
	flows := listener.FlowIDs()
	evidence["listener_flow_count"] = strconv.Itoa(len(flows))
	flowStable := client.FlowID() == initialFlowID && server.FlowID() == initialFlowID &&
		len(flows) == 1 && flows[0] == initialFlowID
	evidence["same_session_flow_id_stable"] = strconv.FormatBool(flowStable)
	if !flowStable {
		t.Fatal("redial/attach did not preserve exactly one negotiated flow identity")
	}
	if tracker.count() != 2 {
		t.Fatalf("stream factory dial count=%d, want exactly 2", tracker.count())
	}

	if err := admin.Migrate(newPathID); err != nil {
		t.Fatalf("migrate to redialed path: %v", err)
	}
	if admin.ActivePath() != newPathID {
		t.Fatalf("active path=%d, want redialed path %d", admin.ActivePath(), newPathID)
	}
	if err := tier5StreamRoundTrip(client, server, "after-same-session-redial-attach"); err != nil {
		t.Fatalf("post-fallback payload round trip: %v", err)
	}
	migrationDelta := admin.MigrationCount() - migrationsBefore
	evidence["migration_count_delta"] = strconv.FormatUint(migrationDelta, 10)
	evidence["attach_negotiation"] = "bridge_tag_existing_flow"
	evidence["fallback_outcome"] = "manual_same_session_redial_attach"
	evidence["leaf_mobility"] = "redial_attach"
	evidence["post_fallback_payload_ok"] = "true"
}

func TestTier5GVisorPacketCarrierOwnedSessionUnprivileged(t *testing.T) {
	const caseID = "T5.6-gvisor-packet-carrier-unprivileged"
	evidence := newLinuxProbeEvidence(caseID)
	defer emitLinuxProbeEvidence(t, evidence)

	evidence["behavior"] = "gvisor_owned_udp_packet_carrier_session"
	evidence["fallback_relation"] = "independent_gvisor_session"
	evidence["group_executor"] = "legacy_prime"
	evidence["gvisor_endpoint_owner"] = "gvisor_from_session_start"
	evidence["gvisor_packet_link_rebind_observed"] = "false"
	evidence["kernel_tcp_to_gvisor_conversion"] = "false"
	evidence["leaf_mobility"] = "framed_path_switch_between_gvisor_owned_leaves"
	evidence["outer_carrier"] = "udp"
	evidence["session_protocol"] = fmt.Sprintf("framed_stream_v%d", proto.Version)
	if !captureUnprivilegedCapabilityEvidence(evidence) {
		return
	}
	runGVisorOwnedSessionSmoke(t, evidence, "gvisor-packet")
}

func newLinuxProbeEvidence(caseID string) map[string]string {
	return map[string]string{
		"case_id":            caseID,
		"goos":               runtime.GOOS,
		"prerequisite_valid": "false",
		"schema":             tier5EvidenceSchema,
	}
}

func emitLinuxProbeEvidence(t *testing.T, evidence map[string]string) {
	t.Helper()
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Errorf("encode structured probe evidence: %v", err)
		return
	}
	t.Logf("%s%s", tier5EvidenceMarker, encoded)
}

func captureUnprivilegedCapabilityEvidence(evidence map[string]string) bool {
	evidence["capability_source"] = "proc_self_status"
	evidence["euid"] = strconv.Itoa(os.Geteuid())
	contents, err := os.ReadFile("/proc/self/status")
	if err != nil {
		invalidateProbePrerequisite(evidence, "cannot read process capability status")
		return false
	}

	wanted := map[string]string{
		"CapInh": "cap_inh",
		"CapPrm": "cap_prm",
		"CapEff": "cap_eff",
		"CapBnd": "cap_bnd",
		"CapAmb": "cap_amb",
	}
	values := make(map[string]uint64, len(wanted))
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		evidenceKey, ok := wanted[key]
		if !ok {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 16, 64)
		if parseErr != nil {
			invalidateProbePrerequisite(evidence, "cannot parse process capability status")
			return false
		}
		values[evidenceKey] = value
		evidence[evidenceKey] = fmt.Sprintf("0x%016x", value)
	}
	if len(values) != len(wanted) {
		invalidateProbePrerequisite(evidence, "process capability status is incomplete")
		return false
	}

	const netAdminMask = uint64(1) << capNetAdminBit
	var retained []string
	for _, key := range []string{"cap_inh", "cap_prm", "cap_eff", "cap_bnd", "cap_amb"} {
		if values[key]&netAdminMask != 0 {
			retained = append(retained, key)
		}
	}
	absent := len(retained) == 0
	evidence["cap_net_admin_absent"] = strconv.FormatBool(absent)
	evidence["setpriv_capability_drop_observed"] = strconv.FormatBool(absent)
	if !absent {
		invalidateProbePrerequisite(evidence, "CAP_NET_ADMIN retained in "+strings.Join(retained, ","))
		return false
	}
	evidence["prerequisite_valid"] = "true"
	delete(evidence, "prerequisite_error")
	return true
}

func invalidateProbePrerequisite(evidence map[string]string, reason string) {
	evidence["prerequisite_valid"] = "false"
	evidence["prerequisite_error"] = reason
}

func classifyTCPRepairError(err error) (class string, typedPermission bool) {
	if err == nil {
		return "success", false
	}
	typedPermission = errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
	if typedPermission || strings.Contains(err.Error(), "CAP_NET_ADMIN required") {
		return "permission_denied", typedPermission
	}
	if errors.Is(err, syscall.ENOPROTOOPT) || errors.Is(err, syscall.EOPNOTSUPP) ||
		strings.Contains(err.Error(), "requires Linux") || strings.Contains(err.Error(), "not supported") {
		return "unsupported", false
	}
	return "other_error", false
}

func errorMentionsGVisor(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "gvisor")
}

func runGVisorOwnedSessionSmoke(t *testing.T, evidence map[string]string, transportName string) {
	t.Helper()
	if err := gvisor.Available(); err != nil {
		evidence["workload_result"] = "adapter_unavailable"
		t.Errorf("gVisor adapter unavailable: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	result := smoke.RunG1(ctx, smoke.G1Opts{
		Size:       4 << 20,
		Migrations: 2,
		Paths:      2,
		Transport:  transportName,
	})
	evidence["migration_calls_fired"] = fmt.Sprint(result.Detail["migration_calls_fired"])
	evidence["migrations_observed"] = fmt.Sprint(result.Detail["migrations_done"])
	evidence["requested_migrations"] = fmt.Sprint(result.Detail["requested_migrations"])
	evidence["sha256_match"] = fmt.Sprint(result.Detail["sha256_match"])
	switch {
	case result.InvalidReason != "":
		evidence["workload_result"] = "invalid"
		t.Errorf("gVisor-owned session smoke invalid: %s", result.InvalidReason)
	case result.Failure != "":
		evidence["workload_result"] = "fail"
		t.Errorf("gVisor-owned session smoke failed: %s", result.Failure)
	default:
		evidence["workload_result"] = "pass"
	}
}

type tier5AcceptResult struct {
	conn rendr.Conn
	err  error
}

type tier5TCPFactoryTracker struct {
	mu    sync.Mutex
	conns []*net.TCPConn
}

func (t *tier5TCPFactoryTracker) dial(ctx context.Context, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{KeepAlive: -1}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("tier5 stream factory returned %T, want *net.TCPConn", conn)
	}
	_ = tcpConn.SetKeepAlive(false)
	t.mu.Lock()
	t.conns = append(t.conns, tcpConn)
	t.mu.Unlock()
	return tcpConn, nil
}

func (t *tier5TCPFactoryTracker) conn(index int) *net.TCPConn {
	t.mu.Lock()
	defer t.mu.Unlock()
	if index < 0 || index >= len(t.conns) {
		return nil
	}
	return t.conns[index]
}

func (t *tier5TCPFactoryTracker) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

func tier5StreamRoundTrip(client, server net.Conn, value string) error {
	deadline := time.Now().Add(5 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		return fmt.Errorf("client deadline: %w", err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		return fmt.Errorf("server deadline: %w", err)
	}
	defer func() {
		_ = client.SetDeadline(time.Time{})
		_ = server.SetDeadline(time.Time{})
	}()

	payload := []byte(value)
	if err := writeTier5All(client, payload); err != nil {
		return fmt.Errorf("client write: %w", err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(server, received); err != nil {
		return fmt.Errorf("server read: %w", err)
	}
	if string(received) != value {
		return fmt.Errorf("server payload=%q, want %q", received, value)
	}
	if err := writeTier5All(server, received); err != nil {
		return fmt.Errorf("server write: %w", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(client, echoed); err != nil {
		return fmt.Errorf("client read: %w", err)
	}
	if string(echoed) != value {
		return fmt.Errorf("client payload=%q, want %q", echoed, value)
	}
	return nil
}

func writeTier5All(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func waitForTier5PathCounts(ctx context.Context, client, server rendr.Conn, want int) bool {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if len(client.Paths()) == want && len(server.Paths()) == want {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}
