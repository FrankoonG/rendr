package rendr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	basetcp "github.com/FrankoonG/rendr/transport/tcp"
)

func TestProbeLocalReportsOnlyCoreCapabilities(t *testing.T) {
	st, err := ProbeLocal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := CapabilitySet{CapRendr, CapL7, CapPacketMode}
	if !reflect.DeepEqual(st.Caps, want) {
		t.Fatalf("caps=%v want exact core set %v", st.Caps, want)
	}

	adapterCapabilities := []CapabilityID{
		"tcp_repair",
		"gvisor",
		"tun",
		"mixed",
		"quic_datagram",
	}
	for _, adapterCapability := range adapterCapabilities {
		filtered, err := ProbeLocal(context.Background(), adapterCapability)
		if err != nil {
			t.Fatal(err)
		}
		if len(filtered.Caps) != 0 {
			t.Fatalf("adapter capability %q leaked from root probe: %v", adapterCapability, filtered.Caps)
		}
	}

	unknown, err := ProbeLocal(context.Background(), CapabilityID("unknown-capability"))
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown.Caps) != 0 {
		t.Fatalf("unknown capability filter leaked core capabilities: %v", unknown.Caps)
	}
	duplicate, err := ProbeLocal(context.Background(), CapRendr, CapRendr)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(duplicate.Caps, CapabilitySet{CapRendr}) {
		t.Fatalf("duplicate filter result=%v want one rendr capability", duplicate.Caps)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProbeLocal(canceled); err != context.Canceled {
		t.Fatalf("canceled probe error=%v want context.Canceled", err)
	}

	capabilities := make([]string, len(st.Caps))
	for i, capability := range st.Caps {
		capabilities[i] = string(capability)
	}
	sort.Strings(capabilities)
	evidence := map[string]string{
		"adapter_filter_leaks":          "0",
		"adapter_filter_queries":        "5",
		"canceled_context_typed":        "true",
		"capabilities":                  strings.Join(capabilities, ","),
		"capability_count":              "3",
		"case_id":                       "T8.status.local-default",
		"duplicate_filter_deduplicated": "true",
		"evidence_schema":               "tier8-local-status-v1",
		"negative_control_id":           "adapter-filter-and-cancel-v1",
		"probe_calls":                   "9",
		"structured_evidence":           "true",
		"unknown_filter_empty":          "true",
	}
	emitTier8StatusEvidence(t, evidence)
}

func TestRuntimePeerStatusPublicContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverRuntime, err := NewRuntimeContext(ctx, RuntimeConfig{})
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(ListenConfig{Streams: []StreamSource{{
		Name: "ingress", Carrier: CarrierTCP, Listener: raw,
	}}})
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	listenerClosed := false
	t.Cleanup(func() {
		if !listenerClosed {
			_ = listener.Close()
		}
	})

	clientRuntime, err := NewRuntimeContext(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientRuntime.Dial(ctx, SessionConfig{Root: Path("A", PathSpec{
		Transport: "tcp", Address: raw.Addr().String(),
	})})
	if err != nil {
		t.Fatal(err)
	}
	clientClosed := false
	t.Cleanup(func() {
		if !clientClosed {
			_ = client.Close()
		}
	})
	server, err := listener.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	serverClosed := false
	t.Cleanup(func() {
		if !serverClosed {
			_ = server.Close()
		}
	})

	clientObject := reflect.ValueOf(client).Pointer()
	serverObject := reflect.ValueOf(server).Pointer()
	clientBefore := client.Status()
	serverBefore := server.Status()
	assertTier8PeerStatus(t, "client", clientBefore)
	assertTier8PeerStatus(t, "server", serverBefore)
	if clientBefore.FlowID == ([16]byte{}) || clientBefore.FlowID != serverBefore.FlowID {
		t.Fatalf("flow identities client=%x server=%x", clientBefore.FlowID, serverBefore.FlowID)
	}
	if len(clientBefore.Paths) != 1 || len(serverBefore.Paths) != 1 {
		t.Fatalf("path counts client=%d server=%d", len(clientBefore.Paths), len(serverBefore.Paths))
	}
	clientPath := clientBefore.Paths[0]
	serverPath := serverBefore.Paths[0]
	if clientPath.State != PathAttached || serverPath.State != PathAttached ||
		clientPath.LocalAddr == "" || clientPath.RemoteAddr == "" || serverPath.LocalAddr == "" || serverPath.RemoteAddr == "" ||
		clientPath.LocalAddr != serverPath.RemoteAddr || clientPath.RemoteAddr != serverPath.LocalAddr {
		t.Fatalf("non-reciprocal attached endpoints client=%+v server=%+v", clientPath, serverPath)
	}

	clientPayload := tier8StatusPayload(0x31, 4<<10)
	serverPayload := tier8StatusPayload(0x73, 4<<10)
	tier8StatusRoundTrip(t, client, server, clientPayload)
	tier8StatusRoundTrip(t, server, client, serverPayload)

	clientAfter := client.Status()
	serverAfter := server.Status()
	assertTier8PeerStatus(t, "client after payload", clientAfter)
	assertTier8PeerStatus(t, "server after payload", serverAfter)
	if clientAfter.FlowID != clientBefore.FlowID || serverAfter.FlowID != serverBefore.FlowID ||
		clientAfter.Peer.InstanceID != clientBefore.Peer.InstanceID || serverAfter.Peer.InstanceID != serverBefore.Peer.InstanceID {
		t.Fatalf("identity changed across payload: client=%+v/%+v server=%+v/%+v",
			clientBefore, clientAfter, serverBefore, serverAfter)
	}
	if reflect.ValueOf(client).Pointer() != clientObject || reflect.ValueOf(server).Pointer() != serverObject {
		t.Fatal("application connection object changed across payload")
	}

	var fakeInstance InstanceID
	fakeInstance[0] = 1
	native := peerStatus(PeerNative, fakeInstance, uint32(proto.CapsPacketMode|proto.CapsL3Identity))
	if native.InstanceID != (InstanceID{}) || len(native.Caps) != 0 {
		t.Fatalf("native peer leaked rendr attributes: %+v", native)
	}

	cleanup := true
	if err := client.Close(); err != nil {
		cleanup = false
	}
	clientClosed = true
	if err := server.Close(); err != nil {
		cleanup = false
	}
	serverClosed = true
	if err := listener.Close(); err != nil {
		cleanup = false
	}
	listenerClosed = true
	if !cleanup {
		t.Fatal("peer status fixture cleanup failed")
	}

	emitTier8StatusEvidence(t, map[string]string{
		"application_errors":            "0",
		"application_objects_stable":    "true",
		"bidirectional_payload_bytes":   "8192",
		"case_id":                       "T8.status.peer-rendr",
		"client_peer_caps":              tier8CapabilityNames(clientAfter.Peer.Caps),
		"client_peer_instance_nonzero":  "true",
		"client_to_server_sha256_match": "true",
		"cleanup_confirmed":             "true",
		"endpoints_reciprocal":          "true",
		"evidence_schema":               "tier8-peer-status-v1",
		"flow_id_equal":                 "true",
		"flow_id_stable":                "true",
		"native_caps_hidden":            "true",
		"native_instance_hidden":        "true",
		"negative_control_id":           "native-peer-redaction-v1",
		"path_count_each":               "1",
		"paths_attached":                "true",
		"peer_instance_stable":          "true",
		"public_runtime_api":            "true",
		"server_peer_caps":              tier8CapabilityNames(serverAfter.Peer.Caps),
		"server_peer_instance_nonzero":  "true",
		"server_to_client_sha256_match": "true",
		"session_protocol":              string(SessionProtocolFramedStreamV3),
		"structured_evidence":           "true",
	})
}

func assertTier8PeerStatus(t *testing.T, side string, status Status) {
	t.Helper()
	if status.Peer.Kind != PeerRendr || status.Peer.InstanceID == (InstanceID{}) {
		t.Fatalf("%s peer status=%+v", side, status.Peer)
	}
	if got := tier8CapabilityNames(status.Peer.Caps); got != "l7,rendr" {
		t.Fatalf("%s peer capabilities=%q", side, got)
	}
	if status.Protocol != SessionProtocolFramedStreamV3 || len(status.EffectivePaths) != 1 {
		t.Fatalf("%s protocol/effective paths=%q/%v", side, status.Protocol, status.EffectivePaths)
	}
}

func tier8StatusRoundTrip(t *testing.T, writer, reader net.Conn, payload []byte) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	if err := writer.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := reader.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	written := 0
	for written < len(payload) {
		n, err := writer.Write(payload[written:])
		if err != nil {
			t.Fatal(err)
		}
		if n <= 0 {
			t.Fatal("zero-length application write")
		}
		written += n
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, received); err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(received) != sha256.Sum256(payload) || !bytes.Equal(received, payload) {
		t.Fatal("peer status payload integrity mismatch")
	}
	_ = writer.SetWriteDeadline(time.Time{})
	_ = reader.SetReadDeadline(time.Time{})
}

func tier8StatusPayload(salt byte, size int) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte((index*37 + int(salt)) % 251)
	}
	return payload
}

func tier8CapabilityNames(capabilities CapabilitySet) string {
	values := make([]string, len(capabilities))
	for index, capability := range capabilities {
		values[index] = string(capability)
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func emitTier8StatusEvidence(t *testing.T, evidence map[string]string) {
	t.Helper()
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RENDR_T8_EVIDENCE_JSON=%s", encoded)
}

func TestProbeLocalHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ProbeLocal(ctx)
	if err != context.Canceled {
		t.Fatalf("error=%v want context.Canceled", err)
	}
}

func TestPeerCapabilitiesRequireExplicitRendrPeer(t *testing.T) {
	bits := uint32(proto.CapsPacketMode | proto.CapsL3Identity)
	var instanceID InstanceID
	instanceID[0] = 1
	for _, kind := range []PeerKind{PeerUnknown, PeerNative} {
		got := peerStatus(kind, instanceID, bits)
		if got.InstanceID != (InstanceID{}) || len(got.Caps) != 0 {
			t.Fatalf("kind=%q status=%+v want no inferred rendr evidence", kind, got)
		}
	}

	want := CapabilitySet{CapRendr, CapL7, CapPacketMode, CapL3Identity}
	got := peerStatus(PeerRendr, instanceID, bits)
	if got.InstanceID != instanceID || !reflect.DeepEqual(got.Caps, want) {
		t.Fatalf("rendr peer status=%+v want instance=%v caps=%v", got, instanceID, want)
	}
}

func TestPathStatusDoesNotDependOnTransportName(t *testing.T) {
	statusFor := func(transportName string) []PathStatus {
		spec := specWithTargetName(PathSpec{
			Transport: transportName,
			Address:   "example.invalid:443",
		}, "leaf")
		return newPathStatusTracker([]PathSpec{spec}, "leaf").snapshot(nil, nil)
	}

	baseline := statusFor("custom")
	for _, adapterName := range []string{"tcprepair", "gvisor", "tun", "quic", "udpflow"} {
		if got := statusFor(adapterName); !reflect.DeepEqual(got, baseline) {
			t.Fatalf("transport %q changed generic path evidence: got=%+v want=%+v", adapterName, got, baseline)
		}
	}

	typ := reflect.TypeOf(PathStatus{})
	for _, removed := range []string{"Transport", "Primary", "Caps"} {
		if _, ok := typ.FieldByName(removed); ok {
			t.Fatalf("PathStatus still exposes adapter/config field %q", removed)
		}
	}
}

func TestAttachedGenericPathHasStableRedialMobilityStatus(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{})
	defer e.Close()
	if _, err := e.AttachPath(basetcp.Wrap(left), transport.PathSpec{Transport: "generic"}); err != nil {
		t.Fatal(err)
	}

	first := statusFromEngine(e, nil, nil)
	second := statusFromEngine(e, nil, nil)
	if len(first.Paths) != 1 || len(second.Paths) != 1 {
		t.Fatalf("path snapshots=%d/%d want=1/1", len(first.Paths), len(second.Paths))
	}
	got := first.Paths[0].Mobility
	if got.ID != MobilityRedialAttach || got.State != MobilityStateBaseline || got.Reason != MobilityReasonEndpointNotOwned {
		t.Fatalf("generic mobility=%+v", got)
	}
	if !reflect.DeepEqual(second.Paths[0].Mobility, got) {
		t.Fatalf("generic mobility changed across observations: %+v -> %+v", got, second.Paths[0].Mobility)
	}
	if first.Paths[0].LocalAddr == "" || first.Paths[0].RemoteAddr == "" {
		t.Fatalf("attached path physical endpoints are absent: %+v", first.Paths[0])
	}
}

func TestDialerOptionalPathRetryAttachesAfterForwardingFix(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	native, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	go func() {
		for {
			c, err := native.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("native"))
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan Conn, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err == nil {
			accepted <- c
		}
	}()

	var useNative atomic.Bool
	useNative.Store(true)
	d := &sessionDialer{
		Root: Selector("root", []Target{
			Path("A", PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
			Path("B", PathSpec{Transport: "switch", Address: "B"}),
		}),
		Retry: retryPolicy{MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond},
	}
	if err := d.AddStreamPathFactory("switch", func(ctx context.Context, _ string) (net.Conn, error) {
		addr := ln.Addr().String()
		if useNative.Load() {
			addr = native.Addr().String()
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", addr)
	}); err != nil {
		t.Fatal(err)
	}

	client, err := d.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	st := client.Status()
	if len(st.Paths) != 2 || st.Paths[1].State == PathAttached {
		t.Fatalf("before fix paths=%+v want B not attached", st.Paths)
	}

	useNative.Store(false)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st = client.Status()
		if len(st.Paths) == 2 && st.Paths[1].State == PathAttached {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("B did not attach after forwarding fix; status=%+v", client.Status())
}

func TestDialerOptionalPathFailureDoesNotSurfaceToApp(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	bad, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	badAddr := bad.Addr().String()
	_ = bad.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan Conn, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err == nil {
			accepted <- c
		}
	}()

	client, err := (&sessionDialer{
		Root: Selector("root", []Target{
			Path("A", PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
			Path("B", PathSpec{Transport: "tcp", Address: badAddr}),
		}),
		Retry: retryPolicy{MinBackoff: 20 * time.Millisecond, MaxBackoff: 20 * time.Millisecond},
	}).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	msg := []byte("ok")
	if _, err := client.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("payload=%q want %q", string(buf), string(msg))
	}
}
