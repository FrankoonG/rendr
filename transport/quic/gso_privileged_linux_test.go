//go:build linux

package quic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/platform"
	"github.com/FrankoonG/rendr/transport"
)

const (
	realQUICGSOTestModeEnvironment = "RENDR_UDP_GSO_REAL_TEST"
	realQUICGSONetNSIDEnvironment  = "RENDR_UDP_GSO_REAL_NETNS_ID"
	realQUICGSOTraceReady          = "RENDR_UDP_GSO_TRACE_READY"
	realQUICStreamFrames           = 256
	realQUICStreamFrameSize        = 16 * 1024
	realQUICDatagramPackets        = 256
	realQUICDatagramSize           = 900
)

type realQUICGSOEvidence struct {
	Mode                 string                               `json:"mode"`
	ProbeState           string                               `json:"probe_state"`
	StreamOfferedBytes   int                                  `json:"stream_offered_bytes"`
	StreamReceivedBytes  int                                  `json:"stream_received_bytes"`
	StreamSHA256         string                               `json:"stream_sha256"`
	DatagramOfferedBytes int                                  `json:"datagram_offered_bytes"`
	DatagramReceived     int                                  `json:"datagram_received_packets"`
	StreamStatus         transport.DatagramAccelerationStatus `json:"stream_status"`
	DatagramStatus       transport.DatagramAccelerationStatus `json:"datagram_status"`
}

func TestPrivilegedQUICGSOActive(t *testing.T) {
	runPrivilegedQUICGSO(t, "active")
}

func TestPrivilegedQUICGSOFallback(t *testing.T) {
	runPrivilegedQUICGSO(t, "fallback")
}

func runPrivilegedQUICGSO(t *testing.T, mode string) {
	probeState := prepareRealQUICGSO(t, mode)
	streamStatus, streamBytes, streamDigest := runRealQUICStreamTransfer(t)
	datagramStatus := runRealQUICDatagramTransfer(t)

	switch mode {
	case "active":
		if streamStatus.Mode != transport.DatagramAccelerationGSO ||
			datagramStatus.Mode != transport.DatagramAccelerationGSO {
			t.Fatalf("active selected stream=%+v datagram=%+v", streamStatus, datagramStatus)
		}
		if streamStatus.GSOAttempts == 0 || streamStatus.GSOSuperPackets == 0 || streamStatus.GSOSegments < 2 {
			t.Fatalf("QUIC stream did not exercise successful GSO: %+v", streamStatus)
		}
		// MaxDatagramFrame produces short QUIC packets with quic-go v0.59.1,
		// so this arm is an integrity check, not a DATAGRAM GSO claim. Require
		// actual socket send evidence while the stream arm proves acceleration.
		if datagramStatus.GSOSuperPackets == 0 && datagramStatus.OrdinaryDatagrams == 0 {
			t.Fatalf("QUIC DATAGRAM transfer has no actual send evidence: %+v", datagramStatus)
		}
	case "fallback":
		for name, status := range map[string]transport.DatagramAccelerationStatus{
			"stream": streamStatus, "datagram": datagramStatus,
		} {
			if status.Mode != transport.DatagramAccelerationOrdinary || status.GSOAttempts != 0 ||
				status.GSOSuperPackets != 0 || status.GSOSegments != 0 || status.OrdinaryDatagrams == 0 {
				t.Fatalf("fallback %s status=%+v", name, status)
			}
		}
	default:
		t.Fatalf("unknown real QUIC GSO mode %q", mode)
	}

	evidence := realQUICGSOEvidence{
		Mode: mode, ProbeState: string(probeState),
		StreamOfferedBytes: streamBytes, StreamReceivedBytes: streamBytes,
		StreamSHA256:         fmt.Sprintf("%x", streamDigest),
		DatagramOfferedBytes: realQUICDatagramPackets * realQUICDatagramSize,
		DatagramReceived:     realQUICDatagramPackets,
		StreamStatus:         streamStatus, DatagramStatus: datagramStatus,
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RENDR_QUIC_GSO_EVIDENCE %s", encoded)
}

func prepareRealQUICGSO(t testing.TB, mode string) platform.FeatureState {
	t.Helper()
	if selected := os.Getenv(realQUICGSOTestModeEnvironment); selected != mode {
		t.Skipf("set %s=%s to exercise real QUIC GSO %s", realQUICGSOTestModeEnvironment, mode, mode)
	}
	if os.Geteuid() != 0 {
		t.Fatal("real QUIC GSO qualification requires root in the test namespace")
	}
	self := realQUICNetworkNamespaceIdentity(t, "/proc/self/ns/net")
	init := realQUICNetworkNamespaceIdentity(t, "/proc/1/ns/net")
	expected := os.Getenv(realQUICGSONetNSIDEnvironment)
	if self == init || expected == "" || self != expected {
		t.Fatalf("network namespace self=%q init=%q expected=%q", self, init, expected)
	}
	if err := platform.Invalidate(platform.FeatureUDPGSO); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	snapshot, err := platform.Detect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	evidence, ok := snapshot.Feature(platform.FeatureUDPGSO)
	if !ok {
		t.Fatal("UDP GSO probe produced no evidence")
	}
	if mode == "active" && evidence.State != platform.FeatureAvailable {
		t.Fatalf("active UDP GSO evidence=%+v", evidence)
	}
	if mode == "fallback" && evidence.State != platform.FeatureUnsupported {
		t.Fatalf("fallback UDP GSO evidence=%+v; require injected UDP_SEGMENT unsupported", evidence)
	}
	if mode == "fallback" {
		awaitRealQUICGSOProductionTrace(t)
	}
	return evidence.State
}

func awaitRealQUICGSOProductionTrace(t testing.TB) {
	t.Helper()
	path := os.Getenv(realQUICGSOTraceReady)
	if path == "" {
		t.Fatalf("%s is required for fallback production tracing", realQUICGSOTraceReady)
	}
	if err := publishRealQUICGSOTraceReady(path, os.Getpid()); err != nil {
		t.Fatalf("publish production trace readiness: %v", err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGSTOP); err != nil {
		t.Fatalf("stop for production trace attachment: %v", err)
	}
}

func publishRealQUICGSOTraceReady(path string, pid int) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.WriteString(strconv.Itoa(pid) + "\n"); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Link(temporaryPath, path)
}

func runRealQUICStreamTransfer(t *testing.T) (transport.DatagramAccelerationStatus, int, [sha256.Size]byte) {
	t.Helper()
	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan pathAcceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		path, acceptErr := listener.AcceptPath(ctx)
		accepted <- pathAcceptResult{path: path, err: acceptErr}
	}()
	client, err := (&Transport{ClientTLS: clientTLS}).DialPath(context.Background(), transport.PathSpec{
		Address: listener.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	expectedHash := sha256.New()
	first := realQUICPayload(0, realQUICStreamFrameSize)
	_, _ = expectedHash.Write(first)
	if _, err := client.Write(first); err != nil {
		t.Fatal(err)
	}
	server := awaitPathAccept(t, accepted).path
	t.Cleanup(func() { _ = server.Close() })

	type receiveResult struct {
		bytes  int
		digest [sha256.Size]byte
		err    error
	}
	received := make(chan receiveResult, 1)
	go func() {
		hash := sha256.New()
		buffer := make([]byte, MaxFrameSize)
		var total int
		for range realQUICStreamFrames {
			n, readErr := server.Read(buffer)
			if readErr != nil {
				received <- receiveResult{err: readErr}
				return
			}
			total += n
			_, _ = hash.Write(buffer[:n])
		}
		var digest [sha256.Size]byte
		copy(digest[:], hash.Sum(nil))
		received <- receiveResult{bytes: total, digest: digest}
	}()

	for index := 1; index < realQUICStreamFrames; index++ {
		payload := realQUICPayload(index, realQUICStreamFrameSize)
		_, _ = expectedHash.Write(payload)
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("stream frame %d: %v", index, err)
		}
	}
	var result receiveResult
	select {
	case result = <-received:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out receiving QUIC stream qualification payload")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	var expectedDigest [sha256.Size]byte
	copy(expectedDigest[:], expectedHash.Sum(nil))
	expectedBytes := realQUICStreamFrames * realQUICStreamFrameSize
	if result.bytes != expectedBytes || result.digest != expectedDigest {
		t.Fatalf("stream bytes=%d/%d digest=%x/%x", result.bytes, expectedBytes, result.digest, expectedDigest)
	}
	return realQUICAccelerationStatus(t, client), expectedBytes, expectedDigest
}

func runRealQUICDatagramTransfer(t *testing.T) transport.DatagramAccelerationStatus {
	t.Helper()
	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := ListenDatagram("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan pathAcceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		path, acceptErr := listener.AcceptPath(ctx)
		accepted <- pathAcceptResult{path: path, err: acceptErr}
	}()
	client, err := (&Transport{ClientTLS: clientTLS}).DialPath(context.Background(), transport.PathSpec{
		Address: listener.Addr().String(), Opts: map[string]string{"mode": "datagram"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := awaitPathAccept(t, accepted).path
	t.Cleanup(func() { _ = server.Close() })

	received := make(chan error, 1)
	go func() {
		seen := make([]bool, realQUICDatagramPackets)
		buffer := make([]byte, MaxDatagramFrame)
		for range realQUICDatagramPackets {
			n, readErr := server.Read(buffer)
			if readErr != nil {
				received <- readErr
				return
			}
			if n != realQUICDatagramSize {
				received <- fmt.Errorf("datagram size=%d want=%d", n, realQUICDatagramSize)
				return
			}
			sequence := int(binary.BigEndian.Uint32(buffer[:4]))
			if sequence < 0 || sequence >= len(seen) || seen[sequence] {
				received <- fmt.Errorf("invalid or duplicate datagram sequence %d", sequence)
				return
			}
			if want := realQUICPayload(sequence, realQUICDatagramSize); !bytes.Equal(buffer[:n], want) {
				received <- fmt.Errorf("datagram sequence %d payload mismatch", sequence)
				return
			}
			seen[sequence] = true
		}
		received <- nil
	}()
	for sequence := range realQUICDatagramPackets {
		if _, err := client.Write(realQUICPayload(sequence, realQUICDatagramSize)); err != nil {
			t.Fatalf("datagram %d: %v", sequence, err)
		}
	}
	select {
	case err := <-received:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out receiving QUIC DATAGRAM qualification payload")
	}
	return realQUICAccelerationStatus(t, client)
}

func realQUICPayload(sequence, size int) []byte {
	payload := make([]byte, size)
	binary.BigEndian.PutUint32(payload[:4], uint32(sequence))
	for index := 4; index < len(payload); index++ {
		payload[index] = byte(sequence*37 + index*11)
	}
	return payload
}

func realQUICAccelerationStatus(t testing.TB, path transport.PathConn) transport.DatagramAccelerationStatus {
	t.Helper()
	observer, ok := path.(transport.DatagramAccelerationObserver)
	if !ok {
		t.Fatalf("path %T does not expose datagram acceleration status", path)
	}
	return observer.DatagramAccelerationStatus()
}

func realQUICNetworkNamespaceIdentity(t testing.TB, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		t.Fatalf("%s has no network namespace identity", path)
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
}
