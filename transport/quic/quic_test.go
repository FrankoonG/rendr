package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	qg "github.com/quic-go/quic-go"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

// pairCtx packages the client PathConn and a channel for the server
// side, which is only ready after the client has written at least
// one byte (QUIC streams are lazy - the peer's AcceptStream blocks
// until data is on the wire).
type pairCtx struct {
	client *PathConn
	srvCh  <-chan acceptResult
}

type acceptResult struct {
	pc  *PathConn
	err error
}

func newPair(t *testing.T) pairCtx {
	t.Helper()
	srvTLS, cliTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &qg.Config{
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	}

	ln, err := qg.ListenAddr("127.0.0.1:0", srvTLS, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	addr := ln.Addr().String()

	srvCh := make(chan acceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		if err != nil {
			srvCh <- acceptResult{err: err}
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			srvCh <- acceptResult{err: err}
			return
		}
		srvCh <- acceptResult{pc: Accept(conn, stream)}
	}()

	tp := &Transport{ClientTLS: cliTLS}
	cliPath, err := tp.DialPath(context.Background(), transport.PathSpec{Address: addr})
	if err != nil {
		t.Fatal(err)
	}
	client := cliPath.(*PathConn)
	t.Cleanup(func() { _ = client.Close() })
	return pairCtx{client: client, srvCh: srvCh}
}

// awaitServer blocks until the server-side accept completes. Caller
// must have produced bytes on the client side first (a Write or
// failed Write attempt - QUIC's lazy-stream semantics requires data
// to be in flight before AcceptStream returns).
func (p pairCtx) awaitServer(t *testing.T) *PathConn {
	t.Helper()
	res := <-p.srvCh
	if res.err != nil {
		t.Fatalf("server accept: %v", res.err)
	}
	t.Cleanup(func() { _ = res.pc.Close() })
	return res.pc
}

func TestQUICRoundTrip(t *testing.T) {
	p := newPair(t)

	frame := bytes.Repeat([]byte{0xAB}, 100)
	if _, err := p.client.Write(frame); err != nil {
		t.Fatal(err)
	}
	server := p.awaitServer(t)

	buf := make([]byte, MaxFrameSize)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], frame) {
		t.Fatalf("frame mismatch: got %x want %x", buf[:n], frame)
	}

	reply := []byte("pong over quic")
	if _, err := server.Write(reply); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, MaxFrameSize)
	rn, err := p.client.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:rn], reply) {
		t.Fatalf("reply mismatch: got %x want %x", got[:rn], reply)
	}
}

func TestQUICAdapterOwnershipDoesNotUpgradeExternalAccept(t *testing.T) {
	p := newPair(t)
	claim := p.client.LeafMobilityClaim()
	if claim == nil {
		t.Fatal("adapter-dialed QUIC path has no sealed claim")
	}
	facts := claim.Snapshot()
	if facts.Kind != leafmobility.KindQUIC || facts.Role != leafmobility.RoleDialer ||
		facts.Scope != leafmobility.ScopeEndpoint || facts.Operations != 0 || facts.Generation == 0 {
		t.Fatalf("adapter-dialed QUIC facts=%+v", facts)
	}
	if _, err := p.client.Write([]byte("ownership")); err != nil {
		t.Fatal(err)
	}
	server := p.awaitServer(t)
	if claim := server.LeafMobilityClaim(); claim != nil {
		t.Fatalf("public Accept upgraded external QUIC connection: %+v", claim.Snapshot())
	}
	if err := p.client.Close(); err != nil {
		t.Fatal(err)
	}
	if !claim.Retired() {
		t.Fatal("direct close did not retire unbound QUIC claim")
	}
}

// TestQUICDatagramRoundTrip exercises the DATAGRAM-mode adapter:
// client dials with Opts["mode"]="datagram", server accepts via the
// Listener.AcceptDatagram path, both sides exchange a sub-MTU frame.
// Validates SendDatagram / ReceiveDatagram plumbing end-to-end.
func TestQUICDatagramRoundTrip(t *testing.T) {
	srvTLS, cliTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", srvTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvCh := make(chan *datagramPathConn, 1)
	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pc, err := ln.AcceptDatagram(ctx)
		if err != nil {
			errCh <- err
			return
		}
		srvCh <- pc
	}()

	tp := &Transport{ClientTLS: cliTLS}
	cliPath, err := tp.DialPath(context.Background(), transport.PathSpec{
		Address: ln.Addr().String(),
		Opts:    map[string]string{"mode": "datagram"},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := cliPath.(*datagramPathConn)
	defer client.Close()

	frame := bytes.Repeat([]byte{0xCD}, 500)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}

	var server *datagramPathConn
	select {
	case server = <-srvCh:
	case err := <-errCh:
		t.Fatalf("accept: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server accept timed out")
	}
	defer server.Close()

	buf := make([]byte, 1500)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf[:n], frame) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", n, len(frame))
	}

	// Reverse direction.
	rep := []byte("server-says-hi")
	if _, err := server.Write(rep); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(buf[:n], rep) {
		t.Fatalf("reply mismatch: got %q want %q", buf[:n], rep)
	}

	// quic-go's internal DATAGRAM receive queue is intentionally only 128
	// entries. Accumulate more than that in rendr before reading from the
	// adapter to prove the dedicated ingress pump drains the internal queue
	// while the engine-facing reader is stalled. DATAGRAM has no peer flow
	// control, so bound each sender stride below quic-go's queue and wait for
	// the pump rather than turning this into a scheduler-dependent loss test.
	const burstFrames = 512
	const ingressDrainStride = 16
	burst := make([]byte, 64)
	for seq := uint64(0); seq < burstFrames; seq++ {
		binary.BigEndian.PutUint64(burst, seq)
		if _, err := client.Write(burst); err != nil {
			t.Fatalf("burst write %d: %v", seq, err)
		}
		if (seq+1)%ingressDrainStride == 0 {
			wantDepth := seq + 1
			deadline := time.Now().Add(time.Second)
			for server.IngressQueueStats().Depth < wantDepth {
				if time.Now().After(deadline) {
					t.Fatalf("ingress pump stalled after frame %d: stats=%+v", seq, server.IngressQueueStats())
				}
				time.Sleep(100 * time.Microsecond)
			}
		}
	}
	burstRead := make(chan error, 1)
	go func() {
		for seq := uint64(0); seq < burstFrames; seq++ {
			n, err := server.Read(buf)
			if err != nil {
				burstRead <- fmt.Errorf("burst read %d: %w", seq, err)
				return
			}
			if n != len(burst) || binary.BigEndian.Uint64(buf[:8]) != seq {
				burstRead <- fmt.Errorf("burst frame %d: n=%d seq=%d", seq, n, binary.BigEndian.Uint64(buf[:8]))
				return
			}
		}
		burstRead <- nil
	}()
	select {
	case err := <-burstRead:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("burst read timed out; ingress lost or stranded a frame")
	}

	ownedPayload := []byte("owned-frame-reader")
	if _, err := client.Write(ownedPayload); err != nil {
		t.Fatal(err)
	}
	owned, ok := any(server).(transport.OwnedFrameReader)
	if !ok {
		t.Fatal("QUIC DATAGRAM path does not expose the owned-frame fast path")
	}
	ownedFrame, err := owned.ReadOwnedFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ownedFrame, ownedPayload) {
		t.Fatalf("owned frame mismatch: got %q want %q", ownedFrame, ownedPayload)
	}
	queue := server.IngressQueueStats()
	if queue.Capacity != datagramIngressQueueLen || queue.HighWater == 0 || queue.HighWater > queue.Capacity {
		t.Fatalf("ingress queue stats = %+v", queue)
	}

	// Counter sanity.
	if server.Reads() < 1 || client.Reads() < 1 {
		t.Errorf("reads not counted: server=%d client=%d", server.Reads(), client.Reads())
	}
	if server.Writes() < 1 || client.Writes() < 1 {
		t.Errorf("writes not counted: server=%d client=%d", server.Writes(), client.Writes())
	}
}

func TestQUICDatagramOwnedFrameRemainsImmutable(t *testing.T) {
	srvTLS, cliTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", srvTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvCh := make(chan *datagramPathConn, 1)
	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pc, err := ln.AcceptDatagram(ctx)
		if err != nil {
			errCh <- err
			return
		}
		srvCh <- pc
	}()

	tp := &Transport{ClientTLS: cliTLS}
	cliPath, err := tp.DialPath(context.Background(), transport.PathSpec{
		Address: ln.Addr().String(),
		Opts:    map[string]string{"mode": "datagram"},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := cliPath.(*datagramPathConn)
	defer client.Close()

	wantRetained := make([]byte, 256)
	for i := range wantRetained {
		wantRetained[i] = byte(i ^ 0xa5)
	}
	if _, err := client.Write(wantRetained); err != nil {
		t.Fatal(err)
	}

	var server *datagramPathConn
	select {
	case server = <-srvCh:
	case err := <-errCh:
		t.Fatalf("accept: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server accept timed out")
	}
	defer server.Close()

	owned, ok := any(server).(transport.OwnedFrameReader)
	if !ok {
		t.Fatal("QUIC DATAGRAM path does not expose the owned-frame fast path")
	}

	done := make(chan error, 1)
	go func() {
		retained, err := owned.ReadOwnedFrame()
		if err != nil {
			done <- fmt.Errorf("read retained frame: %w", err)
			return
		}
		if !bytes.Equal(retained, wantRetained) {
			done <- fmt.Errorf("retained frame mismatch before pressure")
			return
		}

		const reusePressureFrames = 512
		pressure := make([]byte, len(wantRetained))
		for seq := uint64(1); seq <= reusePressureFrames; seq++ {
			for i := range pressure {
				pressure[i] = byte(seq)
			}
			binary.BigEndian.PutUint64(pressure, seq)
			if _, err := client.Write(pressure); err != nil {
				done <- fmt.Errorf("pressure write %d: %w", seq, err)
				return
			}
			frame, err := owned.ReadOwnedFrame()
			if err != nil {
				done <- fmt.Errorf("pressure read %d: %w", seq, err)
				return
			}
			if !bytes.Equal(frame, pressure) {
				done <- fmt.Errorf("pressure frame %d mismatch", seq)
				return
			}
		}
		if !bytes.Equal(retained, wantRetained) {
			done <- fmt.Errorf("retained frame changed after %d subsequent reads", reusePressureFrames)
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		_ = client.Close()
		_ = server.Close()
		t.Fatal("owned-frame reuse pressure timed out")
	}
}

// TestQUICDatagramOversizeRejected: SendDatagram with a frame larger
// than MaxDatagramFrame must return an error without crashing.
func TestQUICDatagramOversizeRejected(t *testing.T) {
	srvTLS, cliTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", srvTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = ln.AcceptDatagram(ctx)
	}()

	tp := &Transport{ClientTLS: cliTLS}
	cliPath, err := tp.DialPath(context.Background(), transport.PathSpec{
		Address: ln.Addr().String(),
		Opts:    map[string]string{"mode": "datagram"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cliPath.Close()
	client := cliPath.(*datagramPathConn)

	huge := make([]byte, MaxDatagramFrame+1)
	if _, err := client.Write(huge); err == nil {
		t.Fatal("expected error for oversize DATAGRAM frame")
	}
}

func TestQUICOversizeRejected(t *testing.T) {
	p := newPair(t)
	huge := make([]byte, MaxFrameSize+1)
	if _, err := p.client.Write(huge); err == nil {
		t.Fatal("expected error for oversize frame")
	}
	// Drain any in-flight server accept so leak-checks remain clean.
	_ = p
}

// TestQUICOptsApplied: verifies the per-path TLS overrides
// (server_name / alpn / insecure / ca_pem). The dev TLS cert has
// CN=rendr-dev; we set server_name=rendr-dev and verify the
// handshake completes when the CA bundle is the embedded cert
// (rather than InsecureSkipVerify).
func TestQUICOptsApplied(t *testing.T) {
	srvTLS, cliTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	// Strip the InsecureSkipVerify so the test actually exercises
	// the cert chain. Bring the cert bundle in via ca_pem instead.
	caPEM := serverCertPEMFor(t, srvTLS)
	cliTLS.InsecureSkipVerify = false

	cfg := &qg.Config{
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	}
	ln, err := qg.ListenAddr("127.0.0.1:0", srvTLS, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srvCh := make(chan acceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		if err != nil {
			srvCh <- acceptResult{err: err}
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			srvCh <- acceptResult{err: err}
			return
		}
		srvCh <- acceptResult{pc: Accept(conn, stream)}
	}()

	tp := &Transport{ClientTLS: cliTLS}
	pc, err := tp.DialPath(context.Background(), transport.PathSpec{
		Address: ln.Addr().String(),
		Opts: map[string]string{
			"server_name": "rendr-dev",
			"ca_pem":      caPEM,
			"alpn":        ALPN,
		},
	})
	if err != nil {
		t.Fatalf("dial with opts: %v", err)
	}
	defer pc.Close()

	if _, err := pc.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	res := <-srvCh
	if res.err != nil {
		t.Fatalf("accept: %v", res.err)
	}
	t.Cleanup(func() { _ = res.pc.Close() })

	buf := make([]byte, 64)
	n, err := res.pc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("got %q want %q", buf[:n], "hello")
	}
}

func TestQUICALPNIsV1Only(t *testing.T) {
	_, base, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	for _, value := range []string{"legacy", "legacy," + ALPN, ALPN + ",other"} {
		t.Run(value, func(t *testing.T) {
			if _, err := applyOptsToTLS(base, map[string]string{"alpn": value}); err == nil {
				t.Fatalf("applyOptsToTLS accepted non-v1-only ALPN %q", value)
			}
		})
	}

	cfg, err := applyOptsToTLS(base, map[string]string{"alpn": "  " + ALPN + "  "})
	if err != nil {
		t.Fatalf("applyOptsToTLS rejected %q: %v", ALPN, err)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != ALPN {
		t.Fatalf("NextProtos = %v, want [%q]", cfg.NextProtos, ALPN)
	}
	if ALPN != "rendr/1" {
		t.Fatalf("ALPN = %q, want rendr/1", ALPN)
	}
}

// serverCertPEMFor extracts the leaf certificate from a server TLS
// config and returns it as a PEM-encoded string suitable for
// ca_pem.
func serverCertPEMFor(t *testing.T, srv *tls.Config) string {
	t.Helper()
	if len(srv.Certificates) == 0 || len(srv.Certificates[0].Certificate) == 0 {
		t.Fatal("server TLS has no cert")
	}
	der := srv.Certificates[0].Certificate[0]
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
