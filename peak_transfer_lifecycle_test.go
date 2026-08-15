package rendr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	transporttcp "github.com/FrankoonG/rendr/transport/tcp"
)

func TestListenerPeakAdmissionSuppressesOnlyCapacityRejectedTarget(t *testing.T) {
	selectorID := proto.DeriveTargetID(proto.GraphNodeKindSelector, "listener-admission-root")
	normalID := proto.DeriveTargetID(proto.GraphNodeKindPath, "listener-admission-normal")
	firstPeak := proto.DeriveTargetID(proto.GraphNodeKindPath, "listener-admission-peak-1")
	secondPeak := proto.DeriveTargetID(proto.GraphNodeKindPath, "listener-admission-peak-2")
	admission := &listenerPeakTransferAdmission{targets: peakTransferTargets{
		selectorID: selectorID, normalTargetID: normalID,
		normalTargetIDs: []proto.TargetID{normalID},
		peakTargetIDs:   []proto.TargetID{firstPeak, secondPeak},
	}}

	admission.observe(selectorID, firstPeak, true, "peak-transfer-rx")
	admission.observe(selectorID, normalID, false, "peak-verify-failed-rx")
	if err := admission.admit(selectorID, firstPeak, "peak-transfer-rx"); err == nil {
		t.Fatal("capacity-rejected listener target remained admissible")
	}
	if err := admission.admit(selectorID, secondPeak, "peak-transfer-rx"); err != nil {
		t.Fatalf("healthy sibling inherited failed candidate suppression: %v", err)
	}

	admission.observe(selectorID, secondPeak, true, "peak-transfer-rx")
	admission.observe(selectorID, normalID, false, "peak-return-rx")
	if err := admission.admit(selectorID, secondPeak, "peak-transfer-rx"); err != nil {
		t.Fatalf("ordinary return incorrectly suppressed candidate: %v", err)
	}
}

func TestPeakTransferConcurrentCloseHighCount(t *testing.T) {
	const (
		rounds  = 8
		callers = 256
	)
	for _, packet := range []bool{false, true} {
		name := "stream"
		if packet {
			name = "packet"
		}
		t.Run(name, func(t *testing.T) {
			for round := 0; round < rounds; round++ {
				fixture := newPeakDirectionalFixture(t,
					Selector("client-root", []Target{
						Path("client-normal", PathSpec{}), Path("client-peak", PathSpec{}),
					}, PeakTransfer{Targets: []string{"client-peak"}}),
					Selector("server-root", []Target{
						Path("server-normal", PathSpec{}), Path("server-peak", PathSpec{}),
					}, PeakTransfer{Targets: []string{"server-peak"}}),
				)
				if err := fixture.controller.start(); err != nil {
					t.Fatal(err)
				}
				e := fixture.client

				var closeConn func() error
				if packet {
					conn := newEnginePacketConn(e, nil, nil)
					conn.peak = fixture.controller
					closeConn = conn.Close
				} else {
					conn := newEngineBackedConn(e, &engine.Conn{E: e})
					conn.peak = fixture.controller
					closeConn = conn.Close
				}

				start := make(chan struct{})
				results := make(chan error, callers)
				var wg sync.WaitGroup
				wg.Add(callers)
				for i := 0; i < callers; i++ {
					go func() {
						defer wg.Done()
						<-start
						results <- closeConn()
					}()
				}
				close(start)
				wg.Wait()
				close(results)

				var first error
				firstSet := false
				for err := range results {
					if !firstSet {
						first, firstSet = err, true
						continue
					}
					if !sameCloseResult(first, err) {
						t.Fatalf("round %d concurrent Close results differ: first=%v next=%v", round, first, err)
					}
				}
				select {
				case <-fixture.controller.policyContext().Done():
				default:
					t.Fatalf("round %d PeakTransfer context remained active", round)
				}
				if !e.IsClosed() {
					t.Fatalf("round %d engine remained open", round)
				}
				_ = fixture.server.Close()
			}
		})
	}
}

func sameCloseResult(left, right error) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Error() == right.Error()
}

func TestPeakTransferStartReturnsLocalInitializationError(t *testing.T) {
	plan, err := compileTargetForDial(Selector("root", []Target{
		Path("normal", PathSpec{}),
		Path("peak", PathSpec{}),
	}, PeakTransfer{Targets: []string{"peak"}}))
	if err != nil {
		t.Fatal(err)
	}
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	defer e.Close()
	if err := e.ConfigureLocalGraph(1, plan.graph.manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, plan.graph.manifest); err != nil {
		t.Fatal(err)
	}
	e.BeginGracefulClose()
	controller := newPeakTransferController(e, plan, nil)
	if err := controller.start(); err == nil {
		t.Fatal("PeakTransfer start ignored local initialization failure")
	}
	controller.stopLoop()
}

func TestPeakTransferPolicyInitializationDoesNotDelaySuccessfulDial(t *testing.T) {
	for _, packet := range []bool{false, true} {
		name := "stream"
		if packet {
			name = "packet"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newUnresponsivePeakPolicyFixture(t, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			accepted := fixture.accept(ctx, packet)

			started := time.Now()
			conn, err := fixture.dial(ctx, packet)
			if err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(started); elapsed >= 2*time.Second {
				_ = conn.Close()
				t.Fatalf("Dial blocked for %s on an unresponsive policy peer", elapsed)
			}
			select {
			case <-fixture.control.policyAckSeen:
			case <-time.After(2 * time.Second):
				_ = conn.Close()
				t.Fatal("asynchronous peer policy initialization was not attempted")
			}
			reporter, ok := conn.(StatusReporter)
			if !ok {
				_ = conn.Close()
				t.Fatal("PeakTransfer connection does not expose Status")
			}
			issueDeadline := time.Now().Add(7 * time.Second)
			for {
				issues := reporter.Status().Issues
				if len(issues) == 1 && issues[0].ID == StatusIssuePeerPolicyInitialization && issues[0].LastError != "" {
					break
				}
				if time.Now().After(issueDeadline) {
					_ = conn.Close()
					t.Fatalf("asynchronous peer policy error was not observable: %+v", issues)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) &&
				!errors.Is(err, engine.ErrGracefulCloseTimeout) {
				t.Fatalf("client Close: %v", err)
			}
			if issues := reporter.Status().Issues; len(issues) != 0 {
				t.Fatalf("shutdown retained inactive PeakTransfer issues: %+v", issues)
			}
			fixture.assertCanceledPeerClean(t, accepted)
		})
	}
}

func TestPeakTransferPolicyInitializationIssueClearsAfterRecovery(t *testing.T) {
	for _, packet := range []bool{false, true} {
		name := "stream"
		if packet {
			name = "packet"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			fixture := newUnresponsivePeakPolicyFixture(t, nil)
			accepted := fixture.accept(ctx, packet)
			conn, err := fixture.dial(ctx, packet)
			if err != nil {
				t.Fatal(err)
			}
			reporter := conn.(StatusReporter)
			if err := waitForPeakIssues(ctx, reporter, func(issues []StatusIssue) bool {
				return len(issues) == 1 && issues[0].ID == StatusIssuePeerPolicyInitialization
			}); err != nil {
				_ = conn.Close()
				t.Fatal(err)
			}

			fixture.control.allowPolicyACKs()
			if err := waitForPeakIssues(ctx, reporter, func(issues []StatusIssue) bool {
				return len(issues) == 0
			}); err != nil {
				_ = conn.Close()
				t.Fatal(err)
			}
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) &&
				!errors.Is(err, engine.ErrGracefulCloseTimeout) {
				t.Fatalf("client Close: %v", err)
			}
			fixture.assertCanceledPeerClean(t, accepted)
		})
	}
}

func waitForPeakIssues(ctx context.Context, reporter StatusReporter, match func([]StatusIssue) bool) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		issues := reporter.Status().Issues
		if match(issues) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("PeakTransfer issues did not converge from %+v: %w", issues, ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestPeakTransferDialDoesNotReturnConnectionAfterTerminalContextCancellation(t *testing.T) {
	for _, packet := range []bool{false, true} {
		name := "stream"
		if packet {
			name = "packet"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			fixture := newUnresponsivePeakPolicyFixture(t, cancel)
			accepted := fixture.accept(context.Background(), packet)
			started := time.Now()
			conn, err := fixture.dial(ctx, packet)
			if conn != nil {
				_ = conn.Close()
				t.Fatal("Dial returned a connection after its context was canceled at terminal admission")
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Dial error=%v want context.Canceled", err)
			}
			if elapsed := time.Since(started); elapsed >= 2*time.Second {
				t.Fatalf("canceled Dial returned after %s", elapsed)
			}
			fixture.assertCanceledPeerClean(t, accepted)
		})
	}
	t.Run("dropped-terminal-ack", testDialCanceledAfterAdmissionDoesNotWaitForDroppedTerminalAck)
}

type peakPolicyPeerControl struct {
	policyAckSeen chan struct{}
	policyOnce    sync.Once
	dropPolicyACK atomic.Bool
	onActivated   func()
	activatedOnce sync.Once
}

func (c *peakPolicyPeerControl) allowPolicyACKs() { c.dropPolicyACK.Store(false) }

type peakPolicyDropPath struct {
	inner   transport.PathConn
	control *peakPolicyPeerControl
}

func (p *peakPolicyDropPath) Read(buffer []byte) (int, error) { return p.inner.Read(buffer) }

func (p *peakPolicyDropPath) Write(frame []byte) (int, error) {
	header, err := proto.DecodeHeader(frame)
	if err == nil && header.Type == proto.FrameCtrl {
		switch proto.CtrlCodeFromFlags(header.Flags) {
		case proto.CtrlPolicyAck:
			p.control.policyOnce.Do(func() { close(p.control.policyAckSeen) })
			if p.control.dropPolicyACK.Load() {
				return len(frame), nil
			}
		case proto.CtrlPathAdmissionAck:
			ack, decodeErr := proto.DecodePathAdmissionAck(frame[proto.HeaderSize:])
			if decodeErr == nil && ack.Phase == proto.PathAdmissionPhaseActivated {
				if p.control.onActivated != nil {
					p.control.activatedOnce.Do(p.control.onActivated)
				}
				return p.inner.Write(frame)
			}
		}
	}
	return p.inner.Write(frame)
}

func (p *peakPolicyDropPath) Close() error                   { return p.inner.Close() }
func (p *peakPolicyDropPath) Quality() transport.PathQuality { return p.inner.Quality() }
func (p *peakPolicyDropPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	reader, ok := p.inner.(transport.PathQualityReader)
	if !ok {
		return transport.PathQuality{}, errors.New("wrapped path has no cancellable quality reader")
	}
	return reader.QualityContext(ctx)
}
func (p *peakPolicyDropPath) OnDeath(fn func(transport.DeathCause, error)) { p.inner.OnDeath(fn) }
func (p *peakPolicyDropPath) LocalAddr() string                            { return p.inner.LocalAddr() }
func (p *peakPolicyDropPath) RemoteAddr() string                           { return p.inner.RemoteAddr() }

type unresponsivePeakPolicyFixture struct {
	listener *SessionListener
	client   *Runtime
	paths    *framedPipeListener
	root     Target
	control  *peakPolicyPeerControl
}

func newUnresponsivePeakPolicyFixture(t *testing.T, onActivated func()) *unresponsivePeakPolicyFixture {
	t.Helper()
	server, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	paths := newFramedPipeListener()
	listener, err := server.Listen(ListenConfig{Framed: []FramedSource{{
		Name: "policy-drop", Carrier: CarrierTCP, Listener: paths,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	control := &peakPolicyPeerControl{policyAckSeen: make(chan struct{}), onActivated: onActivated}
	control.dropPolicyACK.Store(true)
	if err := client.RegisterStreamFactory("policy-drop", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(ctx context.Context, _ string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			path := &peakPolicyDropPath{inner: transporttcp.Wrap(serverConn), control: control}
			if err := paths.Publish(ctx, path); err != nil {
				_ = clientConn.Close()
				_ = path.Close()
				return nil, err
			}
			return clientConn, nil
		},
	}); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	spec := PathSpec{Transport: "policy-drop", Address: "peer"}
	return &unresponsivePeakPolicyFixture{
		listener: listener, client: client, paths: paths, control: control,
		root: Selector("root", []Target{
			Path("normal", spec), Path("peak", spec),
		}, PeakTransfer{Targets: []string{"peak"}}),
	}
}

func (f *unresponsivePeakPolicyFixture) dial(ctx context.Context, packet bool) (interface{ Close() error }, error) {
	if packet {
		return f.client.DialPacket(ctx, SessionConfig{Root: f.root})
	}
	return f.client.Dial(ctx, SessionConfig{Root: f.root})
}

func (f *unresponsivePeakPolicyFixture) accept(ctx context.Context, packet bool) <-chan interface{ Close() error } {
	accepted := make(chan interface{ Close() error }, 1)
	go func() {
		if packet {
			conn, err := f.listener.AcceptPacket(ctx)
			if err == nil {
				accepted <- conn
			}
			return
		}
		conn, err := f.listener.AcceptStream(ctx)
		if err == nil {
			accepted <- conn
		}
	}()
	return accepted
}

func (f *unresponsivePeakPolicyFixture) assertCanceledPeerClean(t *testing.T, accepted <-chan interface{ Close() error }) {
	t.Helper()
	select {
	case conn := <-accepted:
		deadline := time.Now().Add(3 * time.Second)
		buffer := make([]byte, 1)
		switch accepted := conn.(type) {
		case *acceptedStreamConn:
			if err := accepted.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			n, err := accepted.Read(buffer)
			if n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("canceled stream Dial peer Read=(%d,%v), want (0,EOF)", n, err)
			}
		case *acceptedPacketConn:
			if err := accepted.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			n, _, err := accepted.ReadFrom(buffer)
			if n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("canceled packet Dial peer ReadFrom=(%d,%v), want (0,EOF)", n, err)
			}
		default:
			t.Fatalf("unexpected accepted connection type %T", conn)
		}
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close canceled Dial peer: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled Dial did not publish a peer session for clean termination")
	}
}

type listenerPeakQualityPath struct {
	transport.PathConn
	quality    transport.PathQuality
	dataWrites *atomic.Uint64
}

func (p *listenerPeakQualityPath) Quality() transport.PathQuality { return p.quality }

func (p *listenerPeakQualityPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	select {
	case <-ctx.Done():
		return transport.PathQuality{}, ctx.Err()
	default:
		return p.quality, nil
	}
}

func (p *listenerPeakQualityPath) Write(frame []byte) (int, error) {
	header, decodeErr := proto.DecodeHeader(frame)
	n, err := p.PathConn.Write(frame)
	if decodeErr == nil && header.Type == proto.FrameData && err == nil && n == len(frame) && p.dataWrites != nil {
		p.dataWrites.Add(1)
	}
	return n, err
}

func TestRuntimeListenerPeakAdmissionRejectsUnhealthyFirstCandidate(t *testing.T) {
	serverRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	paths := newFramedPipeListener()
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{{
		Name: "listener-peak", Carrier: CarrierTCP, Listener: paths,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	clientRuntime, err := NewRuntime(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	var normalDataWrites, firstDataWrites, secondDataWrites atomic.Uint64
	if err := clientRuntime.RegisterStreamFactory("listener-peak", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			clientPath, serverPath := net.Pipe()
			quality := transport.PathQuality{RTT: 2 * time.Millisecond, At: time.Now()}
			dataWrites := &normalDataWrites
			if address == "peak-first" {
				quality.LossPP = 100
				dataWrites = &firstDataWrites
			} else if address == "peak-second" {
				dataWrites = &secondDataWrites
			}
			wrapped := &listenerPeakQualityPath{
				PathConn: transporttcp.Wrap(serverPath), quality: quality, dataWrites: dataWrites,
			}
			if err := paths.Publish(ctx, wrapped); err != nil {
				_ = clientPath.Close()
				_ = wrapped.Close()
				return nil, err
			}
			return clientPath, nil
		},
	}); err != nil {
		t.Fatal(err)
	}

	spec := func(address string) PathSpec {
		return PathSpec{Transport: "listener-peak", Address: address}
	}
	root := Selector("listener-peak-root", []Target{
		Path("listener-normal", spec("normal")),
		Path("listener-peak-first", spec("peak-first")),
		Path("listener-peak-second", spec("peak-second")),
	}, PeakTransfer{Targets: []string{"listener-peak-first", "listener-peak-second"}})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accepted := make(chan *acceptedStreamConn, 1)
	go func() {
		conn, acceptErr := listener.AcceptStream(ctx)
		if acceptErr == nil {
			accepted <- conn.(*acceptedStreamConn)
		}
	}()
	clientConn, err := clientRuntime.Dial(ctx, SessionConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	var serverConn *acceptedStreamConn
	select {
	case serverConn = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	t.Cleanup(func() { _ = serverConn.Close() })

	client := clientConn.(*engineBackedConn)
	deadline := time.Now().Add(5 * time.Second)
	for (len(client.Paths()) != 3 || len(serverConn.engine.Paths()) != 3) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(client.Paths()) != 3 || len(serverConn.engine.Paths()) != 3 {
		t.Fatalf("listener PeakTransfer paths client/server=%d/%d want 3/3", len(client.Paths()), len(serverConn.engine.Paths()))
	}

	selectorID := proto.DeriveTargetID(proto.GraphNodeKindSelector, "listener-peak-root")
	firstID := proto.DeriveTargetID(proto.GraphNodeKindPath, "listener-peak-first")
	secondID := proto.DeriveTargetID(proto.GraphNodeKindPath, "listener-peak-second")
	requestCtx, requestCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer requestCancel()
	if err := client.e.RequestPeerSelection(requestCtx, selectorID, firstID, "listener-unhealthy-exact"); err == nil {
		t.Fatal("listener admitted an unhealthy exact peak candidate")
	}
	resolved, err := client.e.RequestPeerSelectionClass(requestCtx, selectorID, true, "listener-healthy-class")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != secondID {
		t.Fatalf("listener peer class resolved %x want healthy second %x", resolved, secondID)
	}
	desired, effective, _, ok := serverConn.engine.SelectorSelection(selectorID)
	if !ok || desired != secondID || effective != secondID {
		t.Fatalf("listener peer selection desired/effective=%x/%x ok=%t want %x", desired, effective, ok, secondID)
	}

	normalBefore := normalDataWrites.Load()
	firstBefore := firstDataWrites.Load()
	secondBefore := secondDataWrites.Load()
	payload := make([]byte, 64<<10)
	for index := range payload {
		payload[index] = byte((index*29 + 17) % 251)
	}
	deadline = time.Now().Add(5 * time.Second)
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		written, writeErr := io.Copy(serverConn, bytes.NewReader(payload))
		if writeErr == nil && written != int64(len(payload)) {
			writeErr = fmt.Errorf("wrote %d bytes, want %d", written, len(payload))
		}
		writeDone <- writeErr
	}()
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(clientConn, received); err != nil {
		t.Fatalf("read selected peak payload: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write selected peak payload: %v", err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("selected peak payload mismatch")
	}
	normalDelta := normalDataWrites.Load() - normalBefore
	firstDelta := firstDataWrites.Load() - firstBefore
	secondDelta := secondDataWrites.Load() - secondBefore
	if normalDelta != 0 {
		t.Fatalf("unselected normal candidate carried %d DATA frames", normalDelta)
	}
	if firstDelta != 0 {
		t.Fatalf("unhealthy first peak candidate carried %d DATA frames", firstDelta)
	}
	if secondDelta == 0 {
		t.Fatal("selected healthy second peak candidate carried no DATA frames")
	}

	emitTier8PeakEvidence(t, map[string]string{
		"application_errors":                "0",
		"case_id":                           "T8.runtime.listener-multi-peak-data",
		"class_resolved_healthy_second":     "true",
		"evidence_schema":                   "tier8-runtime-listener-multi-peak-v1",
		"healthy_second_data_observed":      "true",
		"negative_control_id":               "unhealthy-first-exact-reject-v1",
		"normal_data_frames_delta":          "0",
		"path_count_each":                   "3",
		"payload_bytes":                     "65536",
		"payload_integrity_match":           "true",
		"physical_path_data_oracle":         "true",
		"structured_evidence":               "true",
		"unhealthy_first_data_frames_delta": "0",
		"unhealthy_first_exact_rejected":    "true",
	})
}

func emitTier8PeakEvidence(t *testing.T, evidence map[string]string) {
	t.Helper()
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("RENDR_T8_EVIDENCE_JSON=" + string(encoded))
}
