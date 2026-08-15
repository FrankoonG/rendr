package gvisor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func testProcessLocalDescriptorsAndHelloMatchUndrivenClaims(t *testing.T) {
	domain := NewDomain()
	listener, err := domain.Listen("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	factory := listener.Factory()
	for name, value := range map[string]any{
		"domain factory":   domain.Factory(),
		"listener factory": factory,
		"listener":         listener,
	} {
		if _, advertised := value.(leafmobility.ImplementationProvider); advertised {
			t.Fatalf("process-local %s %T advertises specialized mobility", name, value)
		}
	}

	clientFrames := make(chan processLocalNegotiation, 1)
	serverFrames := make(chan processLocalNegotiation, 1)
	clientFactory := &processLocalCaptureFactory{
		base: factory,
		capture: processLocalFrameCapture{
			code: proto.CtrlHello, results: clientFrames,
		},
	}
	serverSource := &processLocalCaptureListener{
		base: listener,
		capture: processLocalFrameCapture{
			code: proto.CtrlHelloAck, results: serverFrames,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	sessionListener, err := serverRuntime.Listen(rendr.ListenConfig{Framed: []rendr.FramedSource{{
		Name: "gvisor-local", Carrier: rendr.CarrierUnknown, Listener: serverSource,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sessionListener.Close() })

	clientRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterFramedFactory("gvisor-local", rendr.FramedFactory{
		Carrier: rendr.CarrierUnknown, Factory: clientFactory,
	}); err != nil {
		t.Fatal(err)
	}
	client, err := clientRuntime.Dial(ctx, rendr.SessionConfig{Root: rendr.Path(
		"gvisor-local",
		rendr.PathSpec{Transport: "gvisor-local", Address: listener.Addr().String()},
	)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := sessionListener.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	assertProcessLocalNegotiation(t, receiveProcessLocalNegotiation(t, ctx, clientFrames), proto.CtrlHello)
	assertProcessLocalNegotiation(t, receiveProcessLocalNegotiation(t, ctx, serverFrames), proto.CtrlHelloAck)
	for side, conn := range map[string]rendr.Conn{
		"client": client,
		"server": server,
	} {
		reporter, ok := conn.(rendr.StatusReporter)
		if !ok {
			t.Fatalf("%s connection %T has no status reporter", side, conn)
		}
		status := reporter.Status()
		if len(status.Paths) != 1 {
			t.Fatalf("%s path count=%d want 1", side, len(status.Paths))
		}
		mobility := status.Paths[0].Mobility
		if mobility.ID != rendr.MobilityRedialAttach || mobility.Negotiated != "" ||
			mobility.Reason != rendr.MobilityReasonOwnedOperationNotQualified {
			t.Fatalf("%s process-local mobility=%+v", side, mobility)
		}
	}
}

type processLocalNegotiation struct {
	code      proto.CtrlCode
	supported proto.LeafMobilitySet
	required  proto.LeafMobilitySet
	err       error
}

type processLocalFrameCapture struct {
	code    proto.CtrlCode
	results chan<- processLocalNegotiation
	once    sync.Once
}

func (capture *processLocalFrameCapture) observe(frame []byte) {
	if capture == nil || len(frame) < proto.HeaderSize {
		return
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != capture.code {
		return
	}
	capture.once.Do(func() {
		result := processLocalNegotiation{code: capture.code}
		switch capture.code {
		case proto.CtrlHello:
			var hello proto.HelloPayload
			hello, result.err = proto.DecodeHello(frame[proto.HeaderSize:])
			result.supported, result.required = hello.MobilitySupported, hello.MobilityRequired
		case proto.CtrlHelloAck:
			var ack proto.HelloAckPayload
			ack, result.err = proto.DecodeHelloAck(frame[proto.HeaderSize:])
			result.supported, result.required = ack.MobilitySupported, ack.MobilityRequired
		default:
			result.err = fmt.Errorf("unexpected control code %d", capture.code)
		}
		capture.results <- result
	})
}

func assertProcessLocalNegotiation(t testing.TB, result processLocalNegotiation, want proto.CtrlCode) {
	t.Helper()
	if result.err != nil {
		t.Fatalf("decode %s: %v", want, result.err)
	}
	if result.code != want || result.supported != 0 || result.required != 0 {
		t.Fatalf("%s mobility supported/required=%#x/%#x", result.code, result.supported, result.required)
	}
}

func receiveProcessLocalNegotiation(
	t testing.TB,
	ctx context.Context,
	results <-chan processLocalNegotiation,
) processLocalNegotiation {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-ctx.Done():
		t.Fatalf("capture process-local negotiation: %v", ctx.Err())
		return processLocalNegotiation{}
	}
}

type processLocalCaptureFactory struct {
	base    *DomainFactory
	capture processLocalFrameCapture
}

func (factory *processLocalCaptureFactory) DialPath(
	ctx context.Context,
	spec transport.PathSpec,
) (transport.PathConn, error) {
	path, err := factory.base.DialPath(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &processLocalCapturePath{PathConn: path, capture: &factory.capture}, nil
}

func (factory *processLocalCaptureFactory) Probe(
	ctx context.Context,
	spec transport.PathSpec,
) (transport.PathQuality, error) {
	return factory.base.Probe(ctx, spec)
}

type processLocalCaptureListener struct {
	base    *LocalListener
	capture processLocalFrameCapture
}

func (listener *processLocalCaptureListener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	path, err := listener.base.AcceptPath(ctx)
	if err != nil {
		return nil, err
	}
	return &processLocalCapturePath{PathConn: path, capture: &listener.capture}, nil
}

func (listener *processLocalCaptureListener) SessionKind() transport.PathSessionKind {
	return listener.base.SessionKind()
}

func (listener *processLocalCaptureListener) Close() error { return listener.base.Close() }

func (listener *processLocalCaptureListener) Addr() net.Addr { return listener.base.Addr() }

type processLocalCapturePath struct {
	transport.PathConn
	capture *processLocalFrameCapture
}

func (path *processLocalCapturePath) Write(frame []byte) (int, error) {
	path.capture.observe(frame)
	return path.PathConn.Write(frame)
}

func (path *processLocalCapturePath) LeafMobilityClaim() *leafmobility.Claim {
	provider, ok := path.PathConn.(leafmobility.Provider)
	if !ok {
		return nil
	}
	return provider.LeafMobilityClaim()
}

var (
	_ transport.PathFactory  = (*processLocalCaptureFactory)(nil)
	_ transport.PathListener = (*processLocalCaptureListener)(nil)
	_ transport.PathConn     = (*processLocalCapturePath)(nil)
	_ leafmobility.Provider  = (*processLocalCapturePath)(nil)
)
