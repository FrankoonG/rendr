package rendr

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	"github.com/FrankoonG/rendr/transport/tcp"
)

func TestRuntimeDialDoesNotForkSessionAfterInitialOutcomeUnknown(t *testing.T) {
	firstListener := newFramedPipeListener()
	firstListener.kind = transport.PathSessionStream
	secondListener := newFramedPipeListener()
	secondListener.kind = transport.PathSessionStream

	serverConfig := DefaultRuntimeConfig()
	serverConfig.Recovery.MigrationBudget = 5 * time.Second
	serverRuntime, err := NewRuntime(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{
		{Name: "first", Carrier: CarrierTCP, Listener: firstListener},
		{Name: "second", Carrier: CarrierTCP, Listener: secondListener},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	firstFactory := &runtimeOutcomeUnknownFactory{listener: firstListener, dropActivated: true}
	secondFactory := &runtimeOutcomeUnknownFactory{listener: secondListener}
	clientConfig := DefaultRuntimeConfig()
	clientConfig.Recovery.MigrationBudget = 100 * time.Millisecond
	clientRuntime, err := NewRuntime(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterFramedFactory("first", FramedFactory{Carrier: CarrierTCP, Factory: firstFactory}); err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterFramedFactory("second", FramedFactory{Carrier: CarrierTCP, Factory: secondFactory}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, dialErr := clientRuntime.Dial(ctx, SessionConfig{Root: Selector("root", []Target{
		Path("first", PathSpec{Transport: "first", Address: "first"}),
		Path("second", PathSpec{Transport: "second", Address: "second"}),
	})})
	if client != nil {
		_ = client.Close()
		t.Fatal("Dial returned a replacement session after an unknown committed outcome")
	}
	if !errors.Is(dialErr, ErrPathAdmissionOutcomeUnknown) {
		t.Fatalf("Dial error=%v want=%v", dialErr, ErrPathAdmissionOutcomeUnknown)
	}
	if got := firstFactory.activatedDrops.Load(); got == 0 {
		t.Fatal("test stimulus invalid: server did not drop ACTIVATED")
	}
	if got := secondFactory.dials.Load(); got != 0 {
		t.Fatalf("second factory dials=%d want=0 after committed outcome became unknown", got)
	}

	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), time.Second)
	server, err := listener.AcceptStream(acceptCtx)
	acceptCancel()
	if err != nil {
		t.Fatalf("test stimulus invalid: server did not publish the committed first session: %v", err)
	}
	_ = server.(*acceptedStreamConn).engine.Close()
	secondAcceptCtx, secondAcceptCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer secondAcceptCancel()
	if duplicate, err := listener.AcceptStream(secondAcceptCtx); err == nil {
		_ = duplicate.Close()
		t.Fatal("one Dial published a second server application session")
	}
}

type runtimeOutcomeUnknownFactory struct {
	listener       *framedPipeListener
	dropActivated  bool
	dials          atomic.Uint32
	activatedDrops atomic.Uint32
}

func (f *runtimeOutcomeUnknownFactory) DialPath(ctx context.Context, _ transport.PathSpec) (transport.PathConn, error) {
	f.dials.Add(1)
	clientRaw, serverRaw := net.Pipe()
	clientPath := tcp.Wrap(clientRaw)
	var serverPath transport.PathConn = tcp.Wrap(serverRaw)
	if f.dropActivated {
		serverPath = &runtimeDropActivatedPath{PathConn: serverPath, drops: &f.activatedDrops}
	}
	if err := f.listener.Publish(ctx, serverPath); err != nil {
		_ = clientPath.Close()
		_ = serverPath.Close()
		return nil, err
	}
	return clientPath, nil
}

func (f *runtimeOutcomeUnknownFactory) Probe(context.Context, transport.PathSpec) (transport.PathQuality, error) {
	return transport.PathQuality{}, nil
}

type runtimeDropActivatedPath struct {
	transport.PathConn
	drops *atomic.Uint32
}

func (p *runtimeDropActivatedPath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlPathAdmissionAck {
			ack, decodeErr := proto.DecodePathAdmissionAck(frame[proto.HeaderSize:])
			if decodeErr == nil && ack.Phase == proto.PathAdmissionPhaseActivated {
				p.drops.Add(1)
				return len(frame), nil
			}
		}
	}
	return p.PathConn.Write(frame)
}
