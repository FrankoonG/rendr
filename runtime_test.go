package rendr

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestNewRuntimeFreezesNormalizedConfig(t *testing.T) {
	input := RuntimeConfig{Selector: SelectorTuning{QualityDwell: time.Second}}
	runtime, err := NewRuntime(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Selector.QualityDwell = 2 * time.Second
	got := runtime.Config()
	if got.Selector.QualityDwell != time.Second || got.Recovery.MigrationBudget != 90*time.Second {
		t.Fatalf("runtime config=%+v", got)
	}
	got.Selector.QualityDwell = 3 * time.Second
	if runtime.Config().Selector.QualityDwell != time.Second {
		t.Fatal("Config returned mutable runtime-owned state")
	}
}

func TestRuntimeSessionDialerSnapshotsFactoriesAndIdentity(t *testing.T) {
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	factory := func(context.Context, string) (net.Conn, error) { return nil, net.ErrClosed }
	if err := runtime.AddStreamPathFactory("custom", factory); err != nil {
		t.Fatal(err)
	}
	root := Path("p", PathSpec{Transport: "custom", Address: "peer"})
	first, err := runtime.sessionDialer(SessionConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if first.InstanceID != runtime.instanceID || first.Runtime != runtime.config {
		t.Fatal("session dialer did not inherit frozen runtime identity/config")
	}
	delete(first.streamFactories, "custom")
	second, err := runtime.sessionDialer(SessionConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if second.streamFactories["custom"] == nil {
		t.Fatal("one session mutated the runtime factory registry")
	}
}

func TestRuntimeRejectsNilAndMissingRoot(t *testing.T) {
	var runtime *Runtime
	if _, err := runtime.Dial(context.Background(), SessionConfig{}); err == nil {
		t.Fatal("nil Runtime Dial succeeded")
	}
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Dial(context.Background(), SessionConfig{}); err == nil {
		t.Fatal("Runtime Dial without Root succeeded")
	}
}

func TestRuntimeDialsStandardNetConnSession(t *testing.T) {
	listener, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := runtime.Dial(context.Background(), SessionConfig{Root: Path("primary", PathSpec{
		Transport: "tcp",
		Address:   listener.Addr().String(),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not accept Runtime session")
	}
	defer server.Close()

	payload := []byte("runtime-net-conn")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload=%q want=%q", got, payload)
	}
}
