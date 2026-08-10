package rendr

import (
	"context"
	"io"
	"net"
	"reflect"
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

	for _, adapterCapability := range []CapabilityID{
		"tcp_repair",
		"gvisor",
		"tun",
		"mixed",
		"quic_datagram",
	} {
		filtered, err := ProbeLocal(context.Background(), adapterCapability)
		if err != nil {
			t.Fatal(err)
		}
		if len(filtered.Caps) != 0 {
			t.Fatalf("adapter capability %q leaked from root probe: %v", adapterCapability, filtered.Caps)
		}
	}
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

	first := statusFromEngine(e, ModeSelector, nil, nil)
	second := statusFromEngine(e, ModeSelector, nil, nil)
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
