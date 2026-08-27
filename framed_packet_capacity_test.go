package rendr

import (
	"context"
	"errors"
	"testing"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/transport"
)

func TestRegisteredFramedFactoryPacketAdmissionRequiresExplicitCapacity(t *testing.T) {
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var opened *factoryBoundaryPathConn
	factory := &factoryBoundaryFramedFactory{dial: func(context.Context, PathSpec) (transport.PathConn, error) {
		opened = &factoryBoundaryPathConn{}
		return opened, nil
	}}
	if err := runtime.RegisterFramedFactory("unknown-packet-capacity", FramedFactory{
		Carrier: CarrierUDP,
		Factory: factory,
	}); err != nil {
		t.Fatal(err)
	}
	dialer, err := runtime.sessionDialer(SessionConfig{Root: Path("only", PathSpec{
		Transport: "unknown-packet-capacity",
		Address:   "opaque",
	})})
	if err != nil {
		t.Fatal(err)
	}
	path, err := dialer.snapshotFactoryResolver().dialPath(context.Background(), PathSpec{
		Transport: "unknown-packet-capacity",
		Address:   "opaque",
	})
	if err != nil {
		t.Fatal(err)
	}

	packetEngine := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	packetEngine.SetPacketMode()
	_, err = packetEngine.AttachPath(path, transport.PathSpec{Transport: "unknown-packet-capacity"})
	if !errors.Is(err, ErrPacketPathCapacityUnavailable) {
		t.Fatalf("packet admission error=%v want ErrPacketPathCapacityUnavailable", err)
	}
	if opened == nil || !opened.closed.Load() {
		t.Fatal("capacity-rejected framed path was not closed by engine ownership")
	}
	if closeErr := packetEngine.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	streamPath := &factoryBoundaryPathConn{}
	streamEngine := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	if _, err := streamEngine.AttachPath(streamPath, transport.PathSpec{Transport: "unknown-packet-capacity"}); err != nil {
		t.Fatalf("stream admission unexpectedly required packet capacity: %v", err)
	}
	if err := streamEngine.Close(); err != nil {
		t.Fatal(err)
	}
}

var _ transport.PathConn = (*factoryBoundaryPathConn)(nil)

func testPacketPathFrameSize(path transport.PathConn) int {
	packetPath, ok := path.(transport.PacketPathConn)
	if !ok {
		panic("rendr test adapter hid an explicit packet frame capacity")
	}
	return packetPath.MaxFrameSize()
}
