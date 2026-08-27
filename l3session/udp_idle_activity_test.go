package l3session

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

func TestUDPReplyActivityTouchesOnlyAfterSuccessfulDelivery(t *testing.T) {
	tests := []struct {
		name      string
		writeN    int
		writeErr  error
		delivered bool
	}{
		{name: "full-write", writeN: -1, delivered: true},
		{name: "short-write", writeN: 1},
		{name: "write-error", writeN: 0, writeErr: errors.New("device write failed")},
	}
	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := time.Unix(20_000+int64(index), 0)
			now := base
			table := l3ingress.NewFlowTable(nil, l3ingress.FlowTableOptions{Now: func() time.Time { return now }})
			id := udpIdleTestIdentity(uint16(43000 + index))
			_, _, snapshot, err := table.Resolve(context.Background(), l3ingress.FlowMeta{
				L3Identity: id, Direction: l3ingress.DirectionIngress,
			}, 7)
			if err != nil {
				t.Fatal(err)
			}
			now = base.Add(10 * time.Second)
			tracker := &udpIdleTestActivity{table: table, ended: make(chan bool, 1)}
			device := &udpIdleTestDevice{writeN: tt.writeN, writeErr: tt.writeErr}
			runUDPIdleReplyLoop(t, table, snapshot.Ref, device, tracker)

			select {
			case delivered := <-tracker.ended:
				if delivered != tt.delivered {
					t.Fatalf("delivered=%v want %v", delivered, tt.delivered)
				}
			default:
				t.Fatal("reply activity did not finish")
			}
			current, ok := table.Snapshot(id)
			if !ok {
				t.Fatal("reply loop removed flow-table state")
			}
			wantLastSeen := base
			if tt.delivered {
				wantLastSeen = now
			}
			if !current.LastSeen.Equal(wantLastSeen) {
				t.Fatalf("LastSeen=%s want %s", current.LastSeen, wantLastSeen)
			}
			if current.Packets != 1 || current.Bytes != 7 {
				t.Fatalf("reply activity changed ingress counters: %+v", current)
			}
		})
	}
}

func TestUDPReplyActivityRemainsInFlightUntilDeviceWriteReturns(t *testing.T) {
	base := time.Unix(21_000, 0)
	now := base
	table := l3ingress.NewFlowTable(nil, l3ingress.FlowTableOptions{Now: func() time.Time { return now }})
	id := udpIdleTestIdentity(44000)
	_, _, snapshot, err := table.Resolve(context.Background(), l3ingress.FlowMeta{
		L3Identity: id, Direction: l3ingress.DirectionIngress,
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	now = base.Add(20 * time.Second)
	tracker := &udpIdleTestActivity{
		table: table,
		began: make(chan struct{}, 1),
		ended: make(chan bool, 1),
	}
	device := &udpIdleTestDevice{
		writeN:  -1,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		runUDPIdleReplyLoop(t, table, snapshot.Ref, device, tracker)
		close(done)
	}()

	select {
	case <-tracker.began:
	case <-time.After(time.Second):
		t.Fatal("reply operation did not begin")
	}
	select {
	case <-device.started:
	case <-time.After(time.Second):
		t.Fatal("reply did not enter device write")
	}
	select {
	case delivered := <-tracker.ended:
		t.Fatalf("activity ended while write was blocked: delivered=%v", delivered)
	default:
	}
	close(device.release)
	select {
	case delivered := <-tracker.ended:
		if !delivered {
			t.Fatal("released full write was not delivered")
		}
	case <-time.After(time.Second):
		t.Fatal("reply activity did not finish after write release")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reply loop did not terminate")
	}
	current, ok := table.Snapshot(id)
	if !ok || !current.LastSeen.Equal(now) {
		t.Fatalf("reply-only activity snapshot=%+v ok=%v", current, ok)
	}
}

func runUDPIdleReplyLoop(
	t *testing.T,
	table *l3ingress.FlowTable,
	ref l3ingress.FlowRef,
	device *udpIdleTestDevice,
	tracker *udpIdleTestActivity,
) {
	t.Helper()
	packetConn := &udpIdleTestPacketConn{payload: []byte("reply")}
	session := &Session{
		request:    l3ingress.SessionRequest{Identity: ref.Identity, Ref: ref},
		packetConn: packetConn,
	}
	manager := &Manager{
		FlowTable: table,
		sessions:  map[l3ingress.L3Identity]*Session{ref.Identity: session},
	}
	relay := &UDPRelay{
		Device: device, Manager: manager, ReplyActivity: tracker,
	}
	relay.readReplies(context.Background(), ref.Identity, session)
}

func udpIdleTestIdentity(srcPort uint16) l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP,
		SrcIP: netip.MustParseAddr("192.0.2.20"), SrcPort: srcPort,
		DstIP: netip.MustParseAddr("198.51.100.20"), DstPort: 53,
	}
}

type udpIdleTestActivity struct {
	table *l3ingress.FlowTable
	began chan struct{}
	ended chan bool
}

func (a *udpIdleTestActivity) BeginUDPReply(l3ingress.FlowRef) bool {
	if a.began != nil {
		a.began <- struct{}{}
	}
	return true
}

func (a *udpIdleTestActivity) EndUDPReply(ref l3ingress.FlowRef, delivered bool) {
	if delivered {
		a.table.TouchRef(ref)
	}
	if a.ended != nil {
		a.ended <- delivered
	}
}

type udpIdleTestPacketConn struct {
	mu      sync.Mutex
	payload []byte
	read    bool
	closed  bool
}

func (c *udpIdleTestPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.read {
		return 0, nil, io.EOF
	}
	c.read = true
	return copy(p, c.payload), packetAddr("idle-test-peer"), nil
}

func (*udpIdleTestPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *udpIdleTestPacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (*udpIdleTestPacketConn) LocalAddr() net.Addr              { return packetAddr("idle-test-local") }
func (*udpIdleTestPacketConn) SetDeadline(time.Time) error      { return nil }
func (*udpIdleTestPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*udpIdleTestPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (*udpIdleTestPacketConn) Paths() []rendr.PathInfo          { return nil }
func (*udpIdleTestPacketConn) FlowID() [16]byte                 { return [16]byte{} }
func (*udpIdleTestPacketConn) Status() rendr.Status             { return rendr.Status{} }

type udpIdleTestDevice struct {
	writeN   int
	writeErr error
	started  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (*udpIdleTestDevice) Read([]byte) (int, error) { return 0, io.EOF }
func (d *udpIdleTestDevice) Write(p []byte) (int, error) {
	return d.WriteContext(context.Background(), p)
}
func (d *udpIdleTestDevice) WriteContext(ctx context.Context, p []byte) (int, error) {
	if d.started != nil {
		d.once.Do(func() { close(d.started) })
	}
	if d.release != nil {
		select {
		case <-d.release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if d.writeErr != nil {
		return d.writeN, d.writeErr
	}
	if d.writeN < 0 {
		return len(p), nil
	}
	return d.writeN, nil
}
func (*udpIdleTestDevice) Close() error { return nil }
func (*udpIdleTestDevice) Name() string { return "udp-idle-test0" }
func (*udpIdleTestDevice) MTU() int     { return 1500 }
