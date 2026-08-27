package udpflow

import (
	"bytes"
	"errors"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestUDPFlowPathsReportExactFrameCapacity(t *testing.T) {
	want := MaxDatagram - proto.UDPFlowHeaderSize
	for name, path := range map[string]any{
		"client": &PathConn{maxDatagramSize: MaxDatagram},
		"server": &ServerPathConn{maxDatagramSize: MaxDatagram},
	} {
		reporter, ok := path.(interface{ MaxFrameSize() int })
		if !ok {
			t.Fatalf("%s path does not report its frame capacity", name)
		}
		if got := reporter.MaxFrameSize(); got != want {
			t.Fatalf("%s MaxFrameSize=%d want %d", name, got, want)
		}
	}
}

func TestWrappedPacketConnUsesCallerReportedDatagramCapacity(t *testing.T) {
	const maxDatagramSize = 1200
	raw := &packetContractConn{}
	peer, err := SnapshotPeer(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	path, err := Wrap(raw, peer, listenerFlowID(8900), maxDatagramSize)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = path.Close() })
	wantFrameSize := maxDatagramSize - proto.UDPFlowHeaderSize
	if got := path.MaxFrameSize(); got != wantFrameSize {
		t.Fatalf("MaxFrameSize=%d want %d", got, wantFrameSize)
	}
	frame := make([]byte, wantFrameSize)
	if n, err := path.Write(frame); err != nil || n != len(frame) {
		t.Fatalf("boundary Write=(%d,%v) want (%d,nil)", n, err, len(frame))
	}
	writes := raw.writeCalls.Load()
	if n, err := path.Write(make([]byte, wantFrameSize+1)); err == nil || n != 0 {
		t.Fatalf("oversize Write=(%d,%v) want rejection", n, err)
	}
	if got := raw.writeCalls.Load(); got != writes {
		t.Fatalf("oversize frame reached PacketConn: writes=%d want %d", got, writes)
	}
}

func TestUDPFlowFrameCapacityRejectsBeforeEnginePublication(t *testing.T) {
	pathConn, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	tracked := &packetFrameLimitConn{Conn: pathConn}
	path := &PathConn{conn: tracked, flowID: listenerFlowID(8901), maxDatagramSize: MaxDatagram}

	e := engine.New(
		engine.SideClient,
		engine.NewClientFlowID(),
		engine.Limits{ProbeInterval: time.Hour}.Clamp(),
	)
	e.SetPacketMode()
	t.Cleanup(func() { _ = e.Close() })
	if _, err := e.AttachPath(path, transport.PathSpec{Transport: "udpflow", Address: "test"}); err != nil {
		t.Fatal(err)
	}

	writesBefore := tracked.writeCalls.Load()
	published, err := e.SendPacketResult(make([]byte, MaxDatagram-proto.UDPFlowHeaderSize))
	if published || !errors.Is(err, engine.ErrPacketTooLarge) {
		t.Fatalf("oversize packet published/error=%t/%v want false/ErrPacketTooLarge", published, err)
	}
	if writes := tracked.writeCalls.Load(); writes != writesBefore {
		t.Fatalf("oversize packet reached path: writes before=%d after=%d", writesBefore, writes)
	}
}

type packetFrameLimitConn struct {
	net.Conn
	writeCalls atomic.Int32
}

func (conn *packetFrameLimitConn) Write(payload []byte) (int, error) {
	conn.writeCalls.Add(1)
	return conn.Conn.Write(payload)
}

func TestPacketAsConnWriteValidatesEveryCount(t *testing.T) {
	peer, err := SnapshotPeer(udpflowTestAddr("peer"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("one-datagram")
	transportErr := errors.New("injected packet write failure")
	tests := []struct {
		name       string
		written    int
		writeErr   error
		want       int
		wantErrors []error
	}{
		{name: "zero without error", written: 0, want: 0, wantErrors: []error{io.ErrShortWrite}},
		{name: "short without error", written: len(payload) - 1, want: len(payload) - 1, wantErrors: []error{io.ErrShortWrite}},
		{name: "negative", written: -1, want: 0, wantErrors: []error{ErrInvalidPacketWriteCount}},
		{name: "oversized", written: len(payload) + 1, want: 0, wantErrors: []error{ErrInvalidPacketWriteCount}},
		{name: "short with error", written: 3, writeErr: transportErr, want: 3, wantErrors: []error{transportErr, io.ErrShortWrite}},
		{name: "full with error", written: len(payload), writeErr: transportErr, want: len(payload), wantErrors: []error{transportErr}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := &packetContractConn{
				writeFn: func([]byte, net.Addr) (int, error) {
					return test.written, test.writeErr
				},
			}
			adapter, err := newPacketAsConn(raw, peer)
			if err != nil {
				t.Fatal(err)
			}
			got, gotErr := adapter.Write(payload)
			if got != test.want {
				t.Fatalf("Write count=%d want=%d", got, test.want)
			}
			for _, wantErr := range test.wantErrors {
				if !errors.Is(gotErr, wantErr) {
					t.Fatalf("Write error=%v does not contain %v", gotErr, wantErr)
				}
			}
			if calls := raw.writeCalls.Load(); calls != 1 {
				t.Fatalf("WriteTo calls=%d want=1; datagram must not be retried", calls)
			}
		})
	}
}

func TestPathConnWriteCountFailureRetiresPacketCarrier(t *testing.T) {
	peer, err := SnapshotPeer(udpflowTestAddr("peer"))
	if err != nil {
		t.Fatal(err)
	}
	flowID := [proto.UDPFlowIDSize]byte{1, 3, 5, 7, 9, 11, 13}
	frame := []byte("frame-payload")
	datagramBytes := proto.UDPFlowHeaderSize + len(frame)
	transportErr := errors.New("injected terminal packet write error")
	tests := []struct {
		name      string
		written   int
		writeErr  error
		want      int
		wantCause error
	}{
		{name: "zero", written: 0, want: 0, wantCause: io.ErrShortWrite},
		{name: "header and partial payload", written: proto.UDPFlowHeaderSize + 2, want: 2, wantCause: io.ErrShortWrite},
		{name: "negative", written: -1, want: 0, wantCause: ErrInvalidPacketWriteCount},
		{name: "oversized", written: datagramBytes + 1, want: 0, wantCause: ErrInvalidPacketWriteCount},
		{name: "partial payload with terminal error", written: proto.UDPFlowHeaderSize + 3, writeErr: transportErr, want: 3, wantCause: transportErr},
		{name: "full datagram with terminal error", written: datagramBytes, writeErr: transportErr, want: len(frame), wantCause: transportErr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := &packetContractConn{
				writeFn: func([]byte, net.Addr) (int, error) {
					return test.written, test.writeErr
				},
			}
			path, err := Wrap(raw, peer, flowID, MaxDatagram)
			if err != nil {
				t.Fatal(err)
			}
			death := make(chan error, 1)
			path.OnDeath(func(_ transport.DeathCause, err error) { death <- err })

			got, gotErr := path.Write(frame)
			if got != test.want {
				t.Fatalf("PathConn.Write count=%d want=%d", got, test.want)
			}
			if !errors.Is(gotErr, net.ErrClosed) {
				t.Fatalf("PathConn.Write error=%v want net.ErrClosed", gotErr)
			}
			select {
			case cause := <-death:
				if !errors.Is(cause, test.wantCause) {
					t.Fatalf("death cause=%v does not contain %v", cause, test.wantCause)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for packet path retirement")
			}
			if closes := raw.closeCalls.Load(); closes != 1 {
				t.Fatalf("PacketConn closes=%d want=1", closes)
			}
			if writes := raw.writeCalls.Load(); writes != 1 {
				t.Fatalf("WriteTo calls=%d want=1", writes)
			}
			if writes := path.Writes(); writes != 0 {
				t.Fatalf("failed datagram incremented success counter to %d", writes)
			}
			if _, err := path.Write(frame); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("post-retirement Write error=%v want net.ErrClosed", err)
			}
			if writes := raw.writeCalls.Load(); writes != 1 {
				t.Fatalf("retired path retried datagram; WriteTo calls=%d", writes)
			}
		})
	}
}

func TestServerPathConnWriteCountFailureRetiresPacketCarrier(t *testing.T) {
	peer, err := SnapshotPeer(udpflowTestAddr("peer"))
	if err != nil {
		t.Fatal(err)
	}
	flowID := [proto.UDPFlowIDSize]byte{7, 6, 5, 4, 3, 2, 1}
	frame := []byte("server-frame-payload")
	for _, test := range []struct {
		name    string
		written int
	}{
		{name: "zero", written: 0},
		{name: "short", written: proto.UDPFlowHeaderSize + 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := &packetContractConn{
				writeFn: func([]byte, net.Addr) (int, error) {
					return test.written, nil
				},
			}
			listener := &Listener{
				conn:            raw,
				maxDatagramSize: MaxDatagram,
				flows:           make(map[[proto.UDPFlowIDSize]byte]*ServerPathConn),
				admitting:       true,
			}
			path := newServerPathConn(listener, flowID, peer.Identity())
			path.accepted = true
			listener.flows[flowID] = path
			t.Cleanup(func() { _ = path.Close() })

			death := make(chan error, 1)
			path.OnDeath(func(_ transport.DeathCause, err error) { death <- err })
			got, gotErr := path.Write(frame)
			if got != 0 || !errors.Is(gotErr, net.ErrClosed) {
				t.Fatalf("ServerPathConn.Write=%d, %v want 0, net.ErrClosed", got, gotErr)
			}
			select {
			case cause := <-death:
				if !errors.Is(cause, io.ErrShortWrite) {
					t.Fatalf("death cause=%v want io.ErrShortWrite", cause)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for server packet path retirement")
			}
			listener.mu.Lock()
			_, live := listener.flows[flowID]
			listener.mu.Unlock()
			if live {
				t.Fatal("short datagram write left server flow attached")
			}
			if writes := raw.writeCalls.Load(); writes != 1 {
				t.Fatalf("WriteTo calls=%d want 1", writes)
			}
			if writes := path.Writes(); writes != 0 {
				t.Fatalf("failed server datagram incremented success counter to %d", writes)
			}
			if _, err := path.Write(frame); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("post-retirement Write error=%v want net.ErrClosed", err)
			}
			if writes := raw.writeCalls.Load(); writes != 1 {
				t.Fatalf("retired server path retried datagram; WriteTo calls=%d", writes)
			}
		})
	}
}

func TestPacketReadFromDeliversDataBeforeTerminalError(t *testing.T) {
	flowID := [proto.UDPFlowIDSize]byte{2, 4, 6, 8, 10, 12, 14}
	peer, err := SnapshotPeer(udpflowTestAddr("peer"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("data-before-read-error")
	datagram := udpflowTestPacket(t, flowID, payload)
	terminal := errors.New("injected ReadFrom terminal error")
	raw := &packetContractConn{
		readFn: func(buffer []byte) (int, net.Addr, error) {
			copy(buffer, datagram)
			return len(datagram), peer.Identity(), terminal
		},
	}
	path, err := Wrap(raw, peer, flowID, MaxDatagram)
	if err != nil {
		t.Fatal(err)
	}
	death := make(chan error, 1)
	path.OnDeath(func(_ transport.DeathCause, err error) { death <- err })

	buffer := make([]byte, len(payload))
	n, err := path.Read(buffer)
	if err != nil || n != len(payload) || !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("first Read=%d, %v, %q want payload before error", n, err, buffer[:n])
	}
	if calls := raw.readCalls.Load(); calls != 1 {
		t.Fatalf("ReadFrom calls after payload=%d want=1", calls)
	}
	n, err = path.Read(buffer)
	if n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Read=%d, %v want 0, net.ErrClosed", n, err)
	}
	select {
	case cause := <-death:
		if !errors.Is(cause, terminal) {
			t.Fatalf("death cause=%v does not contain terminal error", cause)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delayed terminal error")
	}
	if calls := raw.readCalls.Load(); calls != 1 {
		t.Fatalf("terminal replay performed another ReadFrom; calls=%d", calls)
	}
}

func TestPacketReadMsgUDPDeliversDataBeforeTerminalError(t *testing.T) {
	flowID := [proto.UDPFlowIDSize]byte{14, 12, 10, 8, 6, 4, 2}
	peerAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.42"), Port: 4242}
	peer, err := SnapshotPeer(peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("readmsg-data-before-error")
	datagram := udpflowTestPacket(t, flowID, payload)
	terminal := errors.New("injected ReadMsgUDP terminal error")
	raw := &packetMessageContractConn{
		readMsgFn: func(buffer, _ []byte) (int, int, int, *net.UDPAddr, error) {
			copy(buffer, datagram)
			return len(datagram), 0, 0, peerAddr, terminal
		},
	}
	path := wrapInjectedPacketMessageReader(t, raw, peer, flowID)
	death := make(chan error, 1)
	path.OnDeath(func(_ transport.DeathCause, err error) { death <- err })

	buffer := make([]byte, len(payload))
	n, err := path.Read(buffer)
	if err != nil || n != len(payload) || !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("first Read=%d, %v, %q want payload before error", n, err, buffer[:n])
	}
	n, err = path.Read(buffer)
	if n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Read=%d, %v want 0, net.ErrClosed", n, err)
	}
	select {
	case cause := <-death:
		if !errors.Is(cause, terminal) {
			t.Fatalf("death cause=%v does not contain terminal error", cause)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delayed ReadMsgUDP error")
	}
	if calls := raw.readMsgCalls.Load(); calls != 1 {
		t.Fatalf("ReadMsgUDP calls=%d want=1", calls)
	}
	if calls := raw.readFromCalls.Load(); calls != 0 {
		t.Fatalf("ReadFrom fallback calls=%d want=0", calls)
	}
}

func TestPacketReadFromRejectsInvalidCountsPromptly(t *testing.T) {
	peer, err := SnapshotPeer(udpflowTestAddr("peer"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		read int
	}{
		{name: "negative", read: -1},
		{name: "oversized", read: 65},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := &packetContractConn{
				readFn: func([]byte) (int, net.Addr, error) {
					return test.read, peer.Identity(), nil
				},
			}
			adapter, err := newPacketAsConn(raw, peer)
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan struct {
				n   int
				err error
			}, 1)
			go func() {
				n, err := adapter.Read(make([]byte, 64))
				result <- struct {
					n   int
					err error
				}{n: n, err: err}
			}()
			select {
			case got := <-result:
				if got.n != 0 || !errors.Is(got.err, ErrInvalidPacketReadCount) {
					t.Fatalf("Read=%d, %v want 0, invalid-count error", got.n, got.err)
				}
			case <-time.After(time.Second):
				t.Fatal("invalid ReadFrom count caused a spin or block")
			}
			if calls := raw.readCalls.Load(); calls != 1 {
				t.Fatalf("ReadFrom calls=%d want=1", calls)
			}
		})
	}
}

func TestPacketReadMsgUDPRejectsInvalidPayloadAndOOBCounts(t *testing.T) {
	peerAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.7"), Port: 7000}
	peer, err := SnapshotPeer(peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		read      int
		oob       int
		wantError error
	}{
		{name: "negative payload", read: -1, wantError: ErrInvalidPacketReadCount},
		{name: "oversized payload", read: 65, wantError: ErrInvalidPacketReadCount},
		{name: "negative OOB", read: 1, oob: -1, wantError: ErrInvalidPacketOOBCount},
		{name: "oversized OOB", read: 1, oob: packetReadOOBSize + 1, wantError: ErrInvalidPacketOOBCount},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := &packetMessageContractConn{
				readMsgFn: func([]byte, []byte) (int, int, int, *net.UDPAddr, error) {
					return test.read, test.oob, 0, peerAddr, nil
				},
			}
			adapter, err := newPacketAsConn(raw, peer)
			if err != nil {
				t.Fatal(err)
			}
			adapter.messageReader = raw
			n, err := adapter.Read(make([]byte, 64))
			if n != 0 || !errors.Is(err, test.wantError) {
				t.Fatalf("Read=%d, %v want 0, %v", n, err, test.wantError)
			}
			if calls := raw.readMsgCalls.Load(); calls != 1 {
				t.Fatalf("ReadMsgUDP calls=%d want=1", calls)
			}
			if calls := raw.readFromCalls.Load(); calls != 0 {
				t.Fatalf("ReadFrom fallback calls=%d want=0", calls)
			}
		})
	}
}

func TestCustomPacketPeerKeepsReadFromContractWhenReadMsgUDPAlsoExists(t *testing.T) {
	peer, err := SnapshotPeer(udpflowTestAddr("custom-peer"))
	if err != nil {
		t.Fatal(err)
	}
	raw := &packetMessageContractConn{
		readFromFn: func(buffer []byte) (int, net.Addr, error) {
			copy(buffer, "custom-address-payload")
			return len("custom-address-payload"), peer.Identity(), nil
		},
		readMsgFn: func([]byte, []byte) (int, int, int, *net.UDPAddr, error) {
			return 0, 0, 0, nil, errors.New("ReadMsgUDP must not replace a custom peer contract")
		},
	}
	adapter, err := newPacketAsConn(raw, peer)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, err := adapter.Read(buffer)
	if err != nil || string(buffer[:n]) != "custom-address-payload" {
		t.Fatalf("Read=%d, %v, %q", n, err, buffer[:n])
	}
	if calls := raw.readFromCalls.Load(); calls != 1 {
		t.Fatalf("ReadFrom calls=%d want=1", calls)
	}
	if calls := raw.readMsgCalls.Load(); calls != 0 {
		t.Fatalf("ReadMsgUDP calls=%d want=0", calls)
	}
}

func TestStandardUDPPeerWrapperKeepsReadFromContractWhenReadMsgUDPIsPromoted(t *testing.T) {
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	poison := []byte("poison-promoted-readmsg")
	if n, err := sender.WriteToUDP(poison, receiver.LocalAddr().(*net.UDPAddr)); err != nil || n != len(poison) {
		t.Fatalf("seed poison datagram=%d, %v want %d, nil", n, err, len(poison))
	}
	peerAddr := sender.LocalAddr().(*net.UDPAddr)
	peer, err := SnapshotPeer(peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	raw := &standardPeerReadFromWrapper{UDPConn: receiver, source: peerAddr}
	adapter, err := newPacketAsConn(raw, peer)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, err := adapter.Read(buffer)
	if err != nil || string(buffer[:n]) != "authenticated-readfrom" {
		t.Fatalf("Read=%d, %v, %q want authenticated ReadFrom payload", n, err, buffer[:n])
	}
	if calls := raw.readFromCalls.Load(); calls != 1 {
		t.Fatalf("ReadFrom calls=%d want=1", calls)
	}
	queued := make([]byte, 64)
	n, _, _, _, err = receiver.ReadMsgUDP(queued, nil)
	if err != nil || !bytes.Equal(queued[:n], poison) {
		t.Fatalf("promoted ReadMsgUDP consumed poison datagram: ReadMsgUDP=%d, %v, %q", n, err, queued[:n])
	}
}

func TestPacketReadMsgUDPTruncationRetiresCarrierWithoutDelivery(t *testing.T) {
	flowID := [proto.UDPFlowIDSize]byte{3, 1, 4, 1, 5, 9, 2}
	peerAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.19"), Port: 1919}
	peer, err := SnapshotPeer(peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	datagram := udpflowTestPacket(t, flowID, []byte("valid-prefix-must-not-be-delivered"))
	raw := &packetMessageContractConn{
		readMsgFn: func(buffer, _ []byte) (int, int, int, *net.UDPAddr, error) {
			copy(buffer, datagram)
			return len(datagram), 0, packetMSGTruncated, peerAddr, nil
		},
	}
	path := wrapInjectedPacketMessageReader(t, raw, peer, flowID)
	death := make(chan error, 1)
	path.OnDeath(func(_ transport.DeathCause, err error) { death <- err })

	buffer := make([]byte, len(datagram))
	if n, err := path.Read(buffer); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("truncated Read=%d, %v want 0, net.ErrClosed", n, err)
	}
	select {
	case err := <-death:
		if !errors.Is(err, ErrTruncatedPacket) {
			t.Fatalf("death cause=%v want ErrTruncatedPacket", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for truncated packet retirement")
	}
	if got := path.Reads(); got != 0 {
		t.Fatalf("truncated datagram incremented delivered reads to %d", got)
	}
	if closes := raw.closeCalls.Load(); closes != 1 {
		t.Fatalf("truncated datagram closed PacketConn %d times want 1", closes)
	}
}

func TestRealUDPConnOversizedDatagramRetiresCarrierWithoutDelivery(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux MSG_TRUNC runtime contract")
	}
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		receiver.Close()
		t.Fatal(err)
	}
	defer sender.Close()
	flowID := [proto.UDPFlowIDSize]byte{2, 7, 1, 8, 2, 8, 1}
	peer, err := SnapshotPeer(sender.LocalAddr())
	if err != nil {
		receiver.Close()
		t.Fatal(err)
	}
	path, err := Wrap(receiver, peer, flowID, MaxDatagram)
	if err != nil {
		receiver.Close()
		t.Fatal(err)
	}
	defer path.Close()
	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	death := make(chan error, 1)
	path.OnDeath(func(_ transport.DeathCause, err error) { death <- err })
	datagram := udpflowTestPacket(t, flowID, make([]byte, MaxDatagram+128-proto.UDPFlowHeaderSize))
	if n, err := sender.WriteToUDP(datagram, receiver.LocalAddr().(*net.UDPAddr)); err != nil || n != len(datagram) {
		t.Fatalf("oversized WriteToUDP=%d, %v want %d, nil", n, err, len(datagram))
	}
	buffer := make([]byte, MaxDatagram)
	if n, err := path.Read(buffer); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("oversized Read=%d, %v want 0, net.ErrClosed", n, err)
	}
	select {
	case err := <-death:
		if !errors.Is(err, ErrTruncatedPacket) {
			t.Fatalf("death cause=%v want ErrTruncatedPacket", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for oversized datagram retirement")
	}
	if got := path.Reads(); got != 0 {
		t.Fatalf("oversized datagram incremented delivered reads to %d", got)
	}
}

func TestConnectedUDPFactoryCarrierRoundTrip(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	client, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := SnapshotPeer(peer.LocalAddr())
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	flowID := [proto.UDPFlowIDSize]byte{9, 8, 7, 6, 5, 4, 3}
	path, err := Wrap(client, snapshot, flowID, MaxDatagram)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	defer path.Close()
	if err := path.conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	payload := []byte("connected-packet-factory")
	if n, err := path.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("connected Write=%d, %v", n, err)
	}
	datagram := make([]byte, MaxDatagram)
	n, source, err := peer.ReadFromUDP(datagram)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(datagram[:n], source); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload))
	n, err = path.Read(buffer)
	if err != nil || n != len(payload) || !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("connected Read=%d, %v, %q", n, err, buffer[:n])
	}
}

func TestWrapFromSpecRejectsMismatchedConnectedUDPPeerWithoutTakingOwnership(t *testing.T) {
	actual, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer actual.Close()
	configured, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer configured.Close()
	client, err := net.DialUDP("udp", nil, actual.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	path, err := WrapFromSpec(client, transport.PathSpec{Address: configured.LocalAddr().String()}, MaxDatagram)
	if path != nil || !errors.Is(err, ErrConnectedPacketPeerMismatch) {
		t.Fatalf("WrapFromSpec=%v, %v want nil, connected-peer error", path, err)
	}
	if err := client.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("caller-still-owns-connection")); err != nil {
		t.Fatalf("mismatch validation closed caller-owned UDPConn: %v", err)
	}
}

type packetContractConn struct {
	readFn  func([]byte) (int, net.Addr, error)
	writeFn func([]byte, net.Addr) (int, error)

	readCalls  atomic.Int32
	writeCalls atomic.Int32
	closeCalls atomic.Int32
}

func wrapInjectedPacketMessageReader(
	t *testing.T,
	raw *packetMessageContractConn,
	peer PeerSnapshot,
	flowID [proto.UDPFlowIDSize]byte,
) *PathConn {
	t.Helper()
	adapter, err := newPacketAsConn(raw, peer)
	if err != nil {
		t.Fatal(err)
	}
	adapter.messageReader = raw
	return &PathConn{conn: adapter, flowID: flowID, maxDatagramSize: MaxDatagram}
}

func (conn *packetContractConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	conn.readCalls.Add(1)
	if conn.readFn == nil {
		return 0, nil, net.ErrClosed
	}
	return conn.readFn(buffer)
}

func (conn *packetContractConn) WriteTo(buffer []byte, peer net.Addr) (int, error) {
	conn.writeCalls.Add(1)
	if conn.writeFn == nil {
		return len(buffer), nil
	}
	return conn.writeFn(buffer, peer)
}

func (conn *packetContractConn) Close() error {
	conn.closeCalls.Add(1)
	return nil
}

func (*packetContractConn) LocalAddr() net.Addr              { return udpflowTestAddr("local") }
func (*packetContractConn) SetDeadline(time.Time) error      { return nil }
func (*packetContractConn) SetReadDeadline(time.Time) error  { return nil }
func (*packetContractConn) SetWriteDeadline(time.Time) error { return nil }

type packetMessageContractConn struct {
	readFromFn func([]byte) (int, net.Addr, error)
	readMsgFn  func([]byte, []byte) (int, int, int, *net.UDPAddr, error)

	readMsgCalls  atomic.Int32
	readFromCalls atomic.Int32
	closeCalls    atomic.Int32
}

type standardPeerReadFromWrapper struct {
	*net.UDPConn
	source        *net.UDPAddr
	readFromCalls atomic.Int32
}

func (conn *standardPeerReadFromWrapper) ReadFrom(buffer []byte) (int, net.Addr, error) {
	conn.readFromCalls.Add(1)
	copy(buffer, "authenticated-readfrom")
	return len("authenticated-readfrom"), conn.source, nil
}

func (conn *packetMessageContractConn) ReadMsgUDP(payload, oob []byte) (int, int, int, *net.UDPAddr, error) {
	conn.readMsgCalls.Add(1)
	return conn.readMsgFn(payload, oob)
}

func (conn *packetMessageContractConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	conn.readFromCalls.Add(1)
	if conn.readFromFn != nil {
		return conn.readFromFn(buffer)
	}
	return 0, nil, errors.New("unexpected ReadFrom fallback")
}

func (*packetMessageContractConn) WriteTo(buffer []byte, _ net.Addr) (int, error) {
	return len(buffer), nil
}

func (conn *packetMessageContractConn) Close() error {
	conn.closeCalls.Add(1)
	return nil
}

func (*packetMessageContractConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*packetMessageContractConn) SetDeadline(time.Time) error      { return nil }
func (*packetMessageContractConn) SetReadDeadline(time.Time) error  { return nil }
func (*packetMessageContractConn) SetWriteDeadline(time.Time) error { return nil }
