package engine

import (
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

type abnormalOptionalPath struct {
	transport.PathConn
	operation       string
	mode            string
	cause           error
	markCalls       atomic.Int32
	closeWriteCalls atomic.Int32
}

func (path *abnormalOptionalPath) fail(operation string) {
	if path.operation != operation {
		return
	}
	switch path.mode {
	case "panic":
		panic(path.cause)
	case "goexit":
		runtime.Goexit()
	}
}

func (path *abnormalOptionalPath) LocalAddr() string {
	path.fail("diagnostics")
	return "optional-local"
}

func (path *abnormalOptionalPath) RemoteAddr() string { return "optional-remote" }
func (path *abnormalOptionalPath) Reads() uint64      { return 17 }
func (path *abnormalOptionalPath) Writes() uint64     { return 19 }

func (path *abnormalOptionalPath) IngressQueueStats() transport.IngressQueueStats {
	return transport.IngressQueueStats{Depth: 2, Capacity: 8}
}

func (path *abnormalOptionalPath) DatagramAccelerationStatus() transport.DatagramAccelerationStatus {
	return transport.DatagramAccelerationStatus{Mode: transport.DatagramAccelerationOrdinary}
}

func (path *abnormalOptionalPath) MaxFrameSize() int {
	path.fail("frame-size")
	return 1400
}

func (path *abnormalOptionalPath) MarkQuiesced() {
	path.markCalls.Add(1)
	path.fail("mark-quiesced")
}

func (path *abnormalOptionalPath) CloseWrite() error {
	path.closeWriteCalls.Add(1)
	path.fail("close-write")
	if path.operation == "close-write-error" {
		return path.cause
	}
	return nil
}

func TestPathDiagnosticsAbnormalExitReturnsCoreSnapshot(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			local, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
			path := &abnormalOptionalPath{
				PathConn: local, operation: "diagnostics", mode: mode,
				cause: errors.New("abnormal diagnostics"),
			}
			slot := &pathSlot{id: 41, conn: path, attached: time.Unix(7, 0)}
			slot.dataWrites.Store(23)
			infos := pathInfos([]*pathSlot{slot}, slot.id, time.Second)
			if len(infos) != 1 {
				t.Fatalf("path info count=%d want=1", len(infos))
			}
			info := infos[0]
			if info.ID != slot.id || !info.Active || info.DataWrites != 23 {
				t.Fatalf("core path snapshot was lost: %+v", info)
			}
			if info.LocalAddr != "" || info.RemoteAddr != "" || info.Reads != 0 || info.Writes != 0 ||
				info.IngressQueue != (transport.IngressQueueStats{}) ||
				info.DatagramAcceleration != (transport.DatagramAccelerationStatus{}) {
				t.Fatalf("abnormal diagnostics published partial external state: %+v", info)
			}
		})
	}
}

func TestPacketFrameSizeAbnormalExitRejectsPath(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			e.SetPacketMode()
			local, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
			cause := errors.New("abnormal frame-size report")
			path := &abnormalOptionalPath{
				PathConn: local, operation: "frame-size", mode: mode, cause: cause,
			}
			_, _, err := e.validatePacketPathFrameLimit(path, PathBinding{LocalReceiveFrameCapacity: 1400, PeerReceiveFrameCapacity: 1400}, &externalPathCallbackOwner{})
			if mode == "panic" {
				assertDispatchCallbackPanic(t, err, cause, "PathConn.MaxFrameSize")
			} else {
				assertDispatchCallbackGoexit(t, err, "PathConn.MaxFrameSize")
			}
		})
	}
}

func TestPathQuiesceAbnormalExitIsContained(t *testing.T) {
	tests := []struct {
		name             string
		operation        string
		mode             string
		wantCloseWrites  int32
		wantAbnormalOp   string
		wantOrdinaryOnly bool
	}{
		{name: "mark panic", operation: "mark-quiesced", mode: "panic", wantAbnormalOp: "PathConn.MarkQuiesced"},
		{name: "mark Goexit", operation: "mark-quiesced", mode: "goexit", wantAbnormalOp: "PathConn.MarkQuiesced"},
		{name: "close-write panic", operation: "close-write", mode: "panic", wantCloseWrites: 1, wantAbnormalOp: "PathConn.CloseWrite"},
		{name: "close-write Goexit", operation: "close-write", mode: "goexit", wantCloseWrites: 1, wantAbnormalOp: "PathConn.CloseWrite"},
		{name: "ordinary close-write error remains optional", operation: "close-write-error", wantCloseWrites: 1, wantOrdinaryOnly: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			ids := configureLeafSelectorRuntime(t, e, "quiesce")
			local, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = peer.Close() })
			cause := errors.New("optional quiesce failure")
			path := &abnormalOptionalPath{
				PathConn: local, operation: test.operation, mode: test.mode, cause: cause,
			}
			_ = attachFixturePath(
				t, e, path,
				transport.PathSpec{Transport: "optional-quiesce", Address: test.name},
				ids["quiesce"],
			)

			e.QuiesceActivePath()
			if got := path.markCalls.Load(); got != 1 {
				t.Fatalf("MarkQuiesced calls=%d want=1", got)
			}
			if got := path.closeWriteCalls.Load(); got != test.wantCloseWrites {
				t.Fatalf("CloseWrite calls=%d want=%d", got, test.wantCloseWrites)
			}
			err := e.Close()
			if test.wantOrdinaryOnly {
				if err != nil {
					t.Fatalf("optional ordinary CloseWrite error escaped teardown: %v", err)
				}
				return
			}
			if test.mode == "panic" {
				assertDispatchCallbackPanic(t, err, cause, test.wantAbnormalOp)
			} else {
				assertDispatchCallbackGoexit(t, err, test.wantAbnormalOp)
			}
		})
	}
}
