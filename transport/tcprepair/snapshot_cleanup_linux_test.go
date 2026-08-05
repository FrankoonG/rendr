//go:build linux

package tcprepair

import (
	"errors"
	"strings"
	"testing"
)

type recordingSnapshotOps struct {
	fail         map[string]bool
	calls        []string
	currentQueue int
}

func (o *recordingSnapshotOps) setInt(_ int, opt, value int) error {
	name := "set"
	switch {
	case opt == tcpRepair && value == 1:
		name = "enter"
	case opt == tcpRepair && value == 0:
		name = "exit"
	case opt == tcpRepairQueue && value == tcpSendQueue:
		name = "queue-send"
	case opt == tcpRepairQueue && value == tcpRecvQueue:
		name = "queue-recv"
	case opt == tcpRepairQueue && value == tcpNoQueue:
		name = "queue-none"
	}
	if err := o.record(name); err != nil {
		return err
	}
	if opt == tcpRepairQueue {
		o.currentQueue = value
	}
	return nil
}

func (o *recordingSnapshotOps) getInt(_ int, opt int) (int, error) {
	name := "get-int"
	if opt == tcpQueueSeq {
		if o.currentQueue == tcpSendQueue {
			name = "send-seq"
		} else {
			name = "recv-seq"
		}
	} else if opt == tcpTimestamp {
		name = "timestamp"
	}
	return 0, o.record(name)
}

func (o *recordingSnapshotOps) dumpQueue(int) ([]byte, error) {
	name := "dump-recv"
	if o.currentQueue == tcpSendQueue {
		name = "dump-send"
	}
	return nil, o.record(name)
}

func (o *recordingSnapshotOps) getRaw(_ int, opt int, _ []byte) (int, error) {
	name := "raw"
	if opt == tcpInfoOpt {
		name = "tcp-info"
	} else if opt == tcpRepairWindow {
		name = "repair-window"
	}
	return 0, o.record(name)
}

func (o *recordingSnapshotOps) record(name string) error {
	o.calls = append(o.calls, name)
	if o.fail[name] {
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (o *recordingSnapshotOps) called(name string) bool {
	for _, call := range o.calls {
		if call == name {
			return true
		}
	}
	return false
}

func TestCaptureStateRestoresRepairModeOnFailure(t *testing.T) {
	failures := []string{
		"queue-send", "send-seq", "dump-send", "queue-recv", "recv-seq", "dump-recv", "queue-none",
		"tcp-info", "timestamp", "repair-window",
	}
	for _, failure := range failures {
		t.Run(failure, func(t *testing.T) {
			ops := &recordingSnapshotOps{fail: map[string]bool{failure: true}}
			if err := captureState(1, &state{}, ops); err == nil {
				t.Fatal("captureState unexpectedly succeeded")
			}
			if !ops.called("exit") {
				t.Fatalf("calls=%v, want TCP_REPAIR exit after failure", ops.calls)
			}
		})
	}
}

func TestCaptureStateReportsCleanupFailure(t *testing.T) {
	ops := &recordingSnapshotOps{fail: map[string]bool{"repair-window": true, "exit": true}}
	err := captureState(1, &state{}, ops)
	if err == nil || !strings.Contains(err.Error(), "repair-window") || !strings.Contains(err.Error(), "exit repair") {
		t.Fatalf("captureState error=%v, want capture and cleanup failures", err)
	}
}

func TestCaptureStateSuccessKeepsRepairMode(t *testing.T) {
	ops := &recordingSnapshotOps{fail: make(map[string]bool)}
	if err := captureState(1, &state{}, ops); err != nil {
		t.Fatalf("captureState: %v", err)
	}
	if ops.called("exit") {
		t.Fatalf("calls=%v, successful snapshot unexpectedly exited repair mode", ops.calls)
	}
}

func TestSnapshotRejectsNilTCPConn(t *testing.T) {
	if _, err := snapshot(nil); err == nil || !strings.Contains(err.Error(), "nil TCPConn") {
		t.Fatalf("snapshot(nil) error=%v, want nil TCPConn", err)
	}
}
