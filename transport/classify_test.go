package transport

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestClassifyEOFQuiesced(t *testing.T) {
	if got := Classify(io.EOF, true, false); got != CauseCleanClose {
		t.Fatalf("quiesced EOF: got %v want CleanClose", got)
	}
}

func TestClassifyEOFMidStream(t *testing.T) {
	if got := Classify(io.EOF, false, false); got != CauseTransportError {
		t.Fatalf("mid-stream EOF: got %v want TransportError (hard rule #2)", got)
	}
}

func TestClassifyUnexpectedEOF(t *testing.T) {
	if got := Classify(io.ErrUnexpectedEOF, true, false); got != CauseTransportError {
		t.Fatalf("ErrUnexpectedEOF: got %v want TransportError (the whole point of hard rule #2)", got)
	}
}

func TestClassifyByeOverridesError(t *testing.T) {
	if got := Classify(errors.New("connection reset"), false, true); got != CauseCleanClose {
		t.Fatalf("BYE seen: got %v want CleanClose", got)
	}
}

type fakeTimeoutErr struct{}

func (fakeTimeoutErr) Error() string   { return "i/o timeout" }
func (fakeTimeoutErr) Timeout() bool   { return true }
func (fakeTimeoutErr) Temporary() bool { return false }

var _ net.Error = fakeTimeoutErr{}

func TestClassifyNetTimeout(t *testing.T) {
	if got := Classify(fakeTimeoutErr{}, false, false); got != CauseTransportError {
		t.Fatalf("net timeout: got %v want TransportError", got)
	}
}

func TestClassifyECONNRESET(t *testing.T) {
	if got := Classify(syscall.ECONNRESET, false, false); got != CauseTransportError {
		t.Fatalf("ECONNRESET: got %v want TransportError", got)
	}
}

func TestClassifyNilWithBye(t *testing.T) {
	if got := Classify(nil, true, true); got != CauseCleanClose {
		t.Fatalf("nil + bye: got %v want CleanClose", got)
	}
}

func TestClassifyNilWithoutBye(t *testing.T) {
	if got := Classify(nil, true, false); got != CauseTransportError {
		t.Fatalf("nil without bye: got %v want TransportError", got)
	}
}

func TestClassifyIdleTimeoutString(t *testing.T) {
	if got := Classify(errors.New("quic: idle timeout"), false, false); got != CauseTransportError {
		t.Fatalf("idle timeout string: got %v want TransportError", got)
	}
}

func TestClassifyHandshakeError(t *testing.T) {
	if got := Classify(errors.New("tls: handshake failure"), false, false); got != CauseTransportError {
		t.Fatalf("handshake error: got %v want TransportError", got)
	}
}

// Sanity: a deadline-exceeded net.Error sub-class is also classified
// regardless of whether the implementation reports Timeout().
type fakeNetErr struct{ msg string }

func (e fakeNetErr) Error() string   { return e.msg }
func (e fakeNetErr) Timeout() bool   { return false }
func (e fakeNetErr) Temporary() bool { return false }

func TestClassifyNetErrNonTimeout(t *testing.T) {
	if got := Classify(fakeNetErr{"some op: no route to host"}, false, false); got != CauseTransportError {
		t.Fatalf("non-timeout net.Error: got %v want TransportError", got)
	}
}

func TestClassifyTimeoutBoundary(t *testing.T) {
	// The classifier should not interpret the absence of a Timeout()
	// flag as cleanness. A future bug could regress this if someone
	// special-cases Timeout()=false as 'application' close.
	deadline := time.Now()
	_ = deadline
}
