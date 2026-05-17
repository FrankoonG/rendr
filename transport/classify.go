package transport

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

// Classify maps a Go error into a DeathCause. It is the canonical
// helper transport adapters should call before invoking OnDeath.
//
// The bias here is intentional and matches CLAUDE.md hard rule #2:
// when in doubt, classify as TransportError. CleanClose only on
// unambiguous signals.
//
// Currently recognised CleanClose signals:
//   - io.EOF on a stream that has been quiesced (caller signals
//     quiesced=true to opt in).
//   - A protocol-level BYE was already received before the close
//     (caller signals byeSeen=true).
//
// Everything else, including io.ErrUnexpectedEOF, becomes
// TransportError. ErrUnexpectedEOF means data was cut off
// mid-message, which is precisely what should trigger a migration.
func Classify(err error, quiesced bool, byeSeen bool) DeathCause {
	if err == nil {
		// nil with byeSeen is a normal teardown.
		if byeSeen {
			return CauseCleanClose
		}
		// nil without a BYE is treated as a transport error - the
		// caller closed without a reason, which is unusual.
		return CauseTransportError
	}

	if byeSeen {
		// Even an underlying socket error after a BYE is the
		// expected teardown noise; treat as clean.
		return CauseCleanClose
	}

	if errors.Is(err, io.EOF) {
		if quiesced {
			return CauseCleanClose
		}
		// Mid-stream EOF is a transport surprise.
		return CauseTransportError
	}

	// All net.Error timeouts trigger migration.
	var ne net.Error
	if errors.As(err, &ne) {
		// Even non-timeout net.Errors are transport-class for our
		// purposes; the engine will retry on another path.
		return CauseTransportError
	}

	// Bare syscall errno (RST, EPIPE, ECONNRESET, ENETUNREACH ...) -> transport.
	var serr syscall.Errno
	if errors.As(err, &serr) {
		return CauseTransportError
	}

	// os.PathError wraps fd ops; treat as transport.
	var perr *os.PathError
	if errors.As(err, &perr) {
		return CauseTransportError
	}

	// Heuristic: anything mentioning "use of closed network connection",
	// "connection reset", "broken pipe", or "idle timeout" is transport.
	msg := strings.ToLower(err.Error())
	for _, sub := range []string{
		"use of closed network connection",
		"connection reset",
		"broken pipe",
		"idle timeout",
		"handshake",
		"transport",
		"application error",
	} {
		if strings.Contains(msg, sub) {
			return CauseTransportError
		}
	}

	// Default: transport. Hard rule #2.
	return CauseTransportError
}
