package l4

import (
	"context"
	"errors"
	"net"
	"os"
)

// classify maps a target dial error to its Reject code in the fixed order
// of the M4 design (§A8.1, R1-6); the first match wins:
//
//  1. a cancellation (context.Canceled, wrapped anywhere, also inside a
//     *net.DNSError) → CodeDialFailed: the dial was stopped, it did not fail;
//  2. policy (ErrDenied) → CodeNotAllowed;
//  3. DNS (*net.DNSError): not found → CodeDNSNotFound, anything else, a
//     resolver timeout included → CodeDNSFailure;
//  4. a timeout (context.DeadlineExceeded, os.ErrDeadlineExceeded, a
//     net.Error whose Timeout() is true) → CodeTimeout;
//  5. a syscall.Errno by the errno tables (errnoCode);
//  6. anything else → CodeDialFailed.
//
// Handle decides the Server's and the pending context's cancellation
// before it calls classify.
func classify(err error) RejectCode {
	if errors.Is(err, context.Canceled) {
		return CodeDialFailed
	}
	if errors.Is(err, ErrDenied) {
		return CodeNotAllowed
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		if dns.IsNotFound {
			return CodeDNSNotFound
		}
		return CodeDNSFailure
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return CodeTimeout
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return CodeTimeout
	}
	if c, ok := errnoCode(err); ok {
		return c
	}
	return CodeDialFailed
}
