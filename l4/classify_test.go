package l4

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

type classifyRow struct {
	name string
	err  error
	want RejectCode
}

// timeoutErr is a net.Error that reports a timeout (a hook's own error).
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// opErr wraps err as the net package returns a dial error.
func opErr(err error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: err}
}

// dnsErr is a resolver error as the net package builds it: a context error
// is kept for errors.Is (DNSError.UnwrapErr).
func dnsErr(err error, notFound bool) error {
	e := &net.DNSError{Err: "lookup failed", Name: "target.example", IsNotFound: notFound}
	if err != nil {
		e.Err, e.UnwrapErr = err.Error(), err
		e.IsTimeout = errors.Is(err, context.DeadlineExceeded)
	}
	return opErr(e)
}

// ctxErrs returns the errors of the three ways a dial context ends (M4
// design R1-6): Serve's ctx cancelled, the pending context done (Handle's
// AfterFunc cancels the dial context), and the budget's deadline.
func ctxErrs() (serve, pending, budget error) {
	serveCtx, stopServe := context.WithCancel(context.Background())
	dctx, cancel := context.WithDeadline(serveCtx, time.Now().Add(time.Hour))
	stopServe()
	serve = dctx.Err()
	cancel()

	pendingCtx, cancelPending := context.WithCancel(context.Background())
	dctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	stop := context.AfterFunc(pendingCtx, cancel)
	cancelPending()
	<-dctx.Done()
	pending = dctx.Err()
	stop()

	dctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	budget = dctx.Err()
	cancel()
	return serve, pending, budget
}

// TestClassify: every row of M4 design §A8.1 in its order (the first match
// wins): cancellations from each source, plain and inside a *net.DNSError,
// before everything (R1-6); policy; DNS before timeouts; timeouts; this
// OS's errno symbols and the Windows numbers on every OS (errnoRows); the
// rest.
func TestClassify(t *testing.T) {
	serve, pending, budget := ctxErrs()
	if !errors.Is(serve, context.Canceled) || !errors.Is(pending, context.Canceled) || !errors.Is(budget, context.DeadlineExceeded) {
		t.Fatalf("context errors %v, %v, %v", serve, pending, budget)
	}
	rows := []classifyRow{
		// 0b: cancellations (R1-6).
		{"serve ctx", serve, CodeDialFailed},
		{"serve ctx in OpError", opErr(serve), CodeDialFailed},
		{"serve ctx in DNSError", dnsErr(serve, false), CodeDialFailed},
		{"pending ctx", pending, CodeDialFailed},
		{"pending ctx wrapped", fmt.Errorf("hook: %w", pending), CodeDialFailed},
		{"pending ctx in DNSError", dnsErr(pending, false), CodeDialFailed},
		{"canceled with a deadline", errors.Join(context.DeadlineExceeded, context.Canceled), CodeDialFailed},
		{"canceled and denied", errors.Join(ErrDenied, context.Canceled), CodeDialFailed},
		// The budget expiring is a timeout, a resolver's a DNS failure.
		{"budget", budget, CodeTimeout},
		{"budget in OpError", opErr(budget), CodeTimeout},
		{"budget in DNSError", dnsErr(budget, false), CodeDNSFailure},
		// 1: policy.
		{"denied", ErrDenied, CodeNotAllowed},
		{"denied wrapped", fmt.Errorf("policy: %w", ErrDenied), CodeNotAllowed},
		{"denied and DNS", errors.Join(ErrDenied, dnsErr(nil, true)), CodeNotAllowed},
		{"denied and timeout", errors.Join(ErrDenied, os.ErrDeadlineExceeded), CodeNotAllowed},
		// 2: DNS.
		{"dns not found", dnsErr(nil, true), CodeDNSNotFound},
		{"dns not found bare", &net.DNSError{Err: "no such host", Name: "x.example", IsNotFound: true}, CodeDNSNotFound},
		{"dns server failure", dnsErr(nil, false), CodeDNSFailure},
		{"dns temporary", &net.DNSError{Err: "server misbehaving", IsTemporary: true}, CodeDNSFailure},
		{"dns timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, CodeDNSFailure},
		{"dns timeout wrapped", fmt.Errorf("resolve: %w", &net.DNSError{Err: "i/o timeout", IsTimeout: true}), CodeDNSFailure},
		// 3: timeouts.
		{"deadline exceeded", context.DeadlineExceeded, CodeTimeout},
		{"os deadline", os.ErrDeadlineExceeded, CodeTimeout},
		{"os deadline in OpError", opErr(os.ErrDeadlineExceeded), CodeTimeout},
		{"net.Error timeout", timeoutErr{}, CodeTimeout},
		{"net.Error timeout wrapped", fmt.Errorf("hook: %w", opErr(timeoutErr{})), CodeTimeout},
		// 5: the rest.
		{"plain error", errors.New("boom"), CodeDialFailed},
		{"OpError without cause", opErr(errors.New("boom")), CodeDialFailed},
		{"nil conn", errors.New("l4: nil conn"), CodeDialFailed},
	}
	rows = append(rows, errnoRows()...)
	for _, r := range rows {
		if got := classify(r.err); got != r.want {
			t.Errorf("%s: classify(%v) = %v, want %v", r.name, r.err, got, r.want)
		}
	}
}

// TestClassifyRealDial: errors from the net package itself. A dial on a
// context already cancelled or past its deadline does no network I/O; a
// refused loopback connect (a closed port; Windows answers it only after
// its SYN retries, about 1–2 s) is CodeRefused through the OS's own error.
func TestClassifyRealDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel2 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel2()
	var d net.Dialer
	for _, c := range []struct {
		name string
		ctx  context.Context
		want RejectCode
	}{{"canceled", canceled, CodeDialFailed}, {"expired", expired, CodeTimeout}} {
		conn, err := d.DialContext(c.ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			t.Fatalf("%s: dial succeeded", c.name)
		}
		if got := classify(err); got != c.want {
			t.Errorf("%s: classify(%v) = %v, want %v", c.name, err, got, c.want)
		}
	}

	ctx, cancel3 := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel3()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		conn.Close()
		t.Fatal("the closed port accepted a connection")
	}
	if got := classify(err); got != CodeRefused {
		t.Errorf("refused: classify(%v) = %v, want %v", err, got, CodeRefused)
	}
}
