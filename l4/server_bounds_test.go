package l4

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M4 WP5: the Server's bounds, the hook wrapper and the Reject codes
// (M4 design §A6.2–§A6.5, §A9, §A12.1).

// TestServerMaxConns_L48 (M4-D28): MaxConns bounds handlers that dial and
// forwards together; a session beyond it is rejected CodeCapacity at once
// without a hook call, and a slot that frees is used again.
func TestServerMaxConns_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{})
		echo := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		hang, _ := rendrtest.ScriptedDial(rendrtest.OutcomeHang())
		hl := newHookLog(func(ctx context.Context, r Request) (net.Conn, error) {
			if r.Addr == "hang.test:1" {
				return hang(ctx, r.Addr)
			}
			return echo.Dial(ctx, r.Addr)
		})
		s := &Server{Dial: hl.dial, MaxConns: 3}
		sv := serve(w, s)
		live := make([]*rendr.Conn, 2)
		for i := range live {
			c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
			if err != nil {
				t.Fatalf("Dial %d: %v", i, err)
			}
			ping(t, c, 100)
			live[i] = c
		}
		hctx, hcancel := context.WithCancel(context.Background())
		hangCh := dialAsync(hctx, w, "hang.test:1")
		waitFor(t, time.Minute, "the third handler dials", func() bool { return s.Status().Dialing == 1 })
		if st := s.Status(); st.Live != 2 || st.Dialing != 1 {
			t.Fatalf("stimulus: %+v", st)
		}
		calls, _, _, _ := hl.snapshot()
		start := time.Now()
		_, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
		wantReject(t, err, CodeCapacity)
		if el := time.Since(start); el > 100*time.Millisecond {
			t.Fatalf("the refusal took %v, want at once", el)
		}
		if c, _, _, _ := hl.snapshot(); c != calls {
			t.Fatalf("the hook was called for a session beyond MaxConns")
		}
		echoRoundTrip(t, live[0], 1<<10, 3)
		live[0].Close()
		waitFor(t, time.Minute, "a forward ends", func() bool { return s.Status().Live == 1 })
		c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
		if err != nil {
			t.Fatalf("Dial after a slot freed: %v", err)
		}
		ping(t, c, 100)
		if st := s.Status(); st.ByCode[CodeCapacity] != 1 || st.Confirmed != 3 {
			t.Fatalf("status %+v", st)
		}
		hcancel()
		recv(t, hangCh, time.Minute)
		c.Close()
		live[1].Close()
		sv.stop(t)
		w.shutdown()
	})
}

// TestServerAbandonedCap_L51 (R1-9): 1,000 requests over 10 virtual
// seconds with hooks that ignore ctx and run 30 s: at most 192 hook calls
// run at once, abandoned ones included; every newcomer at the cap is
// rejected CodeCapacity without a hook call; when the calls return, their
// late conns are closed and Hooks and Abandoned return to 0.
func TestServerAbandonedCap_L51(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 1000
		w := newSrvWorld(t, srvOpts{worldOpts: worldOpts{n: n}, backlog: 1024})
		dial, counts := rendrtest.ScriptedDial(rendrtest.OutcomeLate(30 * time.Second))
		hl := newHookLog(hookOf(dial))
		s := &Server{Dial: hl.dial}
		sv := serve(w, s)
		results := make(chan dialRes, n)
		start := time.Now()
		maxHooks := 0
		for range n {
			go func() {
				c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
				results <- dialRes{c, err, time.Now()}
			}()
			time.Sleep(10 * time.Millisecond)
			maxHooks = max(maxHooks, s.Status().Hooks)
		}
		capacity, timeouts := 0, 0
		for range n {
			r := <-results
			code, ok := CodeOf(r.err)
			switch {
			case ok && code == CodeCapacity:
				capacity++
			case ok && code == CodeTimeout:
				timeouts++
			default:
				t.Errorf("Dial: %v at %v", r.err, r.at.Sub(start))
			}
		}
		calls, peak, _, _ := hl.snapshot()
		t.Logf("%d hook calls (peak %d, Status peak %d); %d CodeCapacity, %d CodeTimeout", calls, peak, maxHooks, capacity, timeouts)
		if peak > maxHookCalls || maxHooks > maxHookCalls || calls != maxHookCalls {
			t.Fatalf("%d hook calls, %d at once (Status %d); want %d", calls, peak, maxHooks, maxHookCalls)
		}
		if capacity != n-maxHookCalls || timeouts != maxHookCalls {
			t.Fatalf("%d CodeCapacity, %d CodeTimeout", capacity, timeouts)
		}
		if st := s.Status(); st.Abandoned != maxHookCalls || st.Hooks != maxHookCalls {
			t.Fatalf("status while abandoned %+v", st)
		}
		waitFor(t, time.Minute, "the hook calls return", func() bool { return s.Status().Hooks == 0 })
		if st := s.Status(); st.Abandoned != 0 || counts.Unclosed() != 0 {
			t.Fatalf("status %+v; %d late conns open", st, counts.Unclosed())
		}
		sv.stop(t)
		w.shutdown()
	})
}

// TestServerHookAdversarial_L51 (M4-D30, R1-7): the hook wrapper. A panic
// or Goexit is answered CodeDialFailed and counted; (nil, nil) is
// CodeDialFailed; the conn of (conn, err) is closed once and err
// classified; a hook that ignores ctx is answered CodeTimeout at its budget
// + 1 s and abandoned, and its late conn is closed once; a hook that never
// returns does not hold Serve, which returns within the budget + 1 s of a
// cancel, and its conn is closed once when it finally returns.
func TestServerHookAdversarial_L51(t *testing.T) {
	refuse, _ := rendrtest.ScriptedDial(rendrtest.OutcomeRefuse())
	rows := []struct {
		name    string
		outcome rendrtest.DialOutcome
		custom  bool // the row's hook is built below
		code    RejectCode
		at      time.Duration // when the refusal leaves (from the call; 0: at once)
		panics  uint64
	}{
		{name: "panic", outcome: rendrtest.OutcomePanic(), code: CodeDialFailed, panics: 1},
		{name: "goexit", outcome: rendrtest.OutcomeGoexit(), code: CodeDialFailed, panics: 1},
		{name: "nil nil", outcome: rendrtest.OutcomeNilNil(), code: CodeDialFailed},
		{name: "conn and err", custom: true, code: CodeRefused},
		{name: "ignores ctx", outcome: rendrtest.OutcomeIgnoreCtx(20 * time.Second), code: CodeTimeout, at: 2 * time.Second},
		{name: "late conn", outcome: rendrtest.OutcomeLate(20 * time.Second), code: CodeTimeout, at: 2 * time.Second},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSrvWorld(t, srvOpts{})
				dial, counts := rendrtest.ScriptedDial(row.outcome)
				hook := hookOf(dial)
				var spy *spyConn
				if row.custom {
					hook = func(ctx context.Context, r Request) (net.Conn, error) {
						c, _ := rendrtest.TargetPipe(0)
						spy = &spyConn{Conn: c}
						_, err := refuse(ctx, r.Addr)
						return spy, err
					}
				}
				hl := newHookLog(hook)
				s := &Server{Dial: hl.dial, DialTimeout: time.Second}
				sv := serve(w, s)
				r := recv(t, dialAsync(context.Background(), w, kitTarget), time.Minute)
				wantReject(t, r.err, row.code)
				hl.mu.Lock()
				el := r.at.Sub(hl.starts[0])
				hl.mu.Unlock()
				if el < row.at || el > row.at+50*time.Millisecond {
					t.Fatalf("refused %v after the call, want %v", el, row.at)
				}
				if row.at > 0 {
					if st := s.Status(); st.Abandoned != 1 || st.Hooks != 1 {
						t.Fatalf("status while abandoned %+v", st)
					}
				}
				waitFor(t, time.Minute, "the hook call ends", func() bool { return s.Status().Hooks == 0 })
				st := s.Status()
				if st.Panics != row.panics || st.Abandoned != 0 || st.LastErr == nil || counts.Unclosed() != 0 {
					t.Fatalf("status %+v; %d conns open", st, counts.Unclosed())
				}
				if spy != nil {
					if _, _, closes, _ := spy.snapshot(); closes != 1 {
						t.Fatalf("the conn of (conn, err) closed %d times", closes)
					}
				}
				sv.stop(t)
				w.shutdown()
			})
		})
	}
	t.Run("never returns", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSrvWorld(t, srvOpts{})
			release := make(chan struct{})
			var spy *spyConn
			hl := newHookLog(func(ctx context.Context, r Request) (net.Conn, error) {
				<-release // ignores ctx
				c, _ := rendrtest.TargetPipe(0)
				spy = &spyConn{Conn: c}
				return spy, nil
			})
			s := &Server{Dial: hl.dial, DialTimeout: time.Second}
			sv := serve(w, s)
			ch := dialAsync(context.Background(), w, kitTarget)
			waitFor(t, time.Minute, "the hook is called", func() bool { c, _, _, _ := hl.snapshot(); return c == 1 })
			hl.mu.Lock()
			called := hl.starts[0]
			hl.mu.Unlock()
			sv.cancel()
			if err := sv.wait(t, 3*time.Second); !errors.Is(err, context.Canceled) {
				t.Fatalf("Serve: %v", err)
			}
			if el := time.Unix(0, sv.ended.Load()).Sub(called); el > 2*time.Second+10*time.Millisecond {
				t.Fatalf("Serve returned %v after the call, want within the budget + 1 s", el)
			}
			wantReject(t, recv(t, ch, time.Minute).err, CodeDialFailed)
			if st := s.Status(); st.Abandoned != 1 || st.Hooks != 1 {
				t.Fatalf("status after Serve %+v", st)
			}
			time.Sleep(time.Minute)
			close(release)
			waitFor(t, time.Minute, "the hook call ends", func() bool { return s.Status().Hooks == 0 })
			if _, _, closes, _ := spy.snapshot(); closes != 1 || s.Status().Abandoned != 0 {
				t.Fatalf("the late conn closed %d times; status %+v", closes, s.Status())
			}
			w.shutdown()
		})
	})
}

// TestServerBlackholeTimeout (M4-D29, §A9): a target that never answers
// (a dropped SYN) is answered CodeTimeout when the dial budget ends:
// DialTimeout (default 5 s; clamped to 0.5–30 s), never past the pending
// deadline − 250 ms.
func TestServerBlackholeTimeout(t *testing.T) {
	rows := []struct {
		name   string
		dialTO time.Duration
		budget time.Duration
	}{
		{"default", 0, DefaultDialTimeout},
		{"1 s", time.Second, time.Second},
		{"clamped up", 100 * time.Millisecond, 500 * time.Millisecond},
		{"pending deadline", time.Minute, 10*time.Second - 250*time.Millisecond},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSrvWorld(t, srvOpts{})
				dial, _ := rendrtest.ScriptedDial(rendrtest.OutcomeHang())
				hl := newHookLog(hookOf(dial))
				s := &Server{Dial: hl.dial, DialTimeout: row.dialTO}
				sv := serve(w, s)
				r := recv(t, dialAsync(context.Background(), w, kitTarget), time.Minute)
				wantReject(t, r.err, CodeTimeout)
				_, _, _, returns := hl.snapshot()
				hl.mu.Lock()
				took := returns[0].Sub(hl.starts[0])
				hl.mu.Unlock()
				// The pending deadline counts from admission, a moment before
				// the call.
				if took < row.budget-10*time.Millisecond || took > row.budget {
					t.Fatalf("the dial ran %v, want %v", took, row.budget)
				}
				sv.stop(t)
				w.shutdown()
			})
		})
	}
}

// TestServerNonL4Metadata: an OPEN whose metadata is not valid L4 metadata
// is rejected with ParseMetadata's code and its fixed text; the hook is
// never called.
func TestServerNonL4Metadata(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{})
		dial, counts := rendrtest.ScriptedDial(rendrtest.OutcomeHang())
		s := &Server{Dial: hookOf(dial)}
		sv := serve(w, s)
		good, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: "127.0.0.1:443"})
		if err != nil {
			t.Fatal(err)
		}
		mod := func(i int, b byte) []byte { md := append([]byte(nil), good...); md[i] = b; return md }
		for _, row := range []struct {
			name string
			md   []byte
			code RejectCode
		}{
			{"none", nil, CodeBadRequest},
			{"other protocol", []byte("GET / HTTP/1.1"), CodeBadRequest},
			{"truncated", good[:4], CodeBadRequest},
			{"version 2", mod(2, 2), CodeBadVersion},
			{"command 2", mod(3, 2), CodeBadCommand},
			{"atyp 2", mod(4, 2), CodeBadAddress},
			{"port 0", append(good[:len(good)-2:len(good)-2], 0, 0), CodeBadAddress},
		} {
			_, err := w.peer.Dial(context.Background(), rendr.DialOptions{Metadata: row.md})
			if e := checkReject(err, row.code); e != nil {
				t.Errorf("%s: %v", row.name, e)
			}
		}
		if n := counts.Calls(); n != 0 {
			t.Fatalf("%d hook calls", n)
		}
		sv.stop(t)
		w.shutdown()
	})
}

// secret is text a raw dial error carries that must never reach the
// dialer (M4-D32: resolver addresses, interface names).
const secret = "192.0.2.53 via if-x7"

// TestServerRejectMessageFixed (M4-D32): whatever the raw error says, the
// dialer's refusal carries only the code's fixed text; the raw error stays
// on the passive (Status().LastErr).
func TestServerRejectMessageFixed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{})
		errs := map[string]error{
			"denied.test:1":  fmt.Errorf("policy %s: %w", secret, ErrDenied),
			"dns.test:1":     &net.DNSError{Err: "server misbehaving", Name: "dns.test", Server: secret},
			"nx.test:1":      &net.DNSError{Err: "no such host", Name: "nx.test", Server: secret, IsNotFound: true},
			"refused.test:1": &net.OpError{Op: "dial", Net: "tcp", Source: &net.TCPAddr{}, Addr: strAddr(secret), Err: syscall.Errno(10061)},
			"other.test:1":   errors.New("route " + secret),
		}
		s := &Server{Dial: func(ctx context.Context, r Request) (net.Conn, error) { return nil, errs[r.Addr] }}
		sv := serve(w, s)
		for addr, raw := range errs {
			_, err := Dial(context.Background(), w.peer, addr, rendr.DialOptions{})
			var re *rendr.RejectError
			if !errors.As(err, &re) || strings.Contains(re.Msg, "192.0.2.53") || strings.Contains(re.Msg, "if-x7") {
				t.Fatalf("%s: %v", addr, err)
			}
			wantReject(t, err, classify(raw))
			if last := s.Status().LastErr; last != raw || !strings.Contains(last.Error(), secret) {
				t.Fatalf("%s: LastErr %v", addr, last)
			}
		}
		sv.stop(t)
		w.shutdown()
	})
}

// strAddr is a net.Addr with a fixed text.
type strAddr string

func (a strAddr) Network() string { return "tcp" }
func (a strAddr) String() string  { return string(a) }

// TestServerRejectCodes (M4-D33, §A8.1): every classification row through
// a hook and a Runtime pair reaches the dialer as its code.
func TestServerRejectCodes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{})
		scripted := func(o rendrtest.DialOutcome) func(context.Context, string) (net.Conn, error) {
			d, _ := rendrtest.ScriptedDial(o)
			return d
		}
		fail := func(err error) func(context.Context, string) (net.Conn, error) {
			return func(context.Context, string) (net.Conn, error) { return nil, err }
		}
		connectErr := func(errno syscall.Errno) error {
			return &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("connect: %w", errno)}
		}
		rows := []struct {
			name string
			dial func(context.Context, string) (net.Conn, error)
			code RejectCode
		}{
			{"refused", scripted(rendrtest.OutcomeRefuse()), CodeRefused},
			{"net unreachable", scripted(rendrtest.OutcomeNetUnreachable()), CodeNetUnreachable},
			{"host unreachable", scripted(rendrtest.OutcomeHostUnreachable()), CodeHostUnreachable},
			{"dns not found", scripted(rendrtest.OutcomeDNSNotFound()), CodeDNSNotFound},
			{"dns failure", scripted(rendrtest.OutcomeDNSFailure()), CodeDNSFailure},
			{"hang", scripted(rendrtest.OutcomeHang()), CodeTimeout},
			{"ignores ctx", scripted(rendrtest.OutcomeIgnoreCtx(time.Minute)), CodeTimeout},
			{"panic", scripted(rendrtest.OutcomePanic()), CodeDialFailed},
			{"goexit", scripted(rendrtest.OutcomeGoexit()), CodeDialFailed},
			{"nil nil", scripted(rendrtest.OutcomeNilNil()), CodeDialFailed},
			{"denied", fail(fmt.Errorf("policy: %w", ErrDenied)), CodeNotAllowed},
			{"access", fail(connectErr(syscall.Errno(10013))), CodeNotAllowed},
			{"no buffers", fail(connectErr(syscall.Errno(10055))), CodeCapacity},
			{"errno timeout", fail(connectErr(syscall.Errno(10060))), CodeTimeout},
			{"resolver cancelled", fail(&net.DNSError{Err: context.Canceled.Error(), Name: "x.test", UnwrapErr: context.Canceled}), CodeDialFailed},
			{"other", fail(errors.New("unclassified")), CodeDialFailed},
		}
		byAddr := make(map[string]func(context.Context, string) (net.Conn, error))
		for i, row := range rows {
			byAddr[fmt.Sprintf("row%d.test:80", i)] = row.dial
		}
		s := &Server{DialTimeout: time.Second, Dial: func(ctx context.Context, r Request) (net.Conn, error) {
			return byAddr[r.Addr](ctx, r.Addr)
		}}
		sv := serve(w, s)
		var wg sync.WaitGroup
		errs := make([]error, len(rows))
		for i := range rows {
			wg.Go(func() {
				_, errs[i] = Dial(context.Background(), w.peer, fmt.Sprintf("row%d.test:80", i), rendr.DialOptions{})
			})
		}
		wg.Wait()
		for i, row := range rows {
			if e := checkReject(errs[i], row.code); e != nil {
				t.Errorf("%s: %v", row.name, e)
			}
		}
		waitFor(t, 2*time.Minute, "the hook calls end", func() bool { return s.Status().Hooks == 0 })
		st := s.Status()
		total := uint64(0)
		for _, n := range st.ByCode {
			total += n
		}
		if st.Rejected != uint64(len(rows)) || total != st.Rejected || st.Panics != 2 {
			t.Fatalf("status %+v", st)
		}
		sv.stop(t)
		w.shutdown()
	})
}
