package smoke

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunHysteriaRelay(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Hysteria 2 relay smoke is validated on Linux regress hosts")
	}
	if !HysteriaAvailable() {
		t.Skip("hysteria binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := RunHysteriaRelay(ctx, HysteriaRelayOpts{
		Paths:      2,
		Migrations: 2,
		DataSize:   4 << 20,
	})
	if r.Failure != "" || r.InvalidReason != "" {
		t.Fatalf("RunHysteriaRelay failed: failure=%q invalid=%q", r.Failure, r.InvalidReason)
	}
}

func TestHysteriaSpeedtestCancellationJoinsProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := startHysteriaTestProcess(t, ctx)

	type outcome struct {
		log string
		err error
	}
	returned := make(chan outcome, 1)
	go func() {
		log, err := runHysteriaSpeedtestProcess(ctx, p, 0, nil, time.Millisecond, time.Second)
		returned <- outcome{log: log, err: err}
	}()
	cancel()

	select {
	case got := <-returned:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("cancellation error = %v, want context.Canceled", got.err)
		}
		if got.log == "" {
			t.Fatal("joined process log is empty")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("speedtest cancellation did not return")
	}
	assertHysteriaProcessJoined(t, p)
}

func TestHysteriaSpeedtestMigrationFailureKillsAndJoinsProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := startHysteriaTestProcess(t, ctx)
	migrationErr := errors.New("synthetic migration failure")

	log, err := runHysteriaSpeedtestProcess(ctx, p, 1, func() error {
		return migrationErr
	}, time.Millisecond, time.Second)
	if !errors.Is(err, migrationErr) {
		t.Fatalf("migration error = %v, want %v", err, migrationErr)
	}
	if log == "" {
		t.Fatal("joined process log is empty")
	}
	assertHysteriaProcessJoined(t, p)
}

func TestHysteriaProcessUnjoinedIsTypedMustStopFailure(t *testing.T) {
	p := &hysteriaProcess{
		role: "synthetic speedtest",
		done: make(chan struct{}),
		containment: &hysteriaProcessContainment{
			kill:    func() error { return nil },
			confirm: func(time.Duration) error { return nil },
		},
	}
	joinTimeout := 10 * time.Millisecond
	err := p.stop(joinTimeout)
	var joinErr *hysteriaProcessJoinError
	if !errors.As(err, &joinErr) {
		t.Fatalf("stop error = %T %v, want hysteriaProcessJoinError", err, err)
	}
	if !joinErr.MustStop() || joinErr.Timeout != joinTimeout {
		t.Fatalf("join error = %+v, want MustStop with timeout %s", joinErr, joinTimeout)
	}
	if got := p.logTail(); got != "" {
		t.Fatalf("unjoined process exposed log %q", got)
	}

	result := FromError("synthetic", time.Millisecond, errors.New("migration failed"))
	applyHysteriaProcessError(&result, "synthetic", time.Now(), err)
	if result.Failure != "" || !strings.Contains(result.InvalidReason, joinErr.Error()) {
		t.Fatalf("result = %+v, want explicit unjoined INVALID", result)
	}
	if got := result.Detail[hysteriaMustStopEvidence]; got != joinErr.Error() {
		t.Fatalf("MustStop evidence = %v, want %q", got, joinErr.Error())
	}

	speedResult := FromError("synthetic", time.Millisecond, fmt.Errorf("%w; speedtest log: stopped", err))
	if !applyHysteriaMustStop(&speedResult, err) {
		t.Fatal("wrapped speedtest join error was not classified as MustStop")
	}
	if speedResult.Failure != "" || !strings.Contains(speedResult.InvalidReason, "speedtest log: stopped") {
		t.Fatalf("speedtest result = %+v, want typed unjoined INVALID with diagnostics", speedResult)
	}
	if got := speedResult.Detail[hysteriaMustStopEvidence]; got != err.Error() {
		t.Fatalf("speedtest MustStop evidence = %v, want %q", got, err.Error())
	}
}

func TestHysteriaProcessUnconfirmedTeardownIsTypedMustStopFailure(t *testing.T) {
	done := make(chan struct{})
	close(done)
	confirmationErr := errors.New("synthetic descendant remained")
	p := &hysteriaProcess{
		role: "synthetic server",
		done: done,
		containment: &hysteriaProcessContainment{
			kill:    func() error { return nil },
			confirm: func(time.Duration) error { return confirmationErr },
		},
	}

	err := p.stop(20 * time.Millisecond)
	var teardownErr *hysteriaProcessTeardownError
	if !errors.As(err, &teardownErr) {
		t.Fatalf("stop error = %T %v, want hysteriaProcessTeardownError", err, err)
	}
	if !teardownErr.MustStop() || !errors.Is(teardownErr, confirmationErr) {
		t.Fatalf("teardown error = %+v, want typed MustStop wrapping confirmation failure", teardownErr)
	}
	result := Result{Name: "synthetic", Detail: map[string]any{}}
	applyHysteriaProcessError(&result, result.Name, time.Now(), err)
	if result.Failure != "" || !strings.Contains(result.InvalidReason, confirmationErr.Error()) {
		t.Fatalf("result = %+v, want unconfirmed teardown INVALID", result)
	}
	if got := result.Detail[hysteriaMustStopEvidence]; got != err.Error() {
		t.Fatalf("MustStop evidence = %v, want %q", got, err.Error())
	}
}

func TestHysteriaRelayHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HYSTERIA_RELAY_HELPER") != "1" {
		return
	}
	marker := os.Getenv("HYSTERIA_RELAY_HELPER_MARKER")
	fmt.Fprintln(os.Stderr, "helper ready")
	if err := os.WriteFile(marker, []byte("ready"), 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if pidFile := os.Getenv("HYSTERIA_RELAY_DESCENDANT_PID_FILE"); pidFile != "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHysteriaRelayDescendantProcess$")
		cmd.Env = append(os.Environ(), "GO_WANT_HYSTERIA_RELAY_DESCENDANT=1")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(3)
		}
		if err := os.WriteFile(pidFile, []byte(fmt.Sprint(cmd.Process.Pid)), 0600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			_ = cmd.Process.Kill()
			os.Exit(4)
		}
	}
	for i := 0; ; i++ {
		fmt.Fprintf(os.Stderr, "helper log %d\n", i)
		time.Sleep(time.Millisecond)
	}
}

func TestHysteriaRelayDescendantProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HYSTERIA_RELAY_DESCENDANT") != "1" {
		return
	}
	for i := 0; ; i++ {
		fmt.Fprintf(os.Stderr, "descendant log %d\n", i)
		time.Sleep(time.Millisecond)
	}
}

func startHysteriaTestProcess(t *testing.T, ctx context.Context, extraEnv ...string) *hysteriaProcess {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "ready")
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHysteriaRelayHelperProcess$")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HYSTERIA_RELAY_HELPER=1",
		"HYSTERIA_RELAY_HELPER_MARKER="+marker,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	p, err := startHysteriaCommand(cmd, "test helper")
	if err != nil {
		t.Fatalf("start helper process: %v", err)
	}
	t.Cleanup(func() {
		if err := p.stop(time.Second); err != nil {
			t.Errorf("stop helper process: %v", err)
		}
	})
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			return p
		}
		if p.joined() {
			t.Fatalf("helper process exited before readiness: %v; log: %s", p.waitErr, p.logTail())
		}
		if time.Now().After(deadline) {
			t.Fatal("helper process did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
}

func assertHysteriaProcessJoined(t *testing.T, p *hysteriaProcess) {
	t.Helper()
	if !p.joined() {
		t.Fatal("process was not joined before return")
	}
	if p.cmd == nil || p.cmd.ProcessState == nil {
		t.Fatal("process Wait did not publish ProcessState")
	}
	if p.cmd.WaitDelay != hysteriaProcessWaitDelay {
		t.Fatalf("process WaitDelay = %s, want %s", p.cmd.WaitDelay, hysteriaProcessWaitDelay)
	}
}
