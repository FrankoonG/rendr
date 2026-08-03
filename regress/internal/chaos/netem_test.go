//go:build linux || chaosunit

package chaos

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestApplyAndCleanup combines root-only integration coverage with injectable
// lifecycle tests. Keeping one top-level name preserves the strict T1 test
// inventory while exercising each interference state as a subtest.
func TestApplyAndCleanup(t *testing.T) {
	t.Run("injectable apply verify and exact cleanup", func(t *testing.T) {
		tc := newFakeTC()
		lock := &fakeFixtureLock{}
		watcher := newFakeQdiscWatcher()
		fixture, err := applyWithDeps(Realistic50M, fakeFixtureDeps(tc, lock, watcher))
		if err != nil {
			t.Fatalf("applyWithDeps: %v", err)
		}
		if err := fixture.Verify(); err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if err := fixture.Cleanup(); err != nil {
			t.Fatalf("Cleanup: %v", err)
		}
		if !lock.released || !watcher.closed {
			t.Fatalf("resources not released: lock=%v watcher=%v", lock.released, watcher.closed)
		}
		wantDelete := []string{"qdisc", "del", "dev", "lo", "root", "handle", "1234:"}
		if !tc.hasCommand(wantDelete) {
			t.Fatalf("commands=%v, missing ownership-scoped delete %v", tc.commandsSnapshot(), wantDelete)
		}
		if err := fixture.Cleanup(); err != nil {
			t.Fatalf("idempotent Cleanup: %v", err)
		}
	})

	t.Run("preexisting root is rejected without deletion", func(t *testing.T) {
		tc := newFakeTC()
		tc.setState(qdiscJSON(qdiscFixture{Kind: "fq_codel", Handle: "8001:", Root: true, Options: map[string]any{"limit": 10240}}))
		lock := &fakeFixtureLock{}
		_, err := applyWithDeps(Realistic50M, fakeFixtureDeps(tc, lock, newFakeQdiscWatcher()))
		if !errors.Is(err, ErrStimulusInvalid) {
			t.Fatalf("error=%v, want ErrStimulusInvalid", err)
		}
		if tc.hasCommandPrefix("qdisc", "del") {
			t.Fatalf("fixture deleted a preexisting qdisc: %v", tc.commandsSnapshot())
		}
		if !lock.released {
			t.Fatal("ownership lock not released after setup rejection")
		}
	})

	for _, scenario := range []struct {
		name  string
		state []byte
	}{
		{name: "external deletion", state: defaultQdiscJSON()},
		{name: "external replacement", state: qdiscJSON(qdiscFixture{Kind: "fq_codel", Handle: "9001:", Root: true})},
		{name: "same handle changed options", state: qdiscJSON(qdiscFixture{Kind: "tbf", Handle: "1234:", Root: true, Options: map[string]any{"rate": 1}})},
	} {
		t.Run(scenario.name+" is invalid and never broadly deleted", func(t *testing.T) {
			tc := newFakeTC()
			lock := &fakeFixtureLock{}
			fixture, err := applyWithDeps(Realistic50M, fakeFixtureDeps(tc, lock, newFakeQdiscWatcher()))
			if err != nil {
				t.Fatal(err)
			}
			tc.setState(scenario.state)
			if err := fixture.Verify(); !errors.Is(err, ErrStimulusInvalid) {
				t.Fatalf("Verify error=%v, want ErrStimulusInvalid", err)
			}
			beforeDeleteCount := tc.commandPrefixCount("qdisc", "del")
			err = fixture.Cleanup()
			if !errors.Is(err, ErrStimulusInvalid) {
				t.Fatalf("Cleanup error=%v, want ErrStimulusInvalid", err)
			}
			if got := tc.commandPrefixCount("qdisc", "del"); got != beforeDeleteCount {
				t.Fatalf("cleanup deleted unowned qdisc; commands=%v", tc.commandsSnapshot())
			}
			if !lock.released {
				t.Fatal("ownership lock not released after interference")
			}
		})
	}

	t.Run("child netem disappearance is invalid", func(t *testing.T) {
		tc := newFakeTC()
		fixture, err := applyWithDeps(LossyWAN, fakeFixtureDeps(tc, &fakeFixtureLock{}, newFakeQdiscWatcher()))
		if err != nil {
			t.Fatal(err)
		}
		tc.removeHandle("5678:")
		if err := fixture.Verify(); !errors.Is(err, ErrStimulusInvalid) || !strings.Contains(err.Error(), "netem child") {
			t.Fatalf("Verify error=%v, want missing netem child invalidity", err)
		}
		_ = fixture.Cleanup()
	})

	t.Run("queued kernel event invalidates cleanup even after state restoration", func(t *testing.T) {
		tc := newFakeTC()
		watcher := newFakeQdiscWatcher()
		fixture, err := applyWithDeps(Realistic50M, fakeFixtureDeps(tc, &fakeFixtureLock{}, watcher))
		if err != nil {
			t.Fatal(err)
		}
		watcher.changes <- fmt.Errorf("%w: transient replacement event", ErrStimulusInvalid)
		err = fixture.Cleanup()
		if !errors.Is(err, ErrStimulusInvalid) || !strings.Contains(err.Error(), "transient replacement") {
			t.Fatalf("Cleanup error=%v, want queued event invalidity", err)
		}
		if !tc.hasCommand([]string{"qdisc", "del", "dev", "lo", "root", "handle", "1234:"}) {
			t.Fatalf("owned qdisc was not cleaned after event: %v", tc.commandsSnapshot())
		}
	})

	t.Run("delete race is classified as stimulus invalidity", func(t *testing.T) {
		tc := newFakeTC()
		fixture, err := applyWithDeps(Realistic50M, fakeFixtureDeps(tc, &fakeFixtureLock{}, newFakeQdiscWatcher()))
		if err != nil {
			t.Fatal(err)
		}
		tc.failDeleteWithState = defaultQdiscJSON()
		err = fixture.Cleanup()
		if !errors.Is(err, ErrStimulusInvalid) || !strings.Contains(err.Error(), "changed while cleanup") {
			t.Fatalf("Cleanup error=%v, want delete-race invalidity", err)
		}
	})

	t.Run("process lock contention fails closed before probe", func(t *testing.T) {
		tc := newFakeTC()
		deps := fakeFixtureDeps(tc, &fakeFixtureLock{}, newFakeQdiscWatcher())
		deps.acquireLock = func() (fixtureLock, error) {
			return nil, fmt.Errorf("%w: owner pid=42", ErrStimulusInvalid)
		}
		_, err := applyWithDeps(Realistic50M, deps)
		if !errors.Is(err, ErrStimulusInvalid) {
			t.Fatalf("error=%v, want ErrStimulusInvalid", err)
		}
		if got := tc.commandsSnapshot(); len(got) != 0 {
			t.Fatalf("tc commands ran despite lock contention: %v", got)
		}
	})

	t.Run("real tc integration", func(t *testing.T) {
		if testing.Short() || !testCanManageTC() {
			t.Skip("requires Linux root with tc")
		}
		fixture, err := ApplyChecked(Realistic50M)
		if err != nil {
			t.Fatalf("ApplyChecked(Realistic50M): %v", err)
		}
		if err := fixture.Verify(); err != nil {
			_ = fixture.Cleanup()
			t.Fatalf("Verify: %v", err)
		}
		if err := fixture.Cleanup(); err != nil {
			t.Fatalf("Cleanup: %v", err)
		}
	})
}

// TestApplyShapesBandwidth proves the real shaper limits loopback throughput.
func TestApplyShapesBandwidth(t *testing.T) {
	if testing.Short() || !testCanManageTC() {
		t.Skip("requires Linux root with tc")
	}
	fixture, err := ApplyChecked(Profile{Bandwidth: 10_000_000})
	if err != nil {
		t.Fatalf("ApplyChecked: %v", err)
	}
	defer func() {
		if err := fixture.Cleanup(); err != nil {
			t.Errorf("Cleanup: %v", err)
		}
	}()

	const payloadMB = 4
	got := measureTCPThroughput(t, payloadMB)
	t.Logf("measured throughput at 10 Mbps shaper: %.2f Mbps", got)
	if got > 15_000_000 {
		t.Fatalf("measured %.0f bps > 15 Mbps; tbf shaper not engaging", got)
	}
	if got < 5_000_000 {
		t.Fatalf("measured %.0f bps < 5 Mbps; tbf is too aggressive", got)
	}
	if err := fixture.Verify(); err != nil {
		t.Fatalf("shaping changed during throughput test: %v", err)
	}
}

func measureTCPThroughput(t *testing.T, mb int) float64 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	doneRecv := make(chan int64, 1)
	go func() {
		srv, err := ln.Accept()
		if err != nil {
			doneRecv <- -1
			return
		}
		defer srv.Close()
		buf := make([]byte, 64*1024)
		var got int64
		for {
			n, err := srv.Read(buf)
			if n > 0 {
				got += int64(n)
			}
			if err != nil {
				break
			}
		}
		doneRecv <- got
	}()

	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 64*1024)
	start := time.Now()
	remaining := int64(mb) * 1024 * 1024
	for remaining > 0 {
		w := int64(len(payload))
		if w > remaining {
			w = remaining
		}
		n, err := cli.Write(payload[:w])
		if err != nil {
			break
		}
		remaining -= int64(n)
	}
	_ = cli.Close()

	got := <-doneRecv
	if got < 0 {
		t.Fatal("server accept failed")
	}
	return float64(got*8) / time.Since(start).Seconds()
}

type qdiscFixture struct {
	Kind    string
	Handle  string
	Parent  string
	Root    bool
	Options map[string]any
}

func qdiscJSON(fixtures ...qdiscFixture) []byte {
	records := make([]map[string]any, 0, len(fixtures))
	for _, fixture := range fixtures {
		record := map[string]any{
			"kind":   fixture.Kind,
			"handle": fixture.Handle,
		}
		if fixture.Root {
			record["root"] = true
		}
		if fixture.Parent != "" {
			record["parent"] = fixture.Parent
		}
		if fixture.Options != nil {
			record["options"] = fixture.Options
		}
		records = append(records, record)
	}
	out, err := json.Marshal(records)
	if err != nil {
		panic(err)
	}
	return out
}

func defaultQdiscJSON() []byte {
	return qdiscJSON(qdiscFixture{Kind: "noqueue", Handle: "0:", Root: true})
}

type fakeTC struct {
	mu                  sync.Mutex
	state               []byte
	commands            [][]string
	failDeleteWithState []byte
}

func newFakeTC() *fakeTC { return &fakeTC{state: defaultQdiscJSON()} }

func (f *fakeTC) run(args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, append([]string(nil), args...))
	if reflect.DeepEqual(args, []string{"-j", "-details", "qdisc", "show", "dev", "lo"}) {
		return append([]byte(nil), f.state...), nil
	}
	if len(args) >= 2 && args[0] == "qdisc" && args[1] == "add" {
		handle := argAfter(args, "handle")
		parent := argAfter(args, "parent")
		root := containsArg(args, "root")
		kind := ""
		if containsArg(args, "tbf") {
			kind = "tbf"
		} else if containsArg(args, "netem") {
			kind = "netem"
		}
		fixture := qdiscFixture{Kind: kind, Handle: handle, Parent: parent, Root: root, Options: map[string]any{"command": strings.Join(args, " ")}}
		if root {
			f.state = qdiscJSON(fixture)
		} else {
			var existing []map[string]any
			_ = json.Unmarshal(f.state, &existing)
			var added []map[string]any
			_ = json.Unmarshal(qdiscJSON(fixture), &added)
			existing = append(existing, added[0])
			f.state, _ = json.Marshal(existing)
		}
		return nil, nil
	}
	if len(args) >= 2 && args[0] == "qdisc" && args[1] == "del" {
		if f.failDeleteWithState != nil {
			f.state = append([]byte(nil), f.failDeleteWithState...)
			return []byte("qdisc changed concurrently"), errors.New("exit status 2")
		}
		handle := argAfter(args, "handle")
		var records []qdiscRecord
		_ = json.Unmarshal(f.state, &records)
		for _, record := range records {
			if record.Root && record.Handle == handle {
				f.state = defaultQdiscJSON()
				return nil, nil
			}
		}
		return []byte("owned handle not found"), errors.New("exit status 2")
	}
	return nil, fmt.Errorf("unexpected tc command: %v", args)
}

func (f *fakeTC) setState(state []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = append([]byte(nil), state...)
}

func (f *fakeTC) removeHandle(handle string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var records []map[string]any
	_ = json.Unmarshal(f.state, &records)
	kept := records[:0]
	for _, record := range records {
		if record["handle"] != handle {
			kept = append(kept, record)
		}
	}
	f.state, _ = json.Marshal(kept)
}

func (f *fakeTC) commandsSnapshot() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.commands))
	for i := range f.commands {
		out[i] = append([]string(nil), f.commands[i]...)
	}
	return out
}

func (f *fakeTC) hasCommand(want []string) bool {
	for _, command := range f.commandsSnapshot() {
		if reflect.DeepEqual(command, want) {
			return true
		}
	}
	return false
}

func (f *fakeTC) hasCommandPrefix(prefix ...string) bool {
	return f.commandPrefixCount(prefix...) > 0
}

func (f *fakeTC) commandPrefixCount(prefix ...string) int {
	count := 0
	for _, command := range f.commandsSnapshot() {
		if len(command) >= len(prefix) && reflect.DeepEqual(command[:len(prefix)], prefix) {
			count++
		}
	}
	return count
}

type fakeFixtureLock struct{ released bool }

func (l *fakeFixtureLock) Release() error { l.released = true; return nil }

type fakeQdiscWatcher struct {
	changes chan error
	closed  bool
	once    sync.Once
}

func newFakeQdiscWatcher() *fakeQdiscWatcher {
	return &fakeQdiscWatcher{changes: make(chan error, 1)}
}

func (w *fakeQdiscWatcher) Changes() <-chan error { return w.changes }
func (w *fakeQdiscWatcher) Close() error {
	w.once.Do(func() {
		w.closed = true
		close(w.changes)
	})
	return nil
}

func fakeFixtureDeps(tc *fakeTC, lock fixtureLock, watcher qdiscWatcher) fixtureDeps {
	return fixtureDeps{
		run:         tc.run,
		acquireLock: func() (fixtureLock, error) { return lock, nil },
		handles:     func() (string, string, error) { return "1234:", "5678:", nil },
		watch:       func() (qdiscWatcher, error) { return watcher, nil },
	}
}

func argAfter(args []string, key string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key {
			return args[i+1]
		}
	}
	return ""
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}
