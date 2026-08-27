package l3session

import (
	"context"
	"errors"
	"net"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

type hostileSessionPanicPayload struct{}

func (hostileSessionPanicPayload) String() string { panic("panic payload was formatted") }

func TestStarterConfigureSessionAbnormalExitsAreTyped(t *testing.T) {
	tests := []struct {
		name      string
		configure func(l3ingress.SessionRequest, *rendr.SessionConfig) error
		reason    CallbackFailureReason
	}{
		{
			name: "panic",
			configure: func(l3ingress.SessionRequest, *rendr.SessionConfig) error {
				panic(hostileSessionPanicPayload{})
			},
			reason: CallbackFailurePanic,
		},
		{
			name: "goexit",
			configure: func(l3ingress.SessionRequest, *rendr.SessionConfig) error {
				runtime.Goexit()
				return nil
			},
			reason: CallbackFailureGoexit,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			starter := &Starter{ConfigureSession: test.configure}
			_, err := starter.Start(context.Background(), callbackSessionRequest())
			var callbackErr *CallbackError
			if !errors.As(err, &callbackErr) || callbackErr.Reason != test.reason {
				t.Fatalf("error=%v callback=%+v want reason %q", err, callbackErr, test.reason)
			}
			if test.reason == CallbackFailurePanic && callbackErr.PanicType != "l3session.hostileSessionPanicPayload" {
				t.Fatalf("panic type=%q", callbackErr.PanicType)
			}
			_ = callbackErr.Error()
			if starter.resolvedRuntime != nil {
				t.Fatal("abnormal configurator published a session runtime")
			}
		})
	}
}

func TestStarterConfigureSessionTimeoutBoundsWorkersAndLateConfig(t *testing.T) {
	const timeout = 15 * time.Millisecond
	wantErr := errors.New("fresh configure result")
	var calls atomic.Int32
	var release <-chan struct{}
	starter := &Starter{
		configureSessionConcurrency: 2,
		ConfigureSessionTimeout:     timeout,
		ConfigureSession: func(_ l3ingress.SessionRequest, config *rendr.SessionConfig) error {
			if calls.Add(1) == 1 {
				<-release
				config.Root = nil
				return nil
			}
			return wantErr
		},
	}
	var releaseCallback func()
	release, releaseCallback = newSessionCallbackRelease(t, func() bool {
		return len(starter.configureSlots) == 0
	}, "configurator slot release")
	started := time.Now()
	_, err := starter.Start(context.Background(), callbackSessionRequest())
	assertSessionCallbackReason(t, err, CallbackFailureTimeout)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("configurator timeout took %v", elapsed)
	}
	for i := 0; i < 256; i++ {
		_, err = starter.Start(context.Background(), callbackSessionRequest())
		assertSessionCallbackReason(t, err, CallbackFailureSaturated)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("blocked configurator calls=%d want 1", got)
	}
	independent := callbackSessionRequest()
	independent.Identity.DstPort++
	_, err = starter.Start(context.Background(), independent)
	if !errors.Is(err, wantErr) {
		t.Fatalf("independent configurator error=%v want %v", err, wantErr)
	}
	if calls.Load() != 2 {
		t.Fatalf("independent identity did not overlap blocked callback; calls=%d", calls.Load())
	}
	if starter.resolvedRuntime != nil {
		t.Fatal("timed-out configurator initialized runtime")
	}

	releaseCallback()
	waitForSessionCondition(t, time.Second, func() bool { return len(starter.configureSlots) == 0 }, "configurator slot release")
	_, err = starter.Start(context.Background(), callbackSessionRequest())
	if !errors.Is(err, wantErr) {
		t.Fatalf("fresh configurator error=%v want %v", err, wantErr)
	}
	if calls.Load() != 3 || starter.resolvedRuntime != nil {
		t.Fatalf("late result escaped isolation calls=%d runtime=%p", calls.Load(), starter.resolvedRuntime)
	}
}

func TestStarterConfigureSessionCallerCancellationDoesNotWaitForCallback(t *testing.T) {
	entered := make(chan struct{})
	var release <-chan struct{}
	starter := &Starter{
		configureSessionConcurrency: 1,
		ConfigureSessionTimeout:     time.Second,
		ConfigureSession: func(l3ingress.SessionRequest, *rendr.SessionConfig) error {
			close(entered)
			<-release
			return nil
		},
	}
	var releaseCallback func()
	release, releaseCallback = newSessionCallbackRelease(t, func() bool {
		return len(starter.configureSlots) == 0
	}, "canceled configurator release")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := starter.Start(ctx, callbackSessionRequest())
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("configurator did not enter")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start error=%v want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Start waited for canceled configurator")
	}
	releaseCallback()
	waitForSessionCondition(t, time.Second, func() bool { return len(starter.configureSlots) == 0 }, "canceled configurator release")
}

func TestSessionCallbacksDoNotStartWithPreCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var configureCalls atomic.Int32
	starter := &Starter{
		ConfigureSession: func(l3ingress.SessionRequest, *rendr.SessionConfig) error {
			configureCalls.Add(1)
			return nil
		},
	}
	_, err := starter.invokeConfigureSession(ctx, callbackSessionRequest(), rendr.SessionConfig{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ConfigureSession error=%v want context.Canceled", err)
	}
	if configureCalls.Load() != 0 {
		t.Fatal("pre-canceled ConfigureSession entered caller code")
	}

	var onStartCalls atomic.Int32
	manager := &Manager{
		OnStart: func(context.Context, PendingSessionView) error {
			onStartCalls.Add(1)
			return nil
		},
	}
	if err := manager.invokeOnStart(ctx, &Session{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled OnStart error=%v want context.Canceled", err)
	}
	if onStartCalls.Load() != 0 {
		t.Fatal("pre-canceled OnStart entered caller code")
	}
	if len(configureSessionProcessSlots) != 0 || len(onStartProcessSlots) != 0 {
		t.Fatalf(
			"pre-canceled callbacks retained process permits configure=%d on-start=%d",
			len(configureSessionProcessSlots), len(onStartProcessSlots),
		)
	}
}

func TestPendingSessionViewHasNoSessionMutationAuthority(t *testing.T) {
	id := testIdentity(l3ingress.ProtocolTCP)
	sess := &Session{
		request: l3ingress.SessionRequest{
			Identity: id,
			Labels:   map[string]string{"class": "original"},
			Root: rendr.Selector("root", []rendr.Target{
				rendr.Path("path", rendr.PathSpec{Opts: map[string]string{"key": "original"}}),
			}, rendr.PeakTransfer{Targets: []string{"path"}}),
		},
		conn: &fakeConn{},
	}
	view, access := newPendingSessionView(sess)

	typ := reflect.TypeOf(view)
	for index := 0; index < typ.NumField(); index++ {
		if field := typ.Field(index); field.PkgPath == "" {
			t.Fatalf("PendingSessionView exposes mutable field %q", field.Name)
		}
	}
	if _, ok := typ.MethodByName("Close"); ok {
		t.Fatal("PendingSessionView exposes Session.Close authority")
	}
	callbackType := reflect.TypeOf(OnStartFunc(nil))
	if callbackType.In(1) != typ || callbackType.In(1).Kind() == reflect.Pointer {
		t.Fatalf("OnStart argument=%v want immutable value %v", callbackType.In(1), typ)
	}
	if view.Conn() == sess.Conn() {
		t.Fatal("PendingSessionView leaked the manager-owned connection value directly")
	}
	sessionType := reflect.TypeOf(sess).Elem()
	for index := 0; index < sessionType.NumField(); index++ {
		if field := sessionType.Field(index); field.PkgPath == "" {
			t.Fatalf("Session exposes mutable lifecycle field %q", field.Name)
		}
	}
	for _, method := range []string{"Request", "Conn", "PacketConn", "Close"} {
		if _, ok := reflect.TypeOf(sess).MethodByName(method); !ok {
			t.Fatalf("Session missing read/lifecycle accessor %q", method)
		}
	}

	request := view.Request()
	request.Identity = l3ingress.L3Identity{}
	request.Labels["class"] = "mutated"
	request.Labels["new"] = "value"
	requestRoot := request.Root.(rendr.GroupTarget)
	requestRoot.Children[0] = rendr.Path("replacement", rendr.PathSpec{})
	requestRoot.Peak.Targets[0] = "replacement"
	got := view.Request()
	if got.Identity != id || got.Labels["class"] != "original" || got.Labels["new"] != "" {
		t.Fatalf("view request mutated through returned snapshot: %+v", got)
	}
	sessionRequest := sess.Request()
	if sessionRequest.Identity != id || sessionRequest.Labels["class"] != "original" {
		t.Fatalf("manager-owned Session mutated through view: %+v", sessionRequest)
	}
	sessionRequest.Labels["class"] = "mutated-through-session-accessor"
	if sess.Request().Labels["class"] != "original" {
		t.Fatal("Session.Request returned shared mutable labels")
	}
	gotRoot := got.Root.(rendr.GroupTarget)
	if gotRoot.Children[0].Name() != "path" || gotRoot.Peak.Targets[0] != "path" {
		t.Fatalf("view target graph mutated through returned snapshot: %+v", gotRoot)
	}
	sessionRoot := sessionRequest.Root.(rendr.GroupTarget)
	if sessionRoot.Children[0].Name() != "path" || sessionRoot.Peak.Targets[0] != "path" {
		t.Fatalf("manager-owned target graph mutated through view: %+v", sessionRoot)
	}
	if access.closed.Load() {
		t.Fatal("read-only inspection marked candidate closed")
	}
}

func TestPendingSessionViewRevokesRetainedConnectionAuthority(t *testing.T) {
	t.Run("normal return", func(t *testing.T) {
		conn := &fakeConn{}
		sess := &Session{conn: conn}
		var retained rendr.Conn
		manager := &Manager{OnStart: func(_ context.Context, view PendingSessionView) error {
			retained = view.Conn()
			return nil
		}}
		if err := manager.invokeOnStart(context.Background(), sess); err != nil {
			t.Fatal(err)
		}
		if _, err := retained.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("retained Write error=%v want net.ErrClosed", err)
		}
		if err := retained.Close(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("retained Close error=%v want net.ErrClosed", err)
		}
		if conn.closed.Load() != 0 {
			t.Fatal("revoked retained view closed the manager-owned connection")
		}
		if err := sess.Close(); err != nil || conn.closed.Load() != 1 {
			t.Fatalf("manager close err=%v count=%d", err, conn.closed.Load())
		}
	})

	t.Run("timeout", func(t *testing.T) {
		conn := &fakeConn{}
		sess := &Session{conn: conn}
		entered := make(chan struct{})
		release := make(chan struct{})
		lateClose := make(chan error, 1)
		manager := &Manager{
			OnStartTimeout: 10 * time.Millisecond,
			OnStart: func(ctx context.Context, view PendingSessionView) error {
				close(entered)
				<-ctx.Done()
				<-release
				lateClose <- view.Conn().Close()
				return nil
			},
		}
		result := make(chan error, 1)
		go func() { result <- manager.invokeOnStart(context.Background(), sess) }()
		<-entered
		if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("OnStart error=%v want deadline", err)
		}
		if err := sess.Close(); err != nil {
			t.Fatal(err)
		}
		close(release)
		if err := <-lateClose; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("late retained Close error=%v want net.ErrClosed", err)
		}
		waitForSessionCondition(t, time.Second, func() bool {
			return len(manager.onStartSlots) == 0 && len(onStartProcessSlots) == 0
		}, "timed-out retained callback release")
		if conn.closed.Load() != 1 {
			t.Fatalf("underlying close count=%d want 1", conn.closed.Load())
		}
	})

	t.Run("close hook registration linearizes with Session.Close", func(t *testing.T) {
		for iteration := 0; iteration < 500; iteration++ {
			sess := &Session{conn: &fakeConn{}}
			var hookCalls atomic.Int32
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				sess.addOnClose(func() { hookCalls.Add(1) })
			}()
			go func() {
				defer wg.Done()
				<-start
				_ = sess.Close()
			}()
			close(start)
			wg.Wait()
			if hookCalls.Load() != 1 {
				t.Fatalf("iteration %d hook calls=%d want 1", iteration, hookCalls.Load())
			}
		}
	})
}

func TestManagerRejectsOnStartClosedCandidate(t *testing.T) {
	listener := newTestStreamSessionListener(t, "tcp")
	defer listener.Close()
	accepted := acceptManagerCallbackSessions(t, listener, 1)
	id := testIdentity(l3ingress.ProtocolTCP)
	manager := &Manager{OnStart: func(_ context.Context, view PendingSessionView) error {
		if view.Conn() == nil || view.PacketConn() != nil {
			return errors.New("OnStart received the wrong pending connection kind")
		}
		_ = view.Conn().Close()
		return nil
	}}

	sess, err := manager.EnsureSession(context.Background(), managerCallbackEvent(listener, id))
	if sess != nil || !errors.Is(err, ErrSessionClosedDuringStart) {
		t.Fatalf("closed OnStart candidate result=(%p, %v), want closed-during-start", sess, err)
	}
	if _, ok := manager.Session(id); ok {
		t.Fatal("OnStart-closed candidate was published")
	}
	closeAcceptedManagerSessions(t, accepted, 1)
}

func TestManagerOnStartTimeoutRacingCandidateCloseNeverPublishes(t *testing.T) {
	listener := newTestStreamSessionListener(t, "tcp")
	defer listener.Close()
	accepted := acceptManagerCallbackSessions(t, listener, 1)
	id := testIdentity(l3ingress.ProtocolTCP)
	entered := make(chan struct{})
	callbackReturned := make(chan struct{})
	manager := &Manager{
		OnStartTimeout: 20 * time.Millisecond,
		OnStart: func(ctx context.Context, view PendingSessionView) error {
			close(entered)
			<-ctx.Done()
			_ = view.Conn().Close()
			close(callbackReturned)
			return nil
		},
	}

	result := make(chan error, 1)
	go func() {
		_, err := manager.EnsureSession(context.Background(), managerCallbackEvent(listener, id))
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("OnStart did not enter")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrSessionClosedDuringStart) {
			t.Fatalf("deadline/close race error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline/close race did not terminate")
	}
	select {
	case <-callbackReturned:
	case <-time.After(time.Second):
		t.Fatal("deadline-canceled callback did not return")
	}
	waitForSessionCondition(t, time.Second, func() bool {
		return len(manager.onStartSlots) == 0 && len(onStartProcessSlots) == 0
	}, "deadline/close callback lease release")
	if _, ok := manager.Session(id); ok {
		t.Fatal("deadline/close race published a Session")
	}
	closeAcceptedManagerSessions(t, accepted, 1)
}

func TestManagerOnStartAbnormalExitsRevokeSessionAuthority(t *testing.T) {
	tests := []struct {
		name   string
		reason CallbackFailureReason
		exit   func()
	}{
		{
			name:   "panic",
			reason: CallbackFailurePanic,
			exit: func() {
				panic(hostileSessionPanicPayload{})
			},
		},
		{
			name:   "goexit",
			reason: CallbackFailureGoexit,
			exit:   runtime.Goexit,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener := newTestStreamSessionListener(t, "tcp")
			defer listener.Close()
			accepted := acceptManagerCallbackSessions(t, listener, 2)
			id := testIdentity(l3ingress.ProtocolTCP)
			event := managerCallbackEvent(listener, id)
			var calls atomic.Int32
			var firstFlow [16]byte
			manager := &Manager{OnStart: func(_ context.Context, view PendingSessionView) error {
				if calls.Add(1) == 1 {
					firstFlow = view.Conn().FlowID()
					test.exit()
				}
				return nil
			}}

			_, err := manager.EnsureSession(context.Background(), event)
			assertSessionCallbackReason(t, err, test.reason)
			if test.reason == CallbackFailurePanic {
				var callbackErr *CallbackError
				if !errors.As(err, &callbackErr) || callbackErr.PanicType != "l3session.hostileSessionPanicPayload" {
					t.Fatalf("panic callback error=%+v", callbackErr)
				}
			}
			if _, ok := manager.Session(id); ok {
				t.Fatal("abnormal OnStart published a Session")
			}
			fresh, err := manager.EnsureSession(context.Background(), event)
			if err != nil {
				t.Fatal(err)
			}
			if fresh.Conn().FlowID() == firstFlow {
				t.Fatal("abnormal OnStart candidate flow was reused")
			}
			if current, ok := manager.Session(id); !ok || current != fresh {
				t.Fatalf("fresh Session current=%p ok=%v want %p", current, ok, fresh)
			}
			if calls.Load() != 2 {
				t.Fatalf("OnStart calls=%d want 2", calls.Load())
			}
			if err := manager.CloseAll(); err != nil {
				t.Fatal(err)
			}
			closeAcceptedManagerSessions(t, accepted, 2)
		})
	}
}

func TestManagerOnStartTimeoutBoundsLateResultAndPreventsReuse(t *testing.T) {
	listener := newTestStreamSessionListener(t, "tcp")
	defer listener.Close()
	accepted := acceptManagerCallbackSessions(t, listener, 2)
	id := testIdentity(l3ingress.ProtocolTCP)
	event := managerCallbackEvent(listener, id)
	entered := make(chan struct{})
	var calls atomic.Int32
	var firstFlow [16]byte
	var release <-chan struct{}
	manager := &Manager{
		onStartConcurrency: 1,
		OnStartTimeout:     100 * time.Millisecond,
		OnStart: func(_ context.Context, view PendingSessionView) error {
			if calls.Add(1) == 1 {
				firstFlow = view.Conn().FlowID()
				close(entered)
				<-release
			}
			return nil
		},
	}
	var releaseCallback func()
	release, releaseCallback = newSessionCallbackRelease(t, func() bool {
		return len(manager.onStartSlots) == 0 && len(onStartProcessSlots) == 0
	}, "late OnStart slot release")

	started := time.Now()
	firstResult := make(chan error, 1)
	go func() {
		_, err := manager.EnsureSession(context.Background(), event)
		firstResult <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("blocking OnStart stimulus did not occur")
	}
	if _, ok := manager.Session(id); ok {
		t.Fatal("in-flight OnStart exposed a partially initialized Session")
	}
	waitingResult := make(chan error, 1)
	go func() {
		_, err := manager.EnsureSession(context.Background(), event)
		waitingResult <- err
	}()
	select {
	case err := <-waitingResult:
		t.Fatalf("same-flow packet bypassed pending OnStart: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	err := <-firstResult
	assertSessionCallbackReason(t, err, CallbackFailureTimeout)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("OnStart timeout took %v", elapsed)
	}
	if _, ok := manager.Session(id); ok {
		t.Fatal("timed-out OnStart published a Session")
	}
	err = <-waitingResult
	assertSessionCallbackReason(t, err, CallbackFailureTimeout)
	if calls.Load() != 1 {
		t.Fatalf("saturated OnStart entered callback; calls=%d", calls.Load())
	}
	if _, ok := manager.Session(id); ok {
		t.Fatal("saturated OnStart published a Session")
	}

	releaseCallback()
	waitForSessionCondition(t, time.Second, func() bool { return len(manager.onStartSlots) == 0 }, "late OnStart slot release")
	if _, ok := manager.Session(id); ok {
		t.Fatal("late OnStart result regained Session authority")
	}
	fresh, err := manager.EnsureSession(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Conn().FlowID() == firstFlow {
		t.Fatal("timed-out OnStart candidate flow was reused")
	}
	if calls.Load() != 2 {
		t.Fatalf("OnStart calls=%d want 2", calls.Load())
	}
	if err := manager.CloseAll(); err != nil {
		t.Fatal(err)
	}
	closeAcceptedManagerSessions(t, accepted, 2)
}

func TestSessionCallbacksAreProcessBoundAcrossOwners(t *testing.T) {
	t.Run("ConfigureSession", func(t *testing.T) {
		if got := len(configureSessionProcessSlots); got != 0 {
			t.Fatalf("initial process slots=%d want 0", got)
		}
		var entered atomic.Int32
		results := make(chan error, configureSessionProcessLimit)
		release, releaseCallbacks := newSessionCallbackRelease(t, func() bool {
			return len(configureSessionProcessSlots) == 0
		}, "process ConfigureSession permit release")
		for index := 0; index < configureSessionProcessLimit; index++ {
			starter := &Starter{
				configureSessionConcurrency: 1,
				ConfigureSessionTimeout:     20 * time.Millisecond,
				ConfigureSession: func(l3ingress.SessionRequest, *rendr.SessionConfig) error {
					entered.Add(1)
					<-release
					return nil
				},
			}
			go func() {
				_, err := starter.invokeConfigureSession(
					context.Background(), l3ingress.SessionRequest{}, rendr.SessionConfig{},
				)
				results <- err
			}()
		}
		waitForSessionCondition(t, time.Second, func() bool {
			return entered.Load() == configureSessionProcessLimit
		}, "process ConfigureSession saturation")
		for index := 0; index < configureSessionProcessLimit; index++ {
			assertSessionCallbackReason(t, <-results, CallbackFailureTimeout)
		}
		var extraCalls atomic.Int32
		extra := &Starter{
			configureSessionConcurrency: 1,
			ConfigureSessionTimeout:     time.Second,
			ConfigureSession: func(l3ingress.SessionRequest, *rendr.SessionConfig) error {
				extraCalls.Add(1)
				return nil
			},
		}
		_, err := extra.invokeConfigureSession(
			context.Background(), l3ingress.SessionRequest{}, rendr.SessionConfig{},
		)
		assertSessionCallbackReason(t, err, CallbackFailureSaturated)
		if extraCalls.Load() != 0 {
			t.Fatal("process-saturated ConfigureSession entered user code")
		}
		releaseCallbacks()
		waitForSessionCondition(t, time.Second, func() bool {
			return len(configureSessionProcessSlots) == 0
		}, "process ConfigureSession permit release")
	})

	t.Run("Manager.OnStart", func(t *testing.T) {
		if got := len(onStartProcessSlots); got != 0 {
			t.Fatalf("initial process slots=%d want 0", got)
		}
		var entered atomic.Int32
		results := make(chan error, onStartProcessLimit)
		release, releaseCallbacks := newSessionCallbackRelease(t, func() bool {
			return len(onStartProcessSlots) == 0
		}, "process OnStart permit release")
		for index := 0; index < onStartProcessLimit; index++ {
			manager := &Manager{
				onStartConcurrency: 1,
				OnStartTimeout:     20 * time.Millisecond,
				OnStart: func(context.Context, PendingSessionView) error {
					entered.Add(1)
					<-release
					return nil
				},
			}
			go func() { results <- manager.invokeOnStart(context.Background(), &Session{}) }()
		}
		waitForSessionCondition(t, time.Second, func() bool {
			return entered.Load() == onStartProcessLimit
		}, "process OnStart saturation")
		for index := 0; index < onStartProcessLimit; index++ {
			assertSessionCallbackReason(t, <-results, CallbackFailureTimeout)
		}
		var extraCalls atomic.Int32
		extra := &Manager{
			onStartConcurrency: 1,
			OnStartTimeout:     time.Second,
			OnStart: func(context.Context, PendingSessionView) error {
				extraCalls.Add(1)
				return nil
			},
		}
		err := extra.invokeOnStart(context.Background(), &Session{})
		assertSessionCallbackReason(t, err, CallbackFailureSaturated)
		if extraCalls.Load() != 0 {
			t.Fatal("process-saturated OnStart entered user code")
		}
		releaseCallbacks()
		waitForSessionCondition(t, time.Second, func() bool {
			return len(onStartProcessSlots) == 0
		}, "process OnStart permit release")
	})
}

func TestSessionCallbackConfiguredConcurrencyCannotExceedHardLimit(t *testing.T) {
	var configureCalls atomic.Int32
	starter := &Starter{
		configureSessionConcurrency: defaultConfigureSessionConcurrency + 1,
		ConfigureSession: func(l3ingress.SessionRequest, *rendr.SessionConfig) error {
			configureCalls.Add(1)
			return nil
		},
	}
	if _, err := starter.invokeConfigureSession(
		context.Background(), l3ingress.SessionRequest{}, rendr.SessionConfig{},
	); err == nil {
		t.Fatal("oversized ConfigureSession concurrency was accepted")
	}
	if configureCalls.Load() != 0 {
		t.Fatal("invalid ConfigureSession configuration entered user code")
	}

	var onStartCalls atomic.Int32
	manager := &Manager{
		onStartConcurrency: defaultOnStartConcurrency + 1,
		OnStart: func(context.Context, PendingSessionView) error {
			onStartCalls.Add(1)
			return nil
		},
	}
	if err := manager.invokeOnStart(context.Background(), &Session{}); err == nil {
		t.Fatal("oversized OnStart concurrency was accepted")
	}
	if onStartCalls.Load() != 0 {
		t.Fatal("invalid OnStart configuration entered user code")
	}
}

func TestManagerCloseRefCancelsPendingOnStart(t *testing.T) {
	listener := newTestStreamSessionListener(t, "tcp")
	defer listener.Close()
	accepted := acceptManagerCallbackSessions(t, listener, 1)
	id := testIdentity(l3ingress.ProtocolTCP)
	ref := l3ingress.FlowRef{Identity: id, Generation: 17}
	event := managerCallbackEvent(listener, id)
	event.Ref = ref
	entered := make(chan struct{})
	var release <-chan struct{}
	manager := &Manager{
		OnStartTimeout: time.Second,
		OnStart: func(context.Context, PendingSessionView) error {
			close(entered)
			<-release
			return nil
		},
	}
	var releaseCallback func()
	release, releaseCallback = newSessionCallbackRelease(t, func() bool {
		return len(manager.onStartSlots) == 0 && len(onStartProcessSlots) == 0
	}, "canceled OnStart release")
	type ensureResult struct {
		sess *Session
		err  error
	}
	result := make(chan ensureResult, 1)
	go func() {
		sess, err := manager.EnsureSession(context.Background(), event)
		result <- ensureResult{sess: sess, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("pending OnStart did not enter")
	}
	staleRef := ref
	staleRef.Generation--
	closed, err := manager.CloseRef(staleRef)
	if err != nil || closed {
		t.Fatalf("stale CloseRef pending result=(%t, %v), want (false, nil)", closed, err)
	}
	select {
	case outcome := <-result:
		t.Fatalf("stale CloseRef canceled current generation: (%p, %v)", outcome.sess, outcome.err)
	case <-time.After(20 * time.Millisecond):
	}
	closed, err = manager.CloseRef(ref)
	if err != nil || !closed {
		t.Fatalf("CloseRef pending result=(%t, %v), want (true, nil)", closed, err)
	}
	select {
	case outcome := <-result:
		if outcome.sess != nil || !errors.Is(outcome.err, net.ErrClosed) {
			t.Fatalf("canceled pending result=(%p, %v), want (nil, net.ErrClosed)", outcome.sess, outcome.err)
		}
	case <-time.After(time.Second):
		releaseCallback()
		t.Fatal("CloseRef did not release pending EnsureSession")
	}
	releaseCallback()
	waitForSessionCondition(t, time.Second, func() bool { return len(onStartProcessSlots) == 0 }, "canceled OnStart release")
	if _, ok := manager.SessionRef(ref); ok {
		t.Fatal("late OnStart resurrected the closed flow generation")
	}
	closeAcceptedManagerSessions(t, accepted, 1)

	for _, closeCase := range []struct {
		name  string
		close func(*Manager, l3ingress.FlowRef) error
	}{
		{name: "Close", close: func(manager *Manager, ref l3ingress.FlowRef) error {
			return manager.Close(ref.Identity)
		}},
		{name: "CloseRef", close: func(manager *Manager, ref l3ingress.FlowRef) error {
			closed, err := manager.CloseRef(ref)
			if err == nil && !closed {
				return errors.New("CloseRef did not match pending generation")
			}
			return err
		}},
		{name: "CloseAll", close: func(manager *Manager, _ l3ingress.FlowRef) error {
			return manager.CloseAll()
		}},
	} {
		t.Run("fences-late-candidate/"+closeCase.name, func(t *testing.T) {
			listener := newTestStreamSessionListener(t, "tcp")
			defer listener.Close()
			accepted := acceptManagerCallbackSessions(t, listener, 1)
			id := testIdentity(l3ingress.ProtocolTCP)
			id.DstPort += 100
			ref := l3ingress.FlowRef{Identity: id, Generation: 23}
			event := managerCallbackEvent(listener, id)
			event.Ref = ref
			entered := make(chan struct{})
			release := make(chan struct{})
			var onStartCalls atomic.Int32
			manager := &Manager{OnStart: func(context.Context, PendingSessionView) error {
				if onStartCalls.Add(1) == 1 {
					close(entered)
				}
				<-release
				return nil
			}}

			const callers = 16
			results := make(chan error, callers)
			for index := 0; index < callers; index++ {
				go func() {
					_, err := manager.EnsureSession(context.Background(), event)
					results <- err
				}()
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				close(release)
				t.Fatal("OnStart did not enter")
			}
			waitForSessionCondition(t, time.Second, func() bool {
				manager.mu.Lock()
				defer manager.mu.Unlock()
				pending := manager.pending[id]
				return pending != nil && pending.waiters == callers
			}, "same-flow pending waiters")
			if err := closeCase.close(manager, ref); err != nil {
				close(release)
				t.Fatal(err)
			}
			for index := 0; index < callers; index++ {
				select {
				case err := <-results:
					if !errors.Is(err, net.ErrClosed) {
						t.Fatalf("waiter %d error=%v want net.ErrClosed", index, err)
					}
				case <-time.After(time.Second):
					close(release)
					t.Fatalf("waiter %d remained blocked", index)
				}
			}
			probeCtx, probeCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			_, probeErr := manager.EnsureSession(probeCtx, event)
			probeCancel()
			var callbackErr *CallbackError
			fencedByActiveCallback := errors.As(probeErr, &callbackErr) &&
				callbackErr.Reason == CallbackFailureSaturated
			if !errors.Is(probeErr, context.DeadlineExceeded) && !fencedByActiveCallback {
				close(release)
				t.Fatalf("fenced physical start probe error=%v want deadline or active-callback fence", probeErr)
			}
			if onStartCalls.Load() != 1 {
				close(release)
				t.Fatalf("fenced start overlapped OnStart calls=%d", onStartCalls.Load())
			}
			close(release)
			waitForSessionCondition(t, time.Second, func() bool {
				manager.mu.Lock()
				defer manager.mu.Unlock()
				return manager.pending[id] == nil
			}, "fenced physical admission exit")
			if _, ok := manager.SessionRef(ref); ok {
				t.Fatal("late candidate crossed Close fence")
			}
			closeAcceptedManagerSessions(t, accepted, 1)
		})
	}
}

func TestManagerSameFlowWaitersShareFailedPendingOutcome(t *testing.T) {
	listener := newTestStreamSessionListener(t, "tcp")
	defer listener.Close()
	accepted := acceptManagerCallbackSessions(t, listener, 1)
	id := testIdentity(l3ingress.ProtocolTCP)
	event := managerCallbackEvent(listener, id)
	startErr := errors.New("injected shared OnStart failure")
	entered := make(chan struct{})
	var configureCalls atomic.Int32
	var onStartCalls atomic.Int32
	var release <-chan struct{}
	manager := &Manager{
		Starter: &Starter{ConfigureSession: func(l3ingress.SessionRequest, *rendr.SessionConfig) error {
			configureCalls.Add(1)
			return nil
		}},
		OnStart: func(context.Context, PendingSessionView) error {
			onStartCalls.Add(1)
			close(entered)
			<-release
			return startErr
		},
	}
	var releaseCallback func()
	release, releaseCallback = newSessionCallbackRelease(t, func() bool {
		return len(manager.onStartSlots) == 0 && len(onStartProcessSlots) == 0
	}, "shared OnStart failure release")
	const callers = 32
	results := make(chan error, callers)
	go func() {
		_, err := manager.EnsureSession(context.Background(), event)
		results <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("initial OnStart did not enter")
	}
	for index := 1; index < callers; index++ {
		go func() {
			_, err := manager.EnsureSession(context.Background(), event)
			results <- err
		}()
	}
	time.Sleep(20 * time.Millisecond)
	releaseCallback()
	for index := 0; index < callers; index++ {
		select {
		case err := <-results:
			if !errors.Is(err, startErr) {
				t.Fatalf("waiter %d error=%v want shared failure", index, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("waiter %d did not receive shared outcome", index)
		}
	}
	if configureCalls.Load() != 1 || onStartCalls.Load() != 1 {
		t.Fatalf("physical starts configure/OnStart=%d/%d want 1/1", configureCalls.Load(), onStartCalls.Load())
	}
	if _, ok := manager.Session(id); ok {
		t.Fatal("failed shared pending outcome published a Session")
	}
	closeAcceptedManagerSessions(t, accepted, 1)

	t.Run("canceled leader preserves live follower", func(t *testing.T) {
		listener := newTestStreamSessionListener(t, "tcp")
		defer listener.Close()
		accepted := acceptManagerCallbackSessions(t, listener, 1)
		id := testIdentity(l3ingress.ProtocolTCP)
		id.DstPort += 200
		event := managerCallbackEvent(listener, id)
		entered := make(chan struct{})
		release := make(chan struct{})
		var configureCalls atomic.Int32
		var onStartCalls atomic.Int32
		manager := &Manager{
			Starter: &Starter{ConfigureSession: func(l3ingress.SessionRequest, *rendr.SessionConfig) error {
				if configureCalls.Add(1) == 1 {
					close(entered)
				}
				<-release
				return nil
			}},
			OnStart: func(context.Context, PendingSessionView) error {
				onStartCalls.Add(1)
				return nil
			},
		}
		leaderCtx, cancelLeader := context.WithCancel(context.Background())
		leader := make(chan error, 1)
		go func() {
			_, err := manager.EnsureSession(leaderCtx, event)
			leader <- err
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("leader did not enter ConfigureSession")
		}
		type ensureResult struct {
			sess *Session
			err  error
		}
		follower := make(chan ensureResult, 1)
		go func() {
			sess, err := manager.EnsureSession(context.Background(), event)
			follower <- ensureResult{sess: sess, err: err}
		}()
		waitForSessionCondition(t, time.Second, func() bool {
			manager.mu.Lock()
			defer manager.mu.Unlock()
			pending := manager.pending[id]
			return pending != nil && pending.waiters == 2
		}, "leader and follower claims")
		cancelLeader()
		if err := <-leader; !errors.Is(err, context.Canceled) {
			close(release)
			t.Fatalf("leader error=%v want context.Canceled", err)
		}
		close(release)
		outcome := <-follower
		if outcome.err != nil || outcome.sess == nil {
			t.Fatalf("live follower result=(%p, %v)", outcome.sess, outcome.err)
		}
		if configureCalls.Load() != 1 || onStartCalls.Load() != 1 {
			t.Fatalf("physical starts configure/OnStart=%d/%d want 1/1", configureCalls.Load(), onStartCalls.Load())
		}
		if current, ok := manager.Session(id); !ok || current != outcome.sess {
			t.Fatalf("follower candidate not published current=%p ok=%v", current, ok)
		}
		if err := manager.CloseAll(); err != nil {
			t.Fatal(err)
		}
		closeAcceptedManagerSessions(t, accepted, 1)
	})

	t.Run("all canceled waiters abandon and close the eventual candidate", func(t *testing.T) {
		listener := newTestStreamSessionListener(t, "tcp")
		defer listener.Close()
		accepted := acceptManagerCallbackSessions(t, listener, 1)
		id := testIdentity(l3ingress.ProtocolTCP)
		id.DstPort += 300
		event := managerCallbackEvent(listener, id)
		entered := make(chan struct{})
		release := make(chan struct{})
		var onStartCalls atomic.Int32
		manager := &Manager{OnStart: func(context.Context, PendingSessionView) error {
			if onStartCalls.Add(1) == 1 {
				close(entered)
			}
			<-release
			return nil
		}}
		const callers = 24
		cancels := make([]context.CancelFunc, callers)
		results := make(chan error, callers)
		for index := 0; index < callers; index++ {
			ctx, cancel := context.WithCancel(context.Background())
			cancels[index] = cancel
			go func(ctx context.Context) {
				_, err := manager.EnsureSession(ctx, event)
				results <- err
			}(ctx)
		}
		select {
		case <-entered:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("OnStart did not enter")
		}
		var pending *pendingSessionStart
		waitForSessionCondition(t, time.Second, func() bool {
			manager.mu.Lock()
			defer manager.mu.Unlock()
			pending = manager.pending[id]
			return pending != nil && pending.waiters == callers
		}, "all cancellation claimants")
		for _, cancel := range cancels {
			cancel()
		}
		for index := 0; index < callers; index++ {
			select {
			case err := <-results:
				if !errors.Is(err, context.Canceled) {
					close(release)
					t.Fatalf("waiter %d error=%v want context.Canceled", index, err)
				}
			case <-time.After(time.Second):
				close(release)
				t.Fatalf("waiter %d did not cancel", index)
			}
		}
		if _, ok := manager.Session(id); ok {
			close(release)
			t.Fatal("canceled waiters published a candidate")
		}
		close(release)
		select {
		case <-pending.physicalDone:
		case <-time.After(time.Second):
			t.Fatal("abandoned physical admission did not finish")
		}
		if pending.sess == nil || !pending.sess.isClosed() {
			t.Fatalf("eventual candidate was not closed: %p", pending.sess)
		}
		manager.mu.Lock()
		stillPending := manager.pending[id]
		manager.mu.Unlock()
		if stillPending != nil || onStartCalls.Load() != 1 {
			t.Fatalf("abandoned admission pending=%p OnStart calls=%d", stillPending, onStartCalls.Load())
		}
		closeAcceptedManagerSessions(t, accepted, 1)
	})

	t.Run("simultaneous cancellation cannot publish an unclaimed candidate", func(t *testing.T) {
		for iteration := 0; iteration < 500; iteration++ {
			id := testIdentity(l3ingress.ProtocolTCP)
			id.SrcPort += uint16(iteration)
			conn := &fakeConn{}
			sess := &Session{request: l3ingress.SessionRequest{Identity: id}, conn: conn}
			pending := &pendingSessionStart{
				done:           make(chan struct{}),
				physicalDone:   make(chan struct{}),
				retired:        make(chan struct{}),
				waiters:        1,
				completed:      true,
				physicalExit:   true,
				sess:           sess,
				doneClosed:     true,
				physicalClosed: true,
			}
			close(pending.done)
			close(pending.physicalDone)
			manager := &Manager{
				sessions: make(map[l3ingress.L3Identity]*Session),
				pending:  map[l3ingress.L3Identity]*pendingSessionStart{id: pending},
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			got, err := manager.waitPendingSession(ctx, id, l3ingress.FlowRef{}, pending)
			if got != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("iteration %d result=(%p, %v)", iteration, got, err)
			}
			if _, ok := manager.Session(id); ok {
				t.Fatalf("iteration %d published canceled claimant", iteration)
			}
			if conn.closed.Load() != 1 {
				t.Fatalf("iteration %d candidate closes=%d want 1", iteration, conn.closed.Load())
			}
		}
	})

	t.Run("last cancellation retains physical fence and closes once", func(t *testing.T) {
		id := testIdentity(l3ingress.ProtocolTCP)
		ref := l3ingress.FlowRef{Identity: id, Generation: 41}
		startCtx, cancelStart := context.WithCancel(context.Background())
		pending := &pendingSessionStart{
			ref: ref, done: make(chan struct{}), physicalDone: make(chan struct{}), retired: make(chan struct{}),
			cancel: cancelStart, waiters: 1,
		}
		manager := &Manager{
			sessions: make(map[l3ingress.L3Identity]*Session),
			pending:  map[l3ingress.L3Identity]*pendingSessionStart{id: pending},
		}
		claimCtx, cancelClaim := context.WithCancel(context.Background())
		cancelClaim()
		if sess, err := manager.waitPendingSession(claimCtx, id, ref, pending); sess != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("last claimant result=(%p, %v)", sess, err)
		}
		select {
		case <-startCtx.Done():
		case <-time.After(time.Second):
			t.Fatal("last claimant did not cancel physical admission")
		}
		var closeWG sync.WaitGroup
		for index := 0; index < 32; index++ {
			closeWG.Add(1)
			go func(index int) {
				defer closeWG.Done()
				switch index % 3 {
				case 0:
					_ = manager.Close(id)
				case 1:
					_, _ = manager.CloseRef(ref)
				default:
					_ = manager.CloseAll()
				}
			}(index)
		}
		closeWG.Wait()
		conn := &fakeConn{}
		candidate := &Session{request: l3ingress.SessionRequest{Identity: id, Ref: ref}, conn: conn}
		manager.finishPendingSessionStart(id, pending, candidate, nil)
		if conn.closed.Load() != 1 {
			t.Fatalf("late candidate closes=%d want 1", conn.closed.Load())
		}
		if _, ok := manager.Session(id); ok {
			t.Fatal("abandoned late candidate was published")
		}
		if err := candidate.Close(); err != nil || conn.closed.Load() != 1 {
			t.Fatalf("candidate close authority err=%v closes=%d", err, conn.closed.Load())
		}
	})

	t.Run("Close preserves one completed definitive outcome", func(t *testing.T) {
		id := testIdentity(l3ingress.ProtocolTCP)
		wantErr := errors.New("definitive admission failure")
		_, cancelStart := context.WithCancel(context.Background())
		pending := &pendingSessionStart{
			done:           make(chan struct{}),
			physicalDone:   make(chan struct{}),
			retired:        make(chan struct{}),
			cancel:         cancelStart,
			waiters:        2,
			completed:      true,
			physicalExit:   true,
			doneClosed:     true,
			physicalClosed: true,
			err:            wantErr,
		}
		close(pending.done)
		close(pending.physicalDone)
		manager := &Manager{
			sessions: make(map[l3ingress.L3Identity]*Session),
			pending:  map[l3ingress.L3Identity]*pendingSessionStart{id: pending},
		}
		if err := manager.Close(id); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < 2; index++ {
			sess, err := manager.waitPendingSession(context.Background(), id, l3ingress.FlowRef{}, pending)
			if sess != nil || !errors.Is(err, wantErr) {
				t.Fatalf("waiter %d result=(%p, %v) want definitive failure", index, sess, err)
			}
		}
	})
}

func managerCallbackEvent(listener *rendr.SessionListener, id l3ingress.L3Identity) l3ingress.PacketEvent {
	return l3ingress.PacketEvent{
		Meta:    l3ingress.PacketMeta{Identity: id},
		Flow:    l3ingress.FlowMeta{L3Identity: id},
		Decided: true,
		Decision: l3ingress.FlowDecision{
			Peer:   "peer",
			Root:   rendr.Path("tcp", rendr.PathSpec{Transport: "tcp", Address: listener.Addr().String()}),
			Egress: "direct",
		},
	}
}

func acceptManagerCallbackSessions(t *testing.T, listener *rendr.SessionListener, count int) <-chan rendr.Conn {
	t.Helper()
	accepted := make(chan rendr.Conn, count)
	go func() {
		for i := 0; i < count; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			conn, err := listener.AcceptStream(ctx)
			cancel()
			if err != nil {
				t.Errorf("AcceptStream %d: %v", i, err)
				return
			}
			accepted <- conn
		}
	}()
	return accepted
}

func closeAcceptedManagerSessions(t *testing.T, accepted <-chan rendr.Conn, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		select {
		case conn := <-accepted:
			if err := conn.Close(); err != nil {
				t.Errorf("close accepted Session %d: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("accepted Sessions=%d want %d", i, count)
		}
	}
}

func callbackSessionRequest() l3ingress.SessionRequest {
	return l3ingress.SessionRequest{
		Kind:               l3ingress.SessionKindStream,
		Identity:           testIdentity(l3ingress.ProtocolTCP),
		Peer:               "peer",
		Root:               rendr.Path("unused", rendr.PathSpec{Transport: "unused", Address: "unused"}),
		Egress:             "direct",
		Labels:             map[string]string{"class": "test"},
		PreserveL3Identity: true,
	}
}

func assertSessionCallbackReason(t *testing.T, err error, want CallbackFailureReason) {
	t.Helper()
	var callbackErr *CallbackError
	if !errors.As(err, &callbackErr) || callbackErr.Reason != want {
		t.Fatalf("error=%v callback=%+v want reason %q", err, callbackErr, want)
	}
}

func waitForSessionCondition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}

func newSessionCallbackRelease(
	t *testing.T,
	drained func() bool,
	description string,
) (<-chan struct{}, func()) {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	releaseCallback := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() {
		releaseCallback()
		waitForSessionCondition(t, time.Second, drained, description)
	})
	return release, releaseCallback
}
