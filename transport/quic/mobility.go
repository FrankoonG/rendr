package quic

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	qg "github.com/FrankoonG/quic-go"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/internal/udpsocket"
	"github.com/FrankoonG/rendr/transport"
)

const (
	cidProbeRevision       uint32 = 1
	cidRefreshPollInterval        = 100 * time.Millisecond
	cidRefreshDebounce            = 25 * time.Millisecond
)

type cidPath interface {
	Probe(context.Context) error
	Switch() error
	Close() error
}

type cidConnection interface {
	AddPath(*qg.Transport) (cidPath, error)
	Context() context.Context
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	CloseWithError(qg.ApplicationErrorCode, string) error
}

type quicCIDConnection struct{ conn *qg.Conn }

func (c quicCIDConnection) AddPath(transport *qg.Transport) (cidPath, error) {
	return c.conn.AddPath(transport)
}
func (c quicCIDConnection) Context() context.Context { return c.conn.Context() }
func (c quicCIDConnection) LocalAddr() net.Addr      { return c.conn.LocalAddr() }
func (c quicCIDConnection) RemoteAddr() net.Addr     { return c.conn.RemoteAddr() }
func (c quicCIDConnection) CloseWithError(code qg.ApplicationErrorCode, reason string) error {
	return c.conn.CloseWithError(code, reason)
}

type cidTransport struct {
	transport *qg.Transport
	socket    *udpsocket.Socket
	source    *net.UDPAddr
	local     net.Addr
	owned     bool
	closeFn   func() error
	closeOnce sync.Once
	closeErr  error
}

func openCIDTransport(ctx context.Context, source *net.UDPAddr) (*cidTransport, error) {
	local := cloneUDPAddr(source)
	if local != nil {
		local.Port = 0
	}
	socket, err := udpSocketWithBuffersPinned(ctx, local, true)
	if err != nil {
		return nil, err
	}
	transport := &qg.Transport{Conn: socket.PacketConn()}
	return &cidTransport{transport: transport, socket: socket, source: local, owned: true}, nil
}

func retainedCIDTransport(transport *qg.Transport, socket *udpsocket.Socket, source *net.UDPAddr) *cidTransport {
	return &cidTransport{transport: transport, socket: socket, source: cloneUDPAddr(source)}
}

func (t *cidTransport) close() error {
	if t == nil || !t.owned {
		return nil
	}
	t.closeOnce.Do(func() {
		if t.closeFn != nil {
			t.closeErr = t.closeFn()
			return
		}
		if t.transport != nil {
			t.closeErr = t.transport.Close()
		}
		if t.socket != nil {
			t.closeErr = errors.Join(t.closeErr, t.socket.Close())
		}
	})
	return t.closeErr
}

func (t *cidTransport) localAddr() net.Addr {
	if t == nil {
		return nil
	}
	if t.local != nil {
		return t.local
	}
	if t.transport == nil || t.transport.Conn == nil {
		return nil
	}
	return t.transport.Conn.LocalAddr()
}

type cidTransportFactory func(context.Context, *net.UDPAddr) (*cidTransport, error)

type cidOwner struct {
	mu sync.Mutex

	conn          cidConnection
	role          leafmobility.Role
	remote        *net.UDPAddr
	active        *cidTransport
	standby       *cidTransport
	activePath    cidPath
	incarnation   uint64
	closed        bool
	transportOpen cidTransportFactory
	observeRoute  routeObserver
	watchRoute    routeChangeWatcherFactory
	refreshPoll   time.Duration
	refreshDelay  time.Duration
	baseline      routeObservation
	current       routeObservation
	release       func()
	releaseOnce   sync.Once
	releaseErr    error

	claim        *leafmobility.Claim
	refreshState *leafmobility.RefreshSourceState
	refresh      *leafmobility.RefreshEmitter
	refreshFn    func(leafmobility.RefreshEvidence)
	refreshCtx   context.Context
	refreshStop  context.CancelFunc
	refreshDone  chan struct{}
	published    [sha256.Size]byte
	unavailable  bool

	probeSequence atomic.Uint64
	probes        atomic.Uint64
	switches      atomic.Uint64
}

func newCIDOwner(
	conn cidConnection,
	role leafmobility.Role,
	session leafmobility.Session,
	active *cidTransport,
	baseline routeObservation,
	release func(),
) (*cidOwner, error) {
	if conn == nil || active == nil || active.transport == nil ||
		(session != leafmobility.SessionAny && session != leafmobility.SessionStream && session != leafmobility.SessionPacket) ||
		(role != leafmobility.RoleDialer && role != leafmobility.RoleAcceptor) {
		return nil, errors.New("quic: invalid owned CID endpoint")
	}
	if release == nil {
		release = func() {}
	}
	remote := addrAsUDP(conn.RemoteAddr())
	if remote == nil {
		return nil, errors.New("quic: owned connection has no UDP peer address")
	}
	owner := &cidOwner{
		conn: conn, role: role, remote: remote, active: active, incarnation: 1,
		transportOpen: openCIDTransport, observeRoute: observeRouteSource,
		watchRoute: openRouteChangeWatcher, refreshPoll: cidRefreshPollInterval,
		refreshDelay: cidRefreshDebounce,
		baseline:     baseline, current: baseline, release: release,
		refreshState: leafmobility.NewRefreshSourceState(),
	}
	driver := &cidDriver{owner: owner}
	claim, err := leafmobility.NewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindQUIC, Role: role, Session: session,
		Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), owner)
	if err != nil {
		return nil, err
	}
	owner.claim = claim
	owner.refresh, err = leafmobility.NewRefreshEmitterWithSourceState(claim, owner.refreshState)
	if err != nil {
		return nil, err
	}
	if baseline.valid() {
		_, _ = owner.refreshState.Update(baseline.digest)
	}
	return owner, nil
}

func newRealCIDOwner(
	conn *qg.Conn,
	role leafmobility.Role,
	session leafmobility.Session,
	active *cidTransport,
	baseline routeObservation,
	release func(),
) (*cidOwner, error) {
	if conn == nil {
		return nil, errors.New("quic: nil owned connection")
	}
	return newCIDOwner(quicCIDConnection{conn: conn}, role, session, active, baseline, release)
}

func (o *cidOwner) LeafMobilityIncarnation() uint64 {
	if o == nil {
		return 0
	}
	o.mu.Lock()
	incarnation := o.incarnation
	o.mu.Unlock()
	return incarnation
}

func (o *cidOwner) accelerationStatus() transport.DatagramAccelerationStatus {
	if o == nil {
		return transport.DatagramAccelerationStatus{}
	}
	o.mu.Lock()
	active := o.active
	o.mu.Unlock()
	if active == nil || active.socket == nil {
		return transport.DatagramAccelerationStatus{}
	}
	return active.socket.DatagramAccelerationStatus()
}

func (o *cidOwner) releaseResources() error {
	if o == nil {
		return nil
	}
	o.releaseOnce.Do(func() {
		o.mu.Lock()
		o.closed = true
		stop := o.refreshStop
		done := o.refreshDone
		active, standby := o.active, o.standby
		o.refreshFn = nil
		o.mu.Unlock()
		if stop != nil {
			stop()
		}
		if done != nil {
			<-done
		}
		result := active.close()
		if standby != active {
			result = errors.Join(result, standby.close())
		}
		o.release()
		o.mu.Lock()
		o.releaseErr = result
		o.mu.Unlock()
	})
	o.mu.Lock()
	result := o.releaseErr
	o.mu.Unlock()
	return result
}

func (o *cidOwner) failClosed() error {
	if o == nil {
		return nil
	}
	err := o.conn.CloseWithError(0x52454e44, "rendr QUIC CID migration failed closed")
	return errors.Join(err, o.releaseResources())
}

func (o *cidOwner) subscribeRefresh(
	ctx context.Context,
	fn func(leafmobility.RefreshEvidence),
) (func(), error) {
	if o == nil || fn == nil {
		return nil, errors.New("quic: invalid CID refresh subscriber")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o.mu.Lock()
	if o.role != leafmobility.RoleDialer {
		o.mu.Unlock()
		return nil, errors.New("quic: accepted endpoint cannot initiate connection migration")
	}
	if o.closed || o.refreshFn != nil || o.refreshStop != nil {
		o.mu.Unlock()
		return nil, errors.New("quic: CID refresh subscriber is unavailable")
	}
	observer := o.observeRoute
	watchFactory := o.watchRoute
	remote := cloneUDPAddr(o.remote)
	baseline := o.baseline
	o.mu.Unlock()
	if observer == nil || remote == nil {
		return nil, errors.New("quic: route/source observation is unavailable")
	}
	if !baseline.valid() {
		observed, err := observer(ctx, remote)
		if err != nil || !observed.valid() {
			return nil, errors.Join(errors.New("quic: establish CID refresh baseline"), err)
		}
		baseline = observed
		if _, err := o.refreshState.Update(baseline.digest); err != nil {
			return nil, err
		}
	}
	monitorCtx, cancel := context.WithCancel(ctx)
	var watcher routeChangeWatcher
	if watchFactory != nil {
		// The watcher is only a latency optimization. Failure leaves the
		// periodic factual observer as the complete correctness path.
		watcher, _ = watchFactory(monitorCtx)
	}
	o.mu.Lock()
	if o.closed || o.refreshFn != nil || o.refreshStop != nil {
		o.mu.Unlock()
		cancel()
		if watcher != nil {
			watcher.Close()
		}
		return nil, errors.New("quic: CID refresh subscriber is unavailable")
	}
	o.baseline = baseline
	o.current = baseline
	o.refreshFn = fn
	o.refreshCtx = monitorCtx
	o.refreshStop = cancel
	o.refreshDone = make(chan struct{})
	done := o.refreshDone
	o.mu.Unlock()
	go o.refreshLoop(monitorCtx, remote, done, watcher)
	var once sync.Once
	return func() {
		once.Do(func() {
			o.mu.Lock()
			o.refreshFn = nil
			o.mu.Unlock()
			cancel()
		})
	}, nil
}

func (o *cidOwner) refreshLoop(
	ctx context.Context,
	remote *net.UDPAddr,
	done chan struct{},
	watcher routeChangeWatcher,
) {
	defer close(done)
	if watcher != nil {
		defer watcher.Close()
	}
	o.mu.Lock()
	pollInterval, debounce := o.refreshPoll, o.refreshDelay
	o.mu.Unlock()
	if pollInterval <= 0 {
		pollInterval = cidRefreshPollInterval
	}
	if debounce <= 0 {
		debounce = cidRefreshDebounce
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	var events <-chan struct{}
	if watcher != nil {
		events = watcher.Events()
	}
	var debounceTimer *time.Timer
	var debounceC <-chan time.Time
	defer func() {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
	}()
	observe := func() {
		o.mu.Lock()
		observer := o.observeRoute
		o.mu.Unlock()
		if observer == nil {
			return
		}
		observed, err := observer(ctx, remote)
		if err != nil || !observed.valid() {
			o.publishUnavailable()
			return
		}
		o.publishObservation(observed)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			observe()
		case _, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if debounceC != nil {
				continue
			}
			if debounceTimer == nil {
				debounceTimer = time.NewTimer(debounce)
			} else {
				debounceTimer.Reset(debounce)
			}
			debounceC = debounceTimer.C
		case <-debounceC:
			debounceC = nil
			observe()
		}
	}
}

func (o *cidOwner) publishUnavailable() {
	snapshot, changed, err := o.refreshState.MarkUnavailable()
	if err != nil || !changed {
		return
	}
	o.mu.Lock()
	o.unavailable = true
	o.published = [sha256.Size]byte{}
	emitter, callback := o.refresh, o.refreshFn
	o.mu.Unlock()
	if emitter == nil || callback == nil {
		return
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceUnavailable, snapshot)
	if err == nil {
		callback(evidence)
	}
}

func (o *cidOwner) publishObservation(observed routeObservation) {
	snapshot, err := o.refreshState.Update(observed.digest)
	if err != nil {
		return
	}
	o.mu.Lock()
	o.current = observed
	baseline := o.baseline.digest
	reason := leafmobility.RefreshReasonRouteSourceChanged
	publish := observed.digest != baseline && observed.digest != o.published
	if observed.digest == baseline && (o.unavailable || o.published != ([sha256.Size]byte{})) {
		reason = leafmobility.RefreshReasonRouteSourceRestored
		publish = true
		o.published = [sha256.Size]byte{}
		o.unavailable = false
	} else if publish {
		o.published = observed.digest
		o.unavailable = false
	}
	emitter, callback := o.refresh, o.refreshFn
	o.mu.Unlock()
	if !publish || emitter == nil || callback == nil {
		return
	}
	evidence, err := emitter.Observe(reason, snapshot)
	if err == nil {
		callback(evidence)
	}
}

func (o *cidOwner) commitRefresh(evidence leafmobility.RefreshEvidence) error {
	if o == nil || o.refreshState == nil {
		return errors.New("quic: CID refresh state is unavailable")
	}
	return o.refreshState.CommitCurrent(evidence, func(digest [32]byte) {
		o.mu.Lock()
		if o.current.digest == digest && o.current.valid() {
			o.baseline = o.current
			o.published = [sha256.Size]byte{}
			o.unavailable = false
		}
		o.mu.Unlock()
	})
}

type cidDriver struct{ owner *cidOwner }

func (*cidDriver) Operation() leafmobility.Operation { return leafmobility.OperationQUICCIDRebind }

func (d *cidDriver) Preflight(
	ctx context.Context,
	request leafmobility.PreflightRequest,
) (leafmobility.DriverAttempt, leafmobility.PreflightResult, error) {
	if d == nil || d.owner == nil {
		return nil, leafmobility.PreflightResult{}, errors.New("quic: CID driver has no owner")
	}
	o := d.owner
	o.mu.Lock()
	if o.closed || o.conn == nil || o.active == nil || o.active.transport == nil || o.conn.Context().Err() != nil {
		o.mu.Unlock()
		return d.ineligible(request, leafmobility.StageEndpoint, leafmobility.ReasonEndpointNotOwned, false,
			cidProbe{ID: leafmobility.ProbeEndpointState, Label: "connection-unavailable"})
	}
	role := o.role
	incarnation := o.incarnation
	active := o.active
	standby := o.standby
	activePath := o.activePath
	baseline := o.baseline
	observer := o.observeRoute
	remote := cloneUDPAddr(o.remote)
	o.mu.Unlock()

	observed := baseline
	peerOnly := role == leafmobility.RoleAcceptor
	if !peerOnly {
		if observer == nil || remote == nil {
			return d.ineligible(request, leafmobility.StageTuple, leafmobility.ReasonTupleNotPreservable, false,
				cidProbe{ID: leafmobility.ProbeTuple, Label: "route-source-observer-unavailable"})
		}
		var err error
		observed, err = observer(ctx, remote)
		if err != nil || !observed.valid() {
			return d.ineligible(request, leafmobility.StageTuple, leafmobility.ReasonTupleNotPreservable, false,
				cidProbe{ID: leafmobility.ProbeTuple, Label: "replacement-route-unavailable"})
		}
		if baseline.valid() && observed.digest == baseline.digest {
			return d.ineligible(request, leafmobility.StagePreflight, leafmobility.ReasonPreflightRejected, true,
				cidProbe{ID: leafmobility.ProbeEndpointState, Label: "route-source-unchanged"})
		}
		if standby != nil && !sameSource(standby.source, observed.source) {
			return d.ineligible(request, leafmobility.StageTuple, leafmobility.ReasonTupleNotPreservable, false,
				cidProbe{ID: leafmobility.ProbeTuple, Label: "bounded-standby-source-mismatch"})
		}
	}

	endpointProbe := cidProbe{
		ID: leafmobility.ProbeEndpointState, Label: "owned-quic-connection-v1",
		Incarnation: incarnation, Active: addrString(active.localAddr()), Remote: addrString(remote),
	}
	tupleProbe := cidProbe{
		ID: leafmobility.ProbeTuple, Label: "quic-addpath-probe-switch-v1",
		Incarnation: incarnation, Active: addrString(active.localAddr()), Remote: addrString(remote),
		Source: addrString(observed.source), Route: observed.digest,
	}
	rollbackProbe := cidProbe{
		ID: leafmobility.ProbeRollbackReadiness, Label: "nonactive-path-close-retained-standby-v1",
		Incarnation: incarnation, Active: addrString(active.localAddr()), Remote: addrString(remote),
		Standby: addrString(standby.localAddr()), HasActivePath: activePath != nil,
	}
	references, err := d.references(request, endpointProbe, tupleProbe, rollbackProbe)
	if err != nil {
		return nil, leafmobility.PreflightResult{}, err
	}
	evidence := digestCIDAttempt(request, references)
	attempt := &cidAttempt{
		driver: d, preflight: request,
		evidence:    leafmobility.AttemptEvidence{Digest: evidence, ProbeReferences: references},
		incarnation: incarnation, active: active, standby: standby, activePath: activePath,
		observation: observed, peerOnly: peerOnly, stage: cidAttemptPreflight,
	}
	return attempt, leafmobility.PreflightResult{
		Eligible: true, Stage: leafmobility.StagePreflightComplete,
		EvidenceDigest: evidence, ProbeReferences: references,
	}, nil
}

type cidProbe struct {
	ID            leafmobility.ProbeID
	Label         string
	Incarnation   uint64
	Active        string
	Standby       string
	Remote        string
	Source        string
	Route         [sha256.Size]byte
	HasActivePath bool
}

func (d *cidDriver) ineligible(
	request leafmobility.PreflightRequest,
	stage leafmobility.Stage,
	reason leafmobility.Reason,
	retryable bool,
	probes ...cidProbe,
) (leafmobility.DriverAttempt, leafmobility.PreflightResult, error) {
	references, err := d.references(request, probes...)
	if err != nil {
		return nil, leafmobility.PreflightResult{}, err
	}
	return nil, leafmobility.PreflightResult{
		Stage: stage, Reason: reason, Retryable: retryable, ProbeReferences: references,
	}, nil
}

func (d *cidDriver) references(
	request leafmobility.PreflightRequest,
	probes ...cidProbe,
) (leafmobility.ProbeReferences, error) {
	references := make([]leafmobility.ProbeReference, 0, len(probes)+1)
	if request.PlatformProbe != (leafmobility.ProbeReference{}) {
		references = append(references, request.PlatformProbe)
	}
	observed := time.Now().UnixNano()
	expires := observed + int64(leafmobility.MaxProbeLifetime)
	if deadline := request.Deadline.UnixNano(); deadline > observed && deadline < expires {
		expires = deadline
	}
	if expires <= observed {
		return leafmobility.ProbeReferences{}, errors.New("quic: CID probe evidence already expired")
	}
	for _, probe := range probes {
		generation := d.owner.probeSequence.Add(1)
		if generation == 0 {
			generation = d.owner.probeSequence.Add(1)
		}
		references = append(references, leafmobility.ProbeReference{
			ID: probe.ID, Revision: cidProbeRevision, Generation: generation,
			EndpointGeneration: request.Facts.Generation,
			ObservedNano:       observed, ExpiresNano: expires, ContextDigest: request.ContextDigest,
			Digest: digestCIDProbe(request, probe),
		})
	}
	return leafmobility.NewProbeReferences(references...)
}

func digestCIDProbe(request leafmobility.PreflightRequest, probe cidProbe) leafmobility.EvidenceDigest {
	hash := sha256.New()
	_, _ = hash.Write([]byte("QCP1"))
	_, _ = hash.Write([]byte{byte(probe.ID)})
	writeCIDString(hash, probe.Label)
	_, _ = hash.Write(request.TransactionID[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], request.Facts.Generation)
	_, _ = hash.Write(scalar[:])
	binary.BigEndian.PutUint64(scalar[:], probe.Incarnation)
	_, _ = hash.Write(scalar[:])
	writeCIDString(hash, probe.Active)
	writeCIDString(hash, probe.Standby)
	writeCIDString(hash, probe.Remote)
	writeCIDString(hash, probe.Source)
	_, _ = hash.Write(probe.Route[:])
	if probe.HasActivePath {
		_, _ = hash.Write([]byte{1})
	} else {
		_, _ = hash.Write([]byte{0})
	}
	var digest leafmobility.EvidenceDigest
	copy(digest[:], hash.Sum(nil))
	return digest
}

func digestCIDAttempt(
	request leafmobility.PreflightRequest,
	references leafmobility.ProbeReferences,
) leafmobility.EvidenceDigest {
	hash := sha256.New()
	_, _ = hash.Write([]byte("QCA1"))
	_, _ = hash.Write(request.TransactionID[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], request.Facts.Generation)
	_, _ = hash.Write(scalar[:])
	for _, reference := range references.All() {
		_, _ = hash.Write([]byte{byte(reference.ID)})
		_, _ = hash.Write(reference.Digest[:])
	}
	var digest leafmobility.EvidenceDigest
	copy(digest[:], hash.Sum(nil))
	return digest
}

type cidByteWriter interface{ Write([]byte) (int, error) }

func writeCIDString(writer cidByteWriter, value string) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write([]byte(value))
}

type cidAttemptStage uint8

const (
	cidAttemptPreflight cidAttemptStage = iota + 1
	cidAttemptPrepared
	cidAttemptStaged
	cidAttemptPublished
	cidAttemptActivated
	cidAttemptRolledBack
	cidAttemptFailedClosed
)

type cidAttempt struct {
	mu sync.Mutex

	driver      *cidDriver
	preflight   leafmobility.PreflightRequest
	evidence    leafmobility.AttemptEvidence
	incarnation uint64
	active      *cidTransport
	standby     *cidTransport
	activePath  cidPath
	observation routeObservation
	peerOnly    bool
	stage       cidAttemptStage
	candidate   cidPath
	published   bool
}

func (a *cidAttempt) Evidence() leafmobility.AttemptEvidence {
	if a == nil {
		return leafmobility.AttemptEvidence{}
	}
	return a.evidence
}

func (a *cidAttempt) Prepare(_ context.Context, request leafmobility.ExecutionRequest) error {
	if a == nil || a.driver == nil || a.driver.owner == nil {
		return errors.New("quic: nil CID attempt")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stage != cidAttemptPreflight || !a.matches(request) {
		return errors.New("quic: CID Prepare does not match preflight")
	}
	if a.peerOnly {
		return errors.New("quic: server cannot initiate connection migration")
	}
	o := a.driver.owner
	o.mu.Lock()
	current := !o.closed && o.role == leafmobility.RoleDialer && o.incarnation == a.incarnation &&
		o.active == a.active && o.standby == a.standby && o.activePath == a.activePath
	o.mu.Unlock()
	if !current {
		return errors.New("quic: CID owner changed after preflight")
	}
	a.stage = cidAttemptPrepared
	return nil
}

func (a *cidAttempt) Stage(
	ctx context.Context,
	request leafmobility.ExecutionRequest,
) (leafmobility.PublicationEvidence, error) {
	if a == nil || a.driver == nil || a.driver.owner == nil {
		return leafmobility.PublicationEvidence{}, errors.New("quic: nil CID attempt")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stage != cidAttemptPrepared || !a.matches(request) || a.peerOnly {
		return leafmobility.PublicationEvidence{}, errors.New("quic: CID Stage is not prepared")
	}
	if err := ctx.Err(); err != nil {
		return leafmobility.PublicationEvidence{}, err
	}
	o := a.driver.owner
	standby := a.standby
	if standby == nil {
		created, err := o.transportOpen(ctx, a.observation.source)
		if err != nil {
			return leafmobility.PublicationEvidence{}, fmt.Errorf("quic: open standby transport: %w", err)
		}
		o.mu.Lock()
		if o.closed || o.incarnation != a.incarnation || o.active != a.active || o.standby != nil {
			o.mu.Unlock()
			_ = created.close()
			return leafmobility.PublicationEvidence{}, errors.New("quic: CID owner changed while opening standby")
		}
		o.standby = created
		standby = created
		a.standby = created
		o.mu.Unlock()
	}
	if standby.transport == nil || !sameSource(standby.source, a.observation.source) {
		return leafmobility.PublicationEvidence{}, errors.New("quic: standby transport does not match the factual source")
	}
	path, err := o.conn.AddPath(standby.transport)
	if err != nil {
		return leafmobility.PublicationEvidence{}, fmt.Errorf("quic: AddPath: %w", err)
	}
	a.candidate = path
	if err := path.Probe(ctx); err != nil {
		return leafmobility.PublicationEvidence{}, fmt.Errorf("quic: probe candidate path: %w", err)
	}
	o.probes.Add(1)
	o.mu.Lock()
	current := !o.closed && o.incarnation == a.incarnation && o.active == a.active &&
		o.standby == standby && o.activePath == a.activePath
	o.mu.Unlock()
	if !current {
		return leafmobility.PublicationEvidence{}, errors.New("quic: CID owner changed while probing standby")
	}
	a.stage = cidAttemptStaged
	digest := digestCIDPublication(request, a.incarnation, standby, a.observation)
	return leafmobility.PublicationEvidence{Digest: digest}, nil
}

func (a *cidAttempt) Publish(ctx context.Context, request leafmobility.ExecutionRequest) error {
	if a == nil || a.driver == nil || a.driver.owner == nil {
		return errors.New("quic: nil CID attempt")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stage != cidAttemptStaged || !a.matches(request) || a.candidate == nil || a.published {
		return errors.New("quic: CID Publish is not staged")
	}
	o := a.driver.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.incarnation != a.incarnation || o.active != a.active ||
		o.standby != a.standby || o.activePath != a.activePath {
		return errors.New("quic: CID owner changed before publish")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.candidate.Switch(); err != nil {
		return fmt.Errorf("quic: switch candidate path: %w", err)
	}
	o.incarnation++
	if o.incarnation == 0 {
		o.incarnation++
	}
	o.switches.Add(1)
	a.published = true
	a.stage = cidAttemptPublished
	return nil
}

func (a *cidAttempt) Activate(_ context.Context, request leafmobility.ExecutionRequest) error {
	if a == nil || a.driver == nil || a.driver.owner == nil {
		return errors.New("quic: nil CID attempt")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stage == cidAttemptActivated {
		return nil
	}
	if a.stage != cidAttemptPublished || !a.matches(request) || !a.published {
		return errors.New("quic: CID Activate is not published")
	}
	o := a.driver.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.active != a.active || o.standby != a.standby || o.activePath != a.activePath {
		return errors.New("quic: CID owner changed before activation")
	}
	if a.activePath != nil {
		if err := a.activePath.Close(); err != nil {
			return fmt.Errorf("quic: retire predecessor path: %w", err)
		}
	}
	o.active, o.standby = o.standby, o.active
	o.activePath = a.candidate
	a.stage = cidAttemptActivated
	return nil
}

func (a *cidAttempt) Rollback(_ context.Context, request leafmobility.ExecutionRequest) error {
	if a == nil || a.driver == nil || a.driver.owner == nil {
		return errors.New("quic: nil CID attempt")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.matches(request) || a.published || a.stage == cidAttemptPublished ||
		a.stage == cidAttemptActivated || a.stage == cidAttemptFailedClosed {
		return errors.New("quic: CID Rollback is not permitted")
	}
	if a.stage == cidAttemptRolledBack {
		return nil
	}
	if a.candidate != nil {
		if err := a.candidate.Close(); err != nil {
			return fmt.Errorf("quic: close rollback path: %w", err)
		}
	}
	a.stage = cidAttemptRolledBack
	return nil
}

func (a *cidAttempt) FailClosed(_ context.Context, request leafmobility.ExecutionRequest) error {
	if a == nil || a.driver == nil || a.driver.owner == nil {
		return errors.New("quic: nil CID attempt")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.matches(request) || a.stage == cidAttemptRolledBack {
		return errors.New("quic: CID FailClosed does not match active attempt")
	}
	if a.stage == cidAttemptFailedClosed {
		return nil
	}
	if err := a.driver.owner.failClosed(); err != nil {
		return err
	}
	a.stage = cidAttemptFailedClosed
	return nil
}

func (a *cidAttempt) EndpointGenerationChanged() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	changed := a.published
	a.mu.Unlock()
	return changed
}

func (a *cidAttempt) matches(request leafmobility.ExecutionRequest) bool {
	plan := request.Plan
	preflight := a.preflight
	return request.Facts == preflight.Facts && plan.TransactionID == preflight.TransactionID &&
		plan.Binding == preflight.Binding && plan.EndpointGeneration == preflight.Facts.Generation &&
		plan.Direction == preflight.Direction && plan.Session == preflight.Session &&
		plan.Operation == leafmobility.OperationQUICCIDRebind &&
		request.Agreement.ActorEndpointGeneration == preflight.Facts.Generation &&
		request.Agreement.AgreementDigest != ([32]byte{})
}

func digestCIDPublication(
	request leafmobility.ExecutionRequest,
	incarnation uint64,
	standby *cidTransport,
	observation routeObservation,
) leafmobility.EvidenceDigest {
	hash := sha256.New()
	_, _ = hash.Write([]byte("QCS1"))
	_, _ = hash.Write(request.Plan.TransactionID[:])
	_, _ = hash.Write(request.Agreement.AgreementDigest[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], incarnation)
	_, _ = hash.Write(scalar[:])
	writeCIDString(hash, addrString(standby.localAddr()))
	writeCIDString(hash, addrString(observation.source))
	_, _ = hash.Write(observation.digest[:])
	var digest leafmobility.EvidenceDigest
	copy(digest[:], hash.Sum(nil))
	return digest
}

func addrAsUDP(address net.Addr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	if udp, ok := address.(*net.UDPAddr); ok {
		return cloneUDPAddr(udp)
	}
	udp, _ := net.ResolveUDPAddr("udp", address.String())
	return udp
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	clone := *address
	clone.IP = append(net.IP(nil), address.IP...)
	return &clone
}

func sameSource(left, right *net.UDPAddr) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Zone == right.Zone && left.IP.Equal(right.IP)
}

func addrString(address net.Addr) string {
	if address == nil {
		return ""
	}
	return address.String()
}
