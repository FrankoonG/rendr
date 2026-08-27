package gvisor

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

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

const gvisorLinkProbeRevision uint32 = 3

var errLinkAttemptSourceChanged = errors.New("gvisor: packet-link source changed")

type linkDriver struct {
	owner         *linkOwner
	probeSequence atomic.Uint64
}

func newLinkDriver(owner *linkOwner) *linkDriver { return &linkDriver{owner: owner} }

func (*linkDriver) Operation() leafmobility.Operation {
	return leafmobility.OperationGVisorLinkRebind
}

func (driver *linkDriver) Preflight(
	ctx context.Context,
	request leafmobility.PreflightRequest,
) (leafmobility.DriverAttempt, leafmobility.PreflightResult, error) {
	if driver == nil || driver.owner == nil {
		return nil, leafmobility.PreflightResult{}, errors.New("gvisor: packet-link driver has no owner")
	}
	owner := driver.owner
	owner.mu.Lock()
	if owner.closed || owner.closing || owner.endpoint == nil || owner.active == nil || owner.active.conn == nil {
		owner.mu.Unlock()
		return driver.ineligible(request, leafmobility.StageEndpoint, leafmobility.ReasonEndpointNotOwned, false,
			linkProbe{ID: leafmobility.ProbeEndpointState, Label: "endpoint-unavailable"})
	}
	incarnation := owner.incarnation
	localGeneration := owner.localGeneration
	peerGeneration := owner.peerGeneration
	active := owner.active
	remote := cloneAddr(owner.peerRemote)
	virtualIP := owner.virtualIP
	wireFault := owner.wireFault
	owner.mu.Unlock()

	owner.bindOuterMTURecoveryDeadline(request.Deadline)
	observation, err := owner.observeOuterRoute(ctx, active, remote)
	if err != nil {
		return driver.ineligible(request, leafmobility.StageTuple, leafmobility.ReasonTupleNotPreservable, true,
			linkProbe{ID: leafmobility.ProbeTuple, Label: "replacement-route-unavailable"})
	}
	if active.error() != nil {
		wireFault = true
	}
	endpointProbe := linkProbe{
		ID: leafmobility.ProbeEndpointState, Label: "owned-gvisor-endpoint-v3",
		Incarnation: incarnation, LocalGeneration: localGeneration, PeerGeneration: peerGeneration,
		LinkID: owner.id, VirtualIP: virtualIP,
	}
	tupleProbe := linkProbe{
		ID: leafmobility.ProbeTuple, Label: "authenticated-outer-successor-v3",
		Incarnation: incarnation, LocalGeneration: localGeneration, PeerGeneration: peerGeneration,
		LinkID: owner.id, VirtualIP: virtualIP,
		Local: active.conn.LocalAddr().String(), Remote: remote.String(), Route: observation.digest,
	}
	rollbackProbe := linkProbe{
		ID: leafmobility.ProbeRollbackReadiness, Label: "prepublish-predecessor-retained-v3",
		Incarnation: incarnation, LocalGeneration: localGeneration, PeerGeneration: peerGeneration,
		LinkID: owner.id, VirtualIP: virtualIP,
	}
	probes, err := driver.references(request, endpointProbe, tupleProbe, rollbackProbe)
	if err != nil {
		return nil, leafmobility.PreflightResult{}, err
	}
	evidence := digestLinkAttempt(request, probes)
	attempt := &linkAttempt{
		driver: driver, preflight: request, evidence: leafmobility.AttemptEvidence{
			Digest: evidence, ProbeReferences: probes,
		},
		incarnation: incarnation, localGeneration: localGeneration, peerGeneration: peerGeneration, active: active,
		remote: remote, route: observation, wireFault: wireFault, stage: linkAttemptPreflight,
	}
	return attempt, leafmobility.PreflightResult{
		Eligible: true, Stage: leafmobility.StagePreflightComplete,
		EvidenceDigest: evidence, ProbeReferences: probes,
	}, nil
}

type linkProbe struct {
	ID              leafmobility.ProbeID
	Label           string
	Incarnation     uint64
	LocalGeneration uint64
	PeerGeneration  uint64
	LinkID          linkID
	VirtualIP       [4]byte
	Local           string
	Remote          string
	Route           [sha256.Size]byte
}

func (driver *linkDriver) ineligible(
	request leafmobility.PreflightRequest,
	stage leafmobility.Stage,
	reason leafmobility.Reason,
	retryable bool,
	probes ...linkProbe,
) (leafmobility.DriverAttempt, leafmobility.PreflightResult, error) {
	references, err := driver.references(request, probes...)
	if err != nil {
		return nil, leafmobility.PreflightResult{}, err
	}
	return nil, leafmobility.PreflightResult{
		Stage: stage, Reason: reason, Retryable: retryable, ProbeReferences: references,
	}, nil
}

func (driver *linkDriver) references(
	request leafmobility.PreflightRequest,
	probes ...linkProbe,
) (leafmobility.ProbeReferences, error) {
	references := make([]leafmobility.ProbeReference, 0, len(probes)+1)
	references = append(references, request.PlatformProbe)
	observed := time.Now().UnixNano()
	expires := request.PlatformProbe.ExpiresNano
	if limit := observed + int64(leafmobility.MaxProbeLifetime); expires > limit {
		expires = limit
	}
	if expires <= observed {
		return leafmobility.ProbeReferences{}, errors.New("gvisor: packet-link probe evidence already expired")
	}
	for _, probe := range probes {
		if probe.ID < leafmobility.ProbeEndpointState || probe.ID > leafmobility.ProbeRollbackReadiness ||
			probe.ID == leafmobility.ProbeQuarantineSchema {
			return leafmobility.ProbeReferences{}, fmt.Errorf("gvisor: invalid packet-link probe %d", probe.ID)
		}
		generation := driver.probeSequence.Add(1)
		if generation == 0 {
			generation = driver.probeSequence.Add(1)
		}
		references = append(references, leafmobility.ProbeReference{
			ID: probe.ID, Revision: gvisorLinkProbeRevision, Generation: generation,
			EndpointGeneration: request.Facts.Generation,
			ObservedNano:       observed, ExpiresNano: expires, ContextDigest: request.ContextDigest,
			Digest: digestLinkProbe(request, probe),
		})
	}
	return leafmobility.NewProbeReferences(references...)
}

func digestLinkProbe(request leafmobility.PreflightRequest, probe linkProbe) leafmobility.EvidenceDigest {
	hash := sha256.New()
	_, _ = hash.Write([]byte("GLP1"))
	_, _ = hash.Write([]byte{byte(probe.ID)})
	writeLinkString(hash, probe.Label)
	_, _ = hash.Write(request.TransactionID[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], request.Facts.Generation)
	_, _ = hash.Write(scalar[:])
	binary.BigEndian.PutUint64(scalar[:], probe.Incarnation)
	_, _ = hash.Write(scalar[:])
	binary.BigEndian.PutUint64(scalar[:], probe.LocalGeneration)
	_, _ = hash.Write(scalar[:])
	binary.BigEndian.PutUint64(scalar[:], probe.PeerGeneration)
	_, _ = hash.Write(scalar[:])
	_, _ = hash.Write(probe.LinkID[:])
	_, _ = hash.Write(probe.VirtualIP[:])
	writeLinkString(hash, probe.Local)
	writeLinkString(hash, probe.Remote)
	_, _ = hash.Write(probe.Route[:])
	var digest leafmobility.EvidenceDigest
	copy(digest[:], hash.Sum(nil))
	return digest
}

func digestLinkAttempt(
	request leafmobility.PreflightRequest,
	probes leafmobility.ProbeReferences,
) leafmobility.EvidenceDigest {
	hash := sha256.New()
	_, _ = hash.Write([]byte("GLA1"))
	_, _ = hash.Write(request.TransactionID[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], request.Facts.Generation)
	_, _ = hash.Write(scalar[:])
	for _, reference := range probes.All() {
		_, _ = hash.Write([]byte{byte(reference.ID)})
		_, _ = hash.Write(reference.Digest[:])
	}
	var digest leafmobility.EvidenceDigest
	copy(digest[:], hash.Sum(nil))
	return digest
}

type linkByteWriter interface {
	Write([]byte) (int, error)
}

func writeLinkString(writer linkByteWriter, value string) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write([]byte(value))
}

type linkAttemptStage uint8

const (
	linkAttemptPreflight linkAttemptStage = iota + 1
	linkAttemptPrepared
	linkAttemptStaged
	linkAttemptPublished
	linkAttemptActivated
	linkAttemptRolledBack
	linkAttemptFailedClosed
)

type linkAttempt struct {
	mu sync.Mutex

	driver          *linkDriver
	preflight       leafmobility.PreflightRequest
	evidence        leafmobility.AttemptEvidence
	incarnation     uint64
	localGeneration uint64
	peerGeneration  uint64
	active          *packetWire
	remote          net.Addr
	route           routeObservation
	wireFault       bool
	stage           linkAttemptStage

	maintenance *linkMaintenance
	candidate   *packetWire
	candidateAt routeObservation
	generation  uint64
	control     outerControl
	nonce       linkNonce
	published   bool
}

type linkAttemptOwnerSnapshot struct {
	incarnation, localGeneration, peerGeneration uint64
	active                                       *packetWire
	remote                                       net.Addr
}

func snapshotLinkAttemptOwnerLocked(owner *linkOwner) linkAttemptOwnerSnapshot {
	if owner == nil {
		return linkAttemptOwnerSnapshot{}
	}
	return linkAttemptOwnerSnapshot{
		incarnation: owner.incarnation, localGeneration: owner.localGeneration,
		peerGeneration: owner.peerGeneration, active: owner.active, remote: cloneAddr(owner.peerRemote),
	}
}

func (attempt *linkAttempt) ownerSnapshot() linkAttemptOwnerSnapshot {
	return linkAttemptOwnerSnapshot{
		incarnation: attempt.incarnation, localGeneration: attempt.localGeneration,
		peerGeneration: attempt.peerGeneration, active: attempt.active, remote: attempt.remote,
	}
}

func (snapshot linkAttemptOwnerSnapshot) currentLocked(owner *linkOwner) bool {
	return owner != nil && !owner.closed && !owner.closing && owner.incarnation == snapshot.incarnation &&
		owner.localGeneration == snapshot.localGeneration && owner.peerGeneration == snapshot.peerGeneration &&
		owner.active == snapshot.active && addrEqualOnWire(snapshot.active, owner.peerRemote, snapshot.remote)
}

func (snapshot linkAttemptOwnerSnapshot) watch(
	ctx context.Context,
	owner *linkOwner,
) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	watched, cancel := context.WithCancelCause(ctx)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			owner.mu.Lock()
			current := snapshot.currentLocked(owner)
			changed := owner.change
			ownerDone := owner.done
			owner.mu.Unlock()
			if !current {
				cancel(errLinkAttemptSourceChanged)
				return
			}
			select {
			case <-changed:
			case <-ownerDone:
				cancel(net.ErrClosed)
				return
			case <-watched.Done():
				return
			case <-stop:
				return
			}
		}
	}()
	var once sync.Once
	return watched, func() {
		once.Do(func() {
			close(stop)
			cancel(context.Canceled)
			<-done
		})
	}
}

func (attempt *linkAttempt) Evidence() leafmobility.AttemptEvidence {
	if attempt == nil {
		return leafmobility.AttemptEvidence{}
	}
	return attempt.evidence
}

func (attempt *linkAttempt) Prepare(ctx context.Context, request leafmobility.ExecutionRequest) error {
	if attempt == nil || attempt.driver == nil || attempt.driver.owner == nil {
		return errors.New("gvisor: nil packet-link attempt")
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.stage != linkAttemptPreflight || !attempt.matches(request) {
		return errors.New("gvisor: packet-link Prepare does not match preflight")
	}
	maintenance, err := attempt.driver.owner.beginMaintenance(ctx, attempt.incarnation)
	if err != nil {
		return err
	}
	owner := attempt.driver.owner
	owner.bindOuterMTURecoveryDeadline(request.Plan.Deadline)
	owner.mu.Lock()
	current := attempt.ownerSnapshot().currentLocked(owner)
	owner.mu.Unlock()
	if !current {
		maintenance.release()
		return errors.New("gvisor: packet-link owner changed after preflight")
	}
	observation, err := owner.observeOuterRoute(ctx, attempt.active, attempt.remote)
	if err != nil || observation.digest != attempt.route.digest {
		maintenance.release()
		return errors.Join(errors.New("gvisor: packet-link route changed after preflight"), err)
	}
	attempt.maintenance = maintenance
	attempt.stage = linkAttemptPrepared
	return nil
}

func (attempt *linkAttempt) Stage(
	ctx context.Context,
	request leafmobility.ExecutionRequest,
) (leafmobility.PublicationEvidence, error) {
	if attempt == nil || attempt.driver == nil || attempt.driver.owner == nil {
		return leafmobility.PublicationEvidence{}, errors.New("gvisor: nil packet-link attempt")
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.stage != linkAttemptPrepared || !attempt.matches(request) || attempt.maintenance == nil {
		return leafmobility.PublicationEvidence{}, errors.New("gvisor: packet-link Stage is not prepared")
	}
	nonce, err := newLinkNonce()
	if err != nil {
		return leafmobility.PublicationEvidence{}, err
	}
	control, err := controlForExecution(request, nonce)
	if err != nil {
		return leafmobility.PublicationEvidence{}, err
	}
	attempt.driver.owner.mu.Lock()
	control.ReceiveNext = attempt.driver.owner.receiveNext
	attempt.driver.owner.mu.Unlock()
	candidate, generation, observation, err := attempt.driver.owner.stageCandidate(
		ctx, attempt.maintenance, control, attempt.ownerSnapshot(),
	)
	attempt.candidate = candidate
	attempt.candidateAt = observation
	attempt.generation = generation
	attempt.control = control
	attempt.nonce = nonce
	if err != nil {
		return leafmobility.PublicationEvidence{}, err
	}
	attempt.stage = linkAttemptStaged
	digest := digestLinkPublication(request, attempt.driver.owner.id, generation, nonce, candidate, observation)
	return leafmobility.PublicationEvidence{Digest: digest}, nil
}

func (attempt *linkAttempt) Publish(ctx context.Context, request leafmobility.ExecutionRequest) error {
	if attempt == nil || attempt.driver == nil || attempt.driver.owner == nil {
		return errors.New("gvisor: nil packet-link attempt")
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.stage != linkAttemptStaged || !attempt.matches(request) || attempt.candidate == nil || attempt.published {
		return errors.New("gvisor: packet-link Publish is not staged")
	}
	if err := attempt.driver.owner.publishCandidate(
		ctx, attempt.maintenance, attempt.candidate, attempt.generation, attempt.control, attempt.candidateAt,
		attempt.ownerSnapshot(),
	); err != nil {
		return err
	}
	attempt.published = true
	attempt.stage = linkAttemptPublished
	return nil
}

func (attempt *linkAttempt) Activate(ctx context.Context, request leafmobility.ExecutionRequest) error {
	if attempt == nil || attempt.driver == nil || attempt.driver.owner == nil {
		return errors.New("gvisor: nil packet-link attempt")
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.stage == linkAttemptActivated {
		return nil
	}
	if attempt.stage != linkAttemptPublished || !attempt.matches(request) || !attempt.published {
		return errors.New("gvisor: packet-link Activate is not published")
	}
	if err := attempt.driver.owner.activateCandidate(
		ctx, attempt.maintenance, attempt.candidate, attempt.generation, attempt.control,
	); err != nil {
		return err
	}
	attempt.stage = linkAttemptActivated
	return nil
}

func (attempt *linkAttempt) Rollback(ctx context.Context, request leafmobility.ExecutionRequest) error {
	if attempt == nil || attempt.driver == nil || attempt.driver.owner == nil {
		return errors.New("gvisor: nil packet-link attempt")
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if !attempt.matches(request) || attempt.published || attempt.stage == linkAttemptPublished ||
		attempt.stage == linkAttemptActivated || attempt.stage == linkAttemptFailedClosed {
		return errors.New("gvisor: packet-link Rollback is not permitted")
	}
	if attempt.stage == linkAttemptRolledBack {
		return nil
	}
	if attempt.maintenance != nil {
		if err := attempt.driver.owner.rollbackCandidate(
			ctx, attempt.maintenance, attempt.candidate, attempt.generation, attempt.control, attempt.remote,
		); err != nil {
			return err
		}
	}
	attempt.stage = linkAttemptRolledBack
	return nil
}

func (attempt *linkAttempt) FailClosed(_ context.Context, request leafmobility.ExecutionRequest) error {
	if attempt == nil || attempt.driver == nil || attempt.driver.owner == nil {
		return errors.New("gvisor: nil packet-link attempt")
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if !attempt.matches(request) || attempt.stage == linkAttemptRolledBack {
		return errors.New("gvisor: packet-link FailClosed does not match active attempt")
	}
	if attempt.stage == linkAttemptFailedClosed {
		return nil
	}
	attempt.driver.owner.failClosed(errors.New("gvisor: packet-link transaction failed closed"))
	if attempt.maintenance != nil {
		attempt.maintenance.release()
	}
	attempt.stage = linkAttemptFailedClosed
	return nil
}

func (attempt *linkAttempt) EndpointGenerationChanged() bool {
	if attempt == nil {
		return false
	}
	attempt.mu.Lock()
	changed := attempt.published
	attempt.mu.Unlock()
	return changed
}

func (attempt *linkAttempt) matches(request leafmobility.ExecutionRequest) bool {
	plan := request.Plan
	preflight := attempt.preflight
	return request.Facts == preflight.Facts && plan.TransactionID == preflight.TransactionID &&
		plan.Binding == preflight.Binding && plan.EndpointGeneration == preflight.Facts.Generation &&
		plan.Direction == preflight.Direction && plan.Session == preflight.Session &&
		plan.Operation == leafmobility.OperationGVisorLinkRebind &&
		request.Agreement.ActorEndpointGeneration == preflight.Facts.Generation &&
		request.Agreement.AgreementDigest != ([32]byte{})
}

func controlForExecution(request leafmobility.ExecutionRequest, nonce linkNonce) (outerControl, error) {
	var control outerControl
	copy(control.Transaction[:], request.Plan.TransactionID[:])
	copy(control.Agreement[:], request.Agreement.AgreementDigest[:])
	control.Nonce = nonce
	if control.Transaction == (linkTransaction{}) || control.Agreement == (linkAgreement{}) ||
		control.Nonce == (linkNonce{}) {
		return outerControl{}, errors.New("gvisor: incomplete packet-link execution agreement")
	}
	return control, nil
}

func digestLinkPublication(
	request leafmobility.ExecutionRequest,
	id linkID,
	generation uint64,
	nonce linkNonce,
	candidate *packetWire,
	observation routeObservation,
) leafmobility.EvidenceDigest {
	hash := sha256.New()
	_, _ = hash.Write([]byte("GLS1"))
	_, _ = hash.Write(request.Plan.TransactionID[:])
	_, _ = hash.Write(request.Agreement.AgreementDigest[:])
	_, _ = hash.Write(id[:])
	_, _ = hash.Write(nonce[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], generation)
	_, _ = hash.Write(scalar[:])
	if candidate != nil && candidate.conn != nil {
		writeLinkString(hash, candidate.conn.LocalAddr().String())
	}
	_, _ = hash.Write(observation.digest[:])
	var digest leafmobility.EvidenceDigest
	copy(digest[:], hash.Sum(nil))
	return digest
}
