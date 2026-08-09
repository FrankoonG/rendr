//go:build linux && amd64

package tcp

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
	"github.com/FrankoonG/rendr/internal/platform"
	"github.com/FrankoonG/rendr/internal/tcpquarantine"
	"github.com/FrankoonG/rendr/internal/tcprepair"
)

const tcpRepairProbeRevision uint32 = 1

type repairKernel interface {
	Inspect(*net.TCPConn) (tcprepair.Inspection, error)
	Capture(*net.TCPConn) (repairSource, error)
	Restore(context.Context, *tcprepair.Snapshot) (*net.TCPConn, error)
	Enter(*net.TCPConn) error
}

type repairSource interface {
	State() tcprepair.SourceState
	Snapshot() *tcprepair.Snapshot
	Resume() error
	Close() error
}

type systemRepairKernel struct{}

func (systemRepairKernel) Inspect(conn *net.TCPConn) (tcprepair.Inspection, error) {
	return tcprepair.Inspect(conn)
}

func (systemRepairKernel) Capture(conn *net.TCPConn) (repairSource, error) {
	return tcprepair.Capture(conn)
}

func (systemRepairKernel) Restore(ctx context.Context, snapshot *tcprepair.Snapshot) (*net.TCPConn, error) {
	return tcprepair.Restore(ctx, snapshot)
}

func (systemRepairKernel) Enter(conn *net.TCPConn) error {
	return tcprepair.Enter(conn)
}

type quarantineLease interface {
	Release(context.Context) error
}

type quarantineManager interface {
	Preflight(context.Context, tcpquarantine.TransactionID, tcpquarantine.Tuple) error
	Install(context.Context, tcpquarantine.TransactionID, tcpquarantine.Tuple) (quarantineLease, error)
}

type repairAttemptExecutor interface {
	Do(context.Context, func(context.Context) error) error
	Close(context.Context) error
}

type repairAttemptExecutorState interface {
	Closed() bool
}

type repairExecutorFactory func(
	context.Context,
	*net.TCPConn,
	leafmobility.ContextDigest,
) (repairAttemptExecutor, error)

type systemQuarantineManager struct {
	manager *tcpquarantine.Manager
}

func (manager systemQuarantineManager) Preflight(
	ctx context.Context,
	transaction tcpquarantine.TransactionID,
	tuple tcpquarantine.Tuple,
) error {
	return manager.manager.Preflight(ctx, transaction, tuple)
}

func (manager systemQuarantineManager) Install(
	ctx context.Context,
	transaction tcpquarantine.TransactionID,
	tuple tcpquarantine.Tuple,
) (quarantineLease, error) {
	return manager.manager.Install(ctx, transaction, tuple)
}

type tcpRepairDriver struct {
	endpoint      *endpointOwner
	kernel        repairKernel
	quarantine    quarantineManager
	quarantineErr error
	newExecutor   repairExecutorFactory
	probeSequence atomic.Uint64
}

func newTCPRepairDriver(endpoint *endpointOwner) *tcpRepairDriver {
	driver := &tcpRepairDriver{
		endpoint: endpoint,
		kernel:   systemRepairKernel{},
		newExecutor: func(ctx context.Context, conn *net.TCPConn, expected leafmobility.ContextDigest) (repairAttemptExecutor, error) {
			return newRepairNamespaceExecutor(ctx, conn, expected)
		},
	}
	manager, err := tcpquarantine.New(tcpquarantine.Config{})
	if err != nil {
		driver.quarantineErr = err
	} else {
		driver.quarantine = systemQuarantineManager{manager: manager}
	}
	return driver
}

func (*tcpRepairDriver) Operation() leafmobility.Operation {
	return leafmobility.OperationTCPRepair
}

func (driver *tcpRepairDriver) Preflight(
	ctx context.Context,
	request leafmobility.PreflightRequest,
) (leafmobility.DriverAttempt, leafmobility.PreflightResult, error) {
	if driver == nil || driver.endpoint == nil || driver.kernel == nil || driver.newExecutor == nil {
		return nil, leafmobility.PreflightResult{}, errors.New("tcp: repair driver has no endpoint backend")
	}
	platformRefs, err := leafmobility.NewProbeReferences(request.PlatformProbe)
	if err != nil {
		return nil, leafmobility.PreflightResult{}, err
	}
	if reason := tcpRepairPlatformReason(ctx, request); reason != leafmobility.ReasonNone {
		if reason == leafmobility.ReasonTransparentBindUnavailable {
			return driver.ineligible(request, leafmobility.StageTuple, reason, false,
				tcpRepairProbe{ID: leafmobility.ProbeTuple, Label: reason.String()})
		}
		return nil, leafmobility.PreflightResult{
			Stage: leafmobility.StagePlatform, Reason: reason, ProbeReferences: platformRefs,
		}, nil
	}

	conn, ownerGeneration, ok := driver.endpoint.current()
	if !ok {
		return driver.ineligible(request, leafmobility.StageEndpoint, leafmobility.ReasonEndpointNotOwned, false,
			tcpRepairProbe{ID: leafmobility.ProbeEndpointState, Label: "endpoint-unavailable"})
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return driver.ineligible(request, leafmobility.StageEndpoint, leafmobility.ReasonNotRawTCP, false,
			tcpRepairProbe{ID: leafmobility.ProbeEndpointState, Label: "not-raw-tcp"})
	}
	if err := repairSourceMatchesCurrentNamespace(tcpConn); err != nil {
		return driver.ineligible(request, leafmobility.StagePreflight, leafmobility.ReasonPreflightRejected, false,
			tcpRepairProbe{ID: leafmobility.ProbeEndpointState, Label: "socket-namespace-mismatch"})
	}
	inspection, inspectErr := driver.kernel.Inspect(tcpConn)
	if inspectErr != nil {
		stage, reason := classifyRepairInspection(inspectErr)
		return driver.ineligible(request, stage, reason, errors.Is(inspectErr, tcprepair.ErrQueueBudget),
			tcpRepairProbe{ID: probeForStage(stage), Label: reason.String()})
	}
	current, currentGeneration, currentOK := driver.endpoint.current()
	if !currentOK || current != conn || currentGeneration != ownerGeneration {
		return driver.ineligible(request, leafmobility.StagePreflight, leafmobility.ReasonPreflightRejected, true,
			tcpRepairProbe{ID: leafmobility.ProbeEndpointState, Label: "owner-generation-changed"})
	}
	endpointProbe := tcpRepairProbe{ID: leafmobility.ProbeEndpointState, Label: "established", Inspection: inspection}
	tupleProbe := tcpRepairProbe{ID: leafmobility.ProbeTuple, Label: "ipv4-same-tuple", Inspection: inspection}
	rollbackProbe := tcpRepairProbe{ID: leafmobility.ProbeRollbackReadiness, Label: "transparent-snapshot-restore-v1", Inspection: inspection}
	if driver.quarantine == nil || driver.quarantineErr != nil {
		return driver.ineligible(request, leafmobility.StageQuarantine, leafmobility.ReasonQuarantineUnavailable, false,
			endpointProbe, tupleProbe,
			tcpRepairProbe{ID: leafmobility.ProbeQuarantineSchema, Label: "nft-unavailable"}, rollbackProbe)
	}
	transaction := tcpquarantine.TransactionID(request.TransactionID)
	tuple := quarantineTuple(inspection.Tuple)
	if err := driver.quarantine.Preflight(ctx, transaction, tuple); err != nil {
		reason := leafmobility.ReasonQuarantineUnverified
		retryable := false
		if errors.Is(err, tcpquarantine.ErrUnsupportedPlatform) ||
			errors.Is(err, tcpquarantine.ErrNFTExecutableUnavailable) {
			reason = leafmobility.ReasonQuarantineUnavailable
			retryable = false
		}
		return driver.ineligible(request, leafmobility.StageQuarantine, reason, retryable,
			endpointProbe, tupleProbe,
			tcpRepairProbe{ID: leafmobility.ProbeQuarantineSchema, Label: reason.String()}, rollbackProbe)
	}
	probes, err := driver.references(request,
		endpointProbe, tupleProbe,
		tcpRepairProbe{ID: leafmobility.ProbeQuarantineSchema, Label: "nft-atomic-v1", Inspection: inspection},
		rollbackProbe,
	)
	if err != nil {
		return nil, leafmobility.PreflightResult{}, err
	}
	evidence := digestRepairAttempt(request, probes)
	attempt := &tcpRepairAttempt{
		driver:          driver,
		preflight:       request,
		inspection:      inspection,
		ownerGeneration: ownerGeneration,
		evidence:        leafmobility.AttemptEvidence{Digest: evidence, ProbeReferences: probes},
		stage:           repairAttemptPreflight,
	}
	return attempt, leafmobility.PreflightResult{
		Eligible: true, Stage: leafmobility.StagePreflightComplete,
		EvidenceDigest: evidence, ProbeReferences: probes,
	}, nil
}

func tcpRepairPlatformReason(ctx context.Context, request leafmobility.PreflightRequest) leafmobility.Reason {
	snapshot, err := platform.Detect(ctx)
	if err != nil || leafmobility.ContextDigest(snapshot.RuntimeContextDigest) != request.ContextDigest {
		return leafmobility.ReasonStateAPIIncomplete
	}
	required := [...]platform.FeatureID{
		platform.FeatureTCPRepairPermission,
		platform.FeatureTCPRepairBase,
		platform.FeatureTCPRepairQueueSeq,
		platform.FeatureTCPRepairWindow,
		platform.FeatureTCPRepairOptions,
	}
	for _, feature := range required {
		evidence, ok := snapshot.Feature(feature)
		if !ok {
			return leafmobility.ReasonStateAPIIncomplete
		}
		switch evidence.State {
		case platform.FeatureAvailable:
			continue
		case platform.FeaturePermissionDenied:
			return leafmobility.ReasonPermissionDenied
		case platform.FeatureUnsupported:
			return leafmobility.ReasonKernelUnsupported
		default:
			return leafmobility.ReasonStateAPIIncomplete
		}
	}
	transparent, ok := snapshot.Feature(platform.FeatureTransparentBindV4)
	if !ok || transparent.State != platform.FeatureAvailable {
		return leafmobility.ReasonTransparentBindUnavailable
	}
	return leafmobility.ReasonNone
}

type tcpRepairProbe struct {
	ID         leafmobility.ProbeID
	Label      string
	Inspection tcprepair.Inspection
}

func (driver *tcpRepairDriver) ineligible(
	request leafmobility.PreflightRequest,
	stage leafmobility.Stage,
	reason leafmobility.Reason,
	retryable bool,
	observations ...tcpRepairProbe,
) (leafmobility.DriverAttempt, leafmobility.PreflightResult, error) {
	probes, err := driver.references(request, observations...)
	if err != nil {
		return nil, leafmobility.PreflightResult{}, err
	}
	return nil, leafmobility.PreflightResult{
		Stage: stage, Reason: reason, Retryable: retryable, ProbeReferences: probes,
	}, nil
}

func (driver *tcpRepairDriver) references(
	request leafmobility.PreflightRequest,
	observations ...tcpRepairProbe,
) (leafmobility.ProbeReferences, error) {
	references := make([]leafmobility.ProbeReference, 0, len(observations)+1)
	references = append(references, request.PlatformProbe)
	observed := time.Now().UnixNano()
	expires := request.PlatformProbe.ExpiresNano
	if lifetime := observed + int64(leafmobility.MaxProbeLifetime); expires > lifetime {
		expires = lifetime
	}
	if expires <= observed {
		return leafmobility.ProbeReferences{}, errors.New("tcp: repair probe evidence already expired")
	}
	for _, observation := range observations {
		if observation.ID < leafmobility.ProbeEndpointState || observation.ID > leafmobility.ProbeRollbackReadiness {
			return leafmobility.ProbeReferences{}, fmt.Errorf("tcp: invalid repair probe id %d", observation.ID)
		}
		generation := driver.probeSequence.Add(1)
		if generation == 0 {
			generation = driver.probeSequence.Add(1)
		}
		references = append(references, leafmobility.ProbeReference{
			ID: observation.ID, Revision: tcpRepairProbeRevision, Generation: generation,
			EndpointGeneration: request.Facts.Generation,
			ObservedNano:       observed, ExpiresNano: expires, ContextDigest: request.ContextDigest,
			Digest: digestRepairProbe(request, observation),
		})
	}
	return leafmobility.NewProbeReferences(references...)
}

func digestRepairProbe(request leafmobility.PreflightRequest, observation tcpRepairProbe) leafmobility.EvidenceDigest {
	hash := sha256.New()
	_, _ = hash.Write([]byte("RTP1"))
	_, _ = hash.Write([]byte{byte(observation.ID)})
	writeRepairString(hash, observation.Label)
	_, _ = hash.Write(request.TransactionID[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], request.Facts.Generation)
	_, _ = hash.Write(scalar[:])
	writeRepairInspection(hash, observation.Inspection)
	var digest leafmobility.EvidenceDigest
	copy(digest[:], hash.Sum(nil))
	return digest
}

func digestRepairAttempt(
	request leafmobility.PreflightRequest,
	probes leafmobility.ProbeReferences,
) leafmobility.EvidenceDigest {
	hash := sha256.New()
	_, _ = hash.Write([]byte("RTA1"))
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

type repairByteWriter interface {
	Write([]byte) (int, error)
}

func writeRepairString(writer repairByteWriter, value string) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write([]byte(value))
}

func writeRepairInspection(writer repairByteWriter, inspection tcprepair.Inspection) {
	for _, endpoint := range []string{inspection.Tuple.Local.String(), inspection.Tuple.Remote.String()} {
		writeRepairString(writer, endpoint)
	}
	var scalar [4]byte
	for _, value := range []uint32{
		inspection.ReceiveQueueBytes, inspection.SendQueueBytes, inspection.UnsentBytes,
	} {
		binary.BigEndian.PutUint32(scalar[:], value)
		_, _ = writer.Write(scalar[:])
	}
	_, _ = writer.Write([]byte{inspection.OptionsMask, inspection.SendScale, inspection.ReceiveScale})
}

func probeForStage(stage leafmobility.Stage) leafmobility.ProbeID {
	switch stage {
	case leafmobility.StageTuple:
		return leafmobility.ProbeTuple
	case leafmobility.StageQuarantine:
		return leafmobility.ProbeQuarantineSchema
	case leafmobility.StageRollback:
		return leafmobility.ProbeRollbackReadiness
	default:
		return leafmobility.ProbeEndpointState
	}
}

func classifyRepairInspection(err error) (leafmobility.Stage, leafmobility.Reason) {
	switch {
	case errors.Is(err, tcprepair.ErrQueueBudget):
		return leafmobility.StageResourceBudget, leafmobility.ReasonResourceBudgetExceeded
	case errors.Is(err, tcprepair.ErrUnsupported):
		return leafmobility.StagePlatform, leafmobility.ReasonStateAPIIncomplete
	case errors.Is(err, tcprepair.ErrUnsupportedOption), errors.Is(err, tcprepair.ErrIneligibleState):
		return leafmobility.StageEndpoint, leafmobility.ReasonTCPStateIneligible
	default:
		return leafmobility.StagePreflight, leafmobility.ReasonPreflightFailed
	}
}

func quarantineTuple(tuple tcprepair.Tuple) tcpquarantine.Tuple {
	return tcpquarantine.Tuple{Local: tuple.Local, Remote: tuple.Remote}
}

type repairAttemptStage uint8

const (
	repairAttemptPreflight repairAttemptStage = iota + 1
	repairAttemptPrepared
	repairAttemptStaged
	repairAttemptPublished
	repairAttemptActivated
	repairAttemptRolledBack
	repairAttemptFailedClosed
)

type tcpRepairAttempt struct {
	mu sync.Mutex

	driver          *tcpRepairDriver
	preflight       leafmobility.PreflightRequest
	inspection      tcprepair.Inspection
	ownerGeneration uint64
	evidence        leafmobility.AttemptEvidence
	stage           repairAttemptStage

	maintenance           *endpointMaintenance
	source                *net.TCPConn
	quarantine            quarantineLease
	snapshot              *tcprepair.Snapshot
	sourceLease           repairSource
	replacement           *net.TCPConn
	replacementPublished  bool
	replacementDiscarding bool
	quarantineUnverified  bool
	restoreCleanupUnknown bool
	endpointChanged       bool
	executor              repairAttemptExecutor
	endpointTerminated    bool
	closeReplacement      func(*net.TCPConn) error
}

func (attempt *tcpRepairAttempt) Evidence() leafmobility.AttemptEvidence {
	if attempt == nil {
		return leafmobility.AttemptEvidence{}
	}
	return attempt.evidence
}

func (attempt *tcpRepairAttempt) Prepare(ctx context.Context, request leafmobility.ExecutionRequest) error {
	if attempt == nil || attempt.driver == nil {
		return errors.New("tcp: nil repair attempt")
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.stage != repairAttemptPreflight || !attempt.matches(request) {
		return errors.New("tcp: repair Prepare request does not match preflight")
	}
	maintenance, err := attempt.driver.endpoint.beginMaintenance(ctx)
	if err != nil {
		return err
	}
	attempt.maintenance = maintenance
	if maintenance.generation != attempt.ownerGeneration {
		return errEndpointStaleLease
	}
	source, ok := maintenance.Conn().(*net.TCPConn)
	if !ok {
		return fmt.Errorf("tcp: repair source is %T", maintenance.Conn())
	}
	attempt.source = source
	executor, err := attempt.driver.newExecutor(ctx, source, attempt.preflight.ContextDigest)
	if err != nil {
		return err
	}
	attempt.executor = executor
	var inspection tcprepair.Inspection
	err = attempt.executor.Do(ctx, func(context.Context) error {
		var inspectErr error
		inspection, inspectErr = attempt.driver.kernel.Inspect(source)
		return inspectErr
	})
	if err != nil {
		return err
	}
	if inspection.Tuple != attempt.inspection.Tuple || inspection.OptionsMask != attempt.inspection.OptionsMask ||
		inspection.SendScale != attempt.inspection.SendScale || inspection.ReceiveScale != attempt.inspection.ReceiveScale {
		return errors.New("tcp: repair endpoint changed after preflight")
	}
	var lease quarantineLease
	err = attempt.executor.Do(ctx, func(operationCtx context.Context) error {
		var installErr error
		lease, installErr = attempt.driver.quarantine.Install(
			operationCtx,
			tcpquarantine.TransactionID(attempt.preflight.TransactionID),
			quarantineTuple(inspection.Tuple),
		)
		return installErr
	})
	if lease != nil {
		attempt.quarantine = lease
		attempt.quarantineUnverified = err != nil
	}
	if err != nil {
		return err
	}
	attempt.stage = repairAttemptPrepared
	return nil
}

func (attempt *tcpRepairAttempt) Stage(
	ctx context.Context,
	request leafmobility.ExecutionRequest,
) (leafmobility.PublicationEvidence, error) {
	if attempt == nil || attempt.driver == nil {
		return leafmobility.PublicationEvidence{}, errors.New("tcp: nil repair attempt")
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.stage != repairAttemptPrepared || !attempt.matches(request) || attempt.source == nil || attempt.quarantine == nil {
		return leafmobility.PublicationEvidence{}, errors.New("tcp: repair Stage is not prepared")
	}
	var sourceLease repairSource
	err := attempt.executor.Do(ctx, func(context.Context) error {
		var captureErr error
		sourceLease, captureErr = attempt.driver.kernel.Capture(attempt.source)
		return captureErr
	})
	attempt.sourceLease = sourceLease
	if sourceLease != nil {
		attempt.snapshot = sourceLease.Snapshot()
	}
	if err != nil {
		return leafmobility.PublicationEvidence{}, err
	}
	if attempt.sourceLease == nil || attempt.sourceLease.State() != tcprepair.SourceStateRepair || attempt.snapshot == nil {
		return leafmobility.PublicationEvidence{}, errors.New("tcp: repair capture returned contradictory source state")
	}
	if attempt.snapshot.Tuple() != attempt.inspection.Tuple {
		return leafmobility.PublicationEvidence{}, errors.New("tcp: repair snapshot tuple changed")
	}
	err = attempt.executor.Do(ctx, func(operationCtx context.Context) error {
		if closeErr := attempt.sourceLease.Close(); closeErr != nil {
			return fmt.Errorf("tcp: close captured source: %w", closeErr)
		}
		if attempt.sourceLease.State() != tcprepair.SourceStateClosed {
			return errors.New("tcp: captured source close was not proven")
		}
		replacement, restoreErr := attempt.driver.kernel.Restore(operationCtx, attempt.snapshot)
		if restoreErr != nil {
			attempt.restoreCleanupUnknown = errors.Is(restoreErr, tcprepair.ErrRestoreCleanupUnknown)
			return restoreErr
		}
		attempt.replacement = replacement
		return nil
	})
	if err != nil {
		return leafmobility.PublicationEvidence{}, err
	}
	attempt.stage = repairAttemptStaged
	return leafmobility.PublicationEvidence{Digest: leafmobility.EvidenceDigest(attempt.snapshot.Digest())}, nil
}

func (attempt *tcpRepairAttempt) Publish(ctx context.Context, request leafmobility.ExecutionRequest) error {
	if attempt == nil || attempt.driver == nil {
		return errors.New("tcp: nil repair attempt")
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.stage != repairAttemptStaged || !attempt.matches(request) || attempt.maintenance == nil ||
		attempt.replacement == nil || attempt.replacementPublished {
		return errors.New("tcp: repair Publish is not staged")
	}
	if err := attempt.maintenance.ReplaceContext(ctx, attempt.replacement); err != nil {
		return err
	}
	attempt.replacementPublished = true
	attempt.endpointChanged = true
	attempt.stage = repairAttemptPublished
	return nil
}

func (attempt *tcpRepairAttempt) Activate(ctx context.Context, request leafmobility.ExecutionRequest) error {
	if attempt == nil || attempt.driver == nil {
		return errors.New("tcp: nil repair attempt")
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.stage == repairAttemptActivated {
		return nil
	}
	if attempt.stage != repairAttemptPublished || !attempt.matches(request) || !attempt.replacementPublished {
		return errors.New("tcp: repair Activate is not published")
	}
	if err := attempt.resumeEndpoint(); err != nil {
		return err
	}
	if attempt.quarantine != nil {
		if attempt.executor == nil {
			return errors.New("tcp: repair Activate lost quarantine namespace ownership")
		}
		if err := attempt.executor.Do(ctx, attempt.releaseQuarantine); err != nil {
			return err
		}
	}
	if err := attempt.closeExecutor(ctx); err != nil {
		return err
	}
	attempt.stage = repairAttemptActivated
	return nil
}

func (attempt *tcpRepairAttempt) Rollback(ctx context.Context, request leafmobility.ExecutionRequest) error {
	if attempt == nil || attempt.driver == nil {
		return errors.New("tcp: nil repair attempt")
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if !attempt.matches(request) || attempt.stage == repairAttemptPublished || attempt.stage == repairAttemptActivated {
		return errors.New("tcp: repair Rollback request does not match active attempt")
	}
	if attempt.stage == repairAttemptRolledBack {
		return nil
	}
	if attempt.endpointTerminated {
		return errors.New("tcp: repair Rollback cannot restore a fail-closed endpoint")
	}
	if attempt.maintenance == nil {
		if attempt.quarantine != nil {
			if attempt.executor == nil {
				return errors.New("tcp: repair Rollback lost quarantine namespace ownership")
			}
			if err := attempt.executor.Do(ctx, attempt.releaseQuarantine); err != nil {
				return err
			}
		}
		if err := attempt.closeExecutor(ctx); err != nil {
			return err
		}
		attempt.stage = repairAttemptRolledBack
		return nil
	}
	needsNamespace := attempt.replacement != nil || attempt.replacementPublished || attempt.sourceLease != nil || attempt.quarantine != nil
	if needsNamespace {
		if attempt.executor == nil {
			return errors.New("tcp: repair Rollback lost its namespace executor")
		}
		if err := attempt.executor.Do(ctx, func(operationCtx context.Context) error {
			if attempt.replacementPublished {
				return nil
			}
			if attempt.replacementDiscarding {
				if discardErr := attempt.discardReplacement(); discardErr != nil {
					return discardErr
				}
				attempt.replacementDiscarding = false
			}
			if attempt.replacement != nil {
				if replaceErr := attempt.maintenance.Replace(attempt.replacement); replaceErr != nil {
					return replaceErr
				}
				attempt.replacementPublished = true
				attempt.endpointChanged = true
			} else if attempt.sourceLease != nil && attempt.sourceLease.State() == tcprepair.SourceStateClosed {
				if attempt.restoreCleanupUnknown {
					return tcprepair.ErrRestoreCleanupUnknown
				}
				if attempt.snapshot == nil {
					return errors.New("tcp: closed repair source has no rollback snapshot")
				}
				replacement, restoreErr := attempt.driver.kernel.Restore(operationCtx, attempt.snapshot)
				if restoreErr != nil {
					return restoreErr
				}
				attempt.replacement = replacement
				if replaceErr := attempt.maintenance.Replace(replacement); replaceErr != nil {
					discardErr := attempt.discardReplacement()
					attempt.replacementDiscarding = discardErr != nil && attempt.replacement != nil
					return errors.Join(replaceErr, discardErr)
				}
				attempt.replacementPublished = true
				attempt.endpointChanged = true
			} else if attempt.sourceLease != nil {
				if resumeErr := attempt.sourceLease.Resume(); resumeErr != nil {
					return resumeErr
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if err := attempt.resumeEndpoint(); err != nil {
		return err
	}
	if attempt.quarantine != nil {
		if attempt.executor == nil {
			return errors.New("tcp: repair Rollback lost quarantine namespace ownership")
		}
		if err := attempt.executor.Do(ctx, attempt.releaseQuarantine); err != nil {
			return err
		}
	}
	if err := attempt.closeExecutor(ctx); err != nil {
		return err
	}
	attempt.stage = repairAttemptRolledBack
	return nil
}

func (attempt *tcpRepairAttempt) FailClosed(ctx context.Context, request leafmobility.ExecutionRequest) error {
	if attempt == nil || attempt.driver == nil {
		return errors.New("tcp: nil repair attempt")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if !attempt.matches(request) || attempt.stage == repairAttemptRolledBack {
		return errors.New("tcp: repair fail-closed request does not match active attempt")
	}
	if attempt.stage == repairAttemptFailedClosed {
		return nil
	}
	if attempt.maintenance == nil && !attempt.endpointTerminated {
		maintenance, err := attempt.driver.endpoint.beginMaintenance(ctx)
		if err != nil {
			return err
		}
		attempt.maintenance = maintenance
	}

	if !attempt.endpointTerminated {
		if err := attempt.ensureFailClosedQuarantine(ctx); err != nil {
			return err
		}
		terminate := func(context.Context) error {
			var closeErr error
			var terminalConn net.Conn
			if attempt.replacement != nil {
				// Enter is best effort: the still-active quarantine is the RST
				// containment boundary. Close is the resource-ownership proof.
				_ = attempt.driver.kernel.Enter(attempt.replacement)
				if attempt.replacementPublished {
					terminalConn = attempt.replacement
				}
				closeErr = attempt.closeReplacementHandle()
				if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
					return fmt.Errorf("tcp: fail-closed replacement close: %w", closeErr)
				}
			}
			if !attempt.replacementPublished && attempt.sourceLease != nil {
				terminalConn = attempt.source
				closeErr = attempt.sourceLease.Close()
				if closeErr != nil && attempt.sourceLease.State() == tcprepair.SourceStateClosed {
					closeErr = nil
				}
			} else if !attempt.replacementPublished && attempt.source != nil {
				terminalConn = attempt.source
				_ = attempt.driver.kernel.Enter(attempt.source)
				closeErr = attempt.source.Close()
			}
			if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				return fmt.Errorf("tcp: fail-closed endpoint close: %w", closeErr)
			}
			if attempt.maintenance != nil {
				if err := attempt.maintenance.FailClosed(); err != nil {
					return err
				}
				attempt.maintenance = nil
			} else if terminalConn != nil {
				if err := attempt.driver.endpoint.failClosedCurrent(terminalConn); err != nil {
					return err
				}
			}
			attempt.endpointTerminated = true
			return nil
		}
		if attempt.executor != nil {
			if err := attempt.executor.Do(ctx, terminate); err != nil {
				return err
			}
		} else if err := terminate(ctx); err != nil {
			return err
		}
	}

	if attempt.quarantine != nil {
		if attempt.restoreCleanupUnknown {
			return tcprepair.ErrRestoreCleanupUnknown
		}
		if attempt.executor == nil {
			return errors.New("tcp: fail-closed lost quarantine namespace ownership")
		}
		if err := attempt.executor.Do(ctx, attempt.releaseQuarantine); err != nil {
			return err
		}
	}
	if err := attempt.closeExecutor(ctx); err != nil {
		return err
	}
	attempt.stage = repairAttemptFailedClosed
	return nil
}

func (attempt *tcpRepairAttempt) EndpointGenerationChanged() bool {
	if attempt == nil {
		return false
	}
	attempt.mu.Lock()
	changed := attempt.endpointChanged
	attempt.mu.Unlock()
	return changed
}

func (attempt *tcpRepairAttempt) matches(request leafmobility.ExecutionRequest) bool {
	plan := request.Plan
	preflight := attempt.preflight
	return request.Facts == preflight.Facts && plan.TransactionID == preflight.TransactionID &&
		plan.Binding == preflight.Binding && plan.EndpointGeneration == preflight.Facts.Generation &&
		plan.Direction == preflight.Direction && plan.Session == preflight.Session &&
		plan.Operation == leafmobility.OperationTCPRepair &&
		request.Agreement.ActorEndpointGeneration == preflight.Facts.Generation
}

func (attempt *tcpRepairAttempt) releaseQuarantine(ctx context.Context) error {
	if attempt.quarantine == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := attempt.quarantine.Release(ctx); err != nil {
		return err
	}
	attempt.quarantine = nil
	attempt.quarantineUnverified = false
	return nil
}

func (attempt *tcpRepairAttempt) ensureFailClosedQuarantine(ctx context.Context) error {
	if attempt.quarantine != nil && !attempt.quarantineUnverified {
		return nil
	}
	if attempt.quarantine != nil {
		if attempt.executor == nil {
			return errors.New("tcp: fail-closed lost unverified quarantine namespace ownership")
		}
		if err := attempt.executor.Do(ctx, attempt.releaseQuarantine); err != nil {
			return err
		}
	}
	if attempt.maintenance == nil || attempt.driver.quarantine == nil || attempt.driver.newExecutor == nil {
		return errors.New("tcp: fail-closed cannot establish RST quarantine")
	}
	conn, ok := attempt.maintenance.Conn().(*net.TCPConn)
	if !ok || conn == nil {
		return errors.New("tcp: fail-closed endpoint is not raw TCP")
	}
	if attempt.executor == nil {
		executor, err := attempt.driver.newExecutor(ctx, conn, attempt.preflight.ContextDigest)
		if err != nil {
			return err
		}
		attempt.executor = executor
	}
	return attempt.executor.Do(ctx, func(operationCtx context.Context) error {
		lease, installErr := attempt.driver.quarantine.Install(
			operationCtx,
			tcpquarantine.TransactionID(attempt.preflight.TransactionID),
			quarantineTuple(attempt.inspection.Tuple),
		)
		if lease != nil {
			attempt.quarantine = lease
			attempt.quarantineUnverified = installErr != nil
		}
		if installErr == nil {
			if lease == nil {
				return errors.New("tcp: fail-closed quarantine install returned no lease")
			}
			return nil
		}
		if lease == nil {
			return installErr
		}
		cleanupErr := attempt.releaseQuarantine(operationCtx)
		return errors.Join(installErr, cleanupErr)
	})
}

func (attempt *tcpRepairAttempt) resumeEndpoint() error {
	if attempt.maintenance == nil {
		return nil
	}
	if err := attempt.maintenance.Resume(); err != nil {
		return err
	}
	attempt.maintenance = nil
	return nil
}

func (attempt *tcpRepairAttempt) discardReplacement() error {
	if attempt.replacement == nil {
		return nil
	}
	conn := attempt.replacement
	return errors.Join(attempt.driver.kernel.Enter(conn), attempt.closeReplacementHandle())
}

func (attempt *tcpRepairAttempt) closeReplacementHandle() error {
	if attempt == nil || attempt.replacement == nil {
		return nil
	}
	conn := attempt.replacement
	closeFn := attempt.closeReplacement
	if closeFn == nil {
		closeFn = (*net.TCPConn).Close
	}
	err := closeFn(conn)
	if err == nil || errors.Is(err, net.ErrClosed) {
		attempt.replacement = nil
		return nil
	}
	return err
}

func (attempt *tcpRepairAttempt) closeExecutor(ctx context.Context) error {
	if attempt.executor == nil {
		return nil
	}
	err := attempt.executor.Close(ctx)
	state, stateKnown := attempt.executor.(repairAttemptExecutorState)
	if err == nil || (stateKnown && state.Closed()) {
		attempt.executor = nil
	}
	return err
}
