package platform

import "context"

var systemDetector = func() *detector {
	detector, err := newSystemDetector()
	if err != nil {
		panic(err)
	}
	return detector
}()

// newSystemDetector builds the factual platform detector used by a Runtime.
// Callers cannot inject results through the public rendr API.
func newSystemDetector() (*detector, error) {
	return newDetector(systemProber{})
}

// Detect returns the process-shared, execution-context-keyed active snapshot.
func Detect(ctx context.Context) (KernelFeatures, error) {
	return systemDetector.Current(ctx)
}

// Invalidate discards cached evidence after a contradictory real syscall.
func Invalidate(feature FeatureID) error {
	return systemDetector.Invalidate(feature)
}

// InvalidationGeneration changes only when contradictory runtime evidence
// revokes every published snapshot.
func InvalidationGeneration() uint64 {
	return systemDetector.invalidationVersion()
}

// CurrentRuntimeContextDigest excludes the per-thread cache shard while still
// binding namespace, credentials, capabilities, seccomp metadata and LSM
// label. It does not execute feature probes.
func CurrentRuntimeContextDigest() ([32]byte, error) {
	unlock := lockExecutionThread()
	defer unlock()
	lease, err := acquireExecutionContext()
	if err != nil {
		return [32]byte{}, err
	}
	digest := digestRuntimeExecutionContext(lease.Identity)
	if err := lease.Close(); err != nil {
		return [32]byte{}, err
	}
	return digest, nil
}
