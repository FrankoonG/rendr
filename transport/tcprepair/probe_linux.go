//go:build linux

package tcprepair

import (
	"context"
	"fmt"
	"syscall"
	"time"

	"github.com/FrankoonG/rendr/internal/platform"
)

// Available actively probes whether this process can use the TCP_REPAIR
// primitives required by the owned-leaf planner. It does not select a
// mobility implementation or imply that a live kernel TCP connection can be
// converted to another backend.
func Available() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snapshot, err := platform.Detect(ctx)
	if err != nil {
		return fmt.Errorf("tcprepair: active platform probe: %w", err)
	}
	for _, id := range []platform.FeatureID{
		platform.FeatureTCPRepairPermission,
		platform.FeatureTCPRepairBase,
		platform.FeatureTCPRepairQueueSeq,
		platform.FeatureTCPRepairWindow,
		platform.FeatureTCPRepairOptions,
	} {
		evidence, ok := snapshot.Feature(id)
		if !ok {
			return fmt.Errorf("tcprepair: active platform probe omitted %s", id)
		}
		if evidence.State == platform.FeatureAvailable {
			continue
		}
		if evidence.State == platform.FeaturePermissionDenied {
			errno := evidence.RawErrno()
			if errno == 0 {
				errno = syscall.EPERM
			}
			return fmt.Errorf("tcprepair: CAP_NET_ADMIN required for %s: %w", id, errno)
		}
		if errno := evidence.RawErrno(); errno != 0 {
			return fmt.Errorf("tcprepair: %s is %s (%s): %w", id, evidence.State, evidence.Reason, errno)
		}
		return fmt.Errorf("tcprepair: %s is %s (%s)", id, evidence.State, evidence.Reason)
	}
	return nil
}
