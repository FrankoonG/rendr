//go:build !linux

package tunfull

import (
	"context"
	"runtime"

	"github.com/FrankoonG/rendr/virtualif"
)

func executeKernelTUNProbePlatform(ctx context.Context, mode string) kernelTUNProbeResult {
	_, bounded := ctx.Deadline()
	return kernelTUNProbeResult{
		Schema:    kernelTUNProbeSchema,
		Mode:      mode,
		Completed: true,
		Bounded:   bounded,
		Available: false,
		Reason:    string(virtualif.ReasonTUNUnavailable),
		Stage:     "platform",
		Detail:    "real kernel TUN probing requires Linux; running on " + runtime.GOOS,
	}
}

func runKernelTUNProbeHelper(mode, nonce string) kernelTUNProbeResult {
	return kernelTUNProbeResult{
		Schema:    kernelTUNProbeSchema,
		Mode:      mode,
		Nonce:     nonce,
		Completed: true,
		Available: false,
		Reason:    string(virtualif.ReasonTUNUnavailable),
		Stage:     "platform",
		Detail:    "real kernel TUN probing requires Linux; running on " + runtime.GOOS,
	}
}
