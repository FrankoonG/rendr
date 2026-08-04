//go:build !linux && !windows

package report

import (
	"fmt"
	"os"
	"runtime"
)

func tryLockReportSetFile(*os.File) (bool, error) {
	return false, fmt.Errorf("report-set locking is unsupported on %s", runtime.GOOS)
}

func unlockReportSetFile(*os.File) error {
	return nil
}
