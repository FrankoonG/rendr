package report

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const reportSetLockRetryInterval = 10 * time.Millisecond

type reportSetLock struct {
	file *os.File
}

func acquireReportSetLock(ctx context.Context, dir string) (*reportSetLock, error) {
	if err := checkReportContext(ctx); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create report directory for lock: %w", err)
	}
	path := filepath.Join(dir, ReportSetLockName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open report-set lock: %w", err)
	}
	if err := waitForReportSetFileLock(ctx, file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire report-set lock: %w", err)
	}
	return &reportSetLock{file: file}, nil
}

func waitForReportSetFileLock(ctx context.Context, file *os.File) error {
	for {
		locked, err := tryLockReportSetFile(file)
		if err != nil {
			return err
		}
		if locked {
			return nil
		}

		timer := time.NewTimer(reportSetLockRetryInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func checkReportContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("report: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (l *reportSetLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unlockReportSetFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		unlockErr = fmt.Errorf("release report-set lock: %w", unlockErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close report-set lock: %w", closeErr)
	}
	return errors.Join(unlockErr, closeErr)
}
