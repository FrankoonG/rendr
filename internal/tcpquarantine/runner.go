package tcpquarantine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const maxCommandOutput = 4 << 20

// RunResult keeps stdout separate from diagnostics so JSON verification never
// parses stderr text.
type RunResult struct {
	Stdout []byte
	Stderr []byte
}

// Runner executes nft with the supplied argument vector and stdin batch. The
// executable is deliberately fixed by the production implementation.
type Runner interface {
	Run(ctx context.Context, args []string, stdin []byte) (RunResult, error)
}

var trustedNFTExecutables = [...]string{
	"/usr/sbin/nft",
	"/sbin/nft",
	"/usr/bin/nft",
	"/bin/nft",
}

type execRunner struct {
	path string
}

func newExecRunner() (execRunner, error) {
	for _, path := range trustedNFTExecutables {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return execRunner{path: path}, nil
	}
	return execRunner{}, ErrNFTExecutableUnavailable
}

func (runner execRunner) Run(ctx context.Context, args []string, stdin []byte) (RunResult, error) {
	if runner.path == "" {
		return RunResult{}, ErrNFTExecutableUnavailable
	}
	command := exec.CommandContext(ctx, runner.path, args...)
	command.Stdin = bytes.NewReader(stdin)
	stdout := newBoundedBuffer(maxCommandOutput)
	stderr := newBoundedBuffer(maxCommandOutput)
	command.Stdout = stdout
	command.Stderr = stderr

	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		err = errors.Join(err, ErrCommandOutputTooLarge)
	}
	return RunResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, err
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{limit: limit}
}

func (buffer *boundedBuffer) Write(payload []byte) (int, error) {
	originalLength := len(payload)
	remaining := buffer.limit - buffer.Len()
	if remaining < len(payload) {
		buffer.exceeded = true
		if remaining < 0 {
			remaining = 0
		}
		payload = payload[:remaining]
	}
	_, _ = buffer.Buffer.Write(payload)
	return originalLength, nil
}

func normalizeRunError(operation string, result RunResult, err error) error {
	if len(result.Stdout) > maxCommandOutput || len(result.Stderr) > maxCommandOutput {
		err = errors.Join(err, ErrCommandOutputTooLarge)
	}
	if err == nil {
		return nil
	}
	diagnosticBytes := result.Stderr
	if len(diagnosticBytes) > 512 {
		diagnosticBytes = diagnosticBytes[:512]
	}
	diagnostic := strings.TrimSpace(string(diagnosticBytes))
	if diagnostic == "" {
		return fmt.Errorf("tcpquarantine: %s: %w", operation, err)
	}
	return fmt.Errorf("tcpquarantine: %s: %w: %s", operation, err, diagnostic)
}
