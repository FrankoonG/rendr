//go:build linux

package gotestjson

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	processCleanupPollInterval = 10 * time.Millisecond
	invocationMarkerEnv        = "RENDR_GOTESTJSON_INVOCATION"
	prSetChildSubreaper        = 36
)

var (
	subreaperOnce sync.Once
	subreaperErr  error
)

type linuxProcessContainment struct {
	cmd     *exec.Cmd
	token   string
	cgroup  *cgroupV2Containment
	knownMu sync.Mutex
	known   map[int]string
}

func configureProcessContainment(cmd *exec.Cmd) (processContainment, error) {
	return configureLinuxProcessContainment(cmd, true)
}

func configureLinuxProcessContainment(cmd *exec.Cmd, allowCgroup bool) (processContainment, error) {
	if cmd == nil {
		return nil, errors.New("configure process containment: nil command")
	}
	token, err := newInvocationToken()
	if err != nil {
		return nil, err
	}
	cmd.Env = environmentWithInvocationMarker(cmd.Env, token)
	configureCommandProcessGroup(cmd)

	var cgroup *cgroupV2Containment
	if allowCgroup {
		var cgroupErr error
		cgroup, cgroupErr = tryCgroupV2Containment(cmd)
		if cgroupErr != nil {
			return nil, cgroupErr
		}
	}
	if cgroup == nil {
		if err := enableSubreaper(); err != nil {
			return nil, fmt.Errorf("configure descendant subreaper fallback: %w", err)
		}
	}

	containment := &linuxProcessContainment{
		cmd:    cmd,
		token:  token,
		cgroup: cgroup,
		known:  make(map[int]string),
	}
	cmd.Cancel = containment.cancel
	return containment, nil
}

func newInvocationToken() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("create process containment marker: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func environmentWithInvocationMarker(environment []string, token string) []string {
	if environment == nil {
		environment = os.Environ()
	}
	prefix := invocationMarkerEnv + "="
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+token)
}

func configureCommandProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	if !cmd.SysProcAttr.Setsid {
		cmd.SysProcAttr.Setpgid = true
		cmd.SysProcAttr.Pgid = 0
	}
}

func enableSubreaper() error {
	subreaperOnce.Do(func() {
		_, _, errno := syscall.Syscall6(
			syscall.SYS_PRCTL,
			prSetChildSubreaper,
			1,
			0,
			0,
			0,
			0,
		)
		if errno != 0 {
			subreaperErr = errno
		}
	})
	return subreaperErr
}

func (p *linuxProcessContainment) cancel() error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return os.ErrProcessDone
	}
	var errs []error
	pids, inspectErr := p.liveDescendants()
	p.rememberProcesses(pids)
	if inspectErr != nil {
		errs = append(errs, inspectErr)
	}
	if p.cgroup != nil {
		if err := p.cgroup.killAll(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := killProcessGroup(p.cmd.Process.Pid); err != nil {
		errs = append(errs, err)
	}
	pids, err := invocationProcessIDs(p.token)
	if err != nil {
		errs = append(errs, err)
	} else {
		p.rememberProcesses(pids)
	}
	if err := killKnownProcesses(p.knownProcesses()); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (p *linuxProcessContainment) cleanup(waitDelay time.Duration, reportLeak bool) processCleanupResult {
	method := ProcessContainmentSubreaper
	if p != nil && p.cgroup != nil {
		method = ProcessContainmentCgroupV2
	}
	result := processCleanupResult{evidence: ProcessCleanupEvidence{Method: method}}
	if p == nil || p.cmd == nil || p.cmd.Process == nil || p.cmd.Process.Pid <= 0 {
		result.err = errors.New("process containment has no started command")
		return result
	}
	if waitDelay <= 0 {
		result.err = fmt.Errorf("invalid process cleanup delay %s", waitDelay)
		return result
	}

	known := p.knownProcesses()
	initial, initialErr := p.liveDescendants()
	rememberProcessIdentities(known, initial)
	if reportLeak && len(initial) != 0 {
		result.evidence.LeakDetected = true
		result.evidence.DescendantCount = len(initial)
	}

	deadline := time.Now().Add(waitDelay)
	var cleanupErrs []error
	seenCleanupErrs := make(map[string]struct{})
	recordCleanupErr := func(err error) {
		if err == nil {
			return
		}
		key := err.Error()
		if _, exists := seenCleanupErrs[key]; exists {
			return
		}
		seenCleanupErrs[key] = struct{}{}
		cleanupErrs = append(cleanupErrs, err)
	}
	recordCleanupErr(initialErr)
	for {
		if err := p.killAll(); err != nil {
			recordCleanupErr(err)
		}
		if err := killKnownProcesses(known); err != nil {
			recordCleanupErr(err)
		}
		reapKnownChildren(known)

		live, inspectErr := p.liveDescendants()
		rememberProcessIdentities(known, live)
		knownLive, knownErr := knownProcessesAlive(known)
		if knownErr != nil {
			inspectErr = errors.Join(inspectErr, knownErr)
		}
		if len(knownLive) != 0 {
			live = append(live, knownLive...)
		}
		if inspectErr != nil {
			recordCleanupErr(inspectErr)
		}
		if reportLeak && len(live) != 0 {
			result.evidence.LeakDetected = true
			if len(known) > result.evidence.DescendantCount {
				result.evidence.DescendantCount = len(known)
			}
		}
		if len(live) == 0 && inspectErr == nil {
			if p.cgroup != nil {
				if err := p.cgroup.closeAndRemove(); err != nil {
					recordCleanupErr(err)
				} else {
					p.cgroup = nil
				}
			}
			if p.cgroup == nil {
				result.evidence.TerminationConfirmed = true
				result.err = errors.Join(cleanupErrs...)
				return result
			}
		}
		if !time.Now().Before(deadline) {
			recordCleanupErr(fmt.Errorf(
				"containment %s retained descendants after %s",
				method,
				waitDelay,
			))
			result.err = errors.Join(cleanupErrs...)
			return result
		}
		time.Sleep(processCleanupPollInterval)
	}
}

func (p *linuxProcessContainment) rememberProcesses(pids []int) {
	p.knownMu.Lock()
	defer p.knownMu.Unlock()
	rememberProcessIdentities(p.known, pids)
}

func (p *linuxProcessContainment) knownProcesses() map[int]string {
	p.knownMu.Lock()
	defer p.knownMu.Unlock()
	result := make(map[int]string, len(p.known))
	for pid, identity := range p.known {
		result[pid] = identity
	}
	return result
}

func (p *linuxProcessContainment) liveDescendants() ([]int, error) {
	unique := make(map[int]struct{})
	var errs []error
	if p.cgroup != nil {
		pids, err := p.cgroup.processIDs()
		if err != nil {
			errs = append(errs, err)
		}
		for _, pid := range pids {
			unique[pid] = struct{}{}
		}
	}
	pids, err := invocationProcessIDs(p.token)
	if err != nil {
		errs = append(errs, err)
	}
	for _, pid := range pids {
		unique[pid] = struct{}{}
	}
	if alive, err := processGroupAlive(p.cmd.Process.Pid); err != nil {
		errs = append(errs, err)
	} else if alive && len(unique) == 0 {
		// A process that cleared its marker is still visible through the group.
		unique[-p.cmd.Process.Pid] = struct{}{}
	}
	result := make([]int, 0, len(unique))
	for pid := range unique {
		result = append(result, pid)
	}
	return result, errors.Join(errs...)
}

func (p *linuxProcessContainment) killAll() error {
	var errs []error
	if p.cgroup != nil {
		if err := p.cgroup.killAll(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := killProcessGroup(p.cmd.Process.Pid); err != nil {
		errs = append(errs, err)
	}
	pids, err := invocationProcessIDs(p.token)
	if err != nil {
		errs = append(errs, err)
	} else if err := killProcessIDs(pids); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func processGroupAlive(processGroupID int) (bool, error) {
	if processGroupID <= 0 {
		return false, fmt.Errorf("invalid process group ID %d", processGroupID)
	}
	err := syscall.Kill(-processGroupID, 0)
	switch {
	case err == nil, errors.Is(err, syscall.EPERM):
		return true, nil
	case errors.Is(err, syscall.ESRCH):
		return false, nil
	default:
		return false, fmt.Errorf("inspect process group %d: %w", processGroupID, err)
	}
}

func killProcessGroup(processGroupID int) error {
	if processGroupID <= 0 {
		return fmt.Errorf("invalid process group ID %d", processGroupID)
	}
	if err := syscall.Kill(-processGroupID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("terminate process group %d: %w", processGroupID, err)
	}
	return nil
}

func invocationProcessIDs(token string) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("scan proc for invocation descendants: %w", err)
	}
	want := invocationMarkerEnv + "=" + token
	self := os.Getpid()
	var result []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == self {
			continue
		}
		environment, err := os.ReadFile("/proc/" + entry.Name() + "/environ")
		if err != nil {
			// Other users' processes and processes racing exit are irrelevant.
			continue
		}
		for _, variable := range strings.Split(string(environment), "\x00") {
			if variable == want {
				result = append(result, pid)
				break
			}
		}
	}
	return result, nil
}

func killProcessIDs(pids []int) error {
	var errs []error
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			errs = append(errs, fmt.Errorf("terminate invocation descendant %d: %w", pid, err))
		}
	}
	return errors.Join(errs...)
}

func rememberProcessIdentities(known map[int]string, pids []int) {
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		if _, exists := known[pid]; exists {
			continue
		}
		identity, err := processStartTime(pid)
		if err == nil {
			known[pid] = identity
		}
	}
}

func processStartTime(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	endCommand := strings.LastIndexByte(string(data), ')')
	if endCommand < 0 {
		return "", fmt.Errorf("parse process %d stat command", pid)
	}
	fields := strings.Fields(string(data[endCommand+1:]))
	if len(fields) <= 19 {
		return "", fmt.Errorf("parse process %d stat start time", pid)
	}
	return fields[19], nil
}

func knownProcessesAlive(known map[int]string) ([]int, error) {
	var alive []int
	var errs []error
	for pid, identity := range known {
		current, err := processStartTime(pid)
		switch {
		case err == nil && current == identity:
			alive = append(alive, pid)
		case err == nil:
			delete(known, pid)
		case errors.Is(err, os.ErrNotExist):
			delete(known, pid)
		default:
			errs = append(errs, fmt.Errorf("verify invocation descendant %d: %w", pid, err))
		}
	}
	return alive, errors.Join(errs...)
}

func killKnownProcesses(known map[int]string) error {
	alive, err := knownProcessesAlive(known)
	if err != nil {
		return err
	}
	return killProcessIDs(alive)
}

func reapKnownChildren(known map[int]string) {
	for pid := range known {
		var status syscall.WaitStatus
		waited, _ := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
		if waited == pid {
			delete(known, pid)
		}
	}
}
