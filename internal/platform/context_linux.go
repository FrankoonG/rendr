//go:build linux

package platform

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func lockExecutionThread() func() {
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}

type executionContextLease struct {
	Identity ExecutionContext
	handles  []*os.File
}

func (lease *executionContextLease) Close() error {
	if lease == nil {
		return nil
	}
	var errs []error
	for index := len(lease.handles) - 1; index >= 0; index-- {
		if err := lease.handles[index].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	lease.handles = nil
	return errors.Join(errs...)
}

func acquireExecutionContext() (*executionContextLease, error) {
	lease := &executionContextLease{}
	fail := func(err error) (*executionContextLease, error) {
		return nil, errors.Join(err, lease.Close())
	}
	namespaces := make(map[string]string, 3)
	for _, name := range []string{"user", "net", "mnt"} {
		handle, err := os.Open("/proc/thread-self/ns/" + name)
		if err != nil {
			return fail(fmt.Errorf("open %s namespace: %w", name, err))
		}
		lease.handles = append(lease.handles, handle)
		var stat unix.Stat_t
		if err := unix.Fstat(int(handle.Fd()), &stat); err != nil {
			return fail(fmt.Errorf("stat %s namespace: %w", name, err))
		}
		namespaces[name] = fmt.Sprintf("%d:%d", uint64(stat.Dev), stat.Ino)
	}

	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fail(fmt.Errorf("read boot id: %w", err))
	}
	credentials, err := executionCredentials("/proc/thread-self/status")
	if err != nil {
		return fail(err)
	}
	securityLabel, err := currentSecurityLabel("/proc/thread-self/attr/current")
	if err != nil {
		return fail(err)
	}
	threadID := "process"
	threadStart := "process"
	if credentials.seccomp != "0" {
		threadID = strconv.Itoa(unix.Gettid())
		threadStart, err = currentThreadStartTime("/proc/thread-self/stat")
		if err != nil {
			return fail(err)
		}
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return fail(fmt.Errorf("uname: %w", err))
	}
	lease.Identity = ExecutionContext{
		OS:                    runtime.GOOS,
		Arch:                  runtime.GOARCH,
		BootID:                strings.TrimSpace(string(bootID)),
		Kernel:                KernelIdentity{System: utsString(uts.Sysname[:]), Release: utsString(uts.Release[:]), Version: utsString(uts.Version[:]), Machine: utsString(uts.Machine[:])},
		UserNamespace:         namespaces["user"],
		NetworkNamespace:      namespaces["net"],
		MountNamespace:        namespaces["mnt"],
		EffectiveCapabilities: credentials.capEff,
		EffectiveUID:          credentials.euid,
		FilesystemUID:         credentials.fsuid,
		EffectiveGID:          credentials.egid,
		FilesystemGID:         credentials.fsgid,
		Groups:                credentials.groups,
		NoNewPrivileges:       credentials.noNewPrivileges,
		SeccompMode:           credentials.seccomp,
		SeccompFilters:        credentials.seccompFilters,
		ThreadID:              threadID,
		ThreadStartTime:       threadStart,
		SecurityLabel:         securityLabel,
		ProbeRevision:         ProbeRevision,
	}
	return lease, nil
}

func currentSecurityLabel(path string) (string, error) {
	value, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "unreported", nil
	}
	if err != nil {
		return "", fmt.Errorf("read security label: %w", err)
	}
	label := strings.TrimSpace(string(value))
	if label == "" {
		return "unreported", nil
	}
	return label, nil
}

func currentThreadStartTime(path string) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read thread start time: %w", err)
	}
	line := string(value)
	endName := strings.LastIndexByte(line, ')')
	if endName < 0 || endName+2 >= len(line) {
		return "", fmt.Errorf("read thread start time: malformed stat")
	}
	fields := strings.Fields(line[endName+2:])
	// The suffix starts at field 3 (state); starttime is field 22.
	if len(fields) <= 19 {
		return "", fmt.Errorf("read thread start time: field 22 missing")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", fmt.Errorf("read thread start time: %w", err)
	}
	return fields[19], nil
}

type credentialFingerprint struct {
	capEff          string
	euid            string
	fsuid           string
	egid            string
	fsgid           string
	groups          string
	noNewPrivileges string
	seccomp         string
	seccompFilters  string
}

func executionCredentials(path string) (credentialFingerprint, error) {
	f, err := os.Open(path)
	if err != nil {
		return credentialFingerprint{}, fmt.Errorf("read execution credentials: %w", err)
	}
	defer f.Close()
	var fingerprint credentialFingerprint
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "CapEff":
			fingerprint.capEff = strings.ToLower(value)
		case "Uid":
			fields := strings.Fields(value)
			if len(fields) == 4 {
				fingerprint.euid, fingerprint.fsuid = fields[1], fields[3]
			}
		case "Gid":
			fields := strings.Fields(value)
			if len(fields) == 4 {
				fingerprint.egid, fingerprint.fsgid = fields[1], fields[3]
			}
		case "Groups":
			fingerprint.groups = strings.Join(strings.Fields(value), ",")
			if fingerprint.groups == "" {
				fingerprint.groups = "none"
			}
		case "NoNewPrivs":
			fingerprint.noNewPrivileges = value
		case "Seccomp":
			fingerprint.seccomp = value
		case "Seccomp_filters":
			fingerprint.seccompFilters = value
		}
	}
	if err := scanner.Err(); err != nil {
		return credentialFingerprint{}, fmt.Errorf("scan execution credentials: %w", err)
	}
	if fingerprint.capEff == "" || fingerprint.euid == "" || fingerprint.fsuid == "" ||
		fingerprint.egid == "" || fingerprint.fsgid == "" || fingerprint.groups == "" ||
		fingerprint.noNewPrivileges == "" || fingerprint.seccomp == "" {
		return credentialFingerprint{}, fmt.Errorf("read execution credentials: required status field missing")
	}
	if fingerprint.seccompFilters == "" {
		fingerprint.seccompFilters = "unreported"
	}
	return fingerprint, nil
}

func utsString(value []byte) string {
	if index := strings.IndexByte(string(value), 0); index >= 0 {
		value = value[:index]
	}
	return string(value)
}
