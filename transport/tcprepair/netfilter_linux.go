//go:build linux

package tcprepair

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"sync"
)

const xtablesLockWaitSeconds = "5"

type netfilterRunner interface {
	Run(name string, args ...string) ([]byte, error)
}

type execNetfilterRunner struct{}

func (execNetfilterRunner) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

type tcpDropRuleManager interface {
	InstallTCPDrop(local, remote *net.TCPAddr) (func() error, error)
}

type iptablesRuleManager struct {
	runner netfilterRunner
}

var tcpDropRules tcpDropRuleManager = iptablesRuleManager{runner: execNetfilterRunner{}}

func installDropRules(local, remote *net.TCPAddr) (func() error, error) {
	return tcpDropRules.InstallTCPDrop(local, remote)
}

func (m iptablesRuleManager) InstallTCPDrop(local, remote *net.TCPAddr) (func() error, error) {
	if local == nil || remote == nil {
		return nil, errors.New("tcprepair: nil local/remote addr")
	}
	runner := m.runner
	if runner == nil {
		runner = execNetfilterRunner{}
	}
	rules := iptablesTCPDropRules(local, remote)
	active := make([]bool, len(rules))
	var cleanupMu sync.Mutex
	cleanup := func() error {
		cleanupMu.Lock()
		defer cleanupMu.Unlock()
		var cleanupErr error
		for i := len(rules) - 1; i >= 0; i-- {
			if !active[i] {
				continue
			}
			deleteRule := rules[i].deleteArgs()
			out, err := runner.Run("iptables", deleteRule...)
			if err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("tcprepair: remove iptables rule %d failed: %v (%s)", i, err, out))
				continue
			}
			active[i] = false
		}
		return cleanupErr
	}
	for i, rule := range rules {
		if out, err := runner.Run("iptables", rule.insertArgs...); err != nil {
			installErr := fmt.Errorf("tcprepair: iptables rule %d failed: %v (%s)", i, err, out)
			return nil, errors.Join(installErr, cleanup())
		}
		active[i] = true
	}
	return cleanup, nil
}

type iptablesRule struct {
	insertArgs []string
}

func (r iptablesRule) deleteArgs() []string {
	args := append([]string(nil), r.insertArgs...)
	args[0] = "-D"
	return args
}

func iptablesTCPDropRules(local, remote *net.TCPAddr) []iptablesRule {
	localIP := local.IP.String()
	remoteIP := remote.IP.String()
	localPort := strconv.Itoa(local.Port)
	remotePort := strconv.Itoa(remote.Port)
	return []iptablesRule{
		{insertArgs: []string{"-I", "INPUT", "-w", xtablesLockWaitSeconds, "-p", "tcp", "-s", remoteIP, "--sport", remotePort, "-d", localIP, "--dport", localPort, "-j", "DROP"}},
		{insertArgs: []string{"-I", "OUTPUT", "-w", xtablesLockWaitSeconds, "-p", "tcp", "-s", localIP, "--sport", localPort, "-d", remoteIP, "--dport", remotePort, "-j", "DROP"}},
	}
}
