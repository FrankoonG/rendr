//go:build linux

package tcprepair

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

type fakeNetfilterRunner struct {
	calls       []netfilterCall
	failOnCall  int
	failMessage string
}

type netfilterCall struct {
	name string
	args []string
}

func (f *fakeNetfilterRunner) Run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, netfilterCall{name: name, args: append([]string(nil), args...)})
	if f.failOnCall > 0 && len(f.calls) == f.failOnCall {
		if f.failMessage == "" {
			f.failMessage = "boom"
		}
		return []byte(f.failMessage), errors.New("forced failure")
	}
	return nil, nil
}

func TestInstallTCPDropBuildsSymmetricRules(t *testing.T) {
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}
	runner := &fakeNetfilterRunner{}
	cleanup, err := (iptablesRuleManager{runner: runner}).InstallTCPDrop(local, remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}

	want := []netfilterCall{
		{name: "iptables", args: []string{"-I", "INPUT", "-w", "5", "-p", "tcp", "-s", "127.0.0.1", "--sport", "2000", "-d", "127.0.0.1", "--dport", "1000", "-j", "DROP"}},
		{name: "iptables", args: []string{"-I", "OUTPUT", "-w", "5", "-p", "tcp", "-s", "127.0.0.1", "--sport", "1000", "-d", "127.0.0.1", "--dport", "2000", "-j", "DROP"}},
		{name: "iptables", args: []string{"-D", "OUTPUT", "-w", "5", "-p", "tcp", "-s", "127.0.0.1", "--sport", "1000", "-d", "127.0.0.1", "--dport", "2000", "-j", "DROP"}},
		{name: "iptables", args: []string{"-D", "INPUT", "-w", "5", "-p", "tcp", "-s", "127.0.0.1", "--sport", "2000", "-d", "127.0.0.1", "--dport", "1000", "-j", "DROP"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("iptables calls mismatch:\ngot  %#v\nwant %#v", runner.calls, want)
	}
}

func TestInstallTCPDropRollsBackOnFailure(t *testing.T) {
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}
	runner := &fakeNetfilterRunner{failOnCall: 2, failMessage: "second rule failed"}
	_, err := (iptablesRuleManager{runner: runner}).InstallTCPDrop(local, remote)
	if err == nil {
		t.Fatal("expected install failure")
	}
	if !strings.Contains(err.Error(), "second rule failed") {
		t.Fatalf("error did not include command output: %v", err)
	}
	want := []netfilterCall{
		{name: "iptables", args: []string{"-I", "INPUT", "-w", "5", "-p", "tcp", "-s", "127.0.0.1", "--sport", "2000", "-d", "127.0.0.1", "--dport", "1000", "-j", "DROP"}},
		{name: "iptables", args: []string{"-I", "OUTPUT", "-w", "5", "-p", "tcp", "-s", "127.0.0.1", "--sport", "1000", "-d", "127.0.0.1", "--dport", "2000", "-j", "DROP"}},
		{name: "iptables", args: []string{"-D", "INPUT", "-w", "5", "-p", "tcp", "-s", "127.0.0.1", "--sport", "2000", "-d", "127.0.0.1", "--dport", "1000", "-j", "DROP"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("iptables rollback calls mismatch:\ngot  %#v\nwant %#v", runner.calls, want)
	}
}

func TestTCPDropCleanupReportsFailureAndCanRetry(t *testing.T) {
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}
	runner := &fakeNetfilterRunner{failOnCall: 3, failMessage: "delete failed"}
	cleanup, err := (iptablesRuleManager{runner: runner}).InstallTCPDrop(local, remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err == nil || !strings.Contains(err.Error(), "delete failed") {
		t.Fatalf("cleanup error=%v, want delete failure", err)
	}
	runner.failOnCall = 0
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup retry: %v", err)
	}
	if got := len(runner.calls); got != 5 {
		t.Fatalf("iptables calls=%d, want 5 (two insert, two first cleanup, one retry)", got)
	}
}

func TestInstallTCPDropRejectsNilAddr(t *testing.T) {
	_, err := (iptablesRuleManager{}).InstallTCPDrop(nil, &net.TCPAddr{})
	if err == nil {
		t.Fatal("expected nil addr error")
	}
}
