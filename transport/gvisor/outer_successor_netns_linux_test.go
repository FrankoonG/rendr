//go:build linux

package gvisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testLinuxOuterSuccessorSocketUsesActiveSocketNetworkNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("network namespace successor test requires root")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("network namespace successor test requires iproute2")
	}

	tests := []struct {
		name      string
		localAddr func(testing.TB, string) net.IP
	}{
		{
			name: "source-address-only-in-active-namespace",
			localAddr: func(t testing.TB, ipCommand string) net.IP {
				t.Helper()
				address := net.IPv4(198, 18, byte(32+os.Getpid()%160), byte(32+time.Now().UnixNano()%160))
				runGVisorNetNSCommand(t, ipCommand, "address", "add", address.String()+"/32", "dev", "lo")
				t.Cleanup(func() {
					_ = exec.Command(ipCommand, "address", "del", address.String()+"/32", "dev", "lo").Run()
				})
				return address
			},
		},
		{
			name:      "same-address-available-but-namespace-identity-differs",
			localAddr: func(testing.TB, string) net.IP { return net.IPv4(127, 0, 0, 1) },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			namespace, namespaceIdentity := newGVisorTestNetworkNamespace(t, ip)
			localIP := test.localAddr(t, ip)

			receiver, err := listenOuterUDPWire(
				outerUDPIPv4, &net.UDPAddr{IP: append(net.IP(nil), localIP...)}, false,
			)
			if err != nil {
				t.Fatalf("open receiver in active namespace: %v", err)
			}
			defer receiver.close()
			active, err := listenOuterUDPWire(
				outerUDPIPv4, &net.UDPAddr{IP: append(net.IP(nil), localIP...)}, false,
			)
			if err != nil {
				t.Fatalf("open active socket: %v", err)
			}
			defer active.close()

			activeIdentity := active.socket.identity
			if !activeIdentity.valid() || sameOuterNetNSIdentity(activeIdentity, namespaceIdentity) {
				t.Fatalf("test namespaces are not distinct active=%+v caller=%+v", activeIdentity, namespaceIdentity)
			}
			owner := &linkOwner{
				active: active, peerRemote: cloneAddr(receiver.conn.LocalAddr()),
				observeRoute: observeUDPRouteForWire,
			}
			originFD, originIdentity, err := openCurrentOuterNetworkNamespace()
			if err != nil {
				t.Fatal(err)
			}
			_ = unix.Close(originFD)

			var candidate *packetWire
			var observation routeObservation
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = runGVisorTestInNetworkNamespace(namespace, namespaceIdentity, func() error {
				var openErr error
				candidate, observation, openErr = owner.openUDPCandidate(ctx, owner.peerRemote)
				return openErr
			})
			if err != nil {
				t.Fatalf("open successor from foreign caller namespace: %v", err)
			}
			if candidate == nil || candidate.conn == nil {
				t.Fatal("successor creation returned no socket")
			}
			candidateIdentity := candidate.socket.identity
			if !sameOuterNetNSIdentity(candidateIdentity, activeIdentity) ||
				!sameOuterNetNSIdentity(observation.networkNamespace, activeIdentity) {
				candidate.close()
				t.Fatalf(
					"successor escaped active namespace active=%+v candidate=%+v route=%+v caller=%+v",
					activeIdentity, candidateIdentity, observation.networkNamespace, namespaceIdentity,
				)
			}
			if sameOuterNetNSIdentity(candidateIdentity, namespaceIdentity) {
				candidate.close()
				t.Fatal("successor inherited the invoking thread network namespace")
			}
			candidateConn := candidate.conn
			candidate.close()
			if candidate.socket.netnsFD != -1 || candidate.socket.identity.valid() {
				t.Fatalf("successor close retained network namespace context: %+v", candidate.socket)
			}
			if _, err := candidateConn.WriteTo([]byte{1}, receiver.conn.LocalAddr()); err == nil {
				t.Fatal("successor close retained a writable UDP descriptor")
			}

			currentFD, currentIdentity, err := openCurrentOuterNetworkNamespace()
			if err != nil {
				t.Fatal(err)
			}
			_ = unix.Close(currentFD)
			if !sameOuterNetNSIdentity(currentIdentity, originIdentity) {
				t.Fatalf("test caller did not return to its original namespace before=%+v after=%+v", originIdentity, currentIdentity)
			}
		})
	}
}

func newGVisorTestNetworkNamespace(t testing.TB, ipCommand string) (*os.File, outerNetNSIdentity) {
	t.Helper()
	name := fmt.Sprintf("rendr-gvisor-%d-%d", os.Getpid(), time.Now().UnixNano())
	command := exec.Command(ipCommand, "netns", "add", name)
	if output, err := command.CombinedOutput(); err != nil {
		message := strings.TrimSpace(string(output))
		if errors.Is(err, os.ErrPermission) || strings.Contains(strings.ToLower(message), "operation not permitted") {
			t.Skipf("network namespace creation is unavailable: %v (%s)", err, message)
		}
		t.Fatalf("create network namespace: %v (%s)", err, message)
	}
	t.Cleanup(func() { _ = exec.Command(ipCommand, "netns", "delete", name).Run() })
	runGVisorNetNSCommand(t, ipCommand, "-n", name, "link", "set", "lo", "up")

	file, err := os.Open(filepath.Join("/run/netns", name))
	if err != nil {
		t.Fatalf("open network namespace: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatalf("stat network namespace: %v", err)
	}
	return file, outerNetNSIdentity{device: uint64(stat.Dev), inode: stat.Ino}
}

func runGVisorTestInNetworkNamespace(
	namespace *os.File,
	want outerNetNSIdentity,
	operation func() error,
) error {
	if namespace == nil || operation == nil || !want.valid() {
		return errors.New("gvisor test: invalid network namespace operation")
	}
	var originFD = -1
	var origin outerNetNSIdentity
	return runOuterNamespaceWorker(
		func() (bool, error) {
			var err error
			originFD, origin, err = openCurrentOuterNetworkNamespace()
			if err != nil {
				return false, err
			}
			if err := unix.Setns(int(namespace.Fd()), unix.CLONE_NEWNET); err != nil {
				return false, err
			}
			currentFD, current, err := openCurrentOuterNetworkNamespace()
			if currentFD >= 0 {
				_ = unix.Close(currentFD)
			}
			if err != nil {
				return true, err
			}
			if !sameOuterNetNSIdentity(current, want) {
				return true, fmt.Errorf("entered namespace=%+v want %+v", current, want)
			}
			return true, nil
		},
		func() error {
			beforeFD, before, err := openCurrentOuterNetworkNamespace()
			if beforeFD >= 0 {
				_ = unix.Close(beforeFD)
			}
			if err != nil || !sameOuterNetNSIdentity(before, want) {
				return errors.Join(errors.New("gvisor test: operation started in wrong namespace"), err)
			}
			operationErr := operation()
			afterFD, after, afterErr := openCurrentOuterNetworkNamespace()
			if afterFD >= 0 {
				_ = unix.Close(afterFD)
			}
			if afterErr != nil || !sameOuterNetNSIdentity(after, want) {
				return errors.Join(operationErr, errors.New("gvisor test: operation changed its caller namespace"), afterErr)
			}
			return operationErr
		},
		func() error {
			if originFD < 0 {
				return nil
			}
			defer unix.Close(originFD)
			if err := unix.Setns(originFD, unix.CLONE_NEWNET); err != nil {
				return err
			}
			currentFD, current, err := openCurrentOuterNetworkNamespace()
			if currentFD >= 0 {
				_ = unix.Close(currentFD)
			}
			if err != nil {
				return err
			}
			if !sameOuterNetNSIdentity(current, origin) {
				return fmt.Errorf("restored namespace=%+v want %+v", current, origin)
			}
			return nil
		},
		outerNamespaceThreadHooks{
			lock: runtime.LockOSThread, unlock: runtime.UnlockOSThread, abandon: runtime.Goexit,
		},
	)
}

func sameOuterNetNSIdentity(left, right outerNetNSIdentity) bool {
	return left.valid() && right.valid() && left.device == right.device && left.inode == right.inode
}

func runGVisorNetNSCommand(t testing.TB, name string, arguments ...string) {
	t.Helper()
	if output, err := exec.Command(name, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v (%s)", name, strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
}
