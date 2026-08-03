//go:build linux

package tun

import (
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestOpenCreatesEphemeralDeviceWhenAvailable(t *testing.T) {
	if cap := Probe(); !cap.Available {
		t.Skipf("TUN unavailable: %v", cap.Err)
	}
	dev, err := Open(Config{Enabled: true, Name: "rendrt%d", MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if dev.Name() == "" {
		t.Fatal("kernel did not assign a TUN name")
	}
	if dev.MTU() != 1400 {
		t.Fatalf("MTU=%d want 1400", dev.MTU())
	}
}

func TestDeviceReadsKernelRoutedIPv4Packet(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to configure temporary TUN address")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skipf("ip command unavailable: %v", err)
	}
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skipf("ping command unavailable: %v", err)
	}
	if cap := Probe(); !cap.Available {
		t.Skipf("TUN unavailable: %v", cap.Err)
	}
	dev, err := Open(Config{Enabled: true, Name: "rendrt%d", MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	runIP(t, "addr", "add", "10.250.0.1/30", "dev", dev.Name())
	runIP(t, "link", "set", "dev", dev.Name(), "up")

	cmd := exec.Command("ping", "-c", "1", "-W", "1", "-I", dev.Name(), "10.250.0.2")
	_ = cmd.Start()
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()

	wantSrc := netip.MustParseAddr("10.250.0.1")
	wantDst := netip.MustParseAddr("10.250.0.2")
	result := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				result <- err
				return
			}
			if n < 20 || buf[0]>>4 != 4 || buf[9] != 1 {
				continue
			}
			src := netip.AddrFrom4([4]byte{buf[12], buf[13], buf[14], buf[15]})
			dst := netip.AddrFrom4([4]byte{buf[16], buf[17], buf[18], buf[19]})
			if src == wantSrc && dst == wantDst {
				result <- nil
				return
			}
		}
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Device.Read TUN packet: %v", err)
		}
	case <-time.After(2 * time.Second):
		_ = dev.Close()
		t.Fatalf("timed out waiting for routed IPv4 packet on %s", dev.Name())
	}
}

func runIP(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v: %v (%s)", args, err, out)
	}
}
