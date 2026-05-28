//go:build linux

package tun

import "testing"

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
