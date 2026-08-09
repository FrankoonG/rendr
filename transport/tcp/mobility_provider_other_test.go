//go:build !linux || !amd64

package tcp

import (
	"net"
	"testing"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

func TestTCPImplementationProviderIsAbsentOnUnsupportedBuilds(t *testing.T) {
	for name, value := range map[string]any{
		"transport": New(),
		"listener":  &Listener{},
	} {
		if _, ok := value.(leafmobility.ImplementationProvider); ok {
			t.Fatalf("%s unexpectedly provides specialized mobility", name)
		}
	}

	local, peer := net.Pipe()
	path := Wrap(local)
	t.Cleanup(func() {
		_ = path.Close()
		_ = peer.Close()
	})
	if _, ok := any(path).(leafmobility.ImplementationProvider); ok {
		t.Fatal("generic tcp.Wrap PathConn became an implementation provider")
	}
}
