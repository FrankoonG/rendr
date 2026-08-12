//go:build !linux

package gvisor

import (
	"context"
	"errors"
	"testing"

	"github.com/FrankoonG/rendr/transport"
)

func TestNonLinuxOuterPacketUnsupportedIsSeparateFromProcessLocal(t *testing.T) {
	if err := Available(); err != nil {
		t.Fatalf("process-local availability=%v", err)
	}
	if err := PacketAvailable(); !errors.Is(err, ErrOuterPacketUnsupported) {
		t.Fatalf("packet availability=%v want ErrOuterPacketUnsupported", err)
	}
	if packet, err := NewPacket(WithTrustedCarrier()); packet != nil || !errors.Is(err, ErrOuterPacketUnsupported) {
		t.Fatalf("NewPacket=(%v,%v) want typed unsupported", packet, err)
	}
	if listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier()); listener != nil || !errors.Is(err, ErrOuterPacketUnsupported) {
		t.Fatalf("ListenPacket=(%v,%v) want typed unsupported", listener, err)
	}
	if path, err := New(WithTrustedCarrier()).DialPath(
		context.Background(), transport.PathSpec{Address: "127.0.0.1:9"},
	); path != nil || !errors.Is(err, ErrOuterPacketUnsupported) {
		t.Fatalf("packet DialPath=(%v,%v) want typed unsupported", path, err)
	}

	domain := NewDomain()
	listener, err := domain.Listen("non-linux-process-local")
	if err != nil {
		t.Fatalf("process-local Listen: %v", err)
	}
	defer listener.Close()
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	assertRoundTrip(t, client, server, []byte("process-local remains available"))
}
