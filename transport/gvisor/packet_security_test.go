package gvisor

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

func TestPacketCarrierRequiresExplicitTrustConfiguration(t *testing.T) {
	if listener, err := ListenPacket("127.0.0.1:0"); !errors.Is(err, ErrPacketTrustRequired) || listener != nil {
		t.Fatalf("unconfigured ListenPacket=(%v,%v) want trust error", listener, err)
	}
	if _, err := NewPacket(); !errors.Is(err, ErrPacketTrustRequired) {
		t.Fatalf("unconfigured NewPacket error=%v", err)
	}
	if _, err := NewPacket(WithPSK(bytes.Repeat([]byte{1}, 31))); err == nil {
		t.Fatal("short packet PSK was accepted")
	}
	_, err := New().DialPath(context.Background(), transport.PathSpec{Address: "127.0.0.1:1"})
	if !errors.Is(err, ErrPacketTrustRequired) {
		t.Fatalf("unconfigured DialPath error=%v", err)
	}
}

func TestPacketCarrierPSKAuthenticatesAdmissionAndData(t *testing.T) {
	requireOuterPacketSupport(t)
	key := bytes.Repeat([]byte{0x51}, 32)
	listener, err := ListenPacket("127.0.0.1:0", WithPSK(key))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	assertRoundTrip(t, client, server, []byte("psk-authenticated packet carrier"))

	listener.packetMu.RLock()
	linksBefore := len(listener.packetLinks)
	listener.packetMu.RUnlock()
	wrong, err := NewPacket(WithPSK(bytes.Repeat([]byte{0x52}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if path, err := wrong.DialPath(ctx, transport.PathSpec{Address: listener.Addr().String()}); err == nil || path != nil {
		if path != nil {
			_ = path.Close()
		}
		t.Fatalf("wrong PSK DialPath=(%v,%v)", path, err)
	}
	listener.packetMu.RLock()
	linksAfter := len(listener.packetLinks)
	listener.packetMu.RUnlock()
	if linksAfter != linksBefore {
		t.Fatalf("wrong PSK allocated packet owner: before=%d after=%d", linksBefore, linksAfter)
	}
}

func TestPacketAdmissionCookieIsStatelessBeforeReturnProof(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	remote := listener.Addr()
	id, public, nonce := rawAdmissionIdentity(t)
	cookie := requestRawAdmissionCookie(t, client, remote, id, public, nonce)
	listener.packetMu.RLock()
	links, pending := len(listener.packetLinks), len(listener.packetPending)
	listener.packetMu.RUnlock()
	if links != 0 || pending != 0 {
		t.Fatalf("stateless cookie request allocated links=%d pending=%d", links, pending)
	}
	completeRawAdmission(t, client, remote, id, public, nonce, cookie)
	listener.packetMu.RLock()
	links, pending = len(listener.packetLinks), len(listener.packetPending)
	listener.packetMu.RUnlock()
	if links != 1 || pending != 1 {
		t.Fatalf("proved admission state links=%d pending=%d", links, pending)
	}
}

func TestPacketAdmissionPendingOwnersAreBounded(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	remote := listener.Addr()
	for range maxPendingPacketLinks {
		id, public, nonce := rawAdmissionIdentity(t)
		cookie := requestRawAdmissionCookie(t, client, remote, id, public, nonce)
		completeRawAdmission(t, client, remote, id, public, nonce, cookie)
	}
	listener.packetMu.RLock()
	links, pending := len(listener.packetLinks), len(listener.packetPending)
	listener.packetMu.RUnlock()
	if links != maxPendingPacketLinks || pending != maxPendingPacketLinks {
		t.Fatalf("pending admission bound links=%d pending=%d want=%d", links, pending, maxPendingPacketLinks)
	}

	id, public, nonce := rawAdmissionIdentity(t)
	cookie := requestRawAdmissionCookie(t, client, remote, id, public, nonce)
	request := rawOpenDatagram(t, id, public, nonce, cookie)
	if _, err := client.WriteTo(request, remote); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, outerHeaderSize+outerOpenAckPayloadSize+outerAuthTagSize+1)
	if _, _, err := client.ReadFrom(buffer); err == nil {
		t.Fatal("admission beyond pending-owner cap received OPEN_ACK")
	}
	listener.packetMu.RLock()
	links, pending = len(listener.packetLinks), len(listener.packetPending)
	listener.packetMu.RUnlock()
	if links != maxPendingPacketLinks || pending != maxPendingPacketLinks {
		t.Fatalf("overflow changed admission state links=%d pending=%d", links, pending)
	}
}

func rawAdmissionIdentity(t testing.TB) (linkID, linkPublicKey, linkNonce) {
	t.Helper()
	id, err := newLinkID()
	if err != nil {
		t.Fatal(err)
	}
	_, public, err := newLinkKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := newLinkNonce()
	if err != nil {
		t.Fatal(err)
	}
	return id, public, nonce
}

func requestRawAdmissionCookie(
	t testing.TB,
	client net.PacketConn,
	remote net.Addr,
	id linkID,
	public linkPublicKey,
	nonce linkNonce,
) outerCookie {
	t.Helper()
	request := rawOpenDatagram(t, id, public, nonce, outerCookie{})
	if _, err := client.WriteTo(request, remote); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, outerHeaderSize+outerCookiePayloadSize+1)
	n, source, err := client.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !addrEqual(source, remote) {
		t.Fatalf("cookie source=%v want=%v", source, remote)
	}
	frame, err := decodeOuter(buffer[:n], linkSecret{})
	if err != nil || frame.Type != outerTypeCookie || frame.LinkID != id {
		t.Fatalf("cookie frame=%+v err=%v", frame, err)
	}
	cookie, err := parseOuterCookie(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return cookie
}

func completeRawAdmission(
	t testing.TB,
	client net.PacketConn,
	remote net.Addr,
	id linkID,
	public linkPublicKey,
	nonce linkNonce,
	cookie outerCookie,
) {
	t.Helper()
	request := rawOpenDatagram(t, id, public, nonce, cookie)
	if _, err := client.WriteTo(request, remote); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, outerHeaderSize+outerOpenAckPayloadSize+outerAuthTagSize+1)
	n, source, err := client.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := decodeOuterHeader(buffer[:n])
	if err != nil || frame.Type != outerTypeOpenAck || frame.LinkID != id || !addrEqual(source, remote) {
		t.Fatalf("OPEN_ACK frame=%+v source=%v err=%v", frame, source, err)
	}
}

func rawOpenDatagram(
	t testing.TB,
	id linkID,
	public linkPublicKey,
	nonce linkNonce,
	cookie outerCookie,
) []byte {
	t.Helper()
	datagram, err := encodeOuter(outerFrame{
		Type: outerTypeOpen, LinkID: id, Generation: 1,
		Payload: marshalOpen(public, nonce, cookie, outerProof{}),
	}, linkSecret{})
	if err != nil {
		t.Fatal(err)
	}
	return datagram
}
