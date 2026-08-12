package l3session

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/l3ingress"
)

func TestTCPEnvelopeRoundTrip(t *testing.T) {
	want := tcpRelayIdentity()
	wire, err := encodeTCPEnvelope(want, "vpn-egress")
	if err != nil {
		t.Fatal(err)
	}
	got, err := readTCPEnvelope(bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	if got.Identity != want || got.Egress != "vpn-egress" {
		t.Fatalf("envelope = %+v, want %s/vpn-egress", got, want)
	}
}

func TestTCPEnvelopeRejectsMalformedAndOversizedMetadata(t *testing.T) {
	valid, err := encodeTCPEnvelope(tcpRelayIdentity(), "direct")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func([]byte) []byte{
		"magic":     func(b []byte) []byte { b[0] ^= 0xff; return b },
		"version":   func(b []byte) []byte { b[4]++; return b },
		"flags":     func(b []byte) []byte { b[5] = 1; return b },
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
		"oversized egress": func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[6:8], tcpEnvelopeMaxEgressName+1)
			return b
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			wire := mutate(append([]byte(nil), valid...))
			if _, err := readTCPEnvelope(bytes.NewReader(wire)); err == nil {
				t.Fatal("accepted malformed TCP envelope")
			}
		})
	}
	udpID := tcpRelayIdentity()
	udpID.Proto = l3ingress.ProtocolUDP
	if _, err := encodeTCPEnvelope(udpID, "direct"); err == nil {
		t.Fatal("accepted UDP identity")
	}
	if _, err := encodeTCPEnvelope(tcpRelayIdentity(), strings.Repeat("x", tcpEnvelopeMaxEgressName+1)); err == nil {
		t.Fatal("accepted oversized egress name")
	}
}

func TestTCPReadinessRoundTripAndRejectsMalformedFrames(t *testing.T) {
	for status := tcpReadyOK; status <= tcpReadyInternalFailure; status++ {
		wire, err := encodeTCPReady(status)
		if err != nil {
			t.Fatalf("encode status %d: %v", status, err)
		}
		got, err := readTCPReady(bytes.NewReader(wire))
		if err != nil || got != status {
			t.Fatalf("read status=%d err=%v, want %d", got, err, status)
		}
	}
	valid, err := encodeTCPReady(tcpReadyOK)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func([]byte) []byte{
		"magic":     func(b []byte) []byte { b[0] ^= 0xff; return b },
		"version":   func(b []byte) []byte { b[4]++; return b },
		"status":    func(b []byte) []byte { b[5] = 0xff; return b },
		"reserved":  func(b []byte) []byte { b[7] = 1; return b },
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := readTCPReady(bytes.NewReader(mutate(append([]byte(nil), valid...)))); err == nil {
				t.Fatal("accepted malformed TCP readiness frame")
			}
		})
	}
	if _, err := encodeTCPReady(tcpReadyInvalid); err == nil {
		t.Fatal("encoded invalid TCP readiness status")
	}
}
