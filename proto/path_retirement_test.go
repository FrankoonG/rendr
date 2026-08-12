package proto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func testPathRetirementPayload() PathRetirementPayload {
	var p PathRetirementPayload
	for i := range p.SessionEpoch {
		p.SessionEpoch[i] = byte(i)
	}
	for i := range p.SenderGraphDigest {
		p.SenderGraphDigest[i] = byte(0x20 + i)
		p.ReceiverGraphDigest[i] = byte(0x50 + i)
	}
	for i := range p.SenderTargetID {
		p.SenderTargetID[i] = byte(0x40 + i)
		p.ReceiverTargetID[i] = byte(0x70 + i)
	}
	p.Direction = SenderDirectionClientToServer
	p.Reason = PathRetirementReasonAdministrative
	p.SenderGraphRevision = 0x0102030405060708
	p.ReceiverGraphRevision = 0x1112131415161718
	p.RouteGeneration = 0x2122232425262728
	return p
}

func TestPathRetirementRoundTripAndWireStability(t *testing.T) {
	want := testPathRetirementPayload()
	wire, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	wantWire, err := hex.DecodeString(
		"5250525401010200" +
			"000102030405060708090a0b0c0d0e0f" +
			"0102030405060708" +
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
			"404142434445464748494a4b4c4d4e4f" +
			"1112131415161718" +
			"505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f" +
			"707172737475767778797a7b7c7d7e7f" +
			"2122232425262728",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, wantWire) {
		t.Fatalf("path retirement wire drift:\n got=%x\nwant=%x", wire, wantWire)
	}
	got, err := DecodePathRetirement(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("path retirement=%+v want=%+v", got, want)
	}
}

func TestPathRetirementRejectsMalformedAndIncompleteBindings(t *testing.T) {
	valid := testPathRetirementPayload()
	wire, err := valid.Encode()
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "short", mutate: func([]byte) {}},
		{name: "magic", mutate: func(w []byte) { w[0] ^= 0xff }},
		{name: "version", mutate: func(w []byte) { w[4]++ }},
		{name: "direction", mutate: func(w []byte) { w[5] = 0xff }},
		{name: "reason", mutate: func(w []byte) { w[6] = 0xff }},
		{name: "reserved", mutate: func(w []byte) { w[7] = 1 }},
		{name: "session", mutate: func(w []byte) { clear(w[8:24]) }},
		{name: "sender revision", mutate: func(w []byte) { clear(w[24:32]) }},
		{name: "sender digest", mutate: func(w []byte) { clear(w[32:64]) }},
		{name: "sender target", mutate: func(w []byte) { clear(w[64:80]) }},
		{name: "receiver revision", mutate: func(w []byte) { clear(w[80:88]) }},
		{name: "receiver digest", mutate: func(w []byte) { clear(w[88:120]) }},
		{name: "receiver target", mutate: func(w []byte) { clear(w[120:136]) }},
		{name: "generation", mutate: func(w []byte) { clear(w[136:144]) }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := append([]byte(nil), wire...)
			if mutation.name == "short" {
				candidate = candidate[:len(candidate)-1]
			} else {
				mutation.mutate(candidate)
			}
			if _, err := DecodePathRetirement(candidate); err == nil {
				t.Fatal("accepted malformed path retirement")
			}
		})
	}
}

func TestPathRetirementEncodeRejectsInvalidFacts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PathRetirementPayload)
	}{
		{name: "session", mutate: func(p *PathRetirementPayload) { p.SessionEpoch = SessionEpoch{} }},
		{name: "direction", mutate: func(p *PathRetirementPayload) { p.Direction = 0xff }},
		{name: "reason", mutate: func(p *PathRetirementPayload) { p.Reason = PathRetirementReasonInvalid }},
		{name: "sender revision", mutate: func(p *PathRetirementPayload) { p.SenderGraphRevision = 0 }},
		{name: "sender digest", mutate: func(p *PathRetirementPayload) { p.SenderGraphDigest = GraphDigest{} }},
		{name: "sender target", mutate: func(p *PathRetirementPayload) { p.SenderTargetID = TargetID{} }},
		{name: "receiver revision", mutate: func(p *PathRetirementPayload) { p.ReceiverGraphRevision = 0 }},
		{name: "receiver digest", mutate: func(p *PathRetirementPayload) { p.ReceiverGraphDigest = GraphDigest{} }},
		{name: "receiver target", mutate: func(p *PathRetirementPayload) { p.ReceiverTargetID = TargetID{} }},
		{name: "generation", mutate: func(p *PathRetirementPayload) { p.RouteGeneration = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := testPathRetirementPayload()
			test.mutate(&candidate)
			if _, err := candidate.Encode(); err == nil {
				t.Fatal("encoded incomplete path retirement")
			}
		})
	}
}

func FuzzDecodePathRetirementNeverPanics(f *testing.F) {
	valid, err := testPathRetirementPayload().Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("RPRT"))
	f.Add(make([]byte, PathRetirementPayloadSize))
	f.Fuzz(func(t *testing.T, wire []byte) {
		decoded, err := DecodePathRetirement(wire)
		if err != nil {
			return
		}
		encoded, err := decoded.Encode()
		if err != nil {
			t.Fatalf("decoded payload cannot be re-encoded: %v", err)
		}
		if !bytes.Equal(encoded, wire) {
			t.Fatalf("accepted path retirement is not canonically stable:\n got=%x\nwant=%x", encoded, wire)
		}
	})
}
