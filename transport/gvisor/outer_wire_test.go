package gvisor

import (
	"bytes"
	"errors"
	"testing"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

func TestOuterDataCodecRoundTrip(t *testing.T) {
	id := linkID{1, 2, 3}
	secret := linkSecret{4, 5, 6}
	payload := bytes.Repeat([]byte{0x5a}, packetMTU)
	wire, err := encodeOuterData(id, 7, 19, payload, secret, leafmobility.RoleDialer)
	if err != nil {
		t.Fatal(err)
	}
	wantWireSize := outerHeaderSize + outerDataSequenceSize + len(payload) + outerAuthTagSize
	if len(wire) != wantWireSize {
		t.Fatalf("wire length=%d want=%d", len(wire), wantWireSize)
	}
	frame, err := decodeOuter(wire, secret, leafmobility.RoleDialer)
	if err != nil {
		t.Fatal(err)
	}
	data, err := parseOuterData(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != outerTypeData || frame.LinkID != id || frame.Generation != 7 ||
		data.Sequence != 19 || !bytes.Equal(data.Packet, payload) {
		t.Fatalf("decoded DATA=%+v", frame)
	}
	wire[len(wire)-outerAuthTagSize-1] ^= 0xff
	if payload[len(payload)-1] != 0x5a {
		t.Fatal("decoded DATA aliases caller wire storage")
	}
	if _, err := decodeOuter(wire, secret, leafmobility.RoleDialer); !errors.Is(err, errOuterAuthentication) {
		t.Fatalf("tampered DATA error=%v want authentication failure", err)
	}
}

func TestOuterAuthenticatedControlCodec(t *testing.T) {
	id := linkID{9, 8, 7}
	secret := linkSecret{6, 5, 4}
	control := outerControl{
		Transaction: linkTransaction{1},
		Agreement:   linkAgreement{2},
		Nonce:       linkNonce{3},
		ReceiveNext: 4,
	}
	payload, err := marshalOuterControl(control)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []outerType{
		outerTypePathChallenge,
		outerTypePathResponse,
		outerTypePathCommit,
		outerTypePathCommitAck,
		outerTypePathAbort,
		outerTypePathAbortAck,
	} {
		t.Run(string(rune('0'+typ)), func(t *testing.T) {
			wire, err := encodeOuterControl(outerFrame{
				Type: typ, Sender: leafmobility.RoleDialer, LinkID: id, Generation: 11, Payload: payload,
			}, secret)
			if err != nil {
				t.Fatal(err)
			}
			frame, err := decodeOuter(wire, secret, leafmobility.RoleDialer)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := parseOuterControl(frame.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if frame.Type != typ || frame.Generation != 11 || decoded != control {
				t.Fatalf("decoded control frame=%+v control=%+v", frame, decoded)
			}
			corrupt := append([]byte(nil), wire...)
			corrupt[outerHeaderSize] ^= 1
			if _, err := decodeOuter(corrupt, secret, leafmobility.RoleDialer); !errors.Is(err, errOuterAuthentication) {
				t.Fatalf("corrupt control error=%v want authentication failure", err)
			}
			if _, err := decodeOuter(wire, linkSecret{99}, leafmobility.RoleDialer); !errors.Is(err, errOuterAuthentication) {
				t.Fatalf("wrong-secret error=%v want authentication failure", err)
			}
		})
	}
}

func TestOuterProgressControlCodec(t *testing.T) {
	id := linkID{7}
	secret := linkSecret{8}
	liveness := outerLiveness{Nonce: linkNonce{9}, ReceiveNext: 1234}
	payload, err := marshalOuterLiveness(liveness)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeOuterControl(outerFrame{
		Type: outerTypeLivenessChallenge, Sender: leafmobility.RoleDialer,
		LinkID: id, Generation: 3, Payload: payload,
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := decodeOuter(wire, secret, leafmobility.RoleDialer)
	if err != nil {
		t.Fatal(err)
	}
	decodedLiveness, err := parseOuterLiveness(frame.Payload)
	if err != nil || decodedLiveness != liveness {
		t.Fatalf("liveness=%+v err=%v", decodedLiveness, err)
	}

	ackPayload, err := marshalOuterDataAck(5678)
	if err != nil {
		t.Fatal(err)
	}
	wire, err = encodeOuterControl(outerFrame{
		Type: outerTypeDataAck, Sender: leafmobility.RoleDialer,
		LinkID: id, Generation: 4, Payload: ackPayload,
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	frame, err = decodeOuter(wire, secret, leafmobility.RoleDialer)
	if err != nil {
		t.Fatal(err)
	}
	receiveNext, err := parseOuterDataAck(frame.Payload)
	if err != nil || receiveNext != 5678 {
		t.Fatalf("DATA_ACK receive_next=%d err=%v", receiveNext, err)
	}
}

func TestOuterAdmissionCodecBindsNonceAndSecret(t *testing.T) {
	id := linkID{1}
	nonce := linkNonce{3}
	cookie := outerCookie{4}
	security, err := resolvePacketSecurity([]PacketOption{WithPSK(bytes.Repeat([]byte{0x5a}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	clientPrivate, clientPublic, err := newLinkKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverPrivate, serverPublic, err := newLinkKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	proof := security.admissionProof(id, clientPublic, nonce, cookie)
	request, err := encodeOuter(outerFrame{
		Type: outerTypeOpen, Sender: leafmobility.RoleDialer, LinkID: id, Generation: 1,
		Payload: marshalOpen(clientPublic, nonce, cookie, proof),
	}, linkSecret{})
	if err != nil {
		t.Fatal(err)
	}
	header, err := decodeOuterHeader(request)
	if err != nil {
		t.Fatal(err)
	}
	gotPublic, gotNonce, gotCookie, gotProof, err := parseOpen(header.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if gotPublic != clientPublic || gotNonce != nonce || gotCookie != cookie || gotProof != proof ||
		!security.validateAdmissionProof(id, gotPublic, gotNonce, gotCookie, gotProof) {
		t.Fatalf("OPEN admission binding mismatch")
	}
	if _, err := decodeOuter(request, linkSecret{}, leafmobility.RoleDialer); err != nil {
		t.Fatal(err)
	}
	serverSecret, err := deriveLinkSecret(serverPrivate, clientPublic, id, nonce, security)
	if err != nil {
		t.Fatal(err)
	}

	ip := [4]byte{10, 64, 0, 1}
	response, err := encodeOuterControl(outerFrame{
		Type: outerTypeOpenAck, Sender: leafmobility.RoleAcceptor, LinkID: id, Generation: 1,
		Payload: marshalOpenAck(serverPublic, ip, nonce),
	}, serverSecret)
	if err != nil {
		t.Fatal(err)
	}
	responseHeader, err := decodeOuterHeader(response)
	if err != nil {
		t.Fatal(err)
	}
	gotServerPublic, gotIP, gotNonce, err := parseOpenAck(responseHeader.Payload)
	if err != nil || gotServerPublic != serverPublic || gotIP != ip || gotNonce != nonce {
		t.Fatalf("OPEN_ACK public=%x ip=%v nonce=%v err=%v", gotServerPublic, gotIP, gotNonce, err)
	}
	clientSecret, err := deriveLinkSecret(clientPrivate, gotServerPublic, id, nonce, security)
	if err != nil || clientSecret != serverSecret {
		t.Fatalf("derived secret mismatch err=%v", err)
	}
	if _, err := decodeOuter(response, clientSecret, leafmobility.RoleAcceptor); err != nil {
		t.Fatal(err)
	}
}

func TestOuterCodecRejectsAuthenticatedReflection(t *testing.T) {
	secret := linkSecret{0x91}
	payload, err := marshalOuterLiveness(outerLiveness{Nonce: linkNonce{0x92}, ReceiveNext: 1})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeOuterControl(outerFrame{
		Type: outerTypeLivenessChallenge, Sender: leafmobility.RoleAcceptor,
		LinkID: linkID{0x93}, Generation: 1, Payload: payload,
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeOuter(wire, secret, leafmobility.RoleDialer); !errors.Is(err, errOuterSender) {
		t.Fatalf("self-reflected acceptor frame error=%v, want sender rejection", err)
	}
	if _, err := decodeOuter(wire, secret, leafmobility.RoleAcceptor); err != nil {
		t.Fatalf("peer acceptor frame rejected by dialer: %v", err)
	}
}

func TestOuterCodecRejectsMalformedEnvelopeBeforeAllocation(t *testing.T) {
	id := linkID{1}
	secret := linkSecret{2}
	control, _ := marshalOuterControl(outerControl{
		Transaction: linkTransaction{1}, Agreement: linkAgreement{2}, Nonce: linkNonce{3}, ReceiveNext: 1,
	})
	valid, err := encodeOuterControl(outerFrame{
		Type: outerTypePathCommit, Sender: leafmobility.RoleDialer,
		LinkID: id, Generation: 2, Payload: control,
	}, secret)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"short":           valid[:outerHeaderSize-1],
		"bad-magic":       append([]byte(nil), valid...),
		"bad-version":     append([]byte(nil), valid...),
		"bad-sender":      append([]byte(nil), valid...),
		"reserved":        append([]byte(nil), valid...),
		"zero-link":       append([]byte(nil), valid...),
		"zero-generation": append([]byte(nil), valid...),
		"trailing":        append(append([]byte(nil), valid...), 0),
	}
	tests["bad-magic"][0] ^= 1
	tests["bad-version"][4]++
	tests["bad-sender"][6] = 0
	tests["reserved"][7] = 1
	clear(tests["zero-link"][8:24])
	clear(tests["zero-generation"][24:32])
	for name, wire := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeOuter(wire, secret, leafmobility.RoleDialer); err == nil {
				t.Fatal("malformed outer datagram was accepted")
			}
		})
	}
}

func FuzzOuterCodec(f *testing.F) {
	f.Add([]byte("short"))
	id := linkID{1}
	wire, _ := encodeOuterData(id, 1, 1, []byte{0x45}, linkSecret{1}, leafmobility.RoleDialer)
	f.Add(wire)
	f.Fuzz(func(t *testing.T, candidate []byte) {
		frame, err := decodeOuter(candidate, linkSecret{1}, leafmobility.RoleDialer)
		if err != nil {
			return
		}
		if !frame.Type.valid() || frame.LinkID == (linkID{}) || frame.Generation == 0 {
			t.Fatalf("decoder returned invalid frame %+v", frame)
		}
	})
}
