package gvisor

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	outerVersion         = uint8(5)
	outerHeaderSize      = 32
	outerAuthTagSize     = 16
	outerSecretSize      = 32
	outerNonceSize       = 16
	outerAgreementSize   = 32
	outerTransactionSize = 16
	outerPublicKeySize   = 32
	outerCookieSize      = 32
	outerProofSize       = 16

	outerOpenPayloadSize     = outerPublicKeySize + outerNonceSize + outerCookieSize + outerProofSize
	outerCookiePayloadSize   = outerCookieSize
	outerOpenAckPayloadSize  = outerPublicKeySize + 4 + outerNonceSize
	outerDataSequenceSize    = 8
	outerDataAckPayloadSize  = 8
	outerControlPayloadSize  = outerTransactionSize + outerAgreementSize + outerNonceSize + 8
	outerLivenessPayloadSize = outerNonceSize + 8

	outerIPv6MinimumMTU  = 1280
	outerIPv4HeaderSize  = 20
	outerIPv6HeaderSize  = 40
	outerUDPHeaderSize   = 8
	outerDataOverhead    = outerHeaderSize + outerDataSequenceSize + outerAuthTagSize
	packetMTU            = outerIPv6MinimumMTU - outerIPv6HeaderSize - outerUDPHeaderSize - outerDataOverhead
	outerMaxDatagramSize = outerDataOverhead + packetMTU

	outerQualificationRevision    = uint8(2)
	outerQualificationContextSize = outerControlPayloadSize
	outerQualificationPayloadSize = outerMaxDatagramSize - outerHeaderSize - outerAuthTagSize
	outerQualificationFixedSize   = 8 + outerNonceSize + outerNonceSize +
		outerQualificationContextSize + outerAgreementSize
)

var outerMagic = [4]byte{'R', 'G', 'L', '1'}

type outerType uint8

const (
	outerTypeOpen outerType = iota + 1
	outerTypeCookie
	outerTypeOpenAck
	outerTypeData
	outerTypePathChallenge
	outerTypePathResponse
	outerTypePathCommit
	outerTypePathCommitAck
	outerTypePathAbort
	outerTypePathAbortAck
	outerTypeLivenessChallenge
	outerTypeLivenessAck
	outerTypeDataAck
	outerTypeQualificationRequest
	outerTypeQualificationResponse
	outerTypeQualificationConfirm
	outerTypeQualificationDone
)

func (typ outerType) valid() bool {
	return typ >= outerTypeOpen && typ <= outerTypeQualificationDone
}

func (typ outerType) authenticated() bool {
	return typ != outerTypeOpen && typ != outerTypeCookie
}

type linkID [16]byte
type linkSecret [outerSecretSize]byte
type linkPublicKey [outerPublicKeySize]byte
type linkNonce [outerNonceSize]byte
type linkTransaction [outerTransactionSize]byte
type linkAgreement [outerAgreementSize]byte
type outerCookie [outerCookieSize]byte
type outerProof [outerProofSize]byte

type outerFrame struct {
	Type       outerType
	LinkID     linkID
	Generation uint64
	Payload    []byte
}

type outerControl struct {
	Transaction linkTransaction
	Agreement   linkAgreement
	Nonce       linkNonce
	ReceiveNext uint64
}

type outerData struct {
	Sequence uint64
	Packet   []byte
}

type outerLiveness struct {
	Nonce       linkNonce
	ReceiveNext uint64
}

type outerQualificationPurpose uint8

const (
	outerQualificationAdmission outerQualificationPurpose = iota + 1
	outerQualificationRebind
)

func (purpose outerQualificationPurpose) valid() bool {
	return purpose == outerQualificationAdmission || purpose == outerQualificationRebind
}

type outerQualification struct {
	Purpose        outerQualificationPurpose
	Round          uint32
	InitiatorNonce linkNonce
	ResponderNonce linkNonce
	Context        [outerQualificationContextSize]byte
	Binding        linkAgreement
}

var (
	errOuterMalformed       = errors.New("gvisor: malformed outer datagram")
	errOuterVersion         = errors.New("gvisor: unsupported outer datagram version")
	errOuterAuthentication  = errors.New("gvisor: outer datagram authentication failed")
	errOuterControlMismatch = errors.New("gvisor: outer control payload mismatch")
)

func newLinkID() (linkID, error) {
	var id linkID
	if _, err := rand.Read(id[:]); err != nil {
		return linkID{}, fmt.Errorf("gvisor: generate link id: %w", err)
	}
	if id == (linkID{}) {
		id[0] = 1
	}
	return id, nil
}

func newLinkKeyPair() (*ecdh.PrivateKey, linkPublicKey, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, linkPublicKey{}, fmt.Errorf("gvisor: generate link key: %w", err)
	}
	var public linkPublicKey
	copy(public[:], private.PublicKey().Bytes())
	if public == (linkPublicKey{}) {
		return nil, linkPublicKey{}, errors.New("gvisor: generated zero link public key")
	}
	return private, public, nil
}

func deriveLinkSecret(
	private *ecdh.PrivateKey,
	peer linkPublicKey,
	id linkID,
	nonce linkNonce,
	binding packetSecurity,
) (linkSecret, error) {
	if private == nil || peer == (linkPublicKey{}) || id == (linkID{}) || nonce == (linkNonce{}) {
		return linkSecret{}, errOuterAuthentication
	}
	peerKey, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return linkSecret{}, fmt.Errorf("gvisor: parse peer link key: %w", err)
	}
	shared, err := private.ECDH(peerKey)
	if err != nil {
		return linkSecret{}, fmt.Errorf("gvisor: derive link secret: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("rendr-gvisor-link-v2\x00"))
	_, _ = hash.Write(shared)
	_, _ = hash.Write(id[:])
	_, _ = hash.Write(nonce[:])
	_, _ = hash.Write([]byte{byte(binding.mode)})
	if binding.mode == packetTrustPSK {
		_, _ = hash.Write(binding.key[:])
	}
	var secret linkSecret
	copy(secret[:], hash.Sum(nil))
	if secret == (linkSecret{}) {
		return linkSecret{}, errOuterAuthentication
	}
	return secret, nil
}

func newLinkNonce() (linkNonce, error) {
	var nonce linkNonce
	if _, err := rand.Read(nonce[:]); err != nil {
		return linkNonce{}, fmt.Errorf("gvisor: generate link nonce: %w", err)
	}
	if nonce == (linkNonce{}) {
		nonce[0] = 1
	}
	return nonce, nil
}

func encodeOuterData(
	id linkID,
	generation uint64,
	sequence uint64,
	packet []byte,
	secret linkSecret,
) ([]byte, error) {
	payload, err := marshalOuterData(sequence, packet)
	if err != nil {
		return nil, err
	}
	return encodeOuter(outerFrame{Type: outerTypeData, LinkID: id, Generation: generation, Payload: payload}, secret)
}

func encodeOuterControl(frame outerFrame, secret linkSecret) ([]byte, error) {
	if !frame.Type.authenticated() || frame.Type == outerTypeData {
		return nil, fmt.Errorf("%w: unauthenticated frame is not a control frame", errOuterMalformed)
	}
	return encodeOuter(frame, secret)
}

func encodeOuter(frame outerFrame, secret linkSecret) ([]byte, error) {
	if !frame.Type.valid() || frame.LinkID == (linkID{}) || frame.Generation == 0 {
		return nil, errOuterMalformed
	}
	if frame.Type.authenticated() && secret == (linkSecret{}) {
		return nil, errOuterAuthentication
	}
	if err := validateOuterPayload(frame.Type, frame.Payload); err != nil {
		return nil, err
	}
	tagSize := 0
	if frame.Type.authenticated() {
		tagSize = outerAuthTagSize
	}
	wire := make([]byte, outerHeaderSize+len(frame.Payload)+tagSize)
	copy(wire[0:4], outerMagic[:])
	wire[4] = outerVersion
	wire[5] = byte(frame.Type)
	copy(wire[8:24], frame.LinkID[:])
	binary.BigEndian.PutUint64(wire[24:32], frame.Generation)
	copy(wire[outerHeaderSize:], frame.Payload)
	if tagSize != 0 {
		tag := outerAuthTag(secret, wire[:len(wire)-outerAuthTagSize])
		copy(wire[len(wire)-outerAuthTagSize:], tag[:])
	}
	return wire, nil
}

func decodeOuterHeader(wire []byte) (outerFrame, error) {
	if len(wire) < outerHeaderSize || string(wire[0:4]) != string(outerMagic[:]) {
		return outerFrame{}, errOuterMalformed
	}
	if wire[4] != outerVersion {
		return outerFrame{}, errOuterVersion
	}
	if wire[6] != 0 || wire[7] != 0 {
		return outerFrame{}, errOuterMalformed
	}
	frame := outerFrame{Type: outerType(wire[5]), Generation: binary.BigEndian.Uint64(wire[24:32])}
	copy(frame.LinkID[:], wire[8:24])
	if !frame.Type.valid() || frame.LinkID == (linkID{}) || frame.Generation == 0 {
		return outerFrame{}, errOuterMalformed
	}
	tagSize := 0
	if frame.Type.authenticated() {
		tagSize = outerAuthTagSize
	}
	if len(wire) < outerHeaderSize+tagSize {
		return outerFrame{}, errOuterMalformed
	}
	frame.Payload = wire[outerHeaderSize : len(wire)-tagSize]
	if err := validateOuterPayload(frame.Type, frame.Payload); err != nil {
		return outerFrame{}, err
	}
	return frame, nil
}

func decodeOuter(wire []byte, secret linkSecret) (outerFrame, error) {
	frame, err := decodeOuterHeader(wire)
	if err != nil {
		return outerFrame{}, err
	}
	if !frame.Type.authenticated() {
		frame.Payload = append([]byte(nil), frame.Payload...)
		return frame, nil
	}
	if secret == (linkSecret{}) || len(wire) < outerAuthTagSize {
		return outerFrame{}, errOuterAuthentication
	}
	want := outerAuthTag(secret, wire[:len(wire)-outerAuthTagSize])
	got := wire[len(wire)-outerAuthTagSize:]
	if !hmac.Equal(got, want[:]) {
		return outerFrame{}, errOuterAuthentication
	}
	frame.Payload = append([]byte(nil), frame.Payload...)
	return frame, nil
}

func validateOuterPayload(typ outerType, payload []byte) error {
	want := -1
	switch typ {
	case outerTypeOpen:
		want = outerOpenPayloadSize
	case outerTypeCookie:
		want = outerCookiePayloadSize
	case outerTypeOpenAck:
		want = outerOpenAckPayloadSize
	case outerTypeData:
		if len(payload) <= outerDataSequenceSize || len(payload) > outerDataSequenceSize+packetMTU {
			return errOuterMalformed
		}
		return nil
	case outerTypePathChallenge, outerTypePathResponse, outerTypePathCommit, outerTypePathCommitAck,
		outerTypePathAbort, outerTypePathAbortAck:
		want = outerControlPayloadSize
	case outerTypeLivenessChallenge, outerTypeLivenessAck:
		want = outerLivenessPayloadSize
	case outerTypeDataAck:
		want = outerDataAckPayloadSize
	case outerTypeQualificationRequest, outerTypeQualificationResponse,
		outerTypeQualificationConfirm, outerTypeQualificationDone:
		want = outerQualificationPayloadSize
	default:
		return errOuterMalformed
	}
	if len(payload) != want {
		return errOuterMalformed
	}
	return nil
}

func outerAuthTag(secret linkSecret, authenticated []byte) [outerAuthTagSize]byte {
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write(authenticated)
	var tag [outerAuthTagSize]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func marshalOpen(public linkPublicKey, nonce linkNonce, cookie outerCookie, proof outerProof) []byte {
	payload := make([]byte, outerOpenPayloadSize)
	copy(payload[:outerPublicKeySize], public[:])
	copy(payload[outerPublicKeySize:outerPublicKeySize+outerNonceSize], nonce[:])
	copy(payload[outerPublicKeySize+outerNonceSize:outerPublicKeySize+outerNonceSize+outerCookieSize], cookie[:])
	copy(payload[outerPublicKeySize+outerNonceSize+outerCookieSize:], proof[:])
	return payload
}

func parseOpen(payload []byte) (linkPublicKey, linkNonce, outerCookie, outerProof, error) {
	if len(payload) != outerOpenPayloadSize {
		return linkPublicKey{}, linkNonce{}, outerCookie{}, outerProof{}, errOuterControlMismatch
	}
	var public linkPublicKey
	var nonce linkNonce
	var cookie outerCookie
	var proof outerProof
	copy(public[:], payload[:outerPublicKeySize])
	copy(nonce[:], payload[outerPublicKeySize:outerPublicKeySize+outerNonceSize])
	copy(cookie[:], payload[outerPublicKeySize+outerNonceSize:outerPublicKeySize+outerNonceSize+outerCookieSize])
	copy(proof[:], payload[outerPublicKeySize+outerNonceSize+outerCookieSize:])
	if public == (linkPublicKey{}) || nonce == (linkNonce{}) {
		return linkPublicKey{}, linkNonce{}, outerCookie{}, outerProof{}, errOuterControlMismatch
	}
	return public, nonce, cookie, proof, nil
}

func marshalOuterCookie(cookie outerCookie) ([]byte, error) {
	if cookie == (outerCookie{}) {
		return nil, errOuterControlMismatch
	}
	return append([]byte(nil), cookie[:]...), nil
}

func parseOuterCookie(payload []byte) (outerCookie, error) {
	if len(payload) != outerCookiePayloadSize {
		return outerCookie{}, errOuterControlMismatch
	}
	var cookie outerCookie
	copy(cookie[:], payload)
	if cookie == (outerCookie{}) {
		return outerCookie{}, errOuterControlMismatch
	}
	return cookie, nil
}

func marshalOpenAck(public linkPublicKey, ip [4]byte, nonce linkNonce) []byte {
	payload := make([]byte, outerOpenAckPayloadSize)
	copy(payload[:outerPublicKeySize], public[:])
	copy(payload[outerPublicKeySize:outerPublicKeySize+4], ip[:])
	copy(payload[outerPublicKeySize+4:], nonce[:])
	return payload
}

func parseOpenAck(payload []byte) (linkPublicKey, [4]byte, linkNonce, error) {
	if len(payload) != outerOpenAckPayloadSize {
		return linkPublicKey{}, [4]byte{}, linkNonce{}, errOuterControlMismatch
	}
	var public linkPublicKey
	var ip [4]byte
	var nonce linkNonce
	copy(public[:], payload[:outerPublicKeySize])
	copy(ip[:], payload[outerPublicKeySize:outerPublicKeySize+4])
	copy(nonce[:], payload[outerPublicKeySize+4:])
	if public == (linkPublicKey{}) || ip == ([4]byte{}) || nonce == (linkNonce{}) {
		return linkPublicKey{}, [4]byte{}, linkNonce{}, errOuterControlMismatch
	}
	return public, ip, nonce, nil
}

func marshalOuterData(sequence uint64, packet []byte) ([]byte, error) {
	if sequence == 0 || len(packet) == 0 || len(packet) > packetMTU {
		return nil, errOuterControlMismatch
	}
	payload := make([]byte, outerDataSequenceSize+len(packet))
	binary.BigEndian.PutUint64(payload[:outerDataSequenceSize], sequence)
	copy(payload[outerDataSequenceSize:], packet)
	return payload, nil
}

func parseOuterData(payload []byte) (outerData, error) {
	if len(payload) <= outerDataSequenceSize || len(payload) > outerDataSequenceSize+packetMTU {
		return outerData{}, errOuterControlMismatch
	}
	sequence := binary.BigEndian.Uint64(payload[:outerDataSequenceSize])
	if sequence == 0 {
		return outerData{}, errOuterControlMismatch
	}
	return outerData{Sequence: sequence, Packet: payload[outerDataSequenceSize:]}, nil
}

func marshalOuterControl(control outerControl) ([]byte, error) {
	if control.Transaction == (linkTransaction{}) || control.Agreement == (linkAgreement{}) ||
		control.Nonce == (linkNonce{}) || control.ReceiveNext == 0 {
		return nil, errOuterControlMismatch
	}
	payload := make([]byte, outerControlPayloadSize)
	copy(payload[:outerTransactionSize], control.Transaction[:])
	copy(payload[outerTransactionSize:outerTransactionSize+outerAgreementSize], control.Agreement[:])
	nonceStart := outerTransactionSize + outerAgreementSize
	copy(payload[nonceStart:nonceStart+outerNonceSize], control.Nonce[:])
	binary.BigEndian.PutUint64(payload[nonceStart+outerNonceSize:], control.ReceiveNext)
	return payload, nil
}

func parseOuterControl(payload []byte) (outerControl, error) {
	if len(payload) != outerControlPayloadSize {
		return outerControl{}, errOuterControlMismatch
	}
	var control outerControl
	copy(control.Transaction[:], payload[:outerTransactionSize])
	copy(control.Agreement[:], payload[outerTransactionSize:outerTransactionSize+outerAgreementSize])
	nonceStart := outerTransactionSize + outerAgreementSize
	copy(control.Nonce[:], payload[nonceStart:nonceStart+outerNonceSize])
	control.ReceiveNext = binary.BigEndian.Uint64(payload[nonceStart+outerNonceSize:])
	if control.Transaction == (linkTransaction{}) || control.Agreement == (linkAgreement{}) ||
		control.Nonce == (linkNonce{}) || control.ReceiveNext == 0 {
		return outerControl{}, errOuterControlMismatch
	}
	return control, nil
}

func marshalOuterLiveness(liveness outerLiveness) ([]byte, error) {
	if liveness.Nonce == (linkNonce{}) || liveness.ReceiveNext == 0 {
		return nil, errOuterControlMismatch
	}
	payload := make([]byte, outerLivenessPayloadSize)
	copy(payload[:outerNonceSize], liveness.Nonce[:])
	binary.BigEndian.PutUint64(payload[outerNonceSize:], liveness.ReceiveNext)
	return payload, nil
}

func parseOuterLiveness(payload []byte) (outerLiveness, error) {
	if len(payload) != outerLivenessPayloadSize {
		return outerLiveness{}, errOuterControlMismatch
	}
	var liveness outerLiveness
	copy(liveness.Nonce[:], payload[:outerNonceSize])
	liveness.ReceiveNext = binary.BigEndian.Uint64(payload[outerNonceSize:])
	if liveness.Nonce == (linkNonce{}) || liveness.ReceiveNext == 0 {
		return outerLiveness{}, errOuterControlMismatch
	}
	return liveness, nil
}

func marshalOuterDataAck(receiveNext uint64) ([]byte, error) {
	if receiveNext == 0 {
		return nil, errOuterControlMismatch
	}
	payload := make([]byte, outerDataAckPayloadSize)
	binary.BigEndian.PutUint64(payload, receiveNext)
	return payload, nil
}

func parseOuterDataAck(payload []byte) (uint64, error) {
	if len(payload) != outerDataAckPayloadSize {
		return 0, errOuterControlMismatch
	}
	receiveNext := binary.BigEndian.Uint64(payload)
	if receiveNext == 0 {
		return 0, errOuterControlMismatch
	}
	return receiveNext, nil
}

func marshalOuterQualification(typ outerType, qualification outerQualification) ([]byte, error) {
	if err := validateOuterQualification(typ, qualification); err != nil {
		return nil, err
	}
	payload := make([]byte, outerQualificationPayloadSize)
	payload[0] = outerQualificationRevision
	payload[1] = byte(qualification.Purpose)
	binary.BigEndian.PutUint32(payload[4:8], qualification.Round)
	offset := 8
	copy(payload[offset:offset+outerNonceSize], qualification.InitiatorNonce[:])
	offset += outerNonceSize
	copy(payload[offset:offset+outerNonceSize], qualification.ResponderNonce[:])
	offset += outerNonceSize
	copy(payload[offset:offset+outerQualificationContextSize], qualification.Context[:])
	offset += outerQualificationContextSize
	copy(payload[offset:offset+outerAgreementSize], qualification.Binding[:])
	return payload, nil
}

func parseOuterQualification(typ outerType, payload []byte) (outerQualification, error) {
	if len(payload) != outerQualificationPayloadSize || payload[0] != outerQualificationRevision ||
		payload[1] == 0 || !allZero(payload[2:4]) || !allZero(payload[outerQualificationFixedSize:]) {
		return outerQualification{}, errOuterControlMismatch
	}
	qualification := outerQualification{
		Purpose: outerQualificationPurpose(payload[1]),
		Round:   binary.BigEndian.Uint32(payload[4:8]),
	}
	offset := 8
	copy(qualification.InitiatorNonce[:], payload[offset:offset+outerNonceSize])
	offset += outerNonceSize
	copy(qualification.ResponderNonce[:], payload[offset:offset+outerNonceSize])
	offset += outerNonceSize
	copy(qualification.Context[:], payload[offset:offset+outerQualificationContextSize])
	offset += outerQualificationContextSize
	copy(qualification.Binding[:], payload[offset:offset+outerAgreementSize])
	if err := validateOuterQualification(typ, qualification); err != nil {
		return outerQualification{}, err
	}
	return qualification, nil
}

func validateOuterQualification(typ outerType, qualification outerQualification) error {
	if !qualification.Purpose.valid() || qualification.Round == 0 || qualification.InitiatorNonce == (linkNonce{}) ||
		qualification.Context == ([outerQualificationContextSize]byte{}) ||
		qualification.Binding == (linkAgreement{}) {
		return errOuterControlMismatch
	}
	switch typ {
	case outerTypeQualificationRequest:
		if qualification.ResponderNonce != (linkNonce{}) {
			return errOuterControlMismatch
		}
	case outerTypeQualificationResponse, outerTypeQualificationConfirm, outerTypeQualificationDone:
		if qualification.ResponderNonce == (linkNonce{}) {
			return errOuterControlMismatch
		}
	default:
		return errOuterControlMismatch
	}
	return nil
}

func qualificationAdmissionContext(nonce linkNonce) ([outerQualificationContextSize]byte, error) {
	if nonce == (linkNonce{}) {
		return [outerQualificationContextSize]byte{}, errOuterControlMismatch
	}
	var context [outerQualificationContextSize]byte
	copy(context[:outerNonceSize], nonce[:])
	return context, nil
}

func qualificationRebindContext(control outerControl) ([outerQualificationContextSize]byte, error) {
	payload, err := marshalOuterControl(control)
	if err != nil {
		return [outerQualificationContextSize]byte{}, err
	}
	var context [outerQualificationContextSize]byte
	copy(context[:], payload)
	return context, nil
}

func parseQualificationRebindContext(context [outerQualificationContextSize]byte) (outerControl, error) {
	return parseOuterControl(context[:])
}

func computeOuterQualificationBinding(
	secret linkSecret,
	id linkID,
	generation uint64,
	purpose outerQualificationPurpose,
	round uint32,
	initiatorNonce linkNonce,
	context [outerQualificationContextSize]byte,
) linkAgreement {
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write([]byte("rendr-gvisor-maximum-data-v5\x00"))
	_, _ = mac.Write(id[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], generation)
	_, _ = mac.Write(scalar[:])
	_, _ = mac.Write([]byte{byte(purpose)})
	binary.BigEndian.PutUint32(scalar[:4], round)
	_, _ = mac.Write(scalar[:4])
	_, _ = mac.Write(initiatorNonce[:])
	_, _ = mac.Write(context[:])
	var binding linkAgreement
	copy(binding[:], mac.Sum(nil))
	return binding
}

func allZero(value []byte) bool {
	for _, octet := range value {
		if octet != 0 {
			return false
		}
	}
	return true
}

func computeOuterProof(
	key linkSecret,
	id linkID,
	public linkPublicKey,
	nonce linkNonce,
	cookie outerCookie,
) outerProof {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("rendr-gvisor-open-proof-v2\x00"))
	_, _ = mac.Write(id[:])
	_, _ = mac.Write(public[:])
	_, _ = mac.Write(nonce[:])
	_, _ = mac.Write(cookie[:])
	var proof outerProof
	copy(proof[:], mac.Sum(nil))
	return proof
}
