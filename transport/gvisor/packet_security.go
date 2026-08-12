package gvisor

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const packetCookiePeriod = 5 * time.Second

// ErrPacketTrustRequired reports that an outer UDP packet carrier was used
// without an explicit carrier-integrity assertion or authentication binding.
var ErrPacketTrustRequired = errors.New("gvisor: packet carrier requires an explicit trust or authentication binding")

// PacketOption configures the trust boundary for an outer UDP packet carrier.
// It is intentionally local to this optional adapter and does not grant a core
// mobility capability.
type PacketOption interface {
	applyPacketSecurity(*packetSecurity) error
}

type packetOptionFunc func(*packetSecurity) error

func (option packetOptionFunc) applyPacketSecurity(security *packetSecurity) error {
	return option(security)
}

type packetTrustMode uint8

const (
	packetTrustUnset packetTrustMode = iota
	packetTrustCarrier
	packetTrustPSK
)

type packetSecurity struct {
	mode packetTrustMode
	key  linkSecret
}

// WithTrustedCarrier asserts that the caller-provided UDP carrier already
// satisfies rendr's C2 integrity boundary, including exclusion of active MITM
// tuple and payload manipulation. The private link handshake remains an
// off-path token exchange in this mode; it is not peer authentication.
func WithTrustedCarrier() PacketOption {
	return packetOptionFunc(func(security *packetSecurity) error {
		if security.mode != packetTrustUnset {
			return errors.New("gvisor: packet trust configured more than once")
		}
		security.mode = packetTrustCarrier
		return nil
	})
}

// WithPSK binds packet admission, DATA, and mobility controls to a shared key.
// It provides integrity and peer possession authentication, not encryption.
// Callers that need confidentiality must still use a confidential carrier or
// an application protocol such as TLS.
func WithPSK(key []byte) PacketOption {
	keyCopy := append([]byte(nil), key...)
	return packetOptionFunc(func(security *packetSecurity) error {
		if security.mode != packetTrustUnset {
			return errors.New("gvisor: packet trust configured more than once")
		}
		if len(keyCopy) < 32 {
			return fmt.Errorf("gvisor: packet PSK must contain at least 32 bytes")
		}
		hash := sha256.New()
		_, _ = hash.Write([]byte("rendr-gvisor-packet-psk-v1\x00"))
		_, _ = hash.Write(keyCopy)
		copy(security.key[:], hash.Sum(nil))
		security.mode = packetTrustPSK
		return nil
	})
}

func resolvePacketSecurity(options []PacketOption) (packetSecurity, error) {
	var security packetSecurity
	for _, option := range options {
		if option == nil {
			return packetSecurity{}, errors.New("gvisor: nil packet option")
		}
		if err := option.applyPacketSecurity(&security); err != nil {
			return packetSecurity{}, err
		}
	}
	if security.mode == packetTrustUnset {
		return packetSecurity{}, ErrPacketTrustRequired
	}
	return security, nil
}

func (security packetSecurity) admissionProof(
	id linkID,
	public linkPublicKey,
	nonce linkNonce,
	cookie outerCookie,
) outerProof {
	if security.mode != packetTrustPSK {
		return outerProof{}
	}
	return computeOuterProof(security.key, id, public, nonce, cookie)
}

func (security packetSecurity) validateAdmissionProof(
	id linkID,
	public linkPublicKey,
	nonce linkNonce,
	cookie outerCookie,
	proof outerProof,
) bool {
	if security.mode == packetTrustCarrier {
		return proof == (outerProof{})
	}
	if security.mode != packetTrustPSK || proof == (outerProof{}) {
		return false
	}
	want := computeOuterProof(security.key, id, public, nonce, cookie)
	return proof == want
}

func newPacketCookieKey() (linkSecret, error) {
	var key linkSecret
	if _, err := rand.Read(key[:]); err != nil {
		return linkSecret{}, fmt.Errorf("gvisor: generate packet admission cookie key: %w", err)
	}
	if key == (linkSecret{}) {
		key[0] = 1
	}
	return key, nil
}

func packetAdmissionCookie(
	key linkSecret,
	remote net.Addr,
	id linkID,
	public linkPublicKey,
	nonce linkNonce,
	bucket int64,
) outerCookie {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("rendr-gvisor-admission-cookie-v2\x00"))
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], uint64(bucket))
	_, _ = mac.Write(scalar[:])
	writeCookieString(mac, remote.Network())
	writeCookieString(mac, remote.String())
	_, _ = mac.Write(id[:])
	_, _ = mac.Write(public[:])
	_, _ = mac.Write(nonce[:])
	var cookie outerCookie
	copy(cookie[:], mac.Sum(nil))
	return cookie
}

func validPacketAdmissionCookie(
	key linkSecret,
	remote net.Addr,
	id linkID,
	public linkPublicKey,
	nonce linkNonce,
	cookie outerCookie,
	now time.Time,
) bool {
	if key == (linkSecret{}) || remote == nil || cookie == (outerCookie{}) {
		return false
	}
	bucket := now.Unix() / int64(packetCookiePeriod/time.Second)
	for _, candidate := range []int64{bucket, bucket - 1} {
		want := packetAdmissionCookie(key, remote, id, public, nonce, candidate)
		if hmac.Equal(cookie[:], want[:]) {
			return true
		}
	}
	return false
}

type cookieWriter interface {
	Write([]byte) (int, error)
}

func writeCookieString(writer cookieWriter, value string) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write([]byte(value))
}
