package tcpquarantine

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"time"
)

const (
	tokenSize               = 16
	defaultReconcileTimeout = 5 * time.Second
	maxReconcileTimeout     = 30 * time.Second
)

var (
	ErrUnsupportedPlatform      = errors.New("tcpquarantine: nft runner requires linux")
	ErrNFTExecutableUnavailable = errors.New("tcpquarantine: trusted nft executable is unavailable")
	ErrInvalidTransactionID     = errors.New("tcpquarantine: invalid transaction ID")
	ErrInvalidTuple             = errors.New("tcpquarantine: invalid IPv4 TCP tuple")
	ErrCommandOutputTooLarge    = errors.New("tcpquarantine: nft command output too large")
	ErrInstallNotApplied        = errors.New("tcpquarantine: install did not produce the quarantine")
	ErrVerificationFailed       = errors.New("tcpquarantine: quarantine verification failed")
	ErrStateUnknown             = errors.New("tcpquarantine: nft state is unknown")
	ErrCleanupIncomplete        = errors.New("tcpquarantine: cleanup could not prove the table absent")
	ErrReleaseNotApplied        = errors.New("tcpquarantine: release did not remove the table")
	ErrPreflightStateChanged    = errors.New("tcpquarantine: preflight did not leave the table absent")
	ErrInvalidReconcileWindow   = errors.New("tcpquarantine: invalid reconcile timeout")
	ErrLeaseBusy                = errors.New("tcpquarantine: transaction already has an active lease")
	ErrLeaseConflict            = errors.New("tcpquarantine: transaction is active for a different tuple or execution scope")
	ErrStaleLease               = errors.New("tcpquarantine: lease incarnation is no longer active")
	ErrLeaseGenerationExhausted = errors.New("tcpquarantine: lease generation exhausted")
)

// TransactionID is a binary transaction identity. Names sent to nft are
// derived from its hexadecimal encoding, never from caller-provided strings.
type TransactionID [tokenSize]byte

// NewTransactionID returns a cryptographically random transaction identity.
func NewTransactionID() (TransactionID, error) {
	var id TransactionID
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return TransactionID{}, fmt.Errorf("tcpquarantine: generate transaction ID: %w", err)
	}
	if id.isZero() {
		return TransactionID{}, fmt.Errorf("%w: random source returned all zeroes", ErrInvalidTransactionID)
	}
	return id, nil
}

func (id TransactionID) isZero() bool {
	var combined byte
	for _, value := range id {
		combined |= value
	}
	return combined == 0
}

// Tuple identifies one established TCP connection from the local host's
// perspective. Both endpoints must be concrete IPv4 address/port pairs.
type Tuple struct {
	Local  netip.AddrPort
	Remote netip.AddrPort
}

func (tuple Tuple) validate() error {
	if err := validateEndpoint(tuple.Local); err != nil {
		return fmt.Errorf("%w: local endpoint: %v", ErrInvalidTuple, err)
	}
	if err := validateEndpoint(tuple.Remote); err != nil {
		return fmt.Errorf("%w: remote endpoint: %v", ErrInvalidTuple, err)
	}
	return nil
}

func validateEndpoint(endpoint netip.AddrPort) error {
	address := endpoint.Addr()
	if !endpoint.IsValid() || !address.Is4() {
		return errors.New("address is not IPv4")
	}
	if address.IsUnspecified() || address.IsMulticast() {
		return errors.New("address is not a concrete unicast address")
	}
	if endpoint.Port() == 0 {
		return errors.New("port is zero")
	}
	return nil
}

// Config supplies package-local dependencies. A nil Runner selects the real
// nft CLI runner. Owner entropy is deliberately not configurable.
type Config struct {
	Runner           Runner
	ReconcileTimeout time.Duration
}

// New creates a quarantine manager with one random owner token. The owner is
// intentionally not caller-configurable.
func New(config Config) (*Manager, error) {
	runner := config.Runner
	if runner == nil {
		if runtime.GOOS != "linux" {
			return nil, ErrUnsupportedPlatform
		}
		resolved, err := newExecRunner()
		if err != nil {
			return nil, err
		}
		runner = resolved
	}
	timeout := config.ReconcileTimeout
	if timeout == 0 {
		timeout = defaultReconcileTimeout
	}
	if timeout < 0 || timeout > maxReconcileTimeout {
		return nil, fmt.Errorf("%w: must be in (0, %s]", ErrInvalidReconcileWindow, maxReconcileTimeout)
	}

	var owner ownerToken
	if _, err := io.ReadFull(rand.Reader, owner[:]); err != nil {
		return nil, fmt.Errorf("tcpquarantine: generate owner token: %w", err)
	}
	if owner.isZero() {
		return nil, errors.New("tcpquarantine: random source returned an all-zero owner token")
	}
	return &Manager{
		runner:           runner,
		owner:            owner,
		reconcileTimeout: timeout,
		activeLeases:     make(map[leaseKey]*leaseState),
	}, nil
}

type ownerToken [tokenSize]byte

func (token ownerToken) isZero() bool {
	var combined byte
	for _, value := range token {
		combined |= value
	}
	return combined == 0
}
