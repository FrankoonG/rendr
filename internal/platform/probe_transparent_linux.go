//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

type transparentBindProbeOps struct {
	socket          func(domain, typ, protocol int) (int, error)
	setSockoptInt   func(fd, level, option, value int) error
	getSockoptInt   func(fd, level, option int) (int, error)
	bind            func(fd int, address unix.Sockaddr) error
	getSockname     func(fd int) (unix.Sockaddr, error)
	addressAssigned func(netip.Addr) (bool, error)
	close           func(fd int) error
}

type transparentBindProbeFamily struct {
	feature    FeatureID
	domain     int
	level      int
	option     int
	candidates [3]netip.Addr
}

func defaultTransparentBindProbeOps() transparentBindProbeOps {
	return transparentBindProbeOps{
		socket:          unix.Socket,
		setSockoptInt:   unix.SetsockoptInt,
		getSockoptInt:   unix.GetsockoptInt,
		bind:            unix.Bind,
		getSockname:     unix.Getsockname,
		addressAssigned: transparentBindAddressAssigned,
		close:           unix.Close,
	}
}

// probeTransparentBind proves that the current execution context can set the
// transparent option and bind an address not assigned in its network
// namespace. It is platform evidence only, not per-endpoint tuple eligibility.
func probeTransparentBind(ctx context.Context, at time.Time, ops transparentBindProbeOps) ([]FeatureEvidence, error) {
	if err := validateTransparentBindProbeOps(ops); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	families := transparentBindProbeFamilies()
	observations := make([]FeatureEvidence, 0, len(families))
	for _, family := range families {
		if err := ctx.Err(); err != nil {
			return observations, err
		}
		evidence, cleanupComplete, err := probeTransparentBindFamily(ctx, at, family, ops)
		if evidence.ID != "" {
			observations = append(observations, evidence)
		}
		if err != nil {
			return observations, err
		}
		if !cleanupComplete {
			break
		}
	}
	return observations, nil
}

func validateTransparentBindProbeOps(ops transparentBindProbeOps) error {
	if ops.socket == nil || ops.setSockoptInt == nil || ops.getSockoptInt == nil ||
		ops.bind == nil || ops.getSockname == nil || ops.addressAssigned == nil || ops.close == nil {
		return fmt.Errorf("platform: incomplete transparent bind probe operations")
	}
	return nil
}

func transparentBindProbeFamilies() [2]transparentBindProbeFamily {
	return [2]transparentBindProbeFamily{
		{
			feature: FeatureTransparentBindV4,
			domain:  unix.AF_INET,
			level:   unix.SOL_IP,
			option:  unix.IP_TRANSPARENT,
			candidates: [3]netip.Addr{
				netip.AddrFrom4([4]byte{192, 0, 2, 1}),
				netip.AddrFrom4([4]byte{198, 51, 100, 1}),
				netip.AddrFrom4([4]byte{203, 0, 113, 1}),
			},
		},
		{
			feature: FeatureTransparentBindV6,
			domain:  unix.AF_INET6,
			level:   unix.SOL_IPV6,
			option:  unix.IPV6_TRANSPARENT,
			candidates: [3]netip.Addr{
				netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
				netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
				netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}),
			},
		},
	}
}

func probeTransparentBindFamily(ctx context.Context, at time.Time, family transparentBindProbeFamily, ops transparentBindProbeOps) (FeatureEvidence, bool, error) {
	candidate, found, err := selectTransparentBindCandidate(ctx, family, ops)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return FeatureEvidence{}, true, ctxErr
		}
		return classifiedOrFailed(family.feature, at, err), true, nil
	}
	if !found {
		err := fmt.Errorf("no verified nonlocal address candidate for %s", family.feature)
		return semanticFailureEvidence(family.feature, at, err), true, nil
	}
	if err := ctx.Err(); err != nil {
		return FeatureEvidence{}, true, err
	}

	fd, err := ops.socket(family.domain, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return classifiedOrFailed(family.feature, at, err), true, nil
	}
	if err := ctx.Err(); err != nil {
		return finishTransparentBindFD(at, family.feature, fd, ops, nil, false, err)
	}

	if err := ops.setSockoptInt(fd, family.level, family.option, 1); err != nil {
		return finishTransparentBindFD(at, family.feature, fd, ops, err, false, nil)
	}
	if err := ctx.Err(); err != nil {
		return finishTransparentBindFD(at, family.feature, fd, ops, nil, false, err)
	}
	value, err := ops.getSockoptInt(fd, family.level, family.option)
	if err != nil {
		return finishTransparentBindFD(at, family.feature, fd, ops, err, false, nil)
	}
	if value != 1 {
		err := fmt.Errorf("transparent socket option read back as %d, want 1", value)
		return finishTransparentBindFD(at, family.feature, fd, ops, err, true, nil)
	}
	if err := ctx.Err(); err != nil {
		return finishTransparentBindFD(at, family.feature, fd, ops, nil, false, err)
	}

	address, err := transparentBindSockaddr(candidate)
	if err != nil {
		return finishTransparentBindFD(at, family.feature, fd, ops, err, true, nil)
	}
	if err := ops.bind(fd, address); err != nil {
		semantic := errors.Is(err, unix.EADDRNOTAVAIL)
		return finishTransparentBindFD(at, family.feature, fd, ops, err, semantic, nil)
	}
	if err := ctx.Err(); err != nil {
		return finishTransparentBindFD(at, family.feature, fd, ops, nil, false, err)
	}

	bound, err := ops.getSockname(fd)
	if err != nil {
		return finishTransparentBindFD(at, family.feature, fd, ops, err, false, nil)
	}
	if err := validateTransparentBindSockname(candidate, bound); err != nil {
		return finishTransparentBindFD(at, family.feature, fd, ops, err, true, nil)
	}
	if err := ctx.Err(); err != nil {
		return finishTransparentBindFD(at, family.feature, fd, ops, nil, false, err)
	}

	assigned, err := ops.addressAssigned(candidate)
	if err != nil {
		return finishTransparentBindFD(at, family.feature, fd, ops, err, false, nil)
	}
	if err := ctx.Err(); err != nil {
		return finishTransparentBindFD(at, family.feature, fd, ops, nil, false, err)
	}
	if assigned {
		err := fmt.Errorf("transparent bind candidate %s became locally assigned", candidate)
		return finishTransparentBindFD(at, family.feature, fd, ops, err, true, nil)
	}
	return finishTransparentBindFD(at, family.feature, fd, ops, nil, false, nil)
}

func selectTransparentBindCandidate(ctx context.Context, family transparentBindProbeFamily, ops transparentBindProbeOps) (netip.Addr, bool, error) {
	for _, candidate := range family.candidates {
		if err := ctx.Err(); err != nil {
			return netip.Addr{}, false, err
		}
		assigned, err := ops.addressAssigned(candidate)
		if err != nil {
			return netip.Addr{}, false, err
		}
		if err := ctx.Err(); err != nil {
			return netip.Addr{}, false, err
		}
		if !assigned {
			return candidate, true, nil
		}
	}
	return netip.Addr{}, false, nil
}

func finishTransparentBindFD(at time.Time, feature FeatureID, fd int, ops transparentBindProbeOps, probeErr error, semantic bool, cancelErr error) (FeatureEvidence, bool, error) {
	closeErr := ops.close(fd)
	if cancelErr != nil {
		return FeatureEvidence{}, closeErr == nil, errors.Join(cancelErr, closeErr)
	}
	if closeErr != nil {
		return cleanupFailureEvidence(feature, at, errors.Join(closeErr, probeErr)), false, nil
	}
	if probeErr == nil {
		return availableEvidence(feature, at, SourceRuntimeRoundTrip), true, nil
	}
	if semantic {
		return semanticFailureEvidence(feature, at, probeErr), true, nil
	}
	return classifiedOrFailed(feature, at, probeErr), true, nil
}

func transparentBindSockaddr(address netip.Addr) (unix.Sockaddr, error) {
	address = address.Unmap()
	switch {
	case address.Is4():
		return &unix.SockaddrInet4{Addr: address.As4()}, nil
	case address.Is6() && address.Zone() == "":
		return &unix.SockaddrInet6{Addr: address.As16()}, nil
	default:
		return nil, fmt.Errorf("invalid transparent bind address %q", address)
	}
}

func validateTransparentBindSockname(expected netip.Addr, socketName unix.Sockaddr) error {
	expected = expected.Unmap()
	switch address := socketName.(type) {
	case *unix.SockaddrInet4:
		actual := netip.AddrFrom4(address.Addr)
		if !expected.Is4() || actual != expected {
			return fmt.Errorf("transparent bind socket address=%s want %s", actual, expected)
		}
		if address.Port <= 0 || address.Port > 65535 {
			return fmt.Errorf("transparent bind socket port=%d", address.Port)
		}
	case *unix.SockaddrInet6:
		actual := netip.AddrFrom16(address.Addr)
		if !expected.Is6() || actual != expected || address.ZoneId != 0 {
			return fmt.Errorf("transparent bind socket address=%s zone=%d want %s", actual, address.ZoneId, expected)
		}
		if address.Port <= 0 || address.Port > 65535 {
			return fmt.Errorf("transparent bind socket port=%d", address.Port)
		}
	default:
		return fmt.Errorf("transparent bind returned socket address type %T", socketName)
	}
	return nil
}

func transparentBindAddressAssigned(candidate netip.Addr) (bool, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false, err
	}
	candidate = candidate.Unmap()
	for _, address := range addresses {
		actual, err := transparentBindInterfaceAddress(address)
		if err != nil {
			return false, err
		}
		if actual.Unmap() == candidate {
			return true, nil
		}
	}
	return false, nil
}

func transparentBindInterfaceAddress(address net.Addr) (netip.Addr, error) {
	var ip net.IP
	switch value := address.(type) {
	case *net.IPNet:
		ip = value.IP
	case *net.IPAddr:
		ip = value.IP
	default:
		return netip.Addr{}, fmt.Errorf("unexpected interface address type %T", address)
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid interface address %q", address)
	}
	return parsed.Unmap(), nil
}
