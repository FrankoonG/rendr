package quic

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
)

type routeObservation struct {
	source *net.UDPAddr
	digest [sha256.Size]byte
}

func (o routeObservation) valid() bool {
	return o.source != nil && len(o.source.IP) != 0 && !o.source.IP.IsUnspecified() &&
		o.digest != ([sha256.Size]byte{})
}

type routeObserver func(context.Context, *net.UDPAddr) (routeObservation, error)

// routeChangeWatcher is only an early wake-up hint. A notification never
// proves that the selected route changed; the owner must still obtain a fresh
// routeObservation before publishing mobility evidence.
type routeChangeWatcher interface {
	Events() <-chan struct{}
	Close()
}

type routeChangeWatcherFactory func(context.Context) (routeChangeWatcher, error)

func openRouteChangeWatcher(ctx context.Context) (routeChangeWatcher, error) {
	return openRouteChangeWatcherPlatform(ctx)
}

// observeRouteSource asks the host routing stack which source it would use
// for a fresh UDP path. The digest includes the selected source and every
// matching interface's stable identity and link flags. It intentionally
// excludes the ephemeral source port.
func observeRouteSource(ctx context.Context, remote *net.UDPAddr) (routeObservation, error) {
	return observeRouteSourcePlatform(ctx, remote)
}

func dialRouteSource(ctx context.Context, remote *net.UDPAddr) (*net.UDPAddr, error) {
	if ctx == nil {
		return nil, errors.New("quic: nil route/source context")
	}
	if remote == nil || len(remote.IP) == 0 || remote.IP.IsUnspecified() {
		return nil, errors.New("quic: invalid route/source destination")
	}
	network := "udp6"
	if remote.IP.To4() != nil {
		network = "udp4"
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, remote.String())
	if err != nil {
		return nil, err
	}
	local := addrAsUDP(conn.LocalAddr())
	closeErr := conn.Close()
	if closeErr != nil {
		return nil, closeErr
	}
	if local == nil || len(local.IP) == 0 || local.IP.IsUnspecified() {
		return nil, errors.New("quic: routing stack selected an unspecified source")
	}
	return local, nil
}

func canonicalIP(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return append([]byte(nil), v4...)
	}
	return append([]byte(nil), ip.To16()...)
}

type routeByteWriter interface{ Write([]byte) (int, error) }

func writeRouteBytes(writer routeByteWriter, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(value)
}

func writeRouteString(writer routeByteWriter, value string) {
	writeRouteBytes(writer, []byte(value))
}
