//go:build !linux

package quic

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sort"
)

func openRouteChangeWatcherPlatform(context.Context) (routeChangeWatcher, error) {
	return nil, errors.New("quic: route change watcher is unsupported")
}

func observeRouteSourcePlatform(ctx context.Context, remote *net.UDPAddr) (routeObservation, error) {
	local, err := dialRouteSource(ctx, remote)
	if err != nil {
		return routeObservation{}, err
	}
	local.Port = 0
	type interfaceFact struct {
		index int
		mtu   int
		flags net.Flags
		name  string
	}
	var facts []interfaceFact
	interfaces, err := net.Interfaces()
	if err != nil {
		return routeObservation{}, err
	}
	for _, iface := range interfaces {
		addresses, addressErr := iface.Addrs()
		if addressErr != nil {
			return routeObservation{}, addressErr
		}
		for _, address := range addresses {
			ip, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil && ip.Equal(local.IP) {
				facts = append(facts, interfaceFact{
					index: iface.Index, mtu: iface.MTU, flags: iface.Flags, name: iface.Name,
				})
				break
			}
		}
	}
	if len(facts) == 0 {
		return routeObservation{}, errors.New("quic: selected source is not assigned to a local interface")
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].index < facts[j].index })
	hash := sha256.New()
	_, _ = hash.Write([]byte("QRS1"))
	writeRouteBytes(hash, canonicalIP(remote.IP))
	writeRouteString(hash, remote.Zone)
	writeRouteBytes(hash, canonicalIP(local.IP))
	writeRouteString(hash, local.Zone)
	var scalar [8]byte
	for _, fact := range facts {
		binary.BigEndian.PutUint32(scalar[:4], uint32(fact.index))
		_, _ = hash.Write(scalar[:4])
		binary.BigEndian.PutUint32(scalar[:4], uint32(fact.mtu))
		_, _ = hash.Write(scalar[:4])
		binary.BigEndian.PutUint64(scalar[:], uint64(fact.flags))
		_, _ = hash.Write(scalar[:])
		writeRouteString(hash, fact.name)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return routeObservation{source: local, digest: digest}, nil
}
