package tcpquarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const (
	nftFamily     = "inet"
	inputChain    = "input"
	outputChain   = "output"
	chainType     = "filter"
	chainPolicy   = "accept"
	chainPriority = -300
	managedPrefix = "rendr_q2_"
	legacyPrefix  = "rendr_q_"
)

type nftSpec struct {
	table   string
	comment string
	tuple   Tuple
}

type managedTableIdentity struct {
	process       processIdentity
	owner         ownerToken
	transactionID TransactionID
	tuple         Tuple
}

func newNFTSpec(process processIdentity, owner ownerToken, transactionID TransactionID, tuple Tuple) nftSpec {
	ownerHex := hex.EncodeToString(owner[:])
	transactionHex := hex.EncodeToString(transactionID[:])
	local := tuple.Local.Addr().As4()
	remote := tuple.Remote.Addr().As4()
	name := fmt.Sprintf(
		managedPrefix+"%016x_%016x_%016x_%016x_%s_%s_%s_%04x_%s_%04x",
		process.pidNamespaceDevice,
		process.pidNamespaceInode,
		process.pid,
		process.startTime,
		ownerHex,
		transactionHex,
		hex.EncodeToString(local[:]),
		tuple.Local.Port(),
		hex.EncodeToString(remote[:]),
		tuple.Remote.Port(),
	)
	return nftSpec{table: name, comment: managedTableComment(name), tuple: tuple}
}

func managedTableComment(table string) string {
	digest := sha256.Sum256([]byte(table))
	return "rendr_q2c_" + hex.EncodeToString(digest[:])
}

func parseManagedTableName(name string) (managedTableIdentity, bool, error) {
	if !strings.HasPrefix(name, managedPrefix) {
		return managedTableIdentity{}, false, nil
	}
	parts := strings.Split(strings.TrimPrefix(name, managedPrefix), "_")
	lengths := [...]int{16, 16, 16, 16, tokenSize * 2, tokenSize * 2, 8, 4, 8, 4}
	if len(parts) != len(lengths) {
		return managedTableIdentity{}, true, fmt.Errorf("%w: table %q has %d identity fields", ErrManagedTableMalformed, name, len(parts))
	}
	for index, length := range lengths {
		if len(parts[index]) != length {
			return managedTableIdentity{}, true, fmt.Errorf("%w: table %q field %d has length %d", ErrManagedTableMalformed, name, index, len(parts[index]))
		}
	}
	parseScalar := func(index int) (uint64, error) {
		value, err := strconv.ParseUint(parts[index], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: table %q field %d: %v", ErrManagedTableMalformed, name, index, err)
		}
		return value, nil
	}
	var identity managedTableIdentity
	var err error
	if identity.process.pidNamespaceDevice, err = parseScalar(0); err != nil {
		return managedTableIdentity{}, true, err
	}
	if identity.process.pidNamespaceInode, err = parseScalar(1); err != nil {
		return managedTableIdentity{}, true, err
	}
	if identity.process.pid, err = parseScalar(2); err != nil {
		return managedTableIdentity{}, true, err
	}
	if identity.process.startTime, err = parseScalar(3); err != nil {
		return managedTableIdentity{}, true, err
	}
	if !identity.process.valid() {
		return managedTableIdentity{}, true, fmt.Errorf("%w: table %q has an invalid process identity", ErrManagedTableMalformed, name)
	}
	if _, err := hex.Decode(identity.owner[:], []byte(parts[4])); err != nil || identity.owner.isZero() {
		return managedTableIdentity{}, true, fmt.Errorf("%w: table %q has an invalid owner token", ErrManagedTableMalformed, name)
	}
	if _, err := hex.Decode(identity.transactionID[:], []byte(parts[5])); err != nil || identity.transactionID.isZero() {
		return managedTableIdentity{}, true, fmt.Errorf("%w: table %q has an invalid transaction ID", ErrManagedTableMalformed, name)
	}
	local, err := parseManagedIPv4(parts[6])
	if err != nil {
		return managedTableIdentity{}, true, fmt.Errorf("%w: table %q local address: %v", ErrManagedTableMalformed, name, err)
	}
	localPort, err := strconv.ParseUint(parts[7], 16, 16)
	if err != nil {
		return managedTableIdentity{}, true, fmt.Errorf("%w: table %q local port: %v", ErrManagedTableMalformed, name, err)
	}
	remote, err := parseManagedIPv4(parts[8])
	if err != nil {
		return managedTableIdentity{}, true, fmt.Errorf("%w: table %q remote address: %v", ErrManagedTableMalformed, name, err)
	}
	remotePort, err := strconv.ParseUint(parts[9], 16, 16)
	if err != nil {
		return managedTableIdentity{}, true, fmt.Errorf("%w: table %q remote port: %v", ErrManagedTableMalformed, name, err)
	}
	identity.tuple = Tuple{
		Local:  netip.AddrPortFrom(local, uint16(localPort)),
		Remote: netip.AddrPortFrom(remote, uint16(remotePort)),
	}
	if err := identity.tuple.validate(); err != nil {
		return managedTableIdentity{}, true, fmt.Errorf("%w: table %q tuple: %v", ErrManagedTableMalformed, name, err)
	}
	return identity, true, nil
}

func parseManagedIPv4(encoded string) (netip.Addr, error) {
	var address [4]byte
	if _, err := hex.Decode(address[:], []byte(encoded)); err != nil {
		return netip.Addr{}, err
	}
	return netip.AddrFrom4(address), nil
}

func (identity managedTableIdentity) spec() nftSpec {
	return newNFTSpec(identity.process, identity.owner, identity.transactionID, identity.tuple)
}

func (spec nftSpec) installBatch() []byte {
	localAddress := spec.tuple.Local.Addr().String()
	remoteAddress := spec.tuple.Remote.Addr().String()
	localPort := spec.tuple.Local.Port()
	remotePort := spec.tuple.Remote.Port()

	var batch strings.Builder
	fmt.Fprintf(&batch, "add table %s %s\n", nftFamily, spec.table)
	fmt.Fprintf(&batch, "add chain %s %s %s { type %s hook %s priority %d; policy %s; }\n",
		nftFamily, spec.table, inputChain, chainType, inputChain, chainPriority, chainPolicy)
	fmt.Fprintf(&batch, "add chain %s %s %s { type %s hook %s priority %d; policy %s; }\n",
		nftFamily, spec.table, outputChain, chainType, outputChain, chainPriority, chainPolicy)
	fmt.Fprintf(&batch,
		"add rule %s %s %s ip saddr %s ip daddr %s tcp sport %d tcp dport %d counter drop comment \"%s\"\n",
		nftFamily, spec.table, inputChain, remoteAddress, localAddress, remotePort, localPort, spec.comment)
	fmt.Fprintf(&batch,
		"add rule %s %s %s ip saddr %s ip daddr %s tcp sport %d tcp dport %d counter drop comment \"%s\"\n",
		nftFamily, spec.table, outputChain, localAddress, remoteAddress, localPort, remotePort, spec.comment)
	return []byte(batch.String())
}

func (spec nftSpec) deleteBatch() []byte {
	return []byte(fmt.Sprintf("delete table %s %s\n", nftFamily, spec.table))
}

func (spec nftSpec) listTableArgs() []string {
	return []string{"-j", "list", "table", nftFamily, spec.table}
}

func preflightInstallArgs() []string {
	return []string{"-c", "-f", "-"}
}

func nftSchemaProbeArgs() []string {
	return []string{"-j", "list", "tables"}
}

func listTablesArgs() []string {
	return []string{"-j", "list", "tables"}
}
