package tcpquarantine

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	nftFamily     = "inet"
	inputChain    = "input"
	outputChain   = "output"
	chainType     = "filter"
	chainPolicy   = "accept"
	chainPriority = -300
)

type nftSpec struct {
	table   string
	comment string
	tuple   Tuple
}

func newNFTSpec(owner ownerToken, transactionID TransactionID, tuple Tuple) nftSpec {
	ownerHex := hex.EncodeToString(owner[:])
	transactionHex := hex.EncodeToString(transactionID[:])
	name := "rendr_q_" + ownerHex + "_" + transactionHex
	return nftSpec{table: name, comment: name, tuple: tuple}
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

func listTablesArgs() []string {
	return []string{"-j", "list", "tables"}
}
