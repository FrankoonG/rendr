//go:build linux && amd64 && rendr_experimental_gvisor

package gvisor

import "github.com/FrankoonG/rendr/internal/leafmobility"

func expectedPacketLinkOperation() leafmobility.Operation {
	return leafmobility.OperationGVisorLinkRebind
}
