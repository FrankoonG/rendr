//go:build !linux || !amd64

package gvisor

import "github.com/FrankoonG/rendr/internal/leafmobility"

func expectedPacketLinkOperation() leafmobility.Operation { return 0 }
