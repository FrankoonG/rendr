package smoke

import (
	"fmt"

	quictransport "github.com/FrankoonG/rendr/transport/quic"
)

const g3RequiredUDPBufferBytes = int64(quictransport.DefaultUDPBufferBytes)
const g3RequiredLinuxEffectiveUDPBufferBytes = 2 * g3RequiredUDPBufferBytes

func validateG3EffectiveUDPBuffers(receiveBytes, sendBytes int64) error {
	if receiveBytes < g3RequiredLinuxEffectiveUDPBufferBytes || sendBytes < g3RequiredLinuxEffectiveUDPBufferBytes {
		return fmt.Errorf(
			"G3 100k-pps prerequisite unavailable: effective SO_RCVBUF=%d SO_SNDBUF=%d; want both >=%d after requesting %d",
			receiveBytes, sendBytes, g3RequiredLinuxEffectiveUDPBufferBytes, g3RequiredUDPBufferBytes,
		)
	}
	return nil
}
