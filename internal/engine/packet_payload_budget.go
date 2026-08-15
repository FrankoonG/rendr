package engine

import (
	"fmt"

	"github.com/FrankoonG/rendr/transport"
)

type pathFrameSizeReporter interface {
	MaxFrameSize() int
}

func (e *Engine) validatePacketPathFrameLimit(conn transport.PathConn) (int, bool, error) {
	if e == nil || !e.Packetized() || conn == nil {
		return 0, false, nil
	}
	reporter, ok := conn.(pathFrameSizeReporter)
	if !ok {
		return 0, false, nil
	}
	limit := reporter.MaxFrameSize()
	overhead := e.applicationPayloadOverhead()
	if limit < overhead {
		return 0, false, fmt.Errorf(
			"engine: packet path frame budget %d is smaller than session DATA envelope %d",
			limit, overhead,
		)
	}
	return limit, true, nil
}

func (e *Engine) tightenPacketFrameLimit(limit int) {
	if e == nil || limit <= 0 {
		return
	}
	for {
		current := e.packetFrameLimit.Load()
		if current != 0 && current <= int64(limit) {
			return
		}
		if e.packetFrameLimit.CompareAndSwap(current, int64(limit)) {
			return
		}
	}
}

func (e *Engine) packetPayloadLimit() int {
	limit := MaxPayload
	if e == nil {
		return limit
	}
	frameLimit := e.packetFrameLimit.Load()
	if frameLimit == 0 {
		return limit
	}
	carrierLimit := int(frameLimit) - e.applicationPayloadOverhead()
	if carrierLimit < limit {
		limit = carrierLimit
	}
	if limit < 0 {
		return 0
	}
	return limit
}

func (e *Engine) validatePacketPayloadSize(payloadBytes int) error {
	limit := e.packetPayloadLimit()
	if payloadBytes <= limit {
		return nil
	}
	return fmt.Errorf(
		"%w: payload is %d bytes, session limit is %d bytes",
		ErrPacketTooLarge, payloadBytes, limit,
	)
}
