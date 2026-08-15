package engine

import (
	"context"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

const selectorQualityObservationBudget = 50 * time.Millisecond

type pathQualityTicket struct {
	sequence  uint64
	supported bool
}

func (s *pathSlot) requestQualityObservation() pathQualityTicket {
	if s == nil || s.conn == nil {
		return pathQualityTicket{}
	}
	if _, ok := s.conn.(transport.PathQualityReader); !ok {
		return pathQualityTicket{}
	}
	s.qualityObserverMu.Lock()
	if s.qualityObserverStopped {
		ticket := pathQualityTicket{sequence: s.qualityObserverSeq, supported: true}
		s.qualityObserverMu.Unlock()
		return ticket
	}
	if !s.qualityObserverStarted {
		s.qualityObserverStarted = true
		s.qualityObserverRequest = make(chan struct{}, 1)
		s.qualityObserverWake = make(chan struct{})
		s.qualityObserverStop = make(chan struct{})
		s.qualityObserverDone = make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		s.qualityObserverCancel = cancel
		go s.runQualityObserver(ctx)
	}
	ticket := pathQualityTicket{sequence: s.qualityObserverSeq, supported: true}
	requests := s.qualityObserverRequest
	s.qualityObserverMu.Unlock()
	select {
	case requests <- struct{}{}:
	default:
	}
	return ticket
}

func (s *pathSlot) runQualityObserver(ctx context.Context) {
	s.qualityObserverMu.Lock()
	requests := s.qualityObserverRequest
	stop := s.qualityObserverStop
	done := s.qualityObserverDone
	s.qualityObserverMu.Unlock()
	defer close(done)
	for {
		select {
		case <-stop:
			return
		case <-requests:
		}

		observationCtx, cancel := context.WithTimeout(ctx, selectorQualityObservationBudget)
		quality, ok := readPathQuality(observationCtx, s.conn)
		cancel()
		s.qualityObserverMu.Lock()
		if s.qualityObserverStopped {
			s.qualityObserverMu.Unlock()
			return
		}
		if ok {
			s.qualityObserverSeq++
			s.qualityObserverSample = quality
			s.qualityObserverSampled = true
			close(s.qualityObserverWake)
			s.qualityObserverWake = make(chan struct{})
		}
		s.qualityObserverMu.Unlock()
	}
}

func readPathQuality(ctx context.Context, conn transport.PathConn) (transport.PathQuality, bool) {
	if conn == nil {
		return transport.PathQuality{}, false
	}
	reader, ok := conn.(transport.PathQualityReader)
	if !ok {
		return transport.PathQuality{}, false
	}
	quality, err := reader.QualityContext(ctx)
	return quality, err == nil
}

func (s *pathSlot) awaitQualityObservation(
	ctx context.Context,
	ticket pathQualityTicket,
) (transport.PathQuality, bool) {
	if s == nil || !ticket.supported {
		return transport.PathQuality{}, false
	}
	for {
		s.qualityObserverMu.Lock()
		quality := s.qualityObserverSample
		sampled := s.qualityObserverSampled
		if sampled && s.qualityObserverSeq > ticket.sequence {
			s.qualityObserverMu.Unlock()
			return quality, true
		}
		if s.qualityObserverStopped || !s.qualityObserverStarted {
			s.qualityObserverMu.Unlock()
			return quality, sampled
		}
		wake := s.qualityObserverWake
		stop := s.qualityObserverStop
		s.qualityObserverMu.Unlock()
		select {
		case <-ctx.Done():
			return quality, sampled
		case <-stop:
			return quality, sampled
		case <-wake:
		}
	}
}

func (s *pathSlot) latestObservedQuality() transport.PathQuality {
	if s == nil {
		return transport.PathQuality{}
	}
	ticket := s.requestQualityObservation()
	if !ticket.supported {
		return transport.PathQuality{}
	}
	s.qualityObserverMu.Lock()
	quality := s.qualityObserverSample
	s.qualityObserverMu.Unlock()
	return quality
}

func (s *pathSlot) stopQualityObserver() {
	if s == nil {
		return
	}
	s.qualityObserverMu.Lock()
	if s.qualityObserverStopped {
		s.qualityObserverMu.Unlock()
		return
	}
	s.qualityObserverStopped = true
	cancel := s.qualityObserverCancel
	if s.qualityObserverStarted {
		close(s.qualityObserverStop)
		close(s.qualityObserverWake)
		s.qualityObserverWake = make(chan struct{})
	}
	s.qualityObserverMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *pathSlot) waitQualityObserver() {
	if s == nil {
		return
	}
	s.qualityObserverMu.Lock()
	started := s.qualityObserverStarted
	done := s.qualityObserverDone
	s.qualityObserverMu.Unlock()
	if started && done != nil {
		<-done
	}
}

func observePathQualities(
	slots []*pathSlot,
	budget time.Duration,
) map[*pathSlot]transport.PathQuality {
	qualities := make(map[*pathSlot]transport.PathQuality, len(slots))
	if len(slots) == 0 {
		return qualities
	}
	if budget <= 0 {
		budget = selectorQualityObservationBudget
	}
	tickets := make(map[*pathSlot]pathQualityTicket, len(slots))
	for _, slot := range slots {
		if slot != nil {
			tickets[slot] = slot.requestQualityObservation()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	for _, slot := range slots {
		if slot == nil {
			continue
		}
		if quality, ok := slot.awaitQualityObservation(ctx, tickets[slot]); ok {
			qualities[slot] = quality
		}
	}
	return qualities
}
