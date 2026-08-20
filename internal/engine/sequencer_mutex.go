package engine

import (
	"net"
	"sync"
	"time"
)

// sequencerMutex preserves the existing Lock/Unlock surface while allowing an
// application DATA publisher to abandon lock acquisition at a dynamic write
// deadline. Internal protocol work always uses Lock and is never canceled by
// an application deadline.
type sequencerMutex struct {
	once   sync.Once
	permit chan struct{}
}

func (m *sequencerMutex) initialize() {
	m.once.Do(func() {
		m.permit = make(chan struct{}, 1)
		m.permit <- struct{}{}
	})
}

func (m *sequencerMutex) Lock() {
	m.initialize()
	<-m.permit
}

func (m *sequencerMutex) Unlock() {
	m.initialize()
	select {
	case m.permit <- struct{}{}:
	default:
		panic("engine: sequencer mutex unlocked without ownership")
	}
}

func (m *sequencerMutex) lockApplication(e *Engine) error {
	m.initialize()
	for {
		select {
		case <-m.permit:
		default:
			acquired := false
			for !acquired {
				deadline, wake, expired := e.writeDeadlineSnapshot()
				if expired {
					return ErrWriteDeadlineExceeded
				}
				timer, timerC := writeDeadlineTimer(deadline)
				select {
				case <-m.permit:
					stopDeadlineTimer(timer)
					acquired = true
				case <-wake:
					stopDeadlineTimer(timer)
				case <-timerC:
				case <-e.closed:
					stopDeadlineTimer(timer)
					if err := e.CloseErr(); err != nil {
						return err
					}
					return net.ErrClosed
				}
			}
		}

		target, replayWake := e.replayPublicationBarrierSnapshot()
		if target == 0 {
			return nil
		}
		if e.sendAckNext.Load() >= target {
			e.completeReplayPublicationBarrier(e.sendAckNext.Load())
			return nil
		}

		// Policy controls must remain able to preempt the replay that owns this
		// barrier. Return the sequencer permit while only the application caller
		// waits, then re-acquire and revalidate before allocating its SEQ.
		m.Unlock()
		deadline, deadlineWake, expired := e.writeDeadlineSnapshot()
		if expired {
			return ErrWriteDeadlineExceeded
		}
		timer, timerC := writeDeadlineTimer(deadline)
		select {
		case <-replayWake:
			stopDeadlineTimer(timer)
		case <-deadlineWake:
			stopDeadlineTimer(timer)
		case <-timerC:
		case <-e.closed:
			stopDeadlineTimer(timer)
			if err := e.CloseErr(); err != nil {
				return err
			}
			return net.ErrClosed
		}
	}
}

func writeDeadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	timer := time.NewTimer(time.Until(deadline))
	return timer, timer.C
}
