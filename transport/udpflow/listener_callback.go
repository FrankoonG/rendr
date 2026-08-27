package udpflow

import (
	"fmt"
	"reflect"
	"time"
)

const (
	listenerCallbackCapacity = maxListenerFlows
	listenerCallbackGrace    = 200 * time.Millisecond
)

// ListenerCallbackFailureReason classifies an abnormal exit from a
// caller-supplied PacketConn method owned by Listener.
type ListenerCallbackFailureReason string

const (
	ListenerCallbackFailurePanic     ListenerCallbackFailureReason = "panic"
	ListenerCallbackFailureGoexit    ListenerCallbackFailureReason = "goexit"
	ListenerCallbackFailureTimeout   ListenerCallbackFailureReason = "timeout"
	ListenerCallbackFailureSaturated ListenerCallbackFailureReason = "saturated"
)

// ListenerCallbackError is a stable, machine-readable failure from an
// embedding-provided PacketConn method. Panic values are deliberately not
// formatted because their String methods are caller code too.
type ListenerCallbackError struct {
	Callback  string
	Reason    ListenerCallbackFailureReason
	PanicType string
}

func (e *ListenerCallbackError) Error() string {
	if e == nil {
		return "udpflow: listener callback failed"
	}
	if e.PanicType != "" {
		return fmt.Sprintf("udpflow: listener callback %s failed: %s (%s)", e.Callback, e.Reason, e.PanicType)
	}
	return fmt.Sprintf("udpflow: listener callback %s failed: %s", e.Callback, e.Reason)
}

type listenerCallbackClass uint8

const (
	listenerCallbackRead listenerCallbackClass = iota
	listenerCallbackClose
	listenerCallbackClassCount
)

type listenerCallbackExecutor struct {
	slots [listenerCallbackClassCount]chan struct{}
}

func newListenerCallbackExecutor(limit int) *listenerCallbackExecutor {
	if limit <= 0 {
		panic("udpflow: listener callback limit must be positive")
	}
	executor := &listenerCallbackExecutor{}
	for class := listenerCallbackClass(0); class < listenerCallbackClassCount; class++ {
		executor.slots[class] = make(chan struct{}, limit)
	}
	return executor
}

var listenerProcessCallbackExecutor = newListenerCallbackExecutor(listenerCallbackCapacity)

type listenerCallbackResult[T any] struct {
	value T
	err   error
}

type listenerCallbackTask[T any] struct {
	callback string
	done     chan struct{}
	result   listenerCallbackResult[T]
}

func startListenerCallback[T any](
	executor *listenerCallbackExecutor,
	callback string,
	class listenerCallbackClass,
	invoke func() (T, error),
) (*listenerCallbackTask[T], error) {
	if executor == nil || class >= listenerCallbackClassCount {
		return nil, &ListenerCallbackError{Callback: callback, Reason: ListenerCallbackFailureSaturated}
	}
	slots := executor.slots[class]
	select {
	case slots <- struct{}{}:
	default:
		return nil, &ListenerCallbackError{Callback: callback, Reason: ListenerCallbackFailureSaturated}
	}

	task := &listenerCallbackTask[T]{callback: callback, done: make(chan struct{})}
	go func() {
		result := listenerCallbackResult[T]{
			err: &ListenerCallbackError{Callback: callback, Reason: ListenerCallbackFailureGoexit},
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				panicType := "<nil>"
				if valueType := reflect.TypeOf(recovered); valueType != nil {
					panicType = valueType.String()
				}
				result = listenerCallbackResult[T]{err: &ListenerCallbackError{
					Callback: callback, Reason: ListenerCallbackFailurePanic, PanicType: panicType,
				}}
			}
			task.result = result
			<-slots
			close(task.done)
		}()
		result.value, result.err = invoke()
	}()
	return task, nil
}

func (task *listenerCallbackTask[T]) waitUntilStopped(stop <-chan struct{}) (zero T, err error) {
	if task == nil {
		return zero, &ListenerCallbackError{Reason: ListenerCallbackFailureSaturated}
	}
	select {
	case <-task.done:
		return task.result.value, task.result.err
	case <-stop:
	}

	timer := time.NewTimer(listenerCallbackGrace)
	defer timer.Stop()
	select {
	case <-task.done:
		return task.result.value, task.result.err
	case <-timer.C:
		return zero, &ListenerCallbackError{
			Callback: task.callback,
			Reason:   ListenerCallbackFailureTimeout,
		}
	}
}

func (task *listenerCallbackTask[T]) waitBounded() (zero T, err error) {
	if task == nil {
		return zero, &ListenerCallbackError{Reason: ListenerCallbackFailureSaturated}
	}
	timer := time.NewTimer(listenerCallbackGrace)
	defer timer.Stop()
	select {
	case <-task.done:
		return task.result.value, task.result.err
	case <-timer.C:
		return zero, &ListenerCallbackError{
			Callback: task.callback,
			Reason:   ListenerCallbackFailureTimeout,
		}
	}
}
