package l3ingress

import "sync"

const l3IngressProcessCallbackLimit = 64

type l3IngressCallbackClass uint8

const (
	l3IngressCallbackAuthoritative l3IngressCallbackClass = iota
	l3IngressCallbackOptional
	l3IngressCallbackEgressInvoke
	l3IngressCallbackEgressCleanup
	l3IngressCallbackClassCount
)

var l3IngressProcessCallbackSlots = [l3IngressCallbackClassCount]chan struct{}{
	l3IngressCallbackAuthoritative: make(chan struct{}, l3IngressProcessCallbackLimit),
	l3IngressCallbackOptional:      make(chan struct{}, l3IngressProcessCallbackLimit),
	l3IngressCallbackEgressInvoke:  make(chan struct{}, l3IngressProcessCallbackLimit),
	l3IngressCallbackEgressCleanup: make(chan struct{}, l3IngressProcessCallbackLimit),
}

func tryAcquireL3IngressCallback(class l3IngressCallbackClass) (func(), bool) {
	if class >= l3IngressCallbackClassCount {
		return nil, false
	}
	slots := l3IngressProcessCallbackSlots[class]
	select {
	case slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-slots }) }, true
	default:
		return nil, false
	}
}
