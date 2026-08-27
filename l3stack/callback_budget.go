package l3stack

import "sync"

const l3StackProcessOptionalCallbackLimit = 64

var l3StackProcessOptionalCallbackSlots = make(chan struct{}, l3StackProcessOptionalCallbackLimit)

func tryAcquireL3StackOptionalCallback() (func(), bool) {
	select {
	case l3StackProcessOptionalCallbackSlots <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-l3StackProcessOptionalCallbackSlots })
		}, true
	default:
		return nil, false
	}
}
