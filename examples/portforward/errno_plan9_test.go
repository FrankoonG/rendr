package main

import "errors"

// plan9 has no errnos: a reset never matches (stopResetsVisible is false
// there, and the refusal rows need an errno: plan9 is a compile-only
// target of this package's tests).
var errConnReset = errors.New("connection reset (no errno on plan9)")
