package main

import "errors"

// plan9 has no errnos: a reset never matches (stopResetsVisible is false
// there).
var errConnReset = errors.New("connection reset (no errno on plan9)")
