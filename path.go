package rendr

import "github.com/FrankoonG/rendr/transport"

// Path types are defined in the transport package so the engine
// (which lives below the public API) can use them without an import
// cycle. rendr re-exports them via type aliases so external callers
// continue to write rendr.PathSpec etc.

type PathSpec = transport.PathSpec
type PathInfo = transport.PathInfo
type PathQuality = transport.PathQuality
