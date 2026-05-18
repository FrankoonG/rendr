package xrayglue

import (
	"testing"

	// Underscore-import the core package: confirms the dependency
	// resolves end-to-end (xray-core's heavy transitive tree all
	// downloaded and compilable) without yet wiring any factory.
	// The real glue lands in factory.go in a follow-up commit.
	_ "github.com/xtls/xray-core/core"
)

// TestXrayCoreImportable is a build-time smoke: it does nothing at
// runtime beyond verifying the xray-core/core package is importable
// from the regress submodule. If go.sum loses an entry or xray-core
// upstream changes break compile, this fails immediately at go test.
func TestXrayCoreImportable(t *testing.T) {
	t.Log("xray-core/core import resolves")
}
