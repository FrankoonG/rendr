package tier1

import (
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/caseexec"
)

func TestCommandTeardownFitsCaseJoinLimit(t *testing.T) {
	if got := tier1CommandWaitDelay + tier1ProcessCleanupTimeout; got >= caseexec.DefaultJoinTimeout {
		t.Fatalf("command teardown bound = %s, must be below case join limit %s", got, caseexec.DefaultJoinTimeout)
	}
}
