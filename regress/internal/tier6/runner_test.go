package tier6

import "testing"

func TestCaseMatches(t *testing.T) {
	if !caseMatches("", "T6.graph.compat-mode") {
		t.Fatal("empty filter should match")
	}
	if !caseMatches("T6.graph.compat-mode", "T6.graph.compat-mode") {
		t.Fatal("exact filter should match")
	}
	if caseMatches("T6.peak.A-to-bulk-bond", "T6.graph.compat-mode") {
		t.Fatal("different case should not match")
	}
}
