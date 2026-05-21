package tier5

import "testing"

func TestCaseMatches(t *testing.T) {
	if !caseMatches("", "T5.1-tcprepair-privileged") {
		t.Fatal("empty filter should match")
	}
	if !caseMatches("T5.3-tcprepair-unprivileged", "T5.3-tcprepair-unprivileged") {
		t.Fatal("exact filter should match")
	}
	if caseMatches("T5.4-gvisor-unprivileged", "T5.3-tcprepair-unprivileged") {
		t.Fatal("different case should not match")
	}
}
