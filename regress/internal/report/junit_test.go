package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSuiteFailureSemantics(t *testing.T) {
	tests := []struct {
		name string
		c    Case
		fail bool
	}{
		{name: "pass", c: Case{Name: "pass", Tier: "T"}},
		{name: "failure", c: Case{Name: "failure", Tier: "T", Failure: "boom"}, fail: true},
		{name: "invalid", c: Case{Name: "invalid", Tier: "T", InvalidReason: "stimulus missing"}, fail: true},
		{name: "mandatory skip", c: Case{Name: "skip", Tier: "T", SkipReason: "dependency missing"}, fail: true},
		{name: "optional skip", c: Case{Name: "optional", Tier: "T", SkipReason: "not requested", Optional: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New()
			s.Add(tt.c)
			if got := s.AnyFailed(); got != tt.fail {
				t.Fatalf("AnyFailed()=%v want %v", got, tt.fail)
			}
			if got := s.AnyFailedAt("T"); got != tt.fail {
				t.Fatalf("AnyFailedAt()=%v want %v", got, tt.fail)
			}
		})
	}
}

func TestMandatorySkipAndInvalidAreJUnitFailures(t *testing.T) {
	s := New()
	s.Add(Case{Name: "skip", Tier: "T", SkipReason: "missing"})
	s.Add(Case{Name: "invalid", Tier: "T", InvalidReason: "no stimulus"})
	s.Add(Case{Name: "optional", Tier: "T", SkipReason: "not selected", Optional: true})

	path := filepath.Join(t.TempDir(), "junit.xml")
	if err := s.WriteJUnit(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{`failures="2"`, `skipped="1"`, `message="mandatory case skipped"`, `message="invalid"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("JUnit missing %q:\n%s", want, text)
		}
	}
}
