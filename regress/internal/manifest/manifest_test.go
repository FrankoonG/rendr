package manifest

import (
	"reflect"
	"strings"
	"testing"
)

func testSpecs() []Spec {
	return []Spec{Required("A", "T1"), Required("B", "T1"), Required("C", "T2")}
}

func TestSelectExactAndResume(t *testing.T) {
	tests := []struct {
		name string
		one  string
		from string
		want []string
	}{
		{name: "all", want: []string{"A", "B", "C"}},
		{name: "exact", one: "B", want: []string{"B"}},
		{name: "resume", from: "B", want: []string{"B", "C"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(testSpecs(), tt.one, tt.from)
			if err != nil {
				t.Fatal(err)
			}
			ids := make([]string, len(got))
			for i := range got {
				ids[i] = got[i].ID
			}
			if !reflect.DeepEqual(ids, tt.want) {
				t.Fatalf("ids=%v want %v", ids, tt.want)
			}
		})
	}
}

func TestSelectRejectsAmbiguousOrMissingFilters(t *testing.T) {
	for _, tc := range []struct {
		name string
		one  string
		from string
		want string
	}{
		{name: "both", one: "A", from: "B", want: "mutually exclusive"},
		{name: "missing exact", one: "missing", want: "--case"},
		{name: "missing resume", from: "missing", want: "--from-case"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Select(testSpecs(), tc.one, tc.from)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidateRejectsDuplicateIDs(t *testing.T) {
	err := Validate([]Spec{Required("same", "T1"), Required("same", "T2")})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("err=%v", err)
	}
}
