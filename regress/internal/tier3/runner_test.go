package tier3

import (
	"reflect"
	"testing"
)

func TestBuildGoTestArgsDefault(t *testing.T) {
	got := buildGoTestArgs(Options{})
	want := []string{"test", "-json", "-count=1", "-timeout", "6m", "./internal/matrix/..."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%#v want %#v", got, want)
	}
}

func TestBuildGoTestArgsCase(t *testing.T) {
	got := buildGoTestArgs(Options{Case: "TestStreamFreedom"})
	want := []string{"test", "-json", "-count=1", "-timeout", "6m", "-run", "^TestStreamFreedom$", "./internal/matrix/..."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%#v want %#v", got, want)
	}
}
