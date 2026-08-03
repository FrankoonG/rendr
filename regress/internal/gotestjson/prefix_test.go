package gotestjson

import (
	"context"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func TestExecutorRunsGoThroughCommandPrefix(t *testing.T) {
	var gotName string
	var gotArgs []string
	executor := syntheticExecutor()
	executor.commandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecutorHelperProcess$")
	}
	request := syntheticRequest(t, "pass", required("TestFirst", "TestSecond"))
	request.CommandPrefix = []string{"setpriv", "--bounding-set=-net_admin"}

	result, err := executor.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if gotName != "setpriv" {
		t.Fatalf("executable = %q, want setpriv", gotName)
	}
	wantArgs := append([]string{"--bounding-set=-net_admin", "synthetic-go"}, buildArgs(request)...)
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("args = %#v, want %#v", gotArgs, wantArgs)
	}
	wantCommand := append([]string{"setpriv", "--bounding-set=-net_admin", "synthetic-go"}, buildArgs(request)...)
	if !reflect.DeepEqual(result.Command, wantCommand) {
		t.Fatalf("recorded command = %#v, want %#v", result.Command, wantCommand)
	}
}

func TestExecutorRejectsEmptyCommandPrefixEntry(t *testing.T) {
	started := false
	executor := Executor{
		commandContext: func(context.Context, string, ...string) *exec.Cmd {
			started = true
			return nil
		},
	}
	request := syntheticRequest(t, "pass", required("TestOne"))
	request.CommandPrefix = []string{"setpriv", ""}

	result, err := executor.Run(context.Background(), request)
	assertValidationError(t, err)
	if started {
		t.Fatal("invalid command prefix started a command")
	}
	if !result.HasIssue(IssueInvalidConfig) {
		t.Fatalf("issues = %+v, want invalid config", result.Issues)
	}
}
