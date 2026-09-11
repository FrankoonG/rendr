package tcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const tcpPackagePath = "github.com/FrankoonG/rendr/transport/tcp"

type listedPackage struct {
	ImportPath string
	GoFiles    []string
}

func TestRootDependencyClosureIncludesDefaultTCPRepair(t *testing.T) {
	root := findModuleRoot(t)
	defaultPackages := listLinuxRootClosure(t, root, "")
	taggedPackages := listLinuxRootClosure(t, root, "rendr_experimental_tcprepair")

	for _, dependency := range []string{
		"github.com/FrankoonG/rendr/internal/tcprepair",
		"github.com/FrankoonG/rendr/internal/tcpquarantine",
	} {
		if _, ok := defaultPackages[dependency]; !ok {
			t.Errorf("default root dependency closure omits TCP_REPAIR implementation %q", dependency)
		}
		if _, ok := taggedPackages[dependency]; !ok {
			t.Errorf("tagged root dependency closure omits TCP_REPAIR implementation %q", dependency)
		}
	}

	defaultTCP, ok := defaultPackages[tcpPackagePath]
	if !ok {
		t.Fatalf("default root dependency closure does not contain %s", tcpPackagePath)
	}
	taggedTCP, ok := taggedPackages[tcpPackagePath]
	if !ok {
		t.Fatalf("tagged root dependency closure does not contain %s", tcpPackagePath)
	}

	implementationFiles := []string{
		"mobility_provider_linux.go",
		"owned_claim_linux.go",
		"refresh_monitor_linux.go",
		"repair_driver_linux.go",
		"repair_executor_linux.go",
	}
	for _, file := range implementationFiles {
		if !containsString(defaultTCP.GoFiles, file) {
			t.Errorf("default transport/tcp source closure omits %q", file)
		}
		if !containsString(taggedTCP.GoFiles, file) {
			t.Errorf("tagged transport/tcp source closure omits %q", file)
		}
	}
	for _, file := range []string{"owned_claim_default_linux.go", "refresh_monitor_default_linux.go"} {
		if containsString(defaultTCP.GoFiles, file) {
			t.Errorf("default transport/tcp source closure retains removed stub %q", file)
		}
		if containsString(taggedTCP.GoFiles, file) {
			t.Errorf("tagged transport/tcp source closure retains removed stub %q", file)
		}
	}
	if strings.Join(defaultTCP.GoFiles, "\x00") != strings.Join(taggedTCP.GoFiles, "\x00") {
		t.Errorf("rendr_experimental_tcprepair still changes product GoFiles: default=%v tagged=%v", defaultTCP.GoFiles, taggedTCP.GoFiles)
	}
}

func listLinuxRootClosure(t *testing.T, root, tags string) map[string]listedPackage {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "-json", "-tags="+tags, ".")
	cmd.Dir = root
	cmd.Env = replaceEnvironment(os.Environ(), map[string]string{
		"CGO_ENABLED": "0",
		"GOARCH":      "amd64",
		"GOFLAGS":     "",
		"GOOS":        "linux",
		"GOWORK":      "off",
	})
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list root closure with tags %q: %v\n%s", tags, err, output)
	}
	packages := make(map[string]listedPackage)
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var pkg listedPackage
		if err := decoder.Decode(&pkg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode go list root closure with tags %q: %v", tags, err)
		}
		packages[pkg.ImportPath] = pkg
	}
	return packages
}

func findModuleRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		goMod := filepath.Join(directory, "go.mod")
		contents, readErr := os.ReadFile(goMod)
		if readErr == nil && bytes.Contains(contents, []byte("module github.com/FrankoonG/rendr")) {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatalf("find rendr module root from %s", directory)
		}
		directory = parent
	}
}

func replaceEnvironment(environment []string, replacements map[string]string) []string {
	result := make([]string, 0, len(environment)+len(replacements))
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if ok {
			if _, replaced := replacements[strings.ToUpper(name)]; replaced {
				continue
			}
		}
		result = append(result, entry)
	}
	for name, value := range replacements {
		result = append(result, fmt.Sprintf("%s=%s", name, value))
	}
	return result
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
