package tcprepair_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/transport/tcprepair"
)

func TestProbeDoesNotPromiseBackendFallback(t *testing.T) {
	err := tcprepair.Available()
	if err == nil {
		return
	}
	if strings.Contains(strings.ToLower(err.Error()), "gvisor") {
		t.Fatalf("capability probe promised a mobility backend: %v", err)
	}
}

func TestNoPublicSocketMutationAPI(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller did not report the package directory")
	}
	dir := filepath.Dir(sourceFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	banned := map[string]bool{
		"MigratePathLocalAddr": true,
		"Restore":              true,
		"Snapshot":             true,
		"State":                true,
		"Wrap":                 true,
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, declaration := range file.Decls {
			switch declaration := declaration.(type) {
			case *ast.FuncDecl:
				if declaration.Recv == nil && banned[declaration.Name.Name] {
					t.Errorf("production package exports forbidden mutation function %s", declaration.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range declaration.Specs {
					typeSpec, ok := spec.(*ast.TypeSpec)
					if ok && banned[typeSpec.Name.Name] {
						t.Errorf("production package exports forbidden mutation type %s", typeSpec.Name.Name)
					}
				}
			}
		}
	}
}
