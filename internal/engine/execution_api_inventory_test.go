package engine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestRecursiveExecutionHasNoFlatCompatibilitySurface(t *testing.T) {
	forbiddenFunctions := []string{
		"dispatchBond",
		"dispatchForExecutionKind",
		"dispatchRace",
		"dispatchSingle",
		"migrateOwnerDecision",
		"recordPathPolicyDecision",
	}
	forbiddenEngineMethods := []string{"ConfigureExecution", "Migrate", "Mode"}
	forbiddenEngineFields := []string{
		"bondCursor",
		"bondPinLeft",
		"bondStuckSkips",
		"dispatchScope",
		"mode",
	}

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller did not report the package directory")
	}
	dir := filepath.Dir(sourceFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	functionSet := make(map[string]bool)
	methodSet := make(map[string]bool)
	fieldSet := make(map[string]bool)
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
				if declaration.Recv == nil {
					functionSet[declaration.Name.Name] = true
					continue
				}
				if receiverTypeName(declaration.Recv.List[0].Type) == "Engine" {
					methodSet[declaration.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, specification := range declaration.Specs {
					typeSpec, ok := specification.(*ast.TypeSpec)
					if !ok || typeSpec.Name.Name != "Engine" {
						continue
					}
					structure, ok := typeSpec.Type.(*ast.StructType)
					if !ok {
						t.Fatal("Engine is not a struct")
					}
					for _, field := range structure.Fields.List {
						for _, name := range field.Names {
							fieldSet[name.Name] = true
						}
					}
				}
			}
		}
	}

	assertAbsent := func(kind string, forbidden []string, present map[string]bool) {
		t.Helper()
		var found []string
		for _, name := range forbidden {
			if present[name] {
				found = append(found, name)
			}
		}
		slices.Sort(found)
		if len(found) != 0 {
			t.Fatalf("legacy flat execution %s returned: %v", kind, found)
		}
	}
	assertAbsent("functions", forbiddenFunctions, functionSet)
	assertAbsent("Engine methods", forbiddenEngineMethods, methodSet)
	assertAbsent("Engine fields", forbiddenEngineFields, fieldSet)
}
