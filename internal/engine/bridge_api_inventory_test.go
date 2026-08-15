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

func TestBridgeTableExportedMethodInventory(t *testing.T) {
	want := []string{
		"Abort",
		"Activate",
		"ActivateSession",
		"AssignSession",
		"Len",
		"Lookup",
		"RemoveActive",
		"Reserve",
		"Snapshot",
		"WaitActive",
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

	var got []string
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
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || !ast.IsExported(function.Name.Name) {
				continue
			}
			if receiverTypeName(function.Recv.List[0].Type) == "BridgeTable" {
				got = append(got, function.Name.Name)
			}
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("BridgeTable exported methods=%v, want canonical inventory %v", got, want)
	}
}

func receiverTypeName(expression ast.Expr) string {
	switch expression := expression.(type) {
	case *ast.Ident:
		return expression.Name
	case *ast.StarExpr:
		return receiverTypeName(expression.X)
	default:
		return ""
	}
}
