package rendr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/transport"
)

func TestV1PublicControlAndObservationInventory(t *testing.T) {
	packetPath := reflect.TypeOf((*transport.PacketPathConn)(nil)).Elem()
	basePath := reflect.TypeOf((*transport.PathConn)(nil)).Elem()
	maxFrame, ok := packetPath.MethodByName("MaxFrameSize")
	if !ok || maxFrame.Type.NumIn() != 0 || maxFrame.Type.NumOut() != 1 || maxFrame.Type.Out(0).Kind() != reflect.Int {
		t.Fatalf("transport.PacketPathConn.MaxFrameSize method=%v present=%t", maxFrame.Type, ok)
	}
	if !packetPath.Implements(basePath) || packetPath.NumMethod() != basePath.NumMethod()+1 {
		t.Fatal("transport.PacketPathConn does not extend transport.PathConn")
	}
	sessionConfig := reflect.TypeOf(SessionConfig{})
	if sessionConfig.NumField() != 2 {
		t.Fatalf("SessionConfig fields=%d want exactly Root and PreserveL3Identity", sessionConfig.NumField())
	}
	wantSessionFields := []struct {
		name   string
		typeOf reflect.Type
	}{
		{name: "Root", typeOf: reflect.TypeOf((*Target)(nil)).Elem()},
		{name: "PreserveL3Identity", typeOf: reflect.TypeOf(false)},
	}
	for index, want := range wantSessionFields {
		field := sessionConfig.Field(index)
		if field.Name != want.name || field.Type != want.typeOf {
			t.Fatalf("SessionConfig field[%d]=%s %s want %s %s",
				index, field.Name, field.Type, want.name, want.typeOf)
		}
	}

	controller := reflect.TypeOf((*MigrationController)(nil)).Elem()
	if controller.NumMethod() != 1 {
		t.Fatalf("MigrationController methods=%d want exactly SelectTarget", controller.NumMethod())
	}
	method := controller.Method(0)
	if method.Name != "SelectTarget" || method.Type.NumIn() != 2 || method.Type.NumOut() != 1 {
		t.Fatalf("MigrationController method=%s %s", method.Name, method.Type)
	}

	stats := reflect.TypeOf(ConnStats{})
	if _, ok := stats.FieldByName("Mode"); ok {
		t.Fatal("ConnStats restored flattened Mode observation")
	}
	peak := reflect.TypeOf(PeakTransfer{})
	if peak.NumField() != 1 {
		t.Fatalf("PeakTransfer fields=%d want exactly Targets", peak.NumField())
	}
	if field := peak.Field(0); field.Name != "Targets" || field.Type != reflect.TypeOf([]string(nil)) {
		t.Fatalf("PeakTransfer field=%s %s want Targets []string", field.Name, field.Type)
	}
	if field, ok := stats.FieldByName("EffectivePaths"); !ok || field.Type != reflect.TypeOf([]uint32(nil)) {
		t.Fatalf("ConnStats.EffectivePaths field=%v present=%t", field.Type, ok)
	}

	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller did not report package directory")
	}
	dir := filepath.Dir(source)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") ||
			entry.Name() == filepath.Base(source) {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, specification := range general.Specs {
				typeSpec, ok := specification.(*ast.TypeSpec)
				if ok && typeSpec.Name.Name == "Mode" {
					t.Fatalf("legacy flattened public Mode type returned in %s", entry.Name())
				}
			}
		}
	}
}
