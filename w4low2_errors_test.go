package rendr

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"strings"
	"testing"
)

// claimedErrors are the values of the exported sentinels package rendr
// documents as session or Dial errors.
var claimedErrors = map[string]error{
	"ErrNoPath":                    ErrNoPath,
	"ErrSessionLost":               ErrSessionLost,
	"ErrAborted":                   ErrAborted,
	"ErrRejected":                  ErrRejected,
	"ErrCapacity":                  ErrCapacity,
	"ErrVersion":                   ErrVersion,
	"ErrProtocol":                  ErrProtocol,
	"ErrMetadataTooLarge":          ErrMetadataTooLarge,
	"ErrIdleTimeout":               ErrIdleTimeout,
	"ErrPacketTooLarge":            ErrPacketTooLarge,
	"ErrPacketDestinationMismatch": ErrPacketDestinationMismatch,
	"ErrDatagramTooLarge":          ErrDatagramTooLarge,
}

// TestErrorsAreNetErrors (W4-L3-2): errors.go documents that every
// sentinel of its "Session and Dial errors" block implements net.Error
// with Timeout() == false. The test reads that block from the source, so
// a sentinel added to it is checked too, and requires errors.As to a
// net.Error with Timeout() == false for each of its names, also through
// %w wrapping. A carrier-facing error (such as ErrDatagramTooLarge, a
// plain error the carrier conns return) belongs outside the block.
func TestErrorsAreNetErrors(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "errors.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.VAR || g.Doc == nil || !strings.HasPrefix(g.Doc.Text(), "Session and Dial errors.") {
			continue
		}
		if !strings.Contains(g.Doc.Text(), "net.Error") {
			t.Fatalf("the block's documentation no longer states the net.Error claim:\n%s", g.Doc.Text())
		}
		for _, s := range g.Specs {
			for _, n := range s.(*ast.ValueSpec).Names {
				names = append(names, n.Name)
			}
		}
	}
	if len(names) < 9 {
		t.Fatalf("the session and Dial error block has %d names %v", len(names), names)
	}
	for _, name := range names {
		v, ok := claimedErrors[name]
		if !ok {
			t.Errorf("%s: in the session and Dial error block but unknown to this test", name)
			continue
		}
		var ne net.Error
		if !errors.As(v, &ne) || ne.Timeout() {
			t.Errorf("%s (%v): not a net.Error with Timeout() == false (got %v)", name, v, ne)
		}
		if !errors.As(fmt.Errorf("op: %w", v), &ne) || ne.Timeout() {
			t.Errorf("%s: the net.Error is lost through %%w wrapping", name)
		}
	}
	t.Logf("checked %d sentinels: %v", len(names), names)
}
