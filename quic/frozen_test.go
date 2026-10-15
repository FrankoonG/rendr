package quic

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// refreeze rewrites testdata/frozen.sha256 from the module's golden vector
// files; it is separate from -update, so regenerating a vector never
// refreezes the list in the same command.
var refreeze = flag.Bool("refreeze", false, "rewrite testdata/frozen.sha256 from the golden vector files (a new ALPN only)")

const (
	frozenPath   = "testdata/frozen.sha256"
	frozenModule = "github.com/FrankoonG/rendr/quic/v2"
)

// frozenRule is the failure message's rule (plan:309, plan:362, plan:635).
const frozenRule = `The golden vectors freeze the QUIC carrier's encapsulation (ALPN
rendr/2-q1) at v2.0.0. After 2.0.0 this list changes only with a new ALPN
(a new encapsulation version) or an optional feature bit of rendr's wire,
together with the vectors that define it; before 2.0.0 a change is
deliberate and recorded in the milestone report. Update the list in the
same change as the vectors:
    go test -run TestQUICGoldenFrozen -refreeze      (in quic/)`

// TestQUICGoldenFrozen is the quic module's wire freeze, the counterpart
// of the root module's TestWireGoldenFrozen: testdata/frozen.sha256 lists
// the SHA-256 of every golden vector file of this module (every file under
// a testdata directory except fuzz corpora and the list itself), and a
// vector that changes, appears or disappears without the list changing
// fails it. The list is in sha256sum's format.
func TestQUICGoldenFrozen(t *testing.T) {
	root, err := frozenModuleRoot(frozenModule)
	if err != nil {
		t.Fatal(err)
	}
	got, err := frozenHashes(root, frozenPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatalf("no golden vector files found under %s", root)
	}
	if *refreeze {
		if err := os.WriteFile(frozenPath, formatFrozen(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(frozenPath)
	if err != nil {
		t.Fatalf("%v\n%s", err, frozenRule)
	}
	want, err := parseFrozen(b)
	if err != nil {
		t.Fatalf("%s: %v\n%s", frozenPath, err, frozenRule)
	}
	if diff := frozenDiff(want, got); diff != "" {
		t.Fatalf("the golden vectors differ from %s:\n%s\n%s", frozenPath, diff, frozenRule)
	}
}

// frozenModuleRoot returns the nearest directory at or above the working
// directory whose go.mod declares module mod.
func frozenModuleRoot(mod string) (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if f := strings.Fields(line); len(f) >= 2 && f[0] == "module" && strings.Trim(f[1], `"`) == mod {
					return dir, nil
				}
			}
		}
		up := filepath.Dir(dir)
		if up == dir {
			return "", fmt.Errorf("no go.mod of module %s at or above the working directory", mod)
		}
		dir = up
	}
}

// frozenVCSDirs are the version-control directories a module zip leaves
// out at any depth (golang.org/x/mod/zip).
var frozenVCSDirs = map[string]bool{".bzr": true, ".git": true, ".hg": true, ".svn": true}

// frozenHashes walks the module at root and returns the SHA-256 of every
// file in a testdata tree, fuzz corpora (testdata/fuzz) and self excepted,
// by its slash path relative to root. It leaves out what the module's zip
// leaves out (a nested module, a version-control directory) and looks for
// testdata trees only outside directories whose names start with "." or
// "_" (the go command ignores those, the zip does not); inside a testdata
// tree every file counts.
func frozenHashes(root, self string) (map[string]string, error) {
	out := map[string]string{}
	inTestdata := func(rel string) bool { return strings.Contains("/"+path.Dir(rel)+"/", "/testdata/") }
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			name := d.Name()
			if frozenVCSDirs[name] || (name == "fuzz" && path.Base(path.Dir(rel)) == "testdata") ||
				(!inTestdata(rel) && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_"))) {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || rel == self || !inTestdata(rel) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	return out, err
}

// formatFrozen writes hashes in sha256sum's format, sorted by path.
func formatFrozen(h map[string]string) []byte {
	paths := make([]string, 0, len(h))
	for p := range h {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var b bytes.Buffer
	for _, p := range paths {
		fmt.Fprintf(&b, "%s  %s\n", h[p], p)
	}
	return b.Bytes()
}

// parseFrozen reads a list in sha256sum's format ("hash  path" or
// "hash *path"); a malformed or repeated line is an error.
func parseFrozen(b []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" {
			continue
		}
		sum, p, ok := strings.Cut(line, " ")
		if raw, err := hex.DecodeString(sum); !ok || err != nil || len(raw) != sha256.Size || len(p) < 2 || (p[0] != ' ' && p[0] != '*') {
			return nil, fmt.Errorf("line %d: %q is not \"<sha256>  <path>\"", n, line)
		}
		p = p[1:]
		if _, dup := out[p]; dup {
			return nil, fmt.Errorf("line %d: %s listed twice", n, p)
		}
		out[p] = strings.ToLower(sum)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("empty list")
	}
	return out, nil
}

// frozenDiff describes how got differs from want: changed, added and
// removed files, each in sha256sum's format; "" when they agree.
func frozenDiff(want, got map[string]string) string {
	var lines []string
	for p, g := range got {
		switch w, ok := want[p]; {
		case !ok:
			lines = append(lines, fmt.Sprintf("  added:   %s  %s", g, p))
		case w != g:
			lines = append(lines, fmt.Sprintf("  changed: %s  %s (listed %s)", g, p, w))
		}
	}
	for p, w := range want {
		if _, ok := got[p]; !ok {
			lines = append(lines, fmt.Sprintf("  removed: %s  %s", w, p))
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// TestQUICGoldenFrozenSelf checks the guard's own parts on a synthetic
// module: the walk finds testdata files at any depth, inside "." and "_"
// directories of a testdata tree too, and leaves out fuzz corpora, the
// list itself, version-control directories, "." and "_" directories above
// a testdata tree, nested modules and files outside testdata; the diff
// reports a changed, an added and a removed file; the list format round
// trips and refuses malformed and repeated lines.
func TestQUICGoldenFrozenSelf(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod":                    "module example.com/m\n",
		"a/testdata/v.txt":          "v",
		"a/testdata/sub/deep.bin":   "d",
		"a/testdata/_v/a.txt":       "underscore inside",
		"a/testdata/.v/a.txt":       "dot inside",
		"a/testdata/.git/HEAD":      "vcs",
		"a/testdata/frozen.sha256":  "self",
		"a/testdata/fuzz/F/seed":    "fuzz",
		"a/notes.txt":               "not a vector",
		".hidden/testdata/h.txt":    "hidden",
		"_x/testdata/u.txt":         "underscore",
		"nested/go.mod":             "module example.com/m/nested\n",
		"nested/testdata/n.txt":     "nested",
		"b/c/testdata/x/testdata.y": "y",
	}
	for p, s := range files {
		fp := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fp, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := frozenHashes(root, "a/testdata/frozen.sha256")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for p := range got {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if want := "a/testdata/.v/a.txt a/testdata/_v/a.txt a/testdata/sub/deep.bin a/testdata/v.txt b/c/testdata/x/testdata.y"; strings.Join(paths, " ") != want {
		t.Errorf("walk found %q, want %q", paths, want)
	}
	if sum := sha256.Sum256([]byte("v")); got["a/testdata/v.txt"] != hex.EncodeToString(sum[:]) {
		t.Errorf("hash of a/testdata/v.txt: %s", got["a/testdata/v.txt"])
	}

	back, err := parseFrozen(formatFrozen(got))
	if err != nil || frozenDiff(back, got) != "" || len(back) != len(got) {
		t.Fatalf("the list does not round trip: %v, %v", back, err)
	}
	moved := map[string]string{}
	for p, h := range got {
		moved[p] = h
	}
	moved["a/testdata/v.txt"] = strings.Repeat("0", 64)
	delete(moved, "a/testdata/sub/deep.bin")
	moved["a/testdata/new.txt"] = strings.Repeat("1", 64)
	d := frozenDiff(got, moved)
	for _, w := range []string{"changed: " + strings.Repeat("0", 64) + "  a/testdata/v.txt", "removed: ", "  a/testdata/sub/deep.bin", "added:   " + strings.Repeat("1", 64) + "  a/testdata/new.txt"} {
		if !strings.Contains(d, w) {
			t.Errorf("diff lacks %q:\n%s", w, d)
		}
	}
	if n := strings.Count(d, "\n") + 1; n != 3 {
		t.Errorf("diff has %d lines, want 3:\n%s", n, d)
	}

	h := strings.Repeat("ab", 32)
	if m, err := parseFrozen([]byte(h + " *bin/x\n\n" + h + "  y\n")); err != nil || m["bin/x"] != h || m["y"] != h {
		t.Errorf("sha256sum's binary and text forms: %v, %v", m, err)
	}
	for _, bad := range []string{"", "\n", h + " x\n", h + "\n", h[:62] + "  x\n", "zz" + h[2:] + "  x\n", h + "  x\n" + h + "  x\n"} {
		if _, err := parseFrozen([]byte(bad)); err == nil {
			t.Errorf("parseFrozen accepted %q", bad)
		}
	}
}
