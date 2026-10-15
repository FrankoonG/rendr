package wire

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

// refreeze rewrites testdata/frozen.sha256 from the golden vector files in
// the tree. It is separate from -update on purpose: regenerating a vector
// never refreezes the list in the same command.
var refreeze = flag.Bool("refreeze", false, "rewrite testdata/frozen.sha256 from the golden vector files (after v2.0.0: a new wire minor version, an optional PREFACE feature bit or a new version of a versioned payload format only)")

const (
	frozenPath   = "testdata/frozen.sha256"
	frozenModule = "github.com/FrankoonG/rendr/v2"
)

// frozenRule is the failure message's rule (plan:309, plan:362; M5 D2-6:
// the one freeze rule, stated in the same words in the headers of
// testdata/golden.txt and l4/testdata/meta-v1.txt).
const frozenRule = `The golden vectors freeze rendr's wire format at v2.0.0. Before v2.0.0 a
change is deliberate and recorded in the milestone report. After v2.0.0 a
frozen vector changes only with a new wire minor version, an optional
PREFACE feature bit, or a new version of a versioned payload format such
as L4 metadata, together with the vectors that define it. Update the list
in the same change as the vectors:
    go test ./internal/wire -run TestWireGoldenFrozen -refreeze`

// TestWireGoldenFrozen is the wire freeze (m5 R4): testdata/frozen.sha256
// lists the SHA-256 of every golden vector file of the root module, and a
// vector that changes, appears or disappears without the list changing
// fails it. A golden vector file is every file in a testdata tree of the
// module except the fuzz corpora (testdata/fuzz, seeds that grow without a
// wire change) and the list itself. The walk leaves out what the module's
// zip leaves out (a nested module, a version-control directory) and the
// directories the root .gitignore anchors, such as /docs/, which the zip
// never sees; it looks for testdata trees only outside directories whose
// names start with "." or "_" (the go command ignores those, the zip does
// not), and inside a testdata tree every file counts. The list is in
// sha256sum's format, so `sha256sum -c` checks it from the module root.
func TestWireGoldenFrozen(t *testing.T) {
	root, err := moduleRoot(frozenModule)
	if err != nil {
		t.Fatal(err)
	}
	got, err := goldenHashes(root, filepath.ToSlash(filepath.Join("internal", "wire", frozenPath)))
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

// moduleRoot returns the nearest directory at or above the working
// directory whose go.mod declares module mod.
func moduleRoot(mod string) (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			if modulePath(b) == mod {
				return dir, nil
			}
		}
		up := filepath.Dir(dir)
		if up == dir {
			return "", fmt.Errorf("no go.mod of module %s at or above the working directory", mod)
		}
		dir = up
	}
}

// modulePath returns the module directive of a go.mod file.
func modulePath(gomod []byte) string {
	for _, line := range strings.Split(string(gomod), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "module" {
			return strings.Trim(f[1], `"`)
		}
	}
	return ""
}

// anchoredDirs returns the top-level directories the root .gitignore
// excludes ("/name/" lines): private material that never enters the
// module.
func anchoredDirs(root string) map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 2 && line[0] == '/' && line[len(line)-1] == '/' && !strings.Contains(line[1:len(line)-1], "/") {
			out[line[1:len(line)-1]] = true
		}
	}
	return out
}

// vcsDirs are the version-control directories a module zip leaves out at
// any depth (golang.org/x/mod/zip).
var vcsDirs = map[string]bool{".bzr": true, ".git": true, ".hg": true, ".svn": true}

// goldenHashes walks the module at root and returns the SHA-256 of every
// golden vector file by its slash path relative to root; self (the list)
// is left out.
func goldenHashes(root, self string) (map[string]string, error) {
	skip := anchoredDirs(root)
	out := map[string]string{}
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
			if vcsDirs[name] || skip[rel] || (name == "fuzz" && path.Base(path.Dir(rel)) == "testdata") ||
				(!inTestdata(rel) && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_"))) {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
				return filepath.SkipDir // a nested module guards its own vectors
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

// inTestdata reports whether the slash path rel lies under a testdata
// directory.
func inTestdata(rel string) bool {
	for _, e := range strings.Split(path.Dir(rel), "/") {
		if e == "testdata" {
			return true
		}
	}
	return false
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
// removed files, each line in sha256sum's format; "" when they agree.
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

// TestWireGoldenFrozenSelf checks the guard's own parts on a synthetic
// module: the walk finds testdata files at any depth, inside "." and "_"
// directories of a testdata tree too, and leaves out fuzz corpora, the
// list itself, version-control directories, "." and "_" directories above
// a testdata tree, nested modules, .gitignore-anchored directories and
// files outside testdata; the diff reports a changed, an added and a
// removed file; the list format round trips and refuses malformed and
// repeated lines.
func TestWireGoldenFrozenSelf(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod":                    "module example.com/m\n",
		".gitignore":                "/docs/\nbin/\n",
		"a/testdata/v.txt":          "v",
		"a/testdata/sub/deep.bin":   "d",
		"a/testdata/_v/a.txt":       "underscore inside",
		"a/testdata/.v/a.txt":       "dot inside",
		"a/testdata/.git/HEAD":      "vcs",
		"a/testdata/frozen.sha256":  "self",
		"a/testdata/fuzz/F/seed":    "fuzz",
		"a/notes.txt":               "not a vector",
		"docs/testdata/p.txt":       "private",
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
	got, err := goldenHashes(root, "a/testdata/frozen.sha256")
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
