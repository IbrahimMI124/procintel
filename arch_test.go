// Package procintel holds the architecture test and nothing else.
//
// arch_test.go sits at the repository root so it can see every package at
// once. It enforces AD-2 — dependency direction is downward only — by
// parsing the import graph directly with go/parser rather than shelling out
// to `go list`, which keeps it stdlib-only, hermetic, and free of the very
// os/exec dependency it exists to forbid elsewhere.
//
// The enforcer is tested in both halves. The rule half — importViolation —
// is exercised by a table of legal and illegal imports, so no rule is
// trusted until it has been shown to reject. The discovery half —
// internalPackage, inProjectPackage, modulePath and the file walk — is
// exercised by its own tables plus a floor assertion inside the walk, so the
// enforcer cannot be silently disabled by an edit to its own plumbing:
// a walk that classifies nothing reports nothing, and would otherwise pass.
package procintel

import (
	"bufio"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// layerRank mirrors the layer table in ARCHITECTURE-SPINE.md. An in-project
// import is legal only when the importee's rank is strictly lower than the
// importer's.
//
// procfs shares rank 0 with model because it is the adapter arm of the
// graph, not a consumer of the pipeline. It may import model and nothing
// else in-project, which is special-cased in importViolation rather than
// encoded as a rank.
var layerRank = map[string]int{
	"model":     0,
	"procfs":    0,
	"diff":      1,
	"trace":     1,
	"behavior":  2,
	"rules":     3,
	"correlate": 4,
	"explain":   5,
	"render":    6,
}

// forbiddenStdlib are the packages that only the kernel adapter may import,
// following AD-1's list — os, io/fs, syscall, path/filepath — plus os/exec,
// which AD-2 names, and the os/* and net/http surfaces that would reopen the
// same holes. Every "os/..." path is forbidden by prefix, so a future
// os/whatever cannot slip through a list that was never updated.
//
// net is deliberately PERMITTED. AD-9 forbids network I/O, not the net
// package: net.IP is the value type used to format addresses parsed out of
// /proc/net text, and every layer that renders a socket needs it. What AD-9
// forbids is dialing and resolving — net.Dial, net.Listen, net.LookupHost,
// net/http — and net/http is on this list for exactly that reason. A rule
// that banned net outright would push address formatting into hand-rolled
// string code for no gain.
var forbiddenStdlib = map[string]bool{
	"os":            true,
	"syscall":       true,
	"io/fs":         true,
	"path/filepath": true,
	"net/http":      true,
}

// isForbiddenStdlib reports whether an import path is one only the adapter
// may reach for.
func isForbiddenStdlib(imported string) bool {
	return forbiddenStdlib[imported] || strings.HasPrefix(imported, "os/")
}

// adapterPackage is the one package exempt from forbiddenStdlib, and the one
// package allowed a same-rank import of model.
const adapterPackage = "procfs"

// skippedDirectories are trees that hold no buildable in-project Go code.
// vendor/ is listed because a vendor tree must never exist here at all — its
// presence is a dependency, and TestNoDependencyManifest fails on it.
var skippedDirectories = map[string]bool{
	"testdata":     true,
	"vendor":       true,
	"_bmad":        true,
	"_bmad-output": true,
}

// fileScope says where a repository-relative Go file sits relative to the
// layered part of the tree.
type fileScope int

const (
	// scopeOutsideInternal is the repository root, cmd/ and demo/. The
	// layer rules do not constrain these: cmd is the entrypoint that
	// wires everything, demo is a standalone program, and this test file
	// must itself import os and path/filepath to do its job.
	scopeOutsideInternal fileScope = iota
	// scopeInternalPackage is a file inside some internal/<package>/.
	scopeInternalPackage
	// scopeLooseInInternal is a file sitting directly at internal/*.go,
	// belonging to no layered package. It is always a failure: such a
	// file has no rank, so it would escape every rule in this test.
	scopeLooseInInternal
)

func TestImportGraphIsDownwardOnly(t *testing.T) {
	root := repositoryRoot(t)
	module := modulePath(t, root)

	// The floor assertions below guard the discovery half of the
	// enforcer. The walk reports violations by iteration, so an empty or
	// misclassified iteration produces no failure and looks identical to
	// a clean repository.
	classified := map[string]string{}
	importsParsed := 0

	for _, file := range goFiles(t, root) {
		relative, err := filepath.Rel(root, file)
		if err != nil {
			t.Fatalf("relativising %s: %v", file, err)
		}
		relative = filepath.ToSlash(relative)
		importer, scope := internalPackage(relative)

		if scope == scopeLooseInInternal {
			t.Errorf("%s: a Go file sits directly in internal/; every package must "+
				"live in internal/<package>/ so the layer table can rank it (AD-2)", relative)
			continue
		}
		if scope == scopeInternalPackage {
			classified[relative] = importer
		}

		for _, imported := range imports(t, file) {
			importsParsed++
			if scope != scopeInternalPackage {
				continue
			}
			if violation := importViolation(module, importer, imported); violation != "" {
				t.Errorf("%s: %s", relative, violation)
			}
		}
	}

	// If the walk, the classifier or the parser were broken, the loop
	// above would silently enforce nothing. Pin a few files it must have
	// seen and classified, and require that imports were actually read.
	expected := map[string]string{
		"internal/model/snapshot.go": "model",
		"internal/model/report.go":   "model",
		"internal/model/enum.go":     "model",
		"internal/model/doc.go":      "model",
		"internal/procfs/doc.go":     "procfs",
		"internal/render/doc.go":     "render",
		"internal/trace/doc.go":      "trace",
	}
	for file, want := range expected {
		got, seen := classified[file]
		if !seen {
			t.Errorf("the walk never reached %s; the import-graph enforcer is not "+
				"actually inspecting the tree", file)
			continue
		}
		if got != want {
			t.Errorf("the walk classified %s as internal/%s, want internal/%s", file, got, want)
		}
	}
	if len(classified) < len(expected) {
		t.Errorf("the walk classified only %d internal files, want at least %d",
			len(classified), len(expected))
	}
	if importsParsed == 0 {
		t.Error("the walk parsed no imports at all; go/parser is not reading these files")
	}
}

// importViolation returns a message explaining why an internal package may
// not make an import, or the empty string when the import is legal. It is a
// pure function so every rule can be exercised by table rather than by
// planting files in the tree.
func importViolation(module, importer, imported string) string {
	// Stdlib rule: only the adapter touches the kernel.
	if isForbiddenStdlib(imported) && importer != adapterPackage {
		return "internal/" + importer + " imports " + strconv.Quote(imported) +
			"; only internal/" + adapterPackage + " may (AD-1, AD-2)"
	}

	// In-project rule: strictly downward, one exception.
	target, isInProject := inProjectPackage(module, imported)
	if !isInProject {
		return ""
	}
	if target == "" {
		return "internal/" + importer + " imports " + strconv.Quote(imported) +
			", which is outside internal/; packages below cmd may not import the " +
			"entrypoint or the demo (AD-2)"
	}
	if importer == adapterPackage {
		if target != "model" {
			return "internal/" + importer + " imports internal/" + target +
				"; the adapter may import internal/model and nothing else in-project (AD-2)"
		}
		return ""
	}

	importerRank, importerKnown := layerRank[importer]
	if !importerKnown {
		return "internal/" + importer + " has no entry in layerRank; add it to the layer " +
			"table in ARCHITECTURE-SPINE.md and to this test (AD-2)"
	}
	targetRank, targetKnown := layerRank[target]
	if !targetKnown {
		return "internal/" + importer + " imports internal/" + target +
			", which has no entry in layerRank; add it to the layer table in " +
			"ARCHITECTURE-SPINE.md and to this test (AD-2)"
	}
	if targetRank >= importerRank {
		direction := "a sideways"
		if targetRank > importerRank {
			direction = "an upward"
		}
		return "internal/" + importer + " (rank " + strconv.Itoa(importerRank) +
			") imports internal/" + target + " (rank " + strconv.Itoa(targetRank) +
			") — " + direction + " in-project import; dependencies flow downward only (AD-2)"
	}
	return ""
}

// TestImportRulesRejectViolations exercises every branch of importViolation
// in both directions. An enforcer that has never been shown to fail is not
// evidence of anything.
func TestImportRulesRejectViolations(t *testing.T) {
	const module = "github.com/IbrahimMI124/procintel"

	tests := []struct {
		name     string
		importer string
		imported string
		// contains is empty when the import must be accepted, and
		// otherwise a substring the rejection message must carry.
		contains string
	}{
		// Legal.
		{"downward render to model", "render", module + "/internal/model", ""},
		{"downward explain to behavior", "explain", module + "/internal/behavior", ""},
		{"adapter to model", "procfs", module + "/internal/model", ""},
		{"adapter may import os", "procfs", "os", ""},
		{"adapter may import syscall", "procfs", "syscall", ""},
		{"adapter may import io/fs", "procfs", "io/fs", ""},
		{"adapter may import path/filepath", "procfs", "path/filepath", ""},
		{"ordinary stdlib is fine", "render", "encoding/json", ""},
		{"strings is fine", "rules", "strings", ""},
		{"net is permitted for net.IP formatting", "render", "net", ""},
		{"net is permitted in the adapter too", "procfs", "net", ""},
		{"path without filepath is fine", "render", "path", ""},
		{"io without fs is fine", "render", "io", ""},
		{"a lookalike module is not in-project", "model", module + "x/internal/procfs", ""},

		// Forbidden stdlib outside the adapter.
		{"render to os", "render", "os", "only internal/procfs may"},
		{"render to syscall", "render", "syscall", "only internal/procfs may"},
		{"render to io/fs", "render", "io/fs", "only internal/procfs may"},
		{"render to path/filepath", "render", "path/filepath", "only internal/procfs may"},
		{"render to os/exec", "render", "os/exec", "only internal/procfs may"},
		{"render to os/signal", "render", "os/signal", "only internal/procfs may"},
		{"render to os/user", "render", "os/user", "only internal/procfs may"},
		{"render to net/http", "render", "net/http", "only internal/procfs may"},
		{"model to os", "model", "os", "only internal/procfs may"},

		// Illegal in-project direction.
		{"sideways model to procfs", "model", module + "/internal/procfs", "a sideways"},
		{"sideways diff to trace", "diff", module + "/internal/trace", "a sideways"},
		{"upward rules to correlate", "rules", module + "/internal/correlate", "an upward"},
		{"upward model to render", "model", module + "/internal/render", "an upward"},
		{"adapter to diff", "procfs", module + "/internal/diff", "and nothing else in-project"},
		{"internal to demo", "explain", module + "/demo", "which is outside internal/"},
		{"internal to cmd", "explain", module + "/cmd/procintel", "which is outside internal/"},
		{"internal to the root package", "explain", module, "which is outside internal/"},

		// Packages missing from the layer table, on both sides.
		{"unranked importer", "sneaky", module + "/internal/model",
			"internal/sneaky has no entry in layerRank"},
		{"unranked target", "render", module + "/internal/sneaky",
			"internal/render imports internal/sneaky, which has no entry in layerRank"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := importViolation(module, tt.importer, tt.imported)
			switch {
			case tt.contains == "" && got != "":
				t.Errorf("internal/%s importing %q must be legal, got rejection: %s",
					tt.importer, tt.imported, got)
			case tt.contains != "" && got == "":
				t.Errorf("internal/%s importing %q must be rejected, got no violation",
					tt.importer, tt.imported)
			case tt.contains != "" && !strings.Contains(got, tt.contains):
				t.Errorf("rejection message %q does not contain %q", got, tt.contains)
			}
			if got != "" && !strings.HasPrefix(got, "internal/") {
				t.Errorf("every rejection message must lead with internal/<importer>, got %q", got)
			}
		})
	}
}

// TestInternalPackageClassification pins the discovery half. A mutation to
// the path guard here would otherwise make the walk classify nothing and
// report nothing, which reads exactly like a clean repository.
func TestInternalPackageClassification(t *testing.T) {
	tests := []struct {
		path      string
		wantName  string
		wantScope fileScope
	}{
		{"arch_test.go", "", scopeOutsideInternal},
		{"cmd/procintel/main.go", "", scopeOutsideInternal},
		{"demo/doc.go", "", scopeOutsideInternal},
		{"internal/model/doc.go", "model", scopeInternalPackage},
		{"internal/model/model_test.go", "model", scopeInternalPackage},
		{"internal/procfs/doc.go", "procfs", scopeInternalPackage},
		{"internal/procfs/parse/hex.go", "procfs", scopeInternalPackage},
		{"internal/loose.go", "", scopeLooseInInternal},
		{"internal/util.go", "", scopeLooseInInternal},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			name, scope := internalPackage(tt.path)
			if name != tt.wantName || scope != tt.wantScope {
				t.Errorf("internalPackage(%q) = (%q, %d), want (%q, %d)",
					tt.path, name, scope, tt.wantName, tt.wantScope)
			}
		})
	}
}

// TestInProjectPackageClassification pins the other half of discovery: which
// import paths belong to this module, and which layer they name.
func TestInProjectPackageClassification(t *testing.T) {
	const module = "github.com/IbrahimMI124/procintel"

	tests := []struct {
		imported        string
		wantName        string
		wantIsInProject bool
	}{
		{"os", "", false},
		{"encoding/json", "", false},
		{"github.com/other/procintel/internal/model", "", false},
		{module + "x/internal/model", "", false},
		{module, "", true},
		{module + "/demo", "", true},
		{module + "/cmd/procintel", "", true},
		{module + "/internal/model", "model", true},
		{module + "/internal/procfs", "procfs", true},
		{module + "/internal/procfs/parse", "procfs", true},
	}
	for _, tt := range tests {
		t.Run(tt.imported, func(t *testing.T) {
			name, isInProject := inProjectPackage(module, tt.imported)
			if name != tt.wantName || isInProject != tt.wantIsInProject {
				t.Errorf("inProjectPackage(%q) = (%q, %v), want (%q, %v)",
					tt.imported, name, isInProject, tt.wantName, tt.wantIsInProject)
			}
		})
	}
}

// TestModulePath checks the go.mod reader against an independent second
// implementation, so a mutation that returns a wrong module path — which
// would make every in-project import look external and unenforced — fails
// here rather than passing everywhere.
func TestModulePath(t *testing.T) {
	root := repositoryRoot(t)
	got := modulePath(t, root)
	if got == "" {
		t.Fatal("modulePath returned an empty module path")
	}

	contents, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	matches := regexp.MustCompile(`(?m)^module[ \t]+(\S+)[ \t]*$`).FindSubmatch(contents)
	if matches == nil {
		t.Fatal("go.mod has no module line")
	}
	if want := string(matches[1]); got != want {
		t.Errorf("modulePath = %q, want %q", got, want)
	}
}

// TestModelImportsNothingInProject is the sharpest single case of AD-2, and
// the one every other layer depends on: the contract package must stay a
// leaf, importing no in-project package at all.
func TestModelImportsNothingInProject(t *testing.T) {
	root := repositoryRoot(t)
	module := modulePath(t, root)

	files := goFiles(t, filepath.Join(root, "internal", "model"))
	if len(files) == 0 {
		t.Fatal("internal/model holds no Go files; this test is inspecting nothing")
	}
	for _, file := range files {
		relative, err := filepath.Rel(root, file)
		if err != nil {
			t.Fatalf("relativising %s: %v", file, err)
		}
		for _, imported := range imports(t, file) {
			if _, isInProject := inProjectPackage(module, imported); isInProject {
				t.Errorf("%s: internal/model imports %q; the contract layer must import "+
					"no in-project package (AD-2)", filepath.ToSlash(relative), imported)
			}
			if isForbiddenStdlib(imported) {
				t.Errorf("%s: internal/model imports %q; the contract layer holds values "+
					"only (AD-1, AD-2)", filepath.ToSlash(relative), imported)
			}
		}
	}
}

// TestEveryStructuralSeedPackageExists checks the tree against the spine's
// Structural Seed, so a package cannot quietly go missing and a later block
// cannot invent a new one without updating the layer table.
func TestEveryStructuralSeedPackageExists(t *testing.T) {
	root := repositoryRoot(t)

	required := []string{
		"cmd/procintel",
		"demo",
		"internal/model",
		"internal/procfs",
		"internal/procfs/testdata/proc",
		"internal/diff",
		"internal/behavior",
		"internal/rules",
		"internal/correlate",
		"internal/explain",
		"internal/render",
		"internal/trace",
	}
	for _, directory := range required {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(directory)))
		if err != nil || !info.IsDir() {
			t.Errorf("Structural Seed directory %s/ is missing", directory)
		}
	}

	entries, err := os.ReadDir(filepath.Join(root, "internal"))
	if err != nil {
		t.Fatalf("reading internal/: %v", err)
	}
	var unexpected []string
	for _, entry := range entries {
		if !entry.IsDir() {
			// A Go file directly in internal/ belongs to no layered
			// package and would escape every rule in this file.
			if strings.HasSuffix(entry.Name(), ".go") {
				t.Errorf("internal/%s sits directly in internal/; every package must live "+
					"in internal/<package>/ so the layer table can rank it (AD-2)", entry.Name())
			}
			continue
		}
		if _, known := layerRank[entry.Name()]; !known {
			unexpected = append(unexpected, entry.Name())
		}
	}
	sort.Strings(unexpected)
	for _, name := range unexpected {
		t.Errorf("internal/%s is not in the layer table; add it to ARCHITECTURE-SPINE.md "+
			"and to layerRank, or remove it (AD-2)", name)
	}
}

// TestNoDependencyManifest is the zero-dependency proof, asserted in the
// test suite rather than only in a build log: go.mod must carry no directive
// that names another module, and nothing beside it may reintroduce one.
func TestNoDependencyManifest(t *testing.T) {
	root := repositoryRoot(t)

	contents, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	// require and replace pull modules in; exclude and tool only make
	// sense alongside a dependency, so their presence is a warning sign
	// even before one is declared.
	forbiddenDirectives := map[string]bool{
		"require": true,
		"replace": true,
		"exclude": true,
		"tool":    true,
	}
	for number, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && forbiddenDirectives[fields[0]] {
			t.Errorf("go.mod:%d: %q — the manifest must stay empty",
				number+1, strings.TrimSpace(line))
		}
	}

	// A file that must not exist, and the reason it must not.
	absent := []struct {
		name   string
		reason string
	}{
		{"go.sum", "a zero-dependency module has no checksums to record"},
		{"go.work", "a workspace can add modules the manifest never names"},
		{"go.work.sum", "a workspace can add modules the manifest never names"},
		{"vendor", "a vendor tree is a dependency, committed"},
	}
	for _, entry := range absent {
		_, err := os.Stat(filepath.Join(root, entry.name))
		switch {
		case err == nil:
			t.Errorf("%s exists; %s", entry.name, entry.reason)
		case !errors.Is(err, fs.ErrNotExist):
			t.Errorf("cannot determine whether %s exists: %v", entry.name, err)
		}
	}
}

// repositoryRoot returns the directory holding go.mod, walking up from the
// test's working directory so the test works from any package.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("no go.mod found above the working directory")
		}
		directory = parent
	}
}

// modulePath reads the module line out of go.mod without go/build's module
// support, which would pull in the toolchain's own resolution.
func modulePath(t *testing.T, root string) string {
	t.Helper()
	file, err := os.Open(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("opening go.mod: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "module" {
			return fields[1]
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanning go.mod: %v", err)
	}
	t.Fatal("go.mod has no module line")
	return ""
}

// goFiles lists every .go file under directory, test files included, skipping
// trees that hold no buildable in-project code.
func goFiles(t *testing.T, directory string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if path != directory && (strings.HasPrefix(name, ".") || skippedDirectories[name]) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(name, ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", directory, err)
	}
	sort.Strings(files)
	return files
}

// imports parses only the import block of file and returns the import paths.
func imports(t *testing.T, file string) []string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	paths := make([]string, 0, len(parsed.Imports))
	for _, spec := range parsed.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("%s: unquoting import %s: %v", file, spec.Path.Value, err)
		}
		paths = append(paths, path)
	}
	return paths
}

// internalPackage maps a repository-relative, slash-separated file path to
// the internal package that owns it, and to the scope that decides which
// rules apply.
func internalPackage(relative string) (name string, scope fileScope) {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if parts[0] != "internal" {
		return "", scopeOutsideInternal
	}
	if len(parts) < 3 {
		return "", scopeLooseInInternal
	}
	return parts[1], scopeInternalPackage
}

// inProjectPackage reports whether an import path belongs to this module,
// and if so returns the internal package name it names — empty for an
// in-project import outside internal/.
func inProjectPackage(module, imported string) (name string, isInProject bool) {
	if imported != module && !strings.HasPrefix(imported, module+"/") {
		return "", false
	}
	suffix := strings.TrimPrefix(strings.TrimPrefix(imported, module), "/")
	parts := strings.Split(suffix, "/")
	if len(parts) < 2 || parts[0] != "internal" {
		return "", true
	}
	return parts[1], true
}
