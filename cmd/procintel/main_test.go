package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/IbrahimMI124/procintel/internal/model"
)

//go:embed testdata/inspect.txt.golden
//go:embed testdata/inspect.json.golden
var goldenFS embed.FS

// fixtureRoot is internal/procfs/testdata/proc/normal reached from this
// package's test working directory. Pid 1234 is the fully-populated process;
// 999999 is absent.
const fixtureRoot = "../../internal/procfs/testdata/proc/normal"

// timestampPattern scrubs the two non-deterministic RFC3339 stamps that
// render.JSON carries (captured_at from procfs.Snapshot, generated_at from
// explain.Explain) so the JSON output can be compared to a committed golden.
var timestampPattern = regexp.MustCompile(`"(captured_at|generated_at)": "[^"]*"`)

func scrubTimestamps(b []byte) []byte {
	return timestampPattern.ReplaceAll(b, []byte(`"$1": "SCRUBBED"`))
}

func golden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := goldenFS.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return data
}

// invoke runs run() with buffer writers and returns code, stdout, stderr.
func invoke(args []string, colorDefault bool) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr, colorDefault)
	return code, stdout.String(), stderr.String()
}

// --- Matrix: happy text -------------------------------------------------

func TestInspectHappyText(t *testing.T) {
	code, stdout, stderr := invoke([]string{"inspect", "1234", "--root", fixtureRoot}, false)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if stdout != string(golden(t, "inspect.txt.golden")) {
		t.Errorf("stdout mismatch\n--- got ---\n%s", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr not empty: %q", stderr)
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Error("non-TTY text output carries an ANSI escape")
	}
}

// --- Matrix: happy JSON -----------------------------------------------

func TestInspectHappyJSON(t *testing.T) {
	code, stdout, stderr := invoke([]string{"inspect", "1234", "--json", "--root", fixtureRoot}, false)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr not empty: %q", stderr)
	}
	var report model.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not one model.Report: %v", err)
	}
	if report.Facts.PID != 1234 {
		t.Errorf("Facts.PID = %d, want 1234", report.Facts.PID)
	}
	if got := scrubTimestamps([]byte(stdout)); !bytes.Equal(got, golden(t, "inspect.json.golden")) {
		t.Errorf("scrubbed JSON mismatch\n--- got ---\n%s", got)
	}
}

// --- Matrix: degraded section ---------------------------------------

func TestInspectDegradedStillSucceeds(t *testing.T) {
	// Pid 6001 is a minimal fixture: several sections read as unsupported,
	// but the inspection is still a fully-observed *result* — exit 0.
	code, stdout, stderr := invoke([]string{"inspect", "6001", "--verbose", "--root", fixtureRoot}, false)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "FACTS") || !strings.Contains(stdout, "ASSESSMENT") {
		t.Error("degraded inspection did not still render the full report")
	}
	if !strings.Contains(stderr, "sockets: unsupported") {
		t.Errorf("--verbose did not report the non-observed section: %q", stderr)
	}
}

// --- Matrix: PID absent -------------------------------------------

func TestInspectPIDAbsent(t *testing.T) {
	code, stdout, stderr := invoke([]string{"inspect", "999999", "--root", fixtureRoot}, false)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if stdout != "" {
		t.Errorf("stdout not empty on absent pid: %q", stdout)
	}
	if !strings.Contains(stderr, "999999") {
		t.Errorf("stderr does not name the absent pid: %q", stderr)
	}
}

// --- Matrix: bad pid --------------------------------------------

func TestInspectBadPID(t *testing.T) {
	for _, args := range [][]string{
		{"inspect", "abc", "--root", fixtureRoot},
		{"inspect", "-3", "--root", fixtureRoot},
		{"inspect"},
		{"inspect", "0", "--root", fixtureRoot},
	} {
		code, stdout, stderr := invoke(args, false)
		if code != 1 {
			t.Errorf("%v: exit code = %d, want 1", args, code)
		}
		if stdout != "" {
			t.Errorf("%v: stdout not empty: %q", args, stdout)
		}
		if stderr == "" {
			t.Errorf("%v: no usage line on stderr", args)
		}
	}
}

// --- Matrix: unknown / no subcommand -------------------------------

func TestUnknownOrNoSubcommand(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}, {"list"}} {
		code, stdout, stderr := invoke(args, false)
		if code != 1 {
			t.Errorf("%v: exit code = %d, want 1", args, code)
		}
		if stdout != "" {
			t.Errorf("%v: stdout not empty: %q", args, stdout)
		}
		if !strings.Contains(stderr, "usage:") {
			t.Errorf("%v: no usage line on stderr: %q", args, stderr)
		}
	}
}

// --- Matrix: help ----------------------------------------------

func TestHelpGoesToStdout(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {"inspect", "-h"}} {
		code, stdout, _ := invoke(args, false)
		if code != 0 {
			t.Errorf("%v: exit code = %d, want 0", args, code)
		}
		if !strings.Contains(stdout, "usage:") {
			t.Errorf("%v: help text did not go to stdout: %q", args, stdout)
		}
	}
}

// --- Matrix: unknown flag ------------------------------------------

func TestUnknownFlag(t *testing.T) {
	code, stdout, stderr := invoke([]string{"inspect", "1234", "--bogus", "--root", fixtureRoot}, false)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stdout != "" {
		t.Errorf("stdout not empty: %q", stdout)
	}
	if stderr == "" {
		t.Error("flag error not reported on stderr")
	}
}

// --- Matrix: --no-color over a colouring default ----------------------

func TestNoColorOverridesDefault(t *testing.T) {
	code, stdout, _ := invoke([]string{"inspect", "1234", "--no-color", "--root", fixtureRoot}, true)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Error("--no-color did not suppress ANSI even though colorDefault was true")
	}
	if stdout != string(golden(t, "inspect.txt.golden")) {
		t.Error("--no-color output should equal the plain text golden")
	}
}

// --- Matrix: verbose ------------------------------------------------

func TestVerboseDiagnostics(t *testing.T) {
	code, stdout, stderr := invoke([]string{"inspect", "1234", "--verbose", "--root", fixtureRoot}, false)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if stdout != string(golden(t, "inspect.txt.golden")) {
		t.Error("--verbose changed stdout from the plain text golden")
	}
	if !strings.Contains(stderr, "root: "+fixtureRoot) {
		t.Errorf("stderr missing resolved-root line: %q", stderr)
	}
	if !strings.Contains(stderr, "pid: 1234") {
		t.Errorf("stderr missing pid line: %q", stderr)
	}
	// Pid 1234 is fully observed: no section lines follow.
	for _, s := range []string{"identity:", "resources:", "security:"} {
		if strings.Contains(stderr, s) {
			t.Errorf("fully-observed pid still emitted a section line: %q", stderr)
		}
	}
}

// --- Matrix: determinism -------------------------------------------

func TestRunIsDeterministic(t *testing.T) {
	for _, args := range [][]string{
		{"inspect", "1234", "--root", fixtureRoot},
		{"inspect", "1234", "--json", "--root", fixtureRoot},
	} {
		c1, o1, e1 := invoke(args, false)
		c2, o2, e2 := invoke(args, false)
		o1, o2 = string(scrubTimestamps([]byte(o1))), string(scrubTimestamps([]byte(o2)))
		if c1 != c2 || o1 != o2 || e1 != e2 {
			t.Errorf("%v: run is not deterministic", args)
		}
	}
}
