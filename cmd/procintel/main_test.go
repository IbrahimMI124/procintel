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
//go:embed testdata/list.txt.golden
//go:embed testdata/list.json.golden
//go:embed testdata/tree.txt.golden
//go:embed testdata/files.txt.golden
//go:embed testdata/network.txt.golden
//go:embed testdata/security.txt.golden
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
	for _, args := range [][]string{nil, {"bogus"}} {
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

// --- list: happy text --------------------------------------------------

func TestListHappyText(t *testing.T) {
	code, stdout, stderr := invoke([]string{"list", "--root", fixtureRoot}, false)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if stdout != string(golden(t, "list.txt.golden")) {
		t.Errorf("stdout mismatch\n--- got ---\n%s", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr not empty: %q", stderr)
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Error("non-TTY text output carries an ANSI escape")
	}
	// PID-ascending, with the two stat-less fixture PIDs absent.
	for _, absent := range []string{"4444", "5100"} {
		if strings.Contains(stdout, absent) {
			t.Errorf("listing contains a stat-less PID %s", absent)
		}
	}
	if i, j := strings.Index(stdout, "1234"), strings.Index(stdout, "5001"); i < 0 || j < 0 || i > j {
		t.Error("rows are not in ascending PID order")
	}
}

// --- list: happy JSON ------------------------------------------------

func TestListHappyJSON(t *testing.T) {
	code, stdout, stderr := invoke([]string{"list", "--json", "--root", fixtureRoot}, false)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr not empty: %q", stderr)
	}
	var listing model.ProcessListing
	if err := json.Unmarshal([]byte(stdout), &listing); err != nil {
		t.Fatalf("stdout is not one model.ProcessListing: %v", err)
	}
	if listing.Availability != model.AvailabilityObserved {
		t.Errorf("Availability = %q, want observed", listing.Availability)
	}
	for i := 1; i < len(listing.Processes); i++ {
		if listing.Processes[i-1].PID >= listing.Processes[i].PID {
			t.Errorf("processes not PID-ascending at %d", i)
		}
	}
	if stdout != string(golden(t, "list.json.golden")) {
		t.Errorf("JSON mismatch\n--- got ---\n%s", stdout)
	}
}

// --- list: unreadable root is availability, not an error --------------

func TestListUnreadableRootExitsZero(t *testing.T) {
	code, stdout, stderr := invoke([]string{"list", "--root", "/no/such/proc/root"}, false)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 for a non-observed listing", code)
	}
	if !strings.Contains(stdout, "unsupported") && !strings.Contains(stdout, "denied") && !strings.Contains(stdout, "absent") {
		t.Errorf("stdout does not show a not-observed availability: %q", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr not empty: %q", stderr)
	}
}

// --- list: verbose ------------------------------------------------

func TestListVerbose(t *testing.T) {
	code, stdout, stderr := invoke([]string{"list", "--verbose", "--root", fixtureRoot}, false)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if stdout != string(golden(t, "list.txt.golden")) {
		t.Error("--verbose changed stdout from the plain text golden")
	}
	if !strings.Contains(stderr, "root: "+fixtureRoot) {
		t.Errorf("stderr missing resolved-root line: %q", stderr)
	}
	// The fixture root is observed, so no availability line follows.
	if strings.Contains(stderr, "availability:") {
		t.Errorf("observed listing still emitted an availability line: %q", stderr)
	}

	// A non-observed root does carry the availability line.
	_, _, stderr2 := invoke([]string{"list", "--verbose", "--root", "/no/such/proc/root"}, false)
	if !strings.Contains(stderr2, "availability:") {
		t.Errorf("non-observed listing did not emit an availability line: %q", stderr2)
	}
}

// --- list: positional arg and unknown flag are usage errors -----------

func TestListRejectsPositionalAndUnknownFlag(t *testing.T) {
	for _, args := range [][]string{
		{"list", "1234"},
		{"list", "foo"},
		{"list", "--bogus", "--root", fixtureRoot},
	} {
		code, stdout, stderr := invoke(args, false)
		if code != 1 {
			t.Errorf("%v: exit code = %d, want 1", args, code)
		}
		if stdout != "" {
			t.Errorf("%v: stdout not empty: %q", args, stdout)
		}
		if stderr == "" {
			t.Errorf("%v: no error on stderr", args)
		}
	}
}

// --- list: help goes to stdout -------------------------------------

func TestListHelpGoesToStdout(t *testing.T) {
	code, stdout, _ := invoke([]string{"list", "-h"}, false)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "usage:") {
		t.Errorf("help text did not go to stdout: %q", stdout)
	}
}

// --- list: --no-color over a colouring default -----------------------

func TestListNoColorOverridesDefault(t *testing.T) {
	code, stdout, _ := invoke([]string{"list", "--no-color", "--root", fixtureRoot}, true)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Error("--no-color did not suppress ANSI even though colorDefault was true")
	}
	if stdout != string(golden(t, "list.txt.golden")) {
		t.Error("--no-color output should equal the plain text golden")
	}
}

// --- views: happy text, one section per subcommand -------------------

var viewNames = []string{"tree", "files", "network", "security"}

func TestViewHappyText(t *testing.T) {
	for _, v := range viewNames {
		t.Run(v, func(t *testing.T) {
			code, stdout, stderr := invoke([]string{v, "1234", "--root", fixtureRoot}, false)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
			}
			if stdout != string(golden(t, v+".txt.golden")) {
				t.Errorf("stdout mismatch\n--- got ---\n%s", stdout)
			}
			if stderr != "" {
				t.Errorf("stderr not empty: %q", stderr)
			}
			if strings.Contains(stdout, "\x1b[") {
				t.Error("non-TTY text output carries an ANSI escape")
			}
			if !strings.HasPrefix(stdout, "PID 1234  python3  [S]\n") {
				t.Errorf("missing the shared header line: %q", stdout)
			}
			for _, block := range []string{"FACTS", "SIGNALS", "ASSESSMENT"} {
				if strings.Contains(stdout, block) {
					t.Errorf("%s view leaked the %s block", v, block)
				}
			}
		})
	}
}

// --- views: a non-observed target section is header-only, exit 0 -----

func TestViewSectionNotObservedExitsZero(t *testing.T) {
	// Pid 6001's sockets and files sections read as unsupported.
	for _, tc := range []struct{ view, header string }{
		{"network", "sockets    unsupported"},
		{"files", "files      unsupported"},
	} {
		code, stdout, stderr := invoke([]string{tc.view, "6001", "--root", fixtureRoot}, false)
		if code != 0 {
			t.Errorf("%s: exit code = %d, want 0", tc.view, code)
		}
		if !strings.Contains(stdout, tc.header) {
			t.Errorf("%s: stdout missing %q:\n%s", tc.view, tc.header, stdout)
		}
		if strings.Count(strings.TrimRight(stdout, "\n"), "\n") != 1 {
			t.Errorf("%s: expected header + one section line, got:\n%s", tc.view, stdout)
		}
		if stderr != "" {
			t.Errorf("%s: stderr not empty: %q", tc.view, stderr)
		}
	}
}

// --- views: shared error / help / colour / verbose rows --------------

func TestViewSharedRows(t *testing.T) {
	for _, v := range viewNames {
		// PID absent → exit 2, stderr names the pid, stdout empty.
		code, stdout, stderr := invoke([]string{v, "999999", "--root", fixtureRoot}, false)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "999999") {
			t.Errorf("%s absent-pid: code=%d stdout=%q stderr=%q", v, code, stdout, stderr)
		}

		// Bad / missing pid → exit 1 with a usage line on stderr.
		for _, args := range [][]string{{v, "abc"}, {v}} {
			code, stdout, stderr := invoke(args, false)
			if code != 1 || stdout != "" || !strings.Contains(stderr, "usage:") {
				t.Errorf("%v: code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
			}
		}

		// Unknown flag (including --json) → flag error on stderr, exit 1.
		code, stdout, stderr = invoke([]string{v, "1234", "--json", "--root", fixtureRoot}, false)
		if code != 1 || stdout != "" || stderr == "" {
			t.Errorf("%s --json: code=%d stdout=%q stderr=%q", v, code, stdout, stderr)
		}

		// -h → usage block to stdout, exit 0.
		code, stdout, _ = invoke([]string{v, "-h"}, false)
		if code != 0 || !strings.Contains(stdout, "usage:") {
			t.Errorf("%s -h: code=%d stdout=%q", v, code, stdout)
		}

		// --no-color over colorDefault=true → no ANSI, equals plain golden.
		code, stdout, _ = invoke([]string{v, "1234", "--no-color", "--root", fixtureRoot}, true)
		if code != 0 || strings.Contains(stdout, "\x1b[") {
			t.Errorf("%s --no-color: code=%d ansi=%v", v, code, strings.Contains(stdout, "\x1b["))
		}
		if stdout != string(golden(t, v+".txt.golden")) {
			t.Errorf("%s --no-color output should equal the plain golden", v)
		}

		// --verbose → stdout unchanged, stderr carries root:/pid: lines.
		code, stdout, stderr = invoke([]string{v, "1234", "--verbose", "--root", fixtureRoot}, false)
		if code != 0 || stdout != string(golden(t, v+".txt.golden")) {
			t.Errorf("%s --verbose: code=%d stdout changed", v, code)
		}
		if !strings.Contains(stderr, "root: "+fixtureRoot) || !strings.Contains(stderr, "pid: 1234") {
			t.Errorf("%s --verbose: stderr missing diagnostics: %q", v, stderr)
		}
	}
}

// --- Matrix: determinism -------------------------------------------

func TestRunIsDeterministic(t *testing.T) {
	for _, args := range [][]string{
		{"inspect", "1234", "--root", fixtureRoot},
		{"inspect", "1234", "--json", "--root", fixtureRoot},
		{"list", "--root", fixtureRoot},
		{"list", "--json", "--root", fixtureRoot},
		{"tree", "1234", "--root", fixtureRoot},
		{"files", "1234", "--root", fixtureRoot},
		{"network", "1234", "--root", fixtureRoot},
		{"security", "1234", "--root", fixtureRoot},
	} {
		c1, o1, e1 := invoke(args, false)
		c2, o2, e2 := invoke(args, false)
		o1, o2 = string(scrubTimestamps([]byte(o1))), string(scrubTimestamps([]byte(o2)))
		if c1 != c2 || o1 != o2 || e1 != e2 {
			t.Errorf("%v: run is not deterministic", args)
		}
	}
}
