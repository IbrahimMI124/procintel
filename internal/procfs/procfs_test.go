package procfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// fixtureRoot is the root a case's Reader resolves under. Every test in this
// file goes through one of these or through a temporary copy of one; none
// reads the live /proc, which is what makes the suite reproducible on any
// machine (AD-3).
func fixtureRoot(name string) string {
	return filepath.Join("testdata", "proc", name)
}

// copyFixture materialises one fixture case in a temporary directory so a
// test may make it unreadable or delete part of it without touching the
// committed tree.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	destination := t.TempDir()
	source := fixtureRoot(name)

	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		switch {
		case entry.IsDir():
			return os.MkdirAll(target, 0o755)
		case entry.Type()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		default:
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, 0o644)
		}
	})
	if err != nil {
		t.Fatalf("copying fixture %s: %v", name, err)
	}
	return destination
}

// --- Matrix row: normal process -------------------------------------------

func TestSnapshotNormalProcess(t *testing.T) {
	reader := New(fixtureRoot("normal"))
	snapshot, err := reader.Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234) returned error: %v", err)
	}

	if snapshot.SchemaVersion != model.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", snapshot.SchemaVersion, model.SchemaVersion)
	}
	if snapshot.CapturedAt.IsZero() {
		t.Error("CapturedAt is zero; it must be stamped once per snapshot")
	}
	if location := snapshot.CapturedAt.Location(); location != nil && location.String() != "UTC" {
		t.Errorf("CapturedAt location = %s, want UTC", location)
	}

	identity := []struct {
		field string
		got   any
		want  any
	}{
		{"PID", snapshot.PID, 1234},
		{"PPID", snapshot.PPID, 1},
		{"Comm", snapshot.Comm, "python3"},
		{"State", snapshot.State, "S"},
		{"StartTime", snapshot.StartTime, uint64(987654)},
		{"Executable", snapshot.Executable, "/usr/bin/python3"},
		{"WorkingDirectory", snapshot.WorkingDirectory, "/srv/app"},
		{"RootDirectory", snapshot.RootDirectory, "/"},
	}
	for _, check := range identity {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %v, want %v", check.field, check.got, check.want)
		}
	}

	wantArguments := []string{"/usr/bin/python3", "-u", "/srv/app/server.py"}
	if !reflect.DeepEqual(snapshot.CommandLine, wantArguments) {
		t.Errorf("CommandLine = %q, want %q", snapshot.CommandLine, wantArguments)
	}

	resources := []struct {
		field string
		got   uint64
		want  uint64
	}{
		{"UserTime", snapshot.UserTime, 1234},
		{"SystemTime", snapshot.SystemTime, 567},
		{"VirtualBytes", snapshot.VirtualBytes, 123456789},
		{"ResidentBytes", snapshot.ResidentBytes, 2048 * uint64(os.Getpagesize())},
		{"ReadBytes", snapshot.ReadBytes, 4096000},
		{"WriteBytes", snapshot.WriteBytes, 8192000},
	}
	for _, check := range resources {
		if check.got != check.want {
			t.Errorf("%s = %d, want %d", check.field, check.got, check.want)
		}
	}
	if snapshot.ThreadCount != 4 {
		t.Errorf("ThreadCount = %d, want 4", snapshot.ThreadCount)
	}
	if snapshot.Priority != 20 || snapshot.Nice != 0 {
		t.Errorf("Priority/Nice = %d/%d, want 20/0", snapshot.Priority, snapshot.Nice)
	}
	if snapshot.OOMScore != 13 {
		t.Errorf("OOMScore = %d, want 13", snapshot.OOMScore)
	}
	if snapshot.CurrentSyscall != -1 {
		t.Errorf("CurrentSyscall = %d, want -1 (not read in this block)", snapshot.CurrentSyscall)
	}

	for _, section := range []struct {
		name string
		got  model.Availability
	}{
		{"identity", snapshot.Availability.Identity},
		{"resources", snapshot.Availability.Resources},
		{"children", snapshot.Availability.Children},
		{"security", snapshot.Availability.Security},
		{"kernel", snapshot.Availability.Kernel},
	} {
		if section.got != model.AvailabilityObserved {
			t.Errorf("%s availability = %q, want observed", section.name, section.got)
		}
	}
}

// Every section this adapter can populate is now populated: files landed with
// Block 1b, sockets with 1c, children with 1d and security with 1e. The former
// TestSnapshotLeavesUnpopulatedSectionsInvalid guarded the last unpopulated
// section (security); with none left, its per-branch coverage lives in the
// per-observer suites (fd_test.go, net_test.go, lineage_test.go,
// security_test.go).

// --- Matrix row: PID absent -----------------------------------------------

func TestSnapshotPIDAbsent(t *testing.T) {
	reader := New(fixtureRoot("vanished"))
	if _, err := reader.Snapshot(9999); !errors.Is(err, ErrProcessNotFound) {
		t.Fatalf("Snapshot(9999) error = %v, want ErrProcessNotFound", err)
	}
}

// A non-positive PID names no process and must not be probed.
func TestSnapshotRejectsNonPositivePID(t *testing.T) {
	reader := New(fixtureRoot("normal"))
	for _, pid := range []int{0, -1} {
		if _, err := reader.Snapshot(pid); !errors.Is(err, ErrProcessNotFound) {
			t.Errorf("Snapshot(%d) error = %v, want ErrProcessNotFound", pid, err)
		}
	}
}

// --- Matrix row: denied read ----------------------------------------------

func TestSnapshotDeniedRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions, so a chmod cannot produce EACCES")
	}
	root := copyFixture(t, "normal")
	if err := os.Chmod(filepath.Join(root, "1234", "status"), 0o000); err != nil {
		t.Fatalf("chmod status: %v", err)
	}

	snapshot, err := New(root).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot returned error for a denied section: %v", err)
	}
	if snapshot.Availability.Resources != model.AvailabilityDenied {
		t.Errorf("resources availability = %q, want denied", snapshot.Availability.Resources)
	}
	if snapshot.Availability.Identity != model.AvailabilityObserved {
		t.Errorf("identity availability = %q, want observed — one denied section must not take down another",
			snapshot.Availability.Identity)
	}
	// The amended contract: a denied source lowers the section's
	// Availability but must not erase what the readable sources supplied.
	if snapshot.UserTime != 1234 || snapshot.ReadBytes != 4096000 {
		t.Errorf("denied status erased stat/io values (utime=%d read_bytes=%d); "+
			"a denied source must not erase what another source read",
			snapshot.UserTime, snapshot.ReadBytes)
	}
	// status was the preferred Threads source; with it denied, the count
	// falls back to stat field 20 rather than vanishing.
	if snapshot.ThreadCount != 4 {
		t.Errorf("ThreadCount = %d, want 4 from stat's fallback", snapshot.ThreadCount)
	}
	if snapshot.PID != 1234 || snapshot.Comm != "python3" {
		t.Errorf("identity lost across a denied resources read: pid=%d comm=%q", snapshot.PID, snapshot.Comm)
	}
}

// --- Matrix row: vanished mid-read ----------------------------------------

// The race is only reachable between two reads, so it is driven at the
// observer level: stat succeeds, the process then exits, and the next read
// must report raced rather than absent or unsupported.
func TestObserverReportsRacedWhenProcessExitsMidInspection(t *testing.T) {
	root := copyFixture(t, "normal")
	reader := New(root)

	if _, availability := reader.stat(1234); availability != model.AvailabilityObserved {
		t.Fatalf("stat availability = %q before the race, want observed", availability)
	}
	if err := os.RemoveAll(filepath.Join(root, "1234")); err != nil {
		t.Fatalf("removing pid directory: %v", err)
	}

	if _, availability := reader.io(1234); availability != model.AvailabilityRaced {
		t.Errorf("io availability = %q after the process vanished, want raced", availability)
	}
	if _, availability := reader.readlink(1234, interfaceExe); availability != model.AvailabilityRaced {
		t.Errorf("exe availability = %q after the process vanished, want raced", availability)
	}
}

// --- Matrix row: zombie / kernel thread -----------------------------------

func TestSnapshotZombie(t *testing.T) {
	snapshot, err := New(fixtureRoot("zombie")).Snapshot(2222)
	if err != nil {
		t.Fatalf("Snapshot(2222) returned error: %v", err)
	}
	if snapshot.State != "Z" {
		t.Errorf("State = %q, want Z", snapshot.State)
	}
	if snapshot.Comm != "worker" {
		t.Errorf("Comm = %q, want worker", snapshot.Comm)
	}
	if len(snapshot.CommandLine) != 0 {
		t.Errorf("CommandLine = %q, want empty for a zombie", snapshot.CommandLine)
	}
	// The matrix row that matters: no exe link, and therefore no path.
	if snapshot.Executable != "" {
		t.Errorf("Executable = %q, want empty — a missing exe link must not be fabricated", snapshot.Executable)
	}
	if snapshot.Availability.Identity == model.AvailabilityObserved {
		t.Error("identity availability is observed although exe, cwd and root were all unreadable")
	}
}

// --- Matrix row: malformed stat -------------------------------------------

func TestSnapshotMalformed(t *testing.T) {
	snapshot, err := New(fixtureRoot("malformed")).Snapshot(3333)
	if err != nil {
		t.Fatalf("Snapshot(3333) returned error: %v", err)
	}
	if snapshot.Availability.Identity != model.AvailabilityAbsent {
		t.Errorf("identity availability = %q, want absent", snapshot.Availability.Identity)
	}
	if snapshot.Availability.Resources != model.AvailabilityAbsent {
		t.Errorf("resources availability = %q, want absent", snapshot.Availability.Resources)
	}
	if snapshot.PID != 3333 {
		t.Errorf("PID = %d, want the requested 3333 — it identifies the subject, not an observation", snapshot.PID)
	}
	if snapshot.PPID != 0 || snapshot.State != "" || snapshot.StartTime != 0 {
		t.Errorf("observed identity fields not zeroed on a malformed stat: ppid=%d state=%q start=%d",
			snapshot.PPID, snapshot.State, snapshot.StartTime)
	}
	if snapshot.Availability.Kernel != model.AvailabilityAbsent {
		t.Errorf("kernel availability = %q, want absent — oom_score is garbage in this fixture",
			snapshot.Availability.Kernel)
	}
	if snapshot.OOMScore != 0 {
		t.Errorf("OOMScore = %d, want 0 for an unparsable oom_score", snapshot.OOMScore)
	}
	if snapshot.UserTime != 0 || snapshot.VirtualBytes != 0 || snapshot.ThreadCount != 0 {
		t.Errorf("resources not zeroed on a malformed stat: utime=%d vsize=%d threads=%d",
			snapshot.UserTime, snapshot.VirtualBytes, snapshot.ThreadCount)
	}
}

// --- Matrix row: comm containing spaces and parentheses --------------------

func TestParseStat(t *testing.T) {
	pageSize := uint64(os.Getpagesize())
	// rest[2..10] filler, then utime, stime, cutime, cstime, priority,
	// nice, num_threads, itrealvalue, starttime, vsize, rss-in-pages.
	const tail = " 0 -1 0 0 0 0 0 0 0 11 12 0 0 20 5 7 0 4242 999 3"

	cases := []struct {
		name string
		line string
		ok   bool
		want statFields
	}{
		{
			name: "plain comm",
			line: "42 (bash) S 1" + tail,
			ok:   true,
			want: statFields{
				PID: 42, Comm: "bash", State: "S", PPID: 1,
				UserTime: 11, SystemTime: 12, Priority: 20, Nice: 5,
				ThreadCount: 7, StartTime: 4242, VirtualBytes: 999,
				ResidentBytes: 3 * pageSize,
			},
		},
		{
			// The classic bug: splitting on whitespace or on the FIRST
			// ')' shifts every subsequent field by one or more.
			name: "comm with spaces and nested parentheses",
			line: "42 (my (odd) proc) S 1" + tail,
			ok:   true,
			want: statFields{
				PID: 42, Comm: "my (odd) proc", State: "S", PPID: 1,
				UserTime: 11, SystemTime: 12, Priority: 20, Nice: 5,
				ThreadCount: 7, StartTime: 4242, VirtualBytes: 999,
				ResidentBytes: 3 * pageSize,
			},
		},
		{
			name: "comm containing a close parenthesis only",
			line: "42 (weird)name) R 9" + tail,
			ok:   true,
			want: statFields{
				PID: 42, Comm: "weird)name", State: "R", PPID: 9,
				UserTime: 11, SystemTime: 12, Priority: 20, Nice: 5,
				ThreadCount: 7, StartTime: 4242, VirtualBytes: 999,
				ResidentBytes: 3 * pageSize,
			},
		},
		{name: "empty", line: "", ok: false},
		{name: "no parentheses", line: "42 bash S 1" + tail, ok: false},
		{name: "truncated after comm", line: "42 (bash) S 1 0 -1", ok: false},
		{name: "non-numeric pid", line: "x (bash) S 1" + tail, ok: false},
		{name: "non-numeric utime", line: "42 (bash) S 1 0 -1 0 0 0 0 0 0 0 x 12 0 0 20 5 7 0 4242 999 3", ok: false},
		{name: "multi-character state", line: "42 (bash) SS 1" + tail, ok: false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := parseStat([]byte(testCase.line), pageSize)
			if ok != testCase.ok {
				t.Fatalf("parseStat ok = %v, want %v (got %+v)", ok, testCase.ok, got)
			}
			if !testCase.ok {
				if got != (statFields{}) {
					t.Errorf("a rejected line returned %+v, want the zero value", got)
				}
				return
			}
			if got != testCase.want {
				t.Errorf("parseStat =\n  %+v\nwant\n  %+v", got, testCase.want)
			}
		})
	}
}

// --- Matrix row: reads never escape the root ------------------------------

func TestReadsNeverEscapeTheRoot(t *testing.T) {
	reader := New(fixtureRoot("normal"))
	if reader.Root() != fixtureRoot("normal") {
		t.Fatalf("Root() = %q, want %q", reader.Root(), fixtureRoot("normal"))
	}

	// A PID directory that is itself a symlink out of the root must not be
	// followed: on a live /proc the inspected process would control where
	// it points.
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "stat"), []byte("1 (escaped) S 1\n"), 0o644); err != nil {
		t.Fatalf("writing outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "1234")); err != nil {
		t.Fatalf("creating escaping symlink: %v", err)
	}

	if _, availability := New(root).stat(1234); availability == model.AvailabilityObserved {
		t.Error("stat read through a symlink pointing outside the root")
	}
}

// A root that does not exist degrades to an Availability, never a panic and
// never a constructor error.
func TestMissingRootDegrades(t *testing.T) {
	reader := New(filepath.Join(t.TempDir(), "no-such-root"))
	if _, err := reader.Snapshot(1); !errors.Is(err, ErrProcessNotFound) {
		t.Errorf("Snapshot under a missing root: err = %v, want ErrProcessNotFound", err)
	}
	if _, availability := reader.stat(1); availability != model.AvailabilityUnsupported {
		t.Errorf("stat availability under a missing root = %q, want unsupported", availability)
	}
}

// --- Section availability combination -------------------------------------

func TestWeakest(t *testing.T) {
	cases := []struct {
		name    string
		sources []model.Availability
		want    model.Availability
	}{
		{"all observed", []model.Availability{model.AvailabilityObserved, model.AvailabilityObserved}, model.AvailabilityObserved},
		{"denied beats every other", []model.Availability{model.AvailabilityObserved, model.AvailabilityAbsent, model.AvailabilityDenied}, model.AvailabilityDenied},
		{"raced beats unsupported", []model.Availability{model.AvailabilityRaced, model.AvailabilityUnsupported}, model.AvailabilityRaced},
		{"unsupported beats absent", []model.Availability{model.AvailabilityAbsent, model.AvailabilityUnsupported}, model.AvailabilityUnsupported},
		{"absent alone", []model.Availability{model.AvailabilityAbsent}, model.AvailabilityAbsent},
		{"no sources is absent, never observed", nil, model.AvailabilityAbsent},
		{"an illegal value cannot be talked up", []model.Availability{model.AvailabilityObserved, model.Availability("")}, model.AvailabilityAbsent},
		{"an unknown value cannot be talked up", []model.Availability{model.AvailabilityObserved, model.Availability("bogus")}, model.AvailabilityAbsent},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := weakest(testCase.sources...); got != testCase.want {
				t.Errorf("weakest(%v) = %q, want %q", testCase.sources, got, testCase.want)
			}
		})
	}
}

// --- status and io parsers ------------------------------------------------

func TestParseStatus(t *testing.T) {
	parsed := parseStatus([]byte("Name:\tpython3\nUid:\t1000\t1000\t1000\t1000\nThreads:\t4\nbroken line\nSeccomp:\t2\n"))

	// Order is the kernel's, so no map is iterated on any output path (AD-6).
	wantKeys := []string{"Name", "Uid", "Threads", "Seccomp"}
	if len(parsed) != len(wantKeys) {
		t.Fatalf("parsed %d entries (%+v), want %d", len(parsed), parsed, len(wantKeys))
	}
	for index, key := range wantKeys {
		if parsed[index].Key != key {
			t.Errorf("entry %d key = %q, want %q", index, parsed[index].Key, key)
		}
	}

	// The multi-field value Block 1e needs is preserved whole.
	if value, _ := parsed.Lookup("Uid"); value != "1000\t1000\t1000\t1000" {
		t.Errorf("Uid = %q, want the four fields intact", value)
	}
	if threads, ok := parsed.LookupUint("Threads"); !ok || threads != 4 {
		t.Errorf("LookupUint(Threads) = %d, %v; want 4, true", threads, ok)
	}
	if _, ok := parsed.Lookup("Absent"); ok {
		t.Error("Lookup reported a key that is not in the file")
	}
	if parseStatus([]byte("no colons at all\n")) != nil {
		t.Error("a file with no parsable line must parse to nil, not an empty non-nil slice")
	}
}

// A present-but-unparsable key is reported missing rather than zero, so no
// caller can read a malformed field as a value.
func TestLookupUintRejectsUnparsableValue(t *testing.T) {
	parsed := parseStatus([]byte("Threads:\tmany\n"))
	if value, ok := parsed.LookupUint("Threads"); ok {
		t.Errorf("LookupUint on an unparsable value = %d, true; want 0, false", value)
	}
}

func TestParseIO(t *testing.T) {
	cases := []struct {
		name  string
		input string
		ok    bool
		want  ioCounters
	}{
		{
			name:  "both counters",
			input: "rchar: 9\nread_bytes: 4096\nwrite_bytes: 8192\n",
			ok:    true,
			want:  ioCounters{ReadBytes: 4096, WriteBytes: 8192},
		},
		{name: "write_bytes missing", input: "read_bytes: 4096\n", ok: false},
		{name: "read_bytes missing", input: "write_bytes: 8192\n", ok: false},
		{name: "unparsable counter", input: "read_bytes: x\nwrite_bytes: 1\n", ok: false},
		{name: "empty", input: "", ok: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := parseIO([]byte(testCase.input))
			if ok != testCase.ok {
				t.Fatalf("parseIO ok = %v, want %v", ok, testCase.ok)
			}
			if got != testCase.want {
				t.Errorf("parseIO = %+v, want %+v", got, testCase.want)
			}
		})
	}
}

func TestSplitNUL(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"trailing NUL is not an argument", "/bin/ls\x00-l\x00", []string{"/bin/ls", "-l"}},
		{"no trailing NUL", "/bin/ls\x00-l", []string{"/bin/ls", "-l"}},
		{"single argument", "/bin/ls", []string{"/bin/ls"}},
		{"empty is nil, not an empty vector", "", nil},
		{"an interior empty argument is preserved", "/bin/sh\x00\x00-c\x00", []string{"/bin/sh", "", "-c"}},
		{"only NULs keeps the interior empties", "\x00\x00", []string{"", ""}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := splitNUL([]byte(testCase.input)); !reflect.DeepEqual(got, testCase.want) {
				t.Errorf("splitNUL = %q, want %q", got, testCase.want)
			}
		})
	}
}

// --- Determinism ----------------------------------------------------------

// Golden-file tests in Block 2 depend on this: two snapshots of the same
// fixture must differ only in their capture timestamp.
func TestSnapshotIsDeterministic(t *testing.T) {
	reader := New(fixtureRoot("normal"))
	first, err := reader.Snapshot(1234)
	if err != nil {
		t.Fatalf("first Snapshot: %v", err)
	}
	second, err := reader.Snapshot(1234)
	if err != nil {
		t.Fatalf("second Snapshot: %v", err)
	}
	second.CapturedAt = first.CapturedAt
	if !reflect.DeepEqual(first, second) {
		t.Errorf("two snapshots of one fixture differ:\n%+v\n%+v", first, second)
	}
}

// --- Findings from review: gaps that survived mutation --------------------

// classify is documented as the only place that decides what a filesystem
// error means, but every denial test path goes through chmod, which is inert
// under uid 0. Feeding synthesized errors straight in verifies the mapping on
// any machine, root included.
func TestClassify(t *testing.T) {
	root, err := os.OpenRoot(fixtureRoot("normal"))
	if err != nil {
		t.Fatalf("opening fixture root: %v", err)
	}
	defer root.Close()

	const livePID = 1234 // present in the fixture
	const deadPID = 4321 // never present

	cases := []struct {
		name         string
		pid          int
		err          error
		missingMeans model.Availability
		want         model.Availability
	}{
		{"nil error is observed", livePID, nil, model.AvailabilityUnsupported, model.AvailabilityObserved},
		{"EACCES is denied", livePID, &fs.PathError{Err: syscall.EACCES}, model.AvailabilityUnsupported, model.AvailabilityDenied},
		{"EPERM is denied", livePID, &fs.PathError{Err: syscall.EPERM}, model.AvailabilityUnsupported, model.AvailabilityDenied},
		{"ESRCH is raced", livePID, &fs.PathError{Err: syscall.ESRCH}, model.AvailabilityUnsupported, model.AvailabilityRaced},
		{"ENOENT on a live pid takes missingMeans", livePID, &fs.PathError{Err: syscall.ENOENT}, model.AvailabilityUnsupported, model.AvailabilityUnsupported},
		{"ENOENT on a live pid, link flavour", livePID, &fs.PathError{Err: syscall.ENOENT}, model.AvailabilityAbsent, model.AvailabilityAbsent},
		{"ENOENT on a vanished pid is raced", deadPID, &fs.PathError{Err: syscall.ENOENT}, model.AvailabilityUnsupported, model.AvailabilityRaced},
		{"EIO on a live pid is absent", livePID, &fs.PathError{Err: syscall.EIO}, model.AvailabilityUnsupported, model.AvailabilityAbsent},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := classify(root, testCase.pid, testCase.err, testCase.missingMeans); got != testCase.want {
				t.Errorf("classify = %q, want %q", got, testCase.want)
			}
		})
	}
}

// An interface file missing under a live PID means the kernel does not offer
// it — unsupported — while a missing symlink node means only that this
// process has no target. No fixture distinguished the two, so flipping any
// missingMeans argument used to pass.
func TestMissingInterfaceIsUnsupportedButMissingLinkIsAbsent(t *testing.T) {
	root := copyFixture(t, "normal")
	if err := os.Remove(filepath.Join(root, "1234", "io")); err != nil {
		t.Fatalf("removing io: %v", err)
	}
	reader := New(root)

	if _, availability := reader.io(1234); availability != model.AvailabilityUnsupported {
		t.Errorf("io availability with the file removed = %q, want unsupported", availability)
	}
	// zombie/2222 has no exe node at all.
	if _, availability := New(fixtureRoot("zombie")).readlink(2222, interfaceExe); availability != model.AvailabilityAbsent {
		t.Errorf("exe availability with no link node = %q, want absent", availability)
	}

	snapshot, err := reader.Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Availability.Resources != model.AvailabilityUnsupported {
		t.Errorf("resources availability = %q, want unsupported", snapshot.Availability.Resources)
	}
}

// threadCount prefers status's named key over stat's positional field. Both
// fixtures carry the same number, so inverting the function used to pass.
func TestThreadCountPrefersStatus(t *testing.T) {
	fields := statFields{ThreadCount: 7}
	cases := []struct {
		name   string
		status string
		want   int
	}{
		{"status wins when the two disagree", "Threads:\t99\n", 99},
		{"falls back to stat when the key is absent", "Name:\tx\n", 7},
		{"falls back to stat when the value is unparsable", "Threads:\tmany\n", 7},
		{"falls back to stat when the value is empty", "Threads:\t\n", 7},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := threadCount(parseStatus([]byte(testCase.status)), fields); got != testCase.want {
				t.Errorf("threadCount = %d, want %d", got, testCase.want)
			}
		})
	}
}

// Comm falls back to stat field 2 when the comm file yields nothing, and an
// empty comm file is absent rather than an observed empty name. Both fixtures
// held the same string in both sources, so dropping either used to pass.
func TestCommFallsBackToStat(t *testing.T) {
	root := copyFixture(t, "normal")
	commPath := filepath.Join(root, "1234", "comm")
	if err := os.WriteFile(commPath, nil, 0o644); err != nil {
		t.Fatalf("truncating comm: %v", err)
	}
	reader := New(root)

	if name, availability := reader.comm(1234); availability != model.AvailabilityAbsent || name != "" {
		t.Errorf("comm on an empty file = %q/%q, want \"\"/absent", name, availability)
	}
	snapshot, err := reader.Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Comm != "python3" {
		t.Errorf("Comm = %q, want python3 from stat field 2", snapshot.Comm)
	}
}

// An empty cmdline is "this process has no command line", not an observed
// empty vector. Both fixtures that have one also lack exe/cwd/root, so the
// identity result could not be attributed to cmdline.
func TestEmptyCmdlineAloneDegradesIdentity(t *testing.T) {
	root := copyFixture(t, "normal")
	if err := os.WriteFile(filepath.Join(root, "1234", "cmdline"), nil, 0o644); err != nil {
		t.Fatalf("truncating cmdline: %v", err)
	}
	reader := New(root)

	if arguments, availability := reader.cmdline(1234); availability != model.AvailabilityAbsent || arguments != nil {
		t.Errorf("cmdline on an empty file = %q/%q, want nil/absent", arguments, availability)
	}
	snapshot, err := reader.Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Availability.Identity != model.AvailabilityAbsent {
		t.Errorf("identity availability = %q, want absent — every other identity source is readable here",
			snapshot.Availability.Identity)
	}
}

// The amended contract, and the case that prompted it: stat is world-readable
// while the links are not, and the readable facts must survive.
func TestDeniedLinksKeepStatDerivedIdentity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions, so a chmod cannot produce EACCES")
	}
	root := copyFixture(t, "normal")
	// A directory with no execute permission denies every lookup inside it,
	// which is how another user's /proc entry behaves for exe/cwd/root.
	if err := os.Chmod(filepath.Join(root, "1234"), 0o600); err != nil {
		t.Fatalf("chmod pid directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "1234"), 0o755) })

	snapshot, err := New(root).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot returned error for a denied process: %v", err)
	}
	if snapshot.PID != 1234 {
		t.Errorf("PID = %d, want the requested 1234 even when every read is denied", snapshot.PID)
	}
	if snapshot.Availability.Identity != model.AvailabilityDenied {
		t.Errorf("identity availability = %q, want denied", snapshot.Availability.Identity)
	}
}

// An unreadable root says nothing about whether the process is running, so it
// must not be reported as "no such process".
func TestUnreadableRootIsNotProcessNotFound(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions, so a chmod cannot produce EACCES")
	}
	root := copyFixture(t, "normal")
	if err := os.Chmod(root, 0o000); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	if _, err := New(root).Snapshot(1234); errors.Is(err, ErrProcessNotFound) {
		t.Error("an unreadable root reported ErrProcessNotFound, fabricating a claim the read never supported")
	}
}

// Identical fixture bytes must yield an identical Snapshot on any page size,
// or the golden files above this layer are not portable.
func TestResidentBytesFollowsTheReaderPageSize(t *testing.T) {
	fields, ok := parseStat([]byte("1 (x) S 1 0 -1 0 0 0 0 0 0 0 1 1 0 0 20 0 1 0 1 0 2"), 16384)
	if !ok {
		t.Fatal("parseStat rejected a well-formed line")
	}
	if fields.ResidentBytes != 2*16384 {
		t.Errorf("ResidentBytes = %d, want %d", fields.ResidentBytes, 2*16384)
	}
}

// A /proc entry describing a different process than the one requested means
// the entry was recycled under the read.
func TestStatNamingAnotherPIDIsRaced(t *testing.T) {
	root := copyFixture(t, "normal")
	if err := os.Rename(filepath.Join(root, "1234"), filepath.Join(root, "5678")); err != nil {
		t.Fatalf("renaming pid directory: %v", err)
	}
	snapshot, err := New(root).Snapshot(5678)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Availability.Identity != model.AvailabilityRaced {
		t.Errorf("identity availability = %q, want raced — stat names pid 1234, not 5678",
			snapshot.Availability.Identity)
	}
}
