package procfs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// --- Matrix row: normal unprivileged ------------------------------------------

func TestSecurityNormalProcess(t *testing.T) {
	snapshot, err := New(fixtureRoot("normal")).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	got := snapshot.Security

	if got.UID != 1000 || got.EffectiveUID != 1000 {
		t.Errorf("UID/EffectiveUID = %d/%d, want 1000/1000", got.UID, got.EffectiveUID)
	}
	if got.GID != 1000 || got.EffectiveGID != 1000 {
		t.Errorf("GID/EffectiveGID = %d/%d, want 1000/1000", got.GID, got.EffectiveGID)
	}
	if got.CapabilityEffective != "0000000000000000" {
		t.Errorf("CapabilityEffective = %q, want the raw hex mask verbatim", got.CapabilityEffective)
	}
	if got.NoNewPrivileges {
		t.Errorf("NoNewPrivileges = true, want false (NoNewPrivs: 0)")
	}
	if got.SeccompMode != 0 {
		t.Errorf("SeccompMode = %d, want 0", got.SeccompMode)
	}

	wantNamespaces := []model.Namespace{
		{Kind: "cgroup", Identifier: "cgroup:[4026531835]"},
		{Kind: "ipc", Identifier: "ipc:[4026531839]"},
		{Kind: "mnt", Identifier: "mnt:[4026531840]"},
		{Kind: "net", Identifier: "net:[4026531992]"},
		{Kind: "pid", Identifier: "pid:[4026531836]"},
		{Kind: "time", Identifier: "time:[4026531834]"},
		{Kind: "user", Identifier: "user:[4026531837]"},
		{Kind: "uts", Identifier: "uts:[4026531838]"},
	}
	if !reflect.DeepEqual(got.Namespaces, wantNamespaces) {
		t.Errorf("Namespaces =\n  %+v\nwant\n  %+v", got.Namespaces, wantNamespaces)
	}

	if got.CgroupPath != "/system.slice/app.service" {
		t.Errorf("CgroupPath = %q, want the 0:: unified path", got.CgroupPath)
	}
	if got.SecurityLabel != "unconfined" {
		t.Errorf("SecurityLabel = %q, want %q", got.SecurityLabel, "unconfined")
	}
	if snapshot.Availability.Security != model.AvailabilityObserved {
		t.Errorf("Availability.Security = %q, want observed", snapshot.Availability.Security)
	}
}

// --- Matrix rows carried by normal/6001 -------------------------------------

// 6001 is privileged/confined (Uid: 1000 0 0 1000, CapEff full, NoNewPrivs 1,
// Seccomp 2), has no attr/current (missing LSM), a cgroup with no 0:: line
// (v1-only) and no ns/time (a namespace kind the kernel lacks).
func TestSecurityPrivilegedConfinedFixture(t *testing.T) {
	snapshot, err := New(fixtureRoot("normal")).Snapshot(6001)
	if err != nil {
		t.Fatalf("Snapshot(6001): %v", err)
	}
	got := snapshot.Security

	if got.UID != 1000 || got.EffectiveUID != 0 {
		t.Errorf("UID/EffectiveUID = %d/%d, want 1000/0 — a retained-privilege setuid layout", got.UID, got.EffectiveUID)
	}
	if got.GID != 1000 || got.EffectiveGID != 0 {
		t.Errorf("GID/EffectiveGID = %d/%d, want 1000/0", got.GID, got.EffectiveGID)
	}
	if got.CapabilityEffective != "000001ffffffffff" {
		t.Errorf("CapabilityEffective = %q, want 000001ffffffffff", got.CapabilityEffective)
	}
	if !got.NoNewPrivileges {
		t.Errorf("NoNewPrivileges = false, want true (NoNewPrivs: 1)")
	}
	if got.SeccompMode != 2 {
		t.Errorf("SeccompMode = %d, want 2 (filter)", got.SeccompMode)
	}

	// Missing LSM label: skipped, not folded.
	if got.SecurityLabel != "" {
		t.Errorf("SecurityLabel = %q, want empty with no attr/current", got.SecurityLabel)
	}
	// v1-only cgroup: no 0:: line.
	if got.CgroupPath != "" {
		t.Errorf("CgroupPath = %q, want empty for a v1-only cgroup file", got.CgroupPath)
	}
	// Namespace kind absent: ns/time is skipped, the other seven remain, in
	// the fixed order.
	wantNamespaces := []model.Namespace{
		{Kind: "cgroup", Identifier: "cgroup:[4026531835]"},
		{Kind: "ipc", Identifier: "ipc:[4026531839]"},
		{Kind: "mnt", Identifier: "mnt:[4026532200]"},
		{Kind: "net", Identifier: "net:[4026532210]"},
		{Kind: "pid", Identifier: "pid:[4026532205]"},
		{Kind: "user", Identifier: "user:[4026531837]"},
		{Kind: "uts", Identifier: "uts:[4026532201]"},
	}
	if !reflect.DeepEqual(got.Namespaces, wantNamespaces) {
		t.Errorf("Namespaces =\n  %+v\nwant\n  %+v (ns/time omitted)", got.Namespaces, wantNamespaces)
	}

	// None of the three tolerated gaps folds: the section stays observed and
	// every other field is populated, so Block 5 can still read uid/caps.
	if snapshot.Availability.Security != model.AvailabilityObserved {
		t.Errorf("Availability.Security = %q, want observed — a missing kind / label / v1 cgroup must not fold",
			snapshot.Availability.Security)
	}
}

// --- Matrix row: denied namespace link -----------------------------------

// A readlink is denied by removing search permission from the ns/ directory:
// readlink does not consult the leaf symlink's own mode, only parent
// traversal, so a single ns/<kind> cannot be denied in isolation via chmod.
// Every ns readlink then returns EACCES, folds via weakest, and the section
// drops to denied while uid / caps / cgroup / label stay readable.
func TestSecurityDeniedNamespaceLink(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions, so a chmod cannot produce EACCES")
	}
	root := copyFixture(t, "normal")
	nsDir := filepath.Join(root, "1234", "ns")
	if err := os.Chmod(nsDir, 0o000); err != nil {
		t.Fatalf("chmod ns dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(nsDir, 0o755) })

	snapshot, err := New(root).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	if snapshot.Availability.Security != model.AvailabilityDenied {
		t.Errorf("Availability.Security = %q, want denied — a denied ns readlink folds via weakest",
			snapshot.Availability.Security)
	}
	for _, ns := range snapshot.Security.Namespaces {
		if ns.Kind == "net" {
			t.Errorf("net namespace present despite a denied readlink: %+v", ns)
		}
	}
	// The denial must not erase what the other sources read.
	if snapshot.Security.UID != 1000 || snapshot.Security.CgroupPath == "" || snapshot.Security.SecurityLabel != "unconfined" {
		t.Errorf("a denied ns read erased other sources: uid=%d cgroup=%q label=%q",
			snapshot.Security.UID, snapshot.Security.CgroupPath, snapshot.Security.SecurityLabel)
	}
}

// --- Matrix row: denied LSM label --------------------------------------

func TestSecurityDeniedLSMLabel(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions, so a chmod cannot produce EACCES")
	}
	root := copyFixture(t, "normal")
	if err := os.Chmod(filepath.Join(root, "1234", "attr", "current"), 0o000); err != nil {
		t.Fatalf("chmod attr/current: %v", err)
	}

	snapshot, err := New(root).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	if snapshot.Security.SecurityLabel != "" {
		t.Errorf("SecurityLabel = %q, want empty for a denied read", snapshot.Security.SecurityLabel)
	}
	if snapshot.Availability.Security != model.AvailabilityDenied {
		t.Errorf("Availability.Security = %q, want denied — a denied attr/current folds in",
			snapshot.Availability.Security)
	}
	// Everything else the observer reads is still present.
	if snapshot.Security.UID != 1000 || len(snapshot.Security.Namespaces) != 8 {
		t.Errorf("denied label erased other sources: uid=%d namespaces=%d",
			snapshot.Security.UID, len(snapshot.Security.Namespaces))
	}
}

// --- Matrix row: denied status --------------------------------------

func TestSecurityDeniedStatus(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions, so a chmod cannot produce EACCES")
	}
	root := copyFixture(t, "normal")
	if err := os.Chmod(filepath.Join(root, "1234", "status"), 0o000); err != nil {
		t.Fatalf("chmod status: %v", err)
	}

	snapshot, err := New(root).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	got := snapshot.Security
	if got.UID != 0 || got.EffectiveUID != 0 || got.GID != 0 || got.CapabilityEffective != "" || got.SeccompMode != 0 || got.NoNewPrivileges {
		t.Errorf("a denied status leaked non-zero uid/caps/seccomp fields: %+v", got)
	}
	if snapshot.Availability.Security != model.AvailabilityDenied {
		t.Errorf("Availability.Security = %q, want denied", snapshot.Availability.Security)
	}
	// The other sources are unaffected by a denied status.
	if len(got.Namespaces) != 8 || got.CgroupPath == "" {
		t.Errorf("a denied status erased ns/cgroup: namespaces=%d cgroup=%q", len(got.Namespaces), got.CgroupPath)
	}
}

// --- Matrix row: process raced away --------------------------------

// The race is only reachable between two reads, so it is driven at the
// observer level: status is captured, the process exits, and the ns / cgroup /
// attr reads that follow must classify raced rather than absent.
func TestSecurityProcessRacedAway(t *testing.T) {
	root := copyFixture(t, "normal")
	reader := New(root)

	status, statusStatus := reader.status(1234)
	if statusStatus != model.AvailabilityObserved {
		t.Fatalf("status availability = %q before the race, want observed", statusStatus)
	}
	if err := os.RemoveAll(filepath.Join(root, "1234")); err != nil {
		t.Fatalf("removing pid directory: %v", err)
	}

	context, availability := reader.security(1234, status, statusStatus)
	if availability != model.AvailabilityRaced {
		t.Errorf("Availability = %q, want raced", availability)
	}
	// The status captured before the race is still assembled; the reads that
	// raced simply contributed nothing.
	if context.UID != 1000 {
		t.Errorf("UID = %d, want 1000 from the captured status", context.UID)
	}
	if len(context.Namespaces) != 0 || context.CgroupPath != "" || context.SecurityLabel != "" {
		t.Errorf("a raced read fabricated ns/cgroup/label: %+v", context)
	}
}

// --- Matrix row: empty label body --------------------------------

func TestSecurityEmptyLabelBody(t *testing.T) {
	root := copyFixture(t, "normal")
	if err := os.WriteFile(filepath.Join(root, "1234", "attr", "current"), nil, 0o644); err != nil {
		t.Fatalf("truncating attr/current: %v", err)
	}

	snapshot, err := New(root).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	if snapshot.Security.SecurityLabel != "" {
		t.Errorf("SecurityLabel = %q, want empty", snapshot.Security.SecurityLabel)
	}
	if snapshot.Availability.Security != model.AvailabilityObserved {
		t.Errorf("Availability.Security = %q, want observed — a readable empty label is kept as read",
			snapshot.Availability.Security)
	}
}

// --- Determinism -----------------------------------------------

func TestSecurityIsDeterministic(t *testing.T) {
	reader := New(fixtureRoot("normal"))
	first, err := reader.Snapshot(1234)
	if err != nil {
		t.Fatalf("first Snapshot: %v", err)
	}
	second, err := reader.Snapshot(1234)
	if err != nil {
		t.Fatalf("second Snapshot: %v", err)
	}
	if !reflect.DeepEqual(first.Security, second.Security) {
		t.Errorf("Security differs between runs:\n  %+v\n  %+v", first.Security, second.Security)
	}
}

// --- JSON round-trip of a produced Security context (AD-17) ---------

func TestSecurityJSONRoundTrip(t *testing.T) {
	snapshot, err := New(fixtureRoot("normal")).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	encoded, err := json.Marshal(snapshot.Security)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded model.SecurityContext
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(snapshot.Security, decoded) {
		t.Errorf("round trip changed the value\n before: %#v\n  after: %#v", snapshot.Security, decoded)
	}
}

// --- parseUIDLine --------------------------------------------

func TestParseUIDLine(t *testing.T) {
	cases := []struct {
		name          string
		value         string
		id, effective int
		ok            bool
	}{
		{"four tab-separated fields", "1000\t1000\t1000\t1000", 1000, 1000, true},
		{"retained privilege", "1000\t0\t0\t1000", 1000, 0, true},
		{"space separated", "1000 1000", 1000, 1000, true},
		{"exactly two fields", "0\t0", 0, 0, true},
		{"one field is not enough", "1000", 0, 0, false},
		{"empty", "", 0, 0, false},
		{"non-numeric real", "abc\tdef", 0, 0, false},
		{"non-numeric effective", "1000\tx", 0, 0, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			id, effective, ok := parseUIDLine(testCase.value)
			if ok != testCase.ok {
				t.Fatalf("ok = %v, want %v", ok, testCase.ok)
			}
			if id != testCase.id || effective != testCase.effective {
				t.Errorf("= %d/%d, want %d/%d", id, effective, testCase.id, testCase.effective)
			}
		})
	}
}

// --- parseUnifiedCgroup -------------------------------------

func TestParseUnifiedCgroup(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{
			name: "v2 unified line present among v1 lines",
			data: "12:pids:/system.slice/app.service\n4:cpu,cpuacct:/system.slice/app.service\n0::/system.slice/app.service\n",
			want: "/system.slice/app.service",
		},
		{
			name: "v1 only, no 0:: line",
			data: "12:pids:/a\n1:name=systemd:/b\n",
			want: "",
		},
		{"empty", "", ""},
		{"no colons at all", "garbage\n", ""},
		{"a path containing a colon is kept whole", "0::/weird:path/here\n", "/weird:path/here"},
		{"a non-zero hierarchy with empty controllers is not the unified line", "1::/x\n", ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := parseUnifiedCgroup([]byte(testCase.data)); got != testCase.want {
				t.Errorf("parseUnifiedCgroup = %q, want %q", got, testCase.want)
			}
		})
	}
}
