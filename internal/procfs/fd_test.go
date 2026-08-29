package procfs

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// wantNormalDescriptors is the classification of testdata/proc/normal/1234/fd,
// in the order AD-6 requires: ascending descriptor number, which is numeric
// and not lexicographic — fd 10 sorts after fd 5, not between 1 and 2.
var wantNormalDescriptors = []model.FileDescriptor{
	{Number: 0, Kind: model.FileDescriptorKindFile, Target: "/srv/app/server.py"},
	{Number: 1, Kind: model.FileDescriptorKindPipe, Target: "pipe:[123456]"},
	{Number: 2, Kind: model.FileDescriptorKindSocket, Target: "socket:[654321]", SocketInode: 654321},
	{Number: 3, Kind: model.FileDescriptorKindAnonymous, Target: "anon_inode:[eventpoll]"},
	{Number: 4, Kind: model.FileDescriptorKindFile, Target: "/srv/app/tmp/scratch.log", Deleted: true},
	{Number: 5, Kind: model.FileDescriptorKindDirectory, Target: "/srv/app"},
	{Number: 10, Kind: model.FileDescriptorKindFile, Target: "/var/log/app.log"},
}

// --- Matrix row: normal fds ------------------------------------------------

func TestFileDescriptorsNormalProcess(t *testing.T) {
	reader := New(fixtureRoot("normal"))
	descriptors, availability := reader.fileDescriptors(1234)

	if availability != model.AvailabilityObserved {
		t.Fatalf("files availability = %q, want observed", availability)
	}
	if !reflect.DeepEqual(descriptors, wantNormalDescriptors) {
		t.Errorf("descriptors =\n%+v\nwant\n%+v", descriptors, wantNormalDescriptors)
	}
}

// The Snapshot seam: the same list, reached through the assembled value, with
// the section availability set. A socket descriptor carries only its inode —
// the join into Snapshot.Sockets belongs to the socket observer (AD-15), so
// this block must leave that list alone.
func TestSnapshotPopulatesFilesSection(t *testing.T) {
	snapshot, err := New(fixtureRoot("normal")).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	if snapshot.Availability.Files != model.AvailabilityObserved {
		t.Errorf("Availability.Files = %q, want observed", snapshot.Availability.Files)
	}
	if !reflect.DeepEqual(snapshot.FileDescriptors, wantNormalDescriptors) {
		t.Errorf("FileDescriptors =\n%+v\nwant\n%+v", snapshot.FileDescriptors, wantNormalDescriptors)
	}
	if snapshot.Sockets != nil {
		t.Errorf("Sockets = %+v, want nil — the fd/socket join is not this block's (AD-15)", snapshot.Sockets)
	}
	if snapshot.Availability.Sockets.Valid() {
		t.Errorf("Availability.Sockets = %q, want the zero value for a section this build does not read",
			snapshot.Availability.Sockets)
	}
}

// --- Matrix row: deleted target --------------------------------------------

// The " (deleted)" suffix is stripped before classification, so a deleted
// path is still classified from the path that remains and the flag records
// why the target no longer resolves.
func TestDeletedSuffixIsStrippedAndRecorded(t *testing.T) {
	reader := New(fixtureRoot("normal"))
	cases := []struct {
		name       string
		rawTarget  string
		wantKind   model.FileDescriptorKind
		wantTarget string
		wantInode  uint64
		wantDelete bool
	}{
		{"plain path", "/srv/app/server.py", model.FileDescriptorKindFile, "/srv/app/server.py", 0, false},
		{"deleted path", "/tmp/x (deleted)", model.FileDescriptorKindFile, "/tmp/x", 0, true},
		{"socket", "socket:[42]", model.FileDescriptorKindSocket, "socket:[42]", 42, false},
		{"deleted socket shape", "socket:[42] (deleted)", model.FileDescriptorKindSocket, "socket:[42]", 42, true},
		{"pipe", "pipe:[7]", model.FileDescriptorKindPipe, "pipe:[7]", 0, false},
		{"anon inode", "anon_inode:[timerfd]", model.FileDescriptorKindAnonymous, "anon_inode:[timerfd]", 0, false},
		{"anon inode without brackets", "anon_inode:inotify", model.FileDescriptorKindAnonymous, "anon_inode:inotify", 0, false},
		// A socket target the kernel does not emit: the descriptor keeps its
		// kind and target, and reports no inode rather than a zero that a
		// later join would read as a real inode number.
		{"socket with unparsable inode", "socket:[abc]", model.FileDescriptorKindSocket, "socket:[abc]", 0, false},
		// A path that merely contains the deleted suffix mid-string is not a
		// deleted marker: only the suffix counts.
		{"suffix mid path", "/tmp/a (deleted)/b", model.FileDescriptorKindFile, "/tmp/a (deleted)/b", 0, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// pid 1234 exists in the fixture; fd 99 has no fdinfo, which is
			// the documented default-to-file path.
			got := reader.classifyDescriptor(1234, 99, "99", testCase.rawTarget)
			want := model.FileDescriptor{
				Number:      99,
				Kind:        testCase.wantKind,
				Target:      testCase.wantTarget,
				SocketInode: testCase.wantInode,
				Deleted:     testCase.wantDelete,
			}
			if got != want {
				t.Errorf("classifyDescriptor = %+v, want %+v", got, want)
			}
		})
	}
}

// --- Matrix row: directory without O_DIRECTORY -----------------------------

// The stated limitation, pinned by a test so it cannot be quietly broken in
// either direction: the bit set means directory, and anything else — bit
// clear, file missing, value unparsable — means file.
func TestDirectorySplitDependsOnODirectoryOnly(t *testing.T) {
	root := copyFixture(t, "normal")
	reader := New(root)
	fdinfo := filepath.Join(root, "1234", interfaceFDInfo, "5")

	cases := []struct {
		name     string
		contents string
		remove   bool
		want     model.FileDescriptorKind
	}{
		{name: "O_DIRECTORY set", contents: "pos:\t0\nflags:\t0300000\nmnt_id:\t29\n", want: model.FileDescriptorKindDirectory},
		{name: "bit set among other flags", contents: "pos:\t0\nflags:\t02300002\n", want: model.FileDescriptorKindDirectory},
		{name: "bit clear", contents: "pos:\t0\nflags:\t0100002\n", want: model.FileDescriptorKindFile},
		{name: "flags line non-numeric", contents: "pos:\t0\nflags:\tO_DIRECTORY\n", want: model.FileDescriptorKindFile},
		{name: "flags line empty", contents: "pos:\t0\nflags:\t\n", want: model.FileDescriptorKindFile},
		{name: "flags line missing", contents: "pos:\t0\nmnt_id:\t29\n", want: model.FileDescriptorKindFile},
		{name: "fdinfo file empty", contents: "", want: model.FileDescriptorKindFile},
		{name: "fdinfo file missing", remove: true, want: model.FileDescriptorKindFile},
		// 9 is octal-invalid: a decimal reading of the kernel's octal value
		// would silently accept it and, worse, misread every legal value.
		{name: "flags line decimal-only digits", contents: "flags:\t99999\n", want: model.FileDescriptorKindFile},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.remove {
				if err := os.Remove(fdinfo); err != nil {
					t.Fatalf("removing fdinfo: %v", err)
				}
				t.Cleanup(func() { _ = os.WriteFile(fdinfo, []byte("flags:\t0300000\n"), 0o644) })
			} else if err := os.WriteFile(fdinfo, []byte(testCase.contents), 0o644); err != nil {
				t.Fatalf("writing fdinfo: %v", err)
			}

			descriptors, availability := reader.fileDescriptors(1234)
			if availability != model.AvailabilityObserved {
				t.Fatalf("files availability = %q, want observed — an unreadable fdinfo is not a section gap", availability)
			}
			for _, descriptor := range descriptors {
				if descriptor.Number != 5 {
					continue
				}
				if descriptor.Kind != testCase.want {
					t.Errorf("fd 5 kind = %q, want %q", descriptor.Kind, testCase.want)
				}
				return
			}
			t.Fatal("fd 5 missing from the enumeration")
		})
	}
}

// Classification is readlink-text-first and fdinfo-second: a socket, pipe or
// anon_inode descriptor is never reclassified by an O_DIRECTORY bit, however
// its fdinfo happens to read.
func TestPseudoTargetsIgnoreFDInfo(t *testing.T) {
	root := copyFixture(t, "normal")
	for _, number := range []string{"1", "2", "3"} {
		path := filepath.Join(root, "1234", interfaceFDInfo, number)
		if err := os.WriteFile(path, []byte("flags:\t0300000\n"), 0o644); err != nil {
			t.Fatalf("writing fdinfo %s: %v", number, err)
		}
	}
	descriptors, _ := New(root).fileDescriptors(1234)
	for _, descriptor := range descriptors {
		if descriptor.Number > 3 {
			continue
		}
		if descriptor.Number != 0 && descriptor.Kind == model.FileDescriptorKindDirectory {
			t.Errorf("fd %d classified %q from fdinfo; the link target already decided it",
				descriptor.Number, descriptor.Kind)
		}
	}
}

// combineFDCandidates is the pure seam that turns per-entry read outcomes
// into the section's descriptors and Availability, so the per-entry Denied
// branch is exercisable without a filesystem shape that could produce it: a
// chmod on fd/ denies the whole directory listing before any entry's
// readlink runs, and readlink permission on a symlink is governed by the
// containing directory's search bit, not the symlink's own mode — there is
// no fixture that denies exactly one entry.
func TestCombineFDCandidatesDeniedEntryIsNotErased(t *testing.T) {
	candidates := []fdCandidate{
		{number: 0, name: "0", target: "/srv/app/server.py", availability: model.AvailabilityObserved},
		{number: 1, name: "1", target: "pipe:[123]", availability: model.AvailabilityDenied},
		{number: 2, name: "2", target: "socket:[456]", availability: model.AvailabilityObserved},
	}
	classify := func(number int, name, target string) model.FileDescriptor {
		return model.FileDescriptor{Number: number, Target: target, Kind: model.FileDescriptorKindFile}
	}

	descriptors, availability := combineFDCandidates(candidates, classify)

	if availability != model.AvailabilityDenied {
		t.Errorf("availability = %q, want denied — a denied entry must not be silently dropped from the section's status", availability)
	}
	wantNumbers := []int{0, 2}
	if len(descriptors) != len(wantNumbers) {
		t.Fatalf("descriptors = %+v, want entries for fd 0 and 2", descriptors)
	}
	for i, number := range wantNumbers {
		if descriptors[i].Number != number {
			t.Errorf("descriptors[%d].Number = %d, want %d — the successfully read entries must still be returned",
				i, descriptors[i].Number, number)
		}
	}
}

// A vanished entry (readlink failed for any reason other than Denied) is
// dropped silently and does not, by itself, pull the section's Availability
// away from observed.
func TestCombineFDCandidatesVanishedEntryStaysObserved(t *testing.T) {
	candidates := []fdCandidate{
		{number: 0, name: "0", target: "/srv/app/server.py", availability: model.AvailabilityObserved},
		{number: 1, name: "1", target: "", availability: model.AvailabilityRaced},
	}
	classify := func(number int, name, target string) model.FileDescriptor {
		return model.FileDescriptor{Number: number, Target: target, Kind: model.FileDescriptorKindFile}
	}

	descriptors, availability := combineFDCandidates(candidates, classify)

	if availability != model.AvailabilityObserved {
		t.Errorf("availability = %q, want observed", availability)
	}
	if len(descriptors) != 1 || descriptors[0].Number != 0 {
		t.Errorf("descriptors = %+v, want just fd 0", descriptors)
	}
}

// --- Matrix row: denied fd/ ------------------------------------------------

func TestDeniedFDDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions, so a chmod cannot produce EACCES")
	}
	root := copyFixture(t, "normal")
	directory := filepath.Join(root, "1234", interfaceFD)
	if err := os.Chmod(directory, 0o000); err != nil {
		t.Fatalf("chmod fd directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o755) })

	snapshot, err := New(root).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot returned error for a denied fd directory: %v", err)
	}
	if snapshot.Availability.Files != model.AvailabilityDenied {
		t.Errorf("Availability.Files = %q, want denied", snapshot.Availability.Files)
	}
	if snapshot.FileDescriptors != nil {
		t.Errorf("FileDescriptors = %+v, want none — an unreadable directory is not an empty one",
			snapshot.FileDescriptors)
	}
	// A denied fd/ says nothing about the sections another source supplied.
	if snapshot.Availability.Identity != model.AvailabilityObserved {
		t.Errorf("Availability.Identity = %q, want observed", snapshot.Availability.Identity)
	}
	if snapshot.Availability.Resources != model.AvailabilityObserved {
		t.Errorf("Availability.Resources = %q, want observed", snapshot.Availability.Resources)
	}
	if snapshot.Comm != "python3" {
		t.Errorf("Comm = %q, want python3 — a denied fd/ must not erase a readable fact", snapshot.Comm)
	}
}

// --- Matrix row: zombie ----------------------------------------------------

// A reaped process still has an fd directory; it is simply empty. An empty
// list that reported observed would claim "this process holds no descriptors"
// with the same words a live process with none would use, so it is absent.
func TestZombieHasEmptyFDDirectory(t *testing.T) {
	snapshot, err := New(fixtureRoot("zombie")).Snapshot(2222)
	if err != nil {
		t.Fatalf("Snapshot(2222): %v", err)
	}
	if len(snapshot.FileDescriptors) != 0 {
		t.Errorf("FileDescriptors = %+v, want none", snapshot.FileDescriptors)
	}
	if snapshot.Availability.Files != model.AvailabilityAbsent {
		t.Errorf("Availability.Files = %q, want absent", snapshot.Availability.Files)
	}
}

// --- Matrix row: vanished mid-enumeration ----------------------------------

// An entry whose readlink fails while the process is still present was closed
// between the directory read and the link read. The list is accurate without
// it, so the entry is dropped and the section stays observed — one bad entry
// degrades, it does not erase (AD-4).
//
// A regular file in fd/ reproduces that signature deterministically: the name
// survives the directory read and the readlink then fails, which is what a
// mid-enumeration close looks like from the reader's side, without a race the
// test would have to win.
func TestUnreadableEntryIsSkippedWithoutDegradingTheSection(t *testing.T) {
	root := copyFixture(t, "normal")
	if err := os.WriteFile(filepath.Join(root, "1234", interfaceFD, "9"), nil, 0o644); err != nil {
		t.Fatalf("writing fd entry: %v", err)
	}

	descriptors, availability := New(root).fileDescriptors(1234)
	if availability != model.AvailabilityObserved {
		t.Errorf("files availability = %q, want observed", availability)
	}
	if !reflect.DeepEqual(descriptors, wantNormalDescriptors) {
		t.Errorf("descriptors =\n%+v\nwant the fixture's, with 9 dropped\n%+v", descriptors, wantNormalDescriptors)
	}
}

// A truly gone PID during enumeration is raced, not observed-empty: nothing
// in the fd list can be trusted once the subject has exited.
func TestVanishedProcessDuringEnumerationIsRaced(t *testing.T) {
	root := copyFixture(t, "normal")
	if err := os.RemoveAll(filepath.Join(root, "1234")); err != nil {
		t.Fatalf("removing pid directory: %v", err)
	}
	if _, availability := New(root).fileDescriptors(1234); availability != model.AvailabilityRaced {
		t.Errorf("files availability = %q, want raced", availability)
	}
}

// --- readdir ---------------------------------------------------------------

// readdir is the one place a non-kernel entry name is judged, so the fixture's
// stray note file must not reach a caller's loop.
func TestReaddirReturnsNumericNamesOnly(t *testing.T) {
	names, availability := New(fixtureRoot("normal")).readdir(1234, interfaceFD)
	if availability != model.AvailabilityObserved {
		t.Fatalf("readdir availability = %q, want observed", availability)
	}
	if len(names) != len(wantNormalDescriptors) {
		t.Errorf("readdir returned %d names (%v), want %d", len(names), names, len(wantNormalDescriptors))
	}
	for _, name := range names {
		if name == "notes" {
			t.Error("readdir returned the fixture's non-numeric entry")
		}
	}
}

// A directory interface missing under a live PID means the kernel does not
// offer it, matching read's treatment of a missing interface file. The
// malformed fixture has no fd directory at all.
func TestReaddirOnAMissingDirectoryIsUnsupported(t *testing.T) {
	if _, availability := New(fixtureRoot("malformed")).readdir(3333, interfaceFD); availability != model.AvailabilityUnsupported {
		t.Errorf("readdir availability with no fd directory = %q, want unsupported", availability)
	}
}

// --- fdinfo parsing --------------------------------------------------------

// The guarded parse, in the shape statusFile.LookupUint established: present
// AND parsable, or nothing. Reporting a malformed value as zero would clear
// the O_DIRECTORY bit as if the kernel had said so.
func TestParseFDInfoFlags(t *testing.T) {
	cases := []struct {
		name     string
		contents string
		want     uint64
		wantOK   bool
	}{
		{"typical directory fdinfo", "pos:\t0\nflags:\t02100000\nmnt_id:\t29\n", 0o2100000, true},
		{"first line", "flags:\t02\n", 2, true},
		{"no trailing newline", "flags:\t0100002", 0o100002, true},
		{"missing key", "pos:\t0\nmnt_id:\t29\n", 0, false},
		{"empty value", "flags:\t\n", 0, false},
		{"non-numeric value", "flags:\tnope\n", 0, false},
		{"non-octal digits", "flags:\t8\n", 0, false},
		{"empty file", "", 0, false},
		{"key without colon", "flags 0100002\n", 0, false},
		{"similar key is not flags", "iflags:\t0300000\n", 0, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			flags, ok := parseFDInfoFlags([]byte(testCase.contents))
			if ok != testCase.wantOK || flags != testCase.want {
				t.Errorf("parseFDInfoFlags = %o/%t, want %o/%t", flags, ok, testCase.want, testCase.wantOK)
			}
		})
	}
}

// The bit is 0200000 octal. Written in decimal it is 65536, a value a reader
// who forgot the base would find plausible — hence the explicit pin.
func TestODirectoryConstant(t *testing.T) {
	if oDirectory != 65536 {
		t.Errorf("oDirectory = %d, want 65536 (0200000 octal)", oDirectory)
	}
}
