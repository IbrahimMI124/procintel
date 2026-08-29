package procfs

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// --- Matrix row: normal tree --------------------------------------------------

func TestLineageNormalTree(t *testing.T) {
	snapshot, err := New(fixtureRoot("normal")).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}

	wantAncestors := []model.ProcessRef{
		{PID: 1, PPID: 0, Comm: "systemd", Executable: "/sbin/init", StartTime: 100},
	}
	if !reflect.DeepEqual(snapshot.Ancestors, wantAncestors) {
		t.Errorf("Ancestors =\n  %+v\nwant\n  %+v", snapshot.Ancestors, wantAncestors)
	}

	wantDescendants := []model.ProcessRef{
		{PID: 5001, PPID: 1234, Comm: "app-worker", StartTime: 1000000, Depth: 1},
		{PID: 5002, PPID: 1234, Comm: "app-worker", StartTime: 1000500, Depth: 1},
		{PID: 5003, PPID: 5001, Comm: "grandchild", StartTime: 1001000, Depth: 2},
	}
	if !reflect.DeepEqual(snapshot.Descendants, wantDescendants) {
		t.Errorf("Descendants =\n  %+v\nwant\n  %+v", snapshot.Descendants, wantDescendants)
	}

	if snapshot.Availability.Children != model.AvailabilityObserved {
		t.Errorf("Availability.Children = %q, want observed", snapshot.Availability.Children)
	}
}

// --- Matrix row: target is PID 1 --------------------------------------------

func TestLineageTargetIsPID1(t *testing.T) {
	snapshot, err := New(fixtureRoot("normal")).Snapshot(1)
	if err != nil {
		t.Fatalf("Snapshot(1): %v", err)
	}
	if len(snapshot.Ancestors) != 0 {
		t.Errorf("Ancestors = %+v, want empty for PID 1", snapshot.Ancestors)
	}
	if snapshot.Availability.Children != model.AvailabilityObserved {
		t.Errorf("Availability.Children = %q, want observed", snapshot.Availability.Children)
	}
	// The whole tree hangs off PID 1: 1234 at depth 1, its children at 2.
	var found1234 bool
	for _, ref := range snapshot.Descendants {
		if ref.PID == 1234 {
			found1234 = true
			if ref.Depth != 1 {
				t.Errorf("pid 1234 depth = %d, want 1", ref.Depth)
			}
		}
		// The per-entry-tolerance PIDs must never appear: 4444 and 5100 have
		// no stat.
		if ref.PID == 4444 || ref.PID == 5100 {
			t.Errorf("descendant %d has no stat and must be omitted", ref.PID)
		}
	}
	if !found1234 {
		t.Error("Descendants of PID 1 does not contain 1234")
	}
}

// --- Matrix row: target stat unobserved -----------------------------------

// normal/4444 has an fd/ directory but no stat: with no PPID to walk from and
// no identity to scan around, both lists are empty and Children is exactly
// the target stat availability, never observed.
func TestLineageTargetStatUnobserved(t *testing.T) {
	reader := New(fixtureRoot("normal"))
	_, statStatus := reader.stat(4444)
	if statStatus == model.AvailabilityObserved {
		t.Fatal("fixture drifted: normal/4444 is expected to have no readable stat")
	}
	snapshot, err := reader.Snapshot(4444)
	if err != nil {
		t.Fatalf("Snapshot(4444): %v", err)
	}
	if len(snapshot.Ancestors) != 0 || len(snapshot.Descendants) != 0 {
		t.Errorf("ancestors=%+v descendants=%+v, want both empty", snapshot.Ancestors, snapshot.Descendants)
	}
	if snapshot.Availability.Children != statStatus {
		t.Errorf("Availability.Children = %q, want the target stat availability %q",
			snapshot.Availability.Children, statStatus)
	}
}

// --- Matrix row: ancestor exited mid-walk --------------------------------

// raced-walk: 300 -> 350 -> 400, and 400 has no stat directory. The walk
// stops at the last readable ancestor (350) and the section drops to raced.
func TestLineageRacedAncestorWalk(t *testing.T) {
	snapshot, err := New(fixtureRoot("raced-walk")).Snapshot(300)
	if err != nil {
		t.Fatalf("Snapshot(300): %v", err)
	}
	wantAncestors := []model.ProcessRef{
		{PID: 350, PPID: 400, Comm: "mid", Executable: "/usr/bin/mid", StartTime: 6000},
	}
	if !reflect.DeepEqual(snapshot.Ancestors, wantAncestors) {
		t.Errorf("Ancestors =\n  %+v\nwant\n  %+v", snapshot.Ancestors, wantAncestors)
	}
	if snapshot.Availability.Children != model.AvailabilityRaced {
		t.Errorf("Availability.Children = %q, want raced", snapshot.Availability.Children)
	}
}

// --- Matrix row: PPID cycle ---------------------------------------------

// cycle: 100 and 200 name each other as parent. Neither the ancestor walk nor
// the descendant BFS may loop.
func TestLineageCycle(t *testing.T) {
	snapshot, err := New(fixtureRoot("cycle")).Snapshot(100)
	if err != nil {
		t.Fatalf("Snapshot(100): %v", err)
	}
	wantAncestors := []model.ProcessRef{
		{PID: 200, PPID: 100, Comm: "pong", StartTime: 5001},
		{PID: 100, PPID: 200, Comm: "ping", StartTime: 5000},
	}
	if !reflect.DeepEqual(snapshot.Ancestors, wantAncestors) {
		t.Errorf("Ancestors =\n  %+v\nwant\n  %+v", snapshot.Ancestors, wantAncestors)
	}
	wantDescendants := []model.ProcessRef{
		{PID: 200, PPID: 100, Comm: "pong", StartTime: 5001, Depth: 1},
	}
	if !reflect.DeepEqual(snapshot.Descendants, wantDescendants) {
		t.Errorf("Descendants =\n  %+v\nwant\n  %+v", snapshot.Descendants, wantDescendants)
	}
	if snapshot.Availability.Children != model.AvailabilityObserved {
		t.Errorf("Availability.Children = %q, want observed — a terminated cycle is not a read gap",
			snapshot.Availability.Children)
	}
}

// --- Matrix row: proc root unreadable ----------------------------------

// Removing read permission from the proc root is what makes the root listing
// fail — and, because every per-PID read re-opens that same root, it takes
// the target stat down with it, so Ancestors is empty here too. The ancestor
// walk's independence from the descendant scan is covered by
// TestWalkAncestors and TestLineageRacedAncestorWalk, where the proc root is
// readable and only a single parent has gone away.
func TestLineageProcRootUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions, so a chmod cannot produce EACCES")
	}
	root := copyFixture(t, "normal")
	if err := os.Chmod(root, 0o311); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	snapshot, err := New(root).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	if snapshot.Availability.Children != model.AvailabilityDenied {
		t.Errorf("Availability.Children = %q, want denied", snapshot.Availability.Children)
	}
	if len(snapshot.Descendants) != 0 {
		t.Errorf("Descendants = %+v, want empty", snapshot.Descendants)
	}
}

// --- Matrix row: leaf process ------------------------------------------

func TestLineageLeafProcess(t *testing.T) {
	// 5003 is the fixture's grandchild: it has no children of its own.
	snapshot, err := New(fixtureRoot("normal")).Snapshot(5003)
	if err != nil {
		t.Fatalf("Snapshot(5003): %v", err)
	}
	if len(snapshot.Descendants) != 0 {
		t.Errorf("Descendants = %+v, want empty for a leaf", snapshot.Descendants)
	}
	if snapshot.Availability.Children != model.AvailabilityObserved {
		t.Errorf("Availability.Children = %q, want observed", snapshot.Availability.Children)
	}
	// Its ancestors climb 5001 -> 1234 -> 1.
	wantAncestors := []model.ProcessRef{
		{PID: 5001, PPID: 1234, Comm: "app-worker", StartTime: 1000000},
		{PID: 1234, PPID: 1, Comm: "python3", Executable: "/usr/bin/python3", StartTime: 987654},
		{PID: 1, PPID: 0, Comm: "systemd", Executable: "/sbin/init", StartTime: 100},
	}
	if !reflect.DeepEqual(snapshot.Ancestors, wantAncestors) {
		t.Errorf("Ancestors =\n  %+v\nwant\n  %+v", snapshot.Ancestors, wantAncestors)
	}
}

// --- Matrix row: unrelated process unreadable ------------------------

// A sibling PID whose stat cannot be read is dropped from the tree with no
// penalty to the section — per-entry tolerance, exactly as a vanished fd is
// dropped. normal/5100 has a comm file but no stat and must not lower
// Children below observed.
func TestLineageUnrelatedProcessUnreadableDoesNotLowerSection(t *testing.T) {
	snapshot, err := New(fixtureRoot("normal")).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	if snapshot.Availability.Children != model.AvailabilityObserved {
		t.Errorf("Availability.Children = %q, want observed despite an unreadable sibling", snapshot.Availability.Children)
	}
	for _, ref := range snapshot.Descendants {
		if ref.PID == 5100 {
			t.Error("pid 5100 has no stat and must not appear in Descendants")
		}
	}
}

// --- Matrix row: ancestor exe absent ------------------------------

// cycle's two PIDs carry no exe symlink: the readlink is absent, the ref's
// Executable stays "" and the ref is still included (the same observable
// outcome an EACCES readlink produces).
func TestLineageAncestorWithoutExe(t *testing.T) {
	snapshot, err := New(fixtureRoot("cycle")).Snapshot(100)
	if err != nil {
		t.Fatalf("Snapshot(100): %v", err)
	}
	if len(snapshot.Ancestors) == 0 {
		t.Fatal("expected a non-empty ancestor chain")
	}
	for _, ref := range snapshot.Ancestors {
		if ref.Executable != "" {
			t.Errorf("ancestor %d Executable = %q, want empty", ref.PID, ref.Executable)
		}
	}
}

// --- Determinism ------------------------------------------------------

func TestLineageIsDeterministic(t *testing.T) {
	reader := New(fixtureRoot("normal"))
	first, err := reader.Snapshot(1)
	if err != nil {
		t.Fatalf("first Snapshot(1): %v", err)
	}
	second, err := reader.Snapshot(1)
	if err != nil {
		t.Fatalf("second Snapshot(1): %v", err)
	}
	if !reflect.DeepEqual(first.Descendants, second.Descendants) {
		t.Errorf("Descendants differ between runs:\n  %+v\n  %+v", first.Descendants, second.Descendants)
	}
}

// --- readProcRoot ---------------------------------------------------

func TestReadProcRoot(t *testing.T) {
	names, availability := New(fixtureRoot("normal")).readProcRoot()
	if availability != model.AvailabilityObserved {
		t.Fatalf("availability = %q, want observed", availability)
	}
	got := make(map[string]bool, len(names))
	for _, name := range names {
		got[name] = true
		if !isDecimalFDName(name) {
			t.Errorf("readProcRoot returned a non-numeric name %q", name)
		}
	}
	for _, want := range []string{"1", "1234", "4444", "5001", "5002", "5003", "5100"} {
		if !got[want] {
			t.Errorf("readProcRoot missing pid directory %q (got %v)", want, names)
		}
	}
	if got["net"] {
		t.Error("readProcRoot returned the non-numeric net/ directory")
	}
}

func TestReadProcRootMissingRootIsUnsupported(t *testing.T) {
	reader := New(filepath.Join(t.TempDir(), "no-such-root"))
	if _, availability := reader.readProcRoot(); availability != model.AvailabilityUnsupported {
		t.Errorf("availability under a missing root = %q, want unsupported", availability)
	}
}

// --- walkAncestors (synthetic next) -------------------------------

func TestWalkAncestors(t *testing.T) {
	// chain models a PPID graph: chain[pid] is that pid's parent.
	stub := func(chain map[int]int, unreadable map[int]model.Availability) func(int) (statFields, model.Availability) {
		return func(pid int) (statFields, model.Availability) {
			if status, ok := unreadable[pid]; ok {
				return statFields{}, status
			}
			return statFields{PID: pid, PPID: chain[pid]}, model.AvailabilityObserved
		}
	}

	t.Run("climbs to PID 1 and stops", func(t *testing.T) {
		calls := map[int]int{}
		next := func(pid int) (statFields, model.Availability) {
			calls[pid]++
			return statFields{PID: pid, PPID: map[int]int{5: 3, 3: 1, 1: 0}[pid]}, model.AvailabilityObserved
		}
		chain, availability := walkAncestors(5, next)
		if want := []int{5, 3, 1}; !reflect.DeepEqual(chain, want) {
			t.Errorf("chain = %v, want %v", chain, want)
		}
		if availability != model.AvailabilityObserved {
			t.Errorf("availability = %q, want observed", availability)
		}
		if calls[0] != 0 {
			t.Error("next was called for pid 0; the walk must stop at PID 1")
		}
	})

	t.Run("start PPID 0 yields an empty chain", func(t *testing.T) {
		next := func(pid int) (statFields, model.Availability) {
			t.Fatalf("next called with %d; a zero start must not read anything", pid)
			return statFields{}, ""
		}
		chain, availability := walkAncestors(0, next)
		if len(chain) != 0 || availability != model.AvailabilityObserved {
			t.Errorf("walkAncestors(0) = %v/%q, want []/observed", chain, availability)
		}
	})

	t.Run("a PPID cycle terminates on the revisited pid", func(t *testing.T) {
		chain, availability := walkAncestors(10, stub(map[int]int{10: 11, 11: 10}, nil))
		if want := []int{10, 11}; !reflect.DeepEqual(chain, want) {
			t.Errorf("chain = %v, want %v", chain, want)
		}
		if availability != model.AvailabilityObserved {
			t.Errorf("availability = %q, want observed", availability)
		}
	})

	t.Run("a raced read stops the walk and lowers the section", func(t *testing.T) {
		chain, availability := walkAncestors(
			5,
			stub(map[int]int{5: 3, 3: 2}, map[int]model.Availability{3: model.AvailabilityRaced}),
		)
		if want := []int{5}; !reflect.DeepEqual(chain, want) {
			t.Errorf("chain = %v, want %v (stops at the last readable ancestor)", chain, want)
		}
		if availability != model.AvailabilityRaced {
			t.Errorf("availability = %q, want raced", availability)
		}
	})

	t.Run("a denied read propagates its own availability", func(t *testing.T) {
		_, availability := walkAncestors(
			5,
			stub(map[int]int{5: 3}, map[int]model.Availability{3: model.AvailabilityDenied}),
		)
		if availability != model.AvailabilityDenied {
			t.Errorf("availability = %q, want denied", availability)
		}
	})

	t.Run("the hard depth cap bounds a chain that never reaches PID 1", func(t *testing.T) {
		// Every pid's parent is pid+1: an ever-climbing chain with no cycle
		// and no PID 1.
		next := func(pid int) (statFields, model.Availability) {
			return statFields{PID: pid, PPID: pid + 1}, model.AvailabilityObserved
		}
		chain, availability := walkAncestors(1000, next)
		if len(chain) != maxAncestorDepth {
			t.Errorf("chain length = %d, want the cap %d", len(chain), maxAncestorDepth)
		}
		if availability != model.AvailabilityObserved {
			t.Errorf("availability = %q, want observed", availability)
		}
	})
}

// --- buildDescendants (synthetic entries) ------------------------

func TestBuildDescendants(t *testing.T) {
	entry := func(pid, ppid int) lineageEntry {
		return lineageEntry{PID: pid, PPID: ppid, Comm: "p", StartTime: uint64(pid)}
	}

	t.Run("children of one parent sort by PID regardless of scan order", func(t *testing.T) {
		got := buildDescendants(0, []lineageEntry{entry(3, 0), entry(1, 0), entry(2, 0)})
		want := []model.ProcessRef{
			{PID: 1, PPID: 0, Comm: "p", StartTime: 1, Depth: 1},
			{PID: 2, PPID: 0, Comm: "p", StartTime: 2, Depth: 1},
			{PID: 3, PPID: 0, Comm: "p", StartTime: 3, Depth: 1},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got\n  %+v\nwant\n  %+v", got, want)
		}
	})

	t.Run("output is sorted (Depth asc, PID asc) across parents", func(t *testing.T) {
		// depth-2 nodes: 5003 under 5001, 4999 under 5002. BFS discovers
		// 5003 first; the final sort must still order them 4999, 5003.
		got := buildDescendants(0, []lineageEntry{
			entry(5001, 0), entry(5002, 0), entry(5003, 5001), entry(4999, 5002),
		})
		var order []int
		for _, ref := range got {
			order = append(order, ref.PID)
		}
		if want := []int{5001, 5002, 4999, 5003}; !reflect.DeepEqual(order, want) {
			t.Errorf("order = %v, want %v", order, want)
		}
	})

	t.Run("a cycle in the adjacency does not loop", func(t *testing.T) {
		got := buildDescendants(10, []lineageEntry{entry(10, 11), entry(11, 10)})
		want := []model.ProcessRef{{PID: 11, PPID: 10, Comm: "p", StartTime: 11, Depth: 1}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a leaf target yields nil", func(t *testing.T) {
		if got := buildDescendants(99, []lineageEntry{entry(1, 0), entry(2, 1)}); got != nil {
			t.Errorf("got %+v, want nil", got)
		}
	})

	t.Run("the depth cap stops collection and admits no ref beyond it", func(t *testing.T) {
		// A linear chain: pid i's parent is i-1, for i in 1..maxDescendantDepth+8.
		var entries []lineageEntry
		for i := 1; i <= maxDescendantDepth+8; i++ {
			entries = append(entries, entry(i, i-1))
		}
		got := buildDescendants(0, entries)
		if len(got) != maxDescendantDepth {
			t.Fatalf("len = %d, want the depth cap %d", len(got), maxDescendantDepth)
		}
		for _, ref := range got {
			if ref.Depth > maxDescendantDepth {
				t.Errorf("ref %+v exceeds the depth cap", ref)
			}
		}
		last := got[len(got)-1]
		if last.Depth != maxDescendantDepth || last.PID != maxDescendantDepth {
			t.Errorf("deepest ref = %+v, want PID/Depth %d", last, maxDescendantDepth)
		}
	})

	t.Run("the count cap bounds a very wide tree", func(t *testing.T) {
		var entries []lineageEntry
		for i := 1; i <= maxDescendantRefs+500; i++ {
			entries = append(entries, entry(i, 0))
		}
		got := buildDescendants(0, entries)
		if len(got) != maxDescendantRefs {
			t.Errorf("len = %d, want the count cap %d", len(got), maxDescendantRefs)
		}
	})

	t.Run("nil entries yield nil", func(t *testing.T) {
		if got := buildDescendants(1, nil); got != nil {
			t.Errorf("got %+v, want nil", got)
		}
	})
}
