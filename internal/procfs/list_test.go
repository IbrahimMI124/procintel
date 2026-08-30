package procfs

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// --- Matrix row: normal tree -------------------------------------------------

func TestListNormalTree(t *testing.T) {
	page := uint64(os.Getpagesize())
	listing := New(fixtureRoot("normal")).List()

	if listing.Availability != model.AvailabilityObserved {
		t.Fatalf("Availability = %q, want observed", listing.Availability)
	}

	want := []model.ProcessSummary{
		{PID: 1, PPID: 0, Comm: "systemd", State: "S", ThreadCount: 1, ResidentBytes: 50 * page, UserTicks: 10, SystemTicks: 20, StartTime: 100},
		{PID: 1234, PPID: 1, Comm: "python3", State: "S", ThreadCount: 4, ResidentBytes: 2048 * page, UserTicks: 1234, SystemTicks: 567, StartTime: 987654},
		{PID: 5001, PPID: 1234, Comm: "app-worker", State: "S", ThreadCount: 2, ResidentBytes: 128 * page, UserTicks: 100, SystemTicks: 40, StartTime: 1000000},
		{PID: 5002, PPID: 1234, Comm: "app-worker", State: "S", ThreadCount: 1, ResidentBytes: 128 * page, UserTicks: 50, SystemTicks: 20, StartTime: 1000500},
		{PID: 5003, PPID: 5001, Comm: "grandchild", State: "S", ThreadCount: 1, ResidentBytes: 64 * page, UserTicks: 10, SystemTicks: 5, StartTime: 1001000},
		{PID: 6001, PPID: 1, Comm: "confined", State: "S", ThreadCount: 1, ResidentBytes: 256 * page, UserTicks: 50, SystemTicks: 20, StartTime: 3000000},
	}
	if !reflect.DeepEqual(listing.Processes, want) {
		t.Errorf("Processes =\n  %+v\nwant\n  %+v", listing.Processes, want)
	}

	// The two stat-less PIDs are dropped by per-entry tolerance, and the
	// non-numeric net/ directory never enters the walk.
	for _, p := range listing.Processes {
		if p.PID == 4444 || p.PID == 5100 {
			t.Errorf("pid %d has no readable stat and must be omitted", p.PID)
		}
	}

	// Sorted strictly ascending by PID, with no unit conversion applied.
	for i := 1; i < len(listing.Processes); i++ {
		if listing.Processes[i-1].PID >= listing.Processes[i].PID {
			t.Errorf("Processes not PID-ascending at %d: %d then %d",
				i, listing.Processes[i-1].PID, listing.Processes[i].PID)
		}
	}
}

// --- Matrix row: missing root ----------------------------------------------

func TestListMissingRootIsUnsupported(t *testing.T) {
	listing := New(filepath.Join(t.TempDir(), "no-such-root")).List()
	if listing.Availability != model.AvailabilityUnsupported {
		t.Errorf("Availability under a missing root = %q, want unsupported", listing.Availability)
	}
	if listing.Processes != nil {
		t.Errorf("Processes = %+v, want nil for a non-observed listing", listing.Processes)
	}
}

// --- Matrix row: unreadable root -----------------------------------------

// raced is N/A for the root walk: readProcRoot has no owning PID to re-check,
// so a chmod-0 root maps to denied, never raced.
func TestListDeniedRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions, so a chmod cannot produce EACCES")
	}
	root := copyFixture(t, "normal")
	if err := os.Chmod(root, 0o000); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	listing := New(root).List()
	if listing.Availability != model.AvailabilityDenied {
		t.Errorf("Availability = %q, want denied", listing.Availability)
	}
	if listing.Processes != nil {
		t.Errorf("Processes = %+v, want nil", listing.Processes)
	}
}

// --- Determinism ---------------------------------------------------------

func TestListIsDeterministic(t *testing.T) {
	reader := New(fixtureRoot("normal"))
	if !reflect.DeepEqual(reader.List(), reader.List()) {
		t.Error("List is not deterministic across two calls")
	}
}
