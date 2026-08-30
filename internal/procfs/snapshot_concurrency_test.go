package procfs

import (
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// The concurrent assembly must land the same Snapshot the sequential one did:
// every section observed, every value in place.
func TestSnapshotConcurrentObservationPopulatesEverySection(t *testing.T) {
	snapshot, err := New(fixtureRoot("normal")).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}

	for _, section := range []struct {
		name string
		got  model.Availability
	}{
		{"identity", snapshot.Availability.Identity},
		{"resources", snapshot.Availability.Resources},
		{"files", snapshot.Availability.Files},
		{"sockets", snapshot.Availability.Sockets},
		{"children", snapshot.Availability.Children},
		{"security", snapshot.Availability.Security},
		{"kernel", snapshot.Availability.Kernel},
	} {
		if section.got != model.AvailabilityObserved {
			t.Errorf("%s availability = %q, want observed", section.name, section.got)
		}
	}

	if snapshot.PID != 1234 || snapshot.Comm != "python3" || snapshot.PPID != 1 {
		t.Errorf("identity = pid %d comm %q ppid %d, want 1234/python3/1",
			snapshot.PID, snapshot.Comm, snapshot.PPID)
	}
	if snapshot.OOMScore != 13 {
		t.Errorf("OOMScore = %d, want 13 — the wave-1 oomScore result was dropped", snapshot.OOMScore)
	}
	if len(snapshot.CommandLine) != 3 {
		t.Errorf("CommandLine = %q, want three arguments", snapshot.CommandLine)
	}
}

// Every dependent observer must see the exact wave-1 value the sequential code
// passed it. zombie/2222 has no exe link (lineage's stat input drives the
// children walk) and malformed/3333 has a garbage stat, so a wave that fed a
// stale or zero input would shift these results.
func TestSnapshotConcurrentDependentObserversSeeFirstWaveInputs(t *testing.T) {
	zombie, err := New(fixtureRoot("zombie")).Snapshot(2222)
	if err != nil {
		t.Fatalf("Snapshot(2222): %v", err)
	}
	if zombie.State != "Z" || zombie.Comm != "worker" {
		t.Errorf("zombie identity = %q/%q, want Z/worker", zombie.State, zombie.Comm)
	}

	malformed, err := New(fixtureRoot("malformed")).Snapshot(3333)
	if err != nil {
		t.Fatalf("Snapshot(3333): %v", err)
	}
	if malformed.Availability.Children != model.AvailabilityAbsent {
		t.Errorf("children availability = %q, want absent — lineage read a malformed stat",
			malformed.Availability.Children)
	}
	if malformed.Availability.Security != model.AvailabilityUnsupported {
		t.Errorf("security availability = %q, want unsupported — security folded the wave-1 status read (no status file)",
			malformed.Availability.Security)
	}
}

// A denied status degrades resources and security without touching identity,
// even though all three now read concurrently — no goroutine may clobber
// another's result.
func TestSnapshotConcurrentDeniedSectionDoesNotCrossContaminate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	root := copyFixture(t, "normal")
	if err := os.Chmod(filepath.Join(root, "1234", "status"), 0o000); err != nil {
		t.Fatalf("chmod status: %v", err)
	}

	snapshot, err := New(root).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	if snapshot.Availability.Resources != model.AvailabilityDenied {
		t.Errorf("resources = %q, want denied", snapshot.Availability.Resources)
	}
	if snapshot.Availability.Security != model.AvailabilityDenied {
		t.Errorf("security = %q, want denied", snapshot.Availability.Security)
	}
	if snapshot.Availability.Identity != model.AvailabilityObserved {
		t.Errorf("identity = %q, want observed — a denied section must not take down another",
			snapshot.Availability.Identity)
	}
	if snapshot.UserTime != 1234 || snapshot.ReadBytes != 4096000 {
		t.Errorf("readable values erased: utime=%d read_bytes=%d", snapshot.UserTime, snapshot.ReadBytes)
	}
}

// Many callers sharing one Reader must all get the same answer. A goroutine
// writing a variable another observer owns would surface here as a mismatch,
// a panic, or a hang — even without the race detector.
func TestSnapshotConcurrentCallersAgree(t *testing.T) {
	reader := New(fixtureRoot("normal"))

	reference, err := reader.Snapshot(1234)
	if err != nil {
		t.Fatalf("reference Snapshot: %v", err)
	}
	reference.CapturedAt = time.Time{}

	const callers = 100
	results := make([]model.Snapshot, callers)
	errs := make([]error, callers)

	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = reader.Snapshot(1234)
		}(i)
	}
	wg.Wait()

	for i := 0; i < callers; i++ {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		results[i].CapturedAt = time.Time{}
		if !reflect.DeepEqual(results[i], reference) {
			t.Fatalf("caller %d produced a different Snapshot than the reference:\n%+v\n%+v",
				i, results[i], reference)
		}
	}
}

// The process vanishing while a snapshot is in flight must degrade to
// Availability, never a panic and never a leaked goroutine. Driven as a
// stress loop: a deleter races a batch of Snapshot calls over fresh copies.
func TestSnapshotConcurrentProcessRacingAwayNeverPanics(t *testing.T) {
	for round := 0; round < 20; round++ {
		root := copyFixture(t, "normal")
		reader := New(root)
		pidDir := filepath.Join(root, "1234")

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = os.RemoveAll(pidDir)
		}()

		for i := 0; i < 8; i++ {
			snapshot, err := reader.Snapshot(1234)
			if err != nil {
				continue // ErrProcessNotFound once the directory is gone — expected.
			}
			if snapshot.PID != 1234 {
				t.Fatalf("round %d: Snapshot returned pid %d, want 1234", round, snapshot.PID)
			}
		}
		wg.Wait()
	}
}
