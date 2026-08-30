package explain

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// fixtureSnapshot is a fully-observed Snapshot with a distinguishable value
// in every section. model_test.go's populatedSnapshot is a package-model test
// helper and cannot be reached from here, so the shape is rebuilt locally.
func fixtureSnapshot() model.Snapshot {
	return model.Snapshot{
		SchemaVersion:    model.SchemaVersion,
		CapturedAt:       time.Date(2026, 8, 29, 12, 34, 56, 0, time.UTC),
		PID:              7312,
		PPID:             1401,
		Comm:             "update",
		CommandLine:      []string{"/tmp/update", "--quiet"},
		Executable:       "/tmp/update",
		WorkingDirectory: "/tmp",
		RootDirectory:    "/",
		State:            "S",
		StartTime:        980412,
		UserTime:         1234,
		SystemTime:       567,
		ResidentBytes:    52 * 1024 * 1024,
		VirtualBytes:     310 * 1024 * 1024,
		ThreadCount:      4,
		Priority:         20,
		ReadBytes:        88123,
		WriteBytes:       4096,
		FileDescriptors: []model.FileDescriptor{
			{Number: 3, Kind: model.FileDescriptorKindFile, Target: "/etc/passwd"},
			{Number: 4, Kind: model.FileDescriptorKindSocket, Target: "socket:[884213]", SocketInode: 884213},
		},
		Sockets: []model.Socket{
			{Protocol: "tcp", LocalAddress: "10.0.0.4", LocalPort: 51422, RemoteAddress: "185.10.20.30", RemotePort: 443, State: "ESTABLISHED", Inode: 884213, FileDescriptor: 4},
		},
		Ancestors: []model.ProcessRef{
			{PID: 1401, PPID: 1, Comm: "nginx", Executable: "/usr/sbin/nginx", StartTime: 4120},
		},
		Descendants: []model.ProcessRef{
			{PID: 7401, PPID: 7312, Comm: "sh", Executable: "/bin/sh", StartTime: 980500, Depth: 1},
		},
		Security: model.SecurityContext{
			CapabilityEffective: "000001ffffffffff",
			Namespaces:          []model.Namespace{{Kind: "net", Identifier: "net:[4026531992]"}},
			CgroupPath:          "/system.slice/nginx.service",
			SecurityLabel:       "unconfined",
		},
		OOMScore:       17,
		CurrentSyscall: -1,
		Availability: model.SectionAvailability{
			Identity:  model.AvailabilityObserved,
			Resources: model.AvailabilityObserved,
			Files:     model.AvailabilityObserved,
			Sockets:   model.AvailabilityObserved,
			Children:  model.AvailabilityObserved,
			Security:  model.AvailabilityObserved,
			Kernel:    model.AvailabilityObserved,
		},
	}
}

// Matrix row: fully-observed snapshot — Facts carries it verbatim.
func TestExplainCarriesFactsVerbatim(t *testing.T) {
	in := fixtureSnapshot()
	report := Explain(in)

	if !reflect.DeepEqual(report.Facts, in) {
		t.Errorf("report.Facts diverged from the input snapshot:\n got %+v\nwant %+v", report.Facts, in)
	}
}

// Matrix row: degraded snapshot — explain neither upgrades nor erases a
// section's Availability (AD-4).
func TestExplainPreservesSectionAvailability(t *testing.T) {
	in := fixtureSnapshot()
	in.Availability.Security = model.AvailabilityDenied
	in.Availability.Files = model.AvailabilityRaced
	in.Availability.Kernel = model.AvailabilityUnsupported

	got := Explain(in).Facts.Availability
	if got != in.Availability {
		t.Errorf("Facts.Availability = %+v, want the input's %+v", got, in.Availability)
	}
}

func TestExplainStampsSchemaVersionAndGeneratedAt(t *testing.T) {
	report := Explain(fixtureSnapshot())

	if report.SchemaVersion != model.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", report.SchemaVersion, model.SchemaVersion)
	}
	if report.GeneratedAt.IsZero() {
		t.Error("GeneratedAt is zero; it must be stamped once per report")
	}
	if location := report.GeneratedAt.Location(); location != time.UTC {
		t.Errorf("GeneratedAt location = %v, want UTC", location)
	}
}

// Matrix row: the diff / behavior / rules / correlate layers are not wired,
// so their sections stay at the zero value — never a fabricated entry.
func TestExplainLeavesDownstreamSectionsEmpty(t *testing.T) {
	report := Explain(fixtureSnapshot())

	if report.Changes != nil {
		t.Errorf("Changes = %+v, want nil — a single-snapshot inspect has no diff", report.Changes)
	}
	if report.Behaviors != nil {
		t.Errorf("Behaviors = %+v, want nil", report.Behaviors)
	}
	if report.Signals != nil {
		t.Errorf("Signals = %+v, want nil", report.Signals)
	}
	if !reflect.DeepEqual(report.Assessment, model.Assessment{}) {
		t.Errorf("Assessment = %+v, want the zero value", report.Assessment)
	}
}

// Matrix row: zero snapshot in, valid report out, no panic.
func TestExplainZeroSnapshot(t *testing.T) {
	report := Explain(model.Snapshot{})

	if !reflect.DeepEqual(report.Facts, model.Snapshot{}) {
		t.Errorf("Facts = %+v, want the zero Snapshot", report.Facts)
	}
	if report.SchemaVersion != model.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", report.SchemaVersion, model.SchemaVersion)
	}
	if report.GeneratedAt.IsZero() {
		t.Error("GeneratedAt is zero for a zero-snapshot report")
	}
}

// Matrix row: determinism — two calls differ only in GeneratedAt.
func TestExplainIsDeterministic(t *testing.T) {
	in := fixtureSnapshot()
	first := Explain(in)
	second := Explain(in)

	first.GeneratedAt = time.Time{}
	second.GeneratedAt = time.Time{}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("two reports of one snapshot differ:\n%+v\n%+v", first, second)
	}
}

// Matrix row: the produced Report survives the JSON boundary intact (AD-17).
func TestExplainReportRoundTrips(t *testing.T) {
	produced := Explain(fixtureSnapshot())

	encoded, err := json.Marshal(produced)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded model.Report
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !decoded.GeneratedAt.Equal(produced.GeneratedAt) {
		t.Errorf("GeneratedAt did not round-trip: got %v, want %v", decoded.GeneratedAt, produced.GeneratedAt)
	}
	decoded.GeneratedAt = time.Time{}
	produced.GeneratedAt = time.Time{}
	if !reflect.DeepEqual(decoded, produced) {
		t.Errorf("Report did not round-trip:\n got %+v\nwant %+v", decoded, produced)
	}
}
