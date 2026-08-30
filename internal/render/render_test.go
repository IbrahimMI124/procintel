package render

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/IbrahimMI124/procintel/internal/model"
)

//go:embed testdata/inspect_observed.txt.golden
//go:embed testdata/inspect_observed.color.golden
//go:embed testdata/inspect_degraded.txt.golden
//go:embed testdata/inspect_observed.json.golden
var goldenFS embed.FS

// sgrPattern strips every SGR sequence, and nothing else, so a coloured
// render can be checked against the plain golden.
var sgrPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// observedSnapshot is a fully-observed snapshot with a distinguishable value
// in every section. model_test.go's populatedSnapshot is package-model and
// cannot be reached here.
func observedSnapshot() model.Snapshot {
	return model.Snapshot{
		SchemaVersion:    model.SchemaVersion,
		CapturedAt:       time.Date(2026, 8, 30, 12, 34, 56, 0, time.UTC),
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
		Nice:             0,
		ReadBytes:        88 * 1024,
		WriteBytes:       4 * 1024,
		FileDescriptors: []model.FileDescriptor{
			{Number: 0, Kind: model.FileDescriptorKindCharacter, Target: "/dev/pts/2"},
			{Number: 3, Kind: model.FileDescriptorKindFile, Target: "/etc/passwd"},
			{Number: 4, Kind: model.FileDescriptorKindSocket, Target: "socket:[884213]", SocketInode: 884213},
			{Number: 5, Kind: model.FileDescriptorKindFile, Target: "/tmp/payload", Deleted: true},
		},
		Sockets: []model.Socket{
			{Protocol: "tcp", LocalAddress: "10.0.0.4", LocalPort: 51422, RemoteAddress: "185.10.20.30", RemotePort: 443, State: "ESTABLISHED", Inode: 884213, FileDescriptor: 4},
			{Protocol: "unix", State: "LISTEN", Path: "/run/example.sock", Inode: 884990, FileDescriptor: 6},
		},
		Ancestors: []model.ProcessRef{
			{PID: 1401, PPID: 1, Comm: "nginx", Executable: "/usr/sbin/nginx", StartTime: 4120},
			{PID: 1, PPID: 0, Comm: "systemd", Executable: "/usr/lib/systemd/systemd", StartTime: 12},
		},
		Descendants: []model.ProcessRef{
			{PID: 7401, PPID: 7312, Comm: "sh", Executable: "/bin/sh", StartTime: 980500, Depth: 1},
		},
		Security: model.SecurityContext{
			UID:                 0,
			EffectiveUID:        0,
			GID:                 0,
			EffectiveGID:        0,
			CapabilityEffective: "000001ffffffffff",
			NoNewPrivileges:     false,
			SeccompMode:         0,
			Namespaces: []model.Namespace{
				{Kind: "mnt", Identifier: "mnt:[4026531840]"},
				{Kind: "net", Identifier: "net:[4026531992]"},
			},
			CgroupPath:    "/system.slice/nginx.service",
			SecurityLabel: "unconfined",
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

func observedReport() model.Report {
	return model.Report{
		SchemaVersion: model.SchemaVersion,
		GeneratedAt:   time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC),
		Facts:         observedSnapshot(),
	}
}

func degradedReport() model.Report {
	r := observedReport()
	r.Facts.Availability.Security = model.AvailabilityDenied
	r.Facts.Availability.Files = model.AvailabilityRaced
	r.Facts.Availability.Kernel = model.AvailabilityUnsupported
	return r
}

func wantGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := goldenFS.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return data
}

func renderText(t *testing.T, r model.Report, color bool) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := Text(&b, r, color); err != nil {
		t.Fatalf("Text: %v", err)
	}
	return b.Bytes()
}

// --- Matrix: fully-observed, no colour -----------------------------------

func TestTextObservedGolden(t *testing.T) {
	out := renderText(t, observedReport(), false)
	if !bytes.Equal(out, wantGolden(t, "inspect_observed.txt.golden")) {
		t.Errorf("output mismatch\n--- got ---\n%s", out)
	}
	for _, header := range []string{"FACTS", "SIGNALS", "ASSESSMENT"} {
		if !bytes.Contains(out, []byte("\n"+header+"\n")) {
			t.Errorf("output is missing a standalone %q block header", header)
		}
	}
	if bytes.Contains(out, []byte("\x1b[")) {
		t.Error("color=false output contains an escape sequence")
	}
}

// --- Matrix: fully-observed, colour ------------------------------------

func TestTextObservedColorGolden(t *testing.T) {
	out := renderText(t, observedReport(), true)
	if !bytes.Equal(out, wantGolden(t, "inspect_observed.color.golden")) {
		t.Errorf("colour output mismatch\n--- got ---\n%s", out)
	}
	stripped := sgrPattern.ReplaceAll(out, nil)
	if !bytes.Equal(stripped, renderText(t, observedReport(), false)) {
		t.Errorf("stripping SGR from the coloured output did not yield the plain output\n--- stripped ---\n%s", stripped)
	}
}

// --- Matrix: degraded sections ---------------------------------------

func TestTextDegradedGolden(t *testing.T) {
	out := renderText(t, degradedReport(), false)
	if !bytes.Equal(out, wantGolden(t, "inspect_degraded.txt.golden")) {
		t.Errorf("degraded output mismatch\n--- got ---\n%s", out)
	}
	if bytes.Contains(out, []byte("capabilities")) {
		t.Error("a denied security section still printed field lines")
	}
	if bytes.Contains(out, []byte("FD  ")) {
		t.Error("a raced files section still printed its table")
	}
	if bytes.Contains(out, []byte("oom_score")) {
		t.Error("an unsupported kernel section still printed field lines")
	}
	if !bytes.Contains(out, []byte("start_time")) {
		t.Error("identity section (still observed) lost its fields")
	}
}

// --- Matrix: JSON --------------------------------------------------

func TestJSONObservedGolden(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, observedReport()); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	out := b.Bytes()
	if !bytes.Equal(out, wantGolden(t, "inspect_observed.json.golden")) {
		t.Errorf("JSON output mismatch\n--- got ---\n%s", out)
	}
	if out[len(out)-1] != '\n' {
		t.Error("JSON output does not end with a newline")
	}
	var back model.Report
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(back, observedReport()) {
		t.Errorf("JSON did not round-trip:\n got %+v\nwant %+v", back, observedReport())
	}
}

// --- Matrix: zero Report ---------------------------------------------

func TestTextZeroReport(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, model.Report{}, false); err != nil {
		t.Fatalf("Text on zero Report: %v", err)
	}
	out := b.Bytes()
	for _, header := range []string{"FACTS", "SIGNALS", "ASSESSMENT"} {
		if !bytes.Contains(out, []byte(header)) {
			t.Errorf("zero-Report output missing %q", header)
		}
	}
	if !bytes.Contains(out, []byte("not observed")) {
		t.Error("zero-Report sections should render as \"not observed\"")
	}
}

// --- Matrix: write failure -----------------------------------------

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestWriteErrorIsReturned(t *testing.T) {
	if err := Text(errWriter{}, observedReport(), false); err == nil {
		t.Error("Text swallowed a write error")
	}
	if err := Text(errWriter{}, observedReport(), true); err == nil {
		t.Error("Text (colour) swallowed a write error")
	}
	if err := JSON(errWriter{}, observedReport()); err == nil {
		t.Error("JSON swallowed a write error")
	}
}

// --- Matrix: determinism -----------------------------------------

func TestRenderersAreDeterministic(t *testing.T) {
	if !bytes.Equal(renderText(t, observedReport(), false), renderText(t, observedReport(), false)) {
		t.Error("Text is not deterministic")
	}
	if !bytes.Equal(renderText(t, observedReport(), true), renderText(t, observedReport(), true)) {
		t.Error("Text (colour) is not deterministic")
	}
	var a, b bytes.Buffer
	_ = JSON(&a, observedReport())
	_ = JSON(&b, observedReport())
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("JSON is not deterministic")
	}
}
