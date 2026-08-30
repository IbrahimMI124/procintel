package render

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// observedListing is a fully-observed listing with a distinguishable value in
// every column: varied states (S, R, D, Z), a comm with a space and
// parentheses, and RSS values that cross the humanBytes unit boundaries.
func observedListing() model.ProcessListing {
	return model.ProcessListing{
		Availability: model.AvailabilityObserved,
		Processes: []model.ProcessSummary{
			{PID: 1, PPID: 0, Comm: "systemd", State: "S", ThreadCount: 1, ResidentBytes: 8 * 1024 * 1024, UserTicks: 120, SystemTicks: 340, StartTime: 12},
			{PID: 42, PPID: 1, Comm: "cron", State: "S", ThreadCount: 1, ResidentBytes: 900, UserTicks: 3, SystemTicks: 1, StartTime: 4200},
			{PID: 1337, PPID: 1, Comm: "update", State: "R", ThreadCount: 8, ResidentBytes: 512 * 1024 * 1024, UserTicks: 99999, SystemTicks: 12345, StartTime: 980412},
			{PID: 2001, PPID: 1337, Comm: "worker (odd)", State: "D", ThreadCount: 4, ResidentBytes: 64 * 1024, UserTicks: 0, SystemTicks: 0, StartTime: 981000},
			{PID: 4096, PPID: 2001, Comm: "defunct", State: "Z", ThreadCount: 1, ResidentBytes: 0, UserTicks: 5, SystemTicks: 5, StartTime: 990000},
		},
	}
}

func degradedListing() model.ProcessListing {
	return model.ProcessListing{Availability: model.AvailabilityDenied}
}

func renderTextList(t *testing.T, l model.ProcessListing, color bool) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := TextList(&b, l, color); err != nil {
		t.Fatalf("TextList: %v", err)
	}
	return b.Bytes()
}

// --- Matrix: fully-observed, no colour ---------------------------------

func TestTextListObservedGolden(t *testing.T) {
	out := renderTextList(t, observedListing(), false)
	if !bytes.Equal(out, wantGolden(t, "list_observed.txt.golden")) {
		t.Errorf("output mismatch\n--- got ---\n%s", out)
	}
	if bytes.Contains(out, []byte("\x1b[")) {
		t.Error("color=false output contains an escape sequence")
	}
	if !bytes.HasPrefix(out, []byte("PID ")) {
		t.Error("output does not begin with the PID-ascending table header")
	}
}

// --- Matrix: fully-observed, colour -----------------------------------

func TestTextListObservedColorGolden(t *testing.T) {
	out := renderTextList(t, observedListing(), true)
	if !bytes.Equal(out, wantGolden(t, "list_observed.color.golden")) {
		t.Errorf("colour output mismatch\n--- got ---\n%s", out)
	}
	stripped := sgrPattern.ReplaceAll(out, nil)
	if !bytes.Equal(stripped, renderTextList(t, observedListing(), false)) {
		t.Errorf("stripping SGR from the coloured output did not yield the plain output\n--- stripped ---\n%s", stripped)
	}
}

// --- Matrix: degraded (non-observed) listing --------------------------

func TestTextListDegradedGolden(t *testing.T) {
	out := renderTextList(t, degradedListing(), false)
	if !bytes.Equal(out, wantGolden(t, "list_degraded.txt.golden")) {
		t.Errorf("degraded output mismatch\n--- got ---\n%s", out)
	}
	if bytes.Contains(out, []byte("PID")) {
		t.Error("a non-observed listing still printed the table header")
	}
	if !bytes.Contains(out, []byte("denied")) {
		t.Error("a non-observed listing did not print its availability")
	}
}

// A non-observed listing carries its status word in colour too, and never a row.
func TestTextListDegradedColorHasNoRows(t *testing.T) {
	out := renderTextList(t, model.ProcessListing{
		Availability: model.AvailabilityUnsupported,
		Processes:    observedListing().Processes,
	}, true)
	if bytes.Count(out, []byte("\n")) != 1 {
		t.Errorf("non-observed listing emitted more than the one status line:\n%s", out)
	}
	if !bytes.Equal(sgrPattern.ReplaceAll(out, nil), []byte("unsupported\n")) {
		t.Errorf("stripped status line = %q, want \"unsupported\\n\"", sgrPattern.ReplaceAll(out, nil))
	}
}

// --- Matrix: JSON round-trip -----------------------------------------

func TestJSONListGolden(t *testing.T) {
	var b bytes.Buffer
	if err := JSONList(&b, observedListing()); err != nil {
		t.Fatalf("JSONList: %v", err)
	}
	out := b.Bytes()
	if !bytes.Equal(out, wantGolden(t, "list.json.golden")) {
		t.Errorf("JSON output mismatch\n--- got ---\n%s", out)
	}
	if out[len(out)-1] != '\n' {
		t.Error("JSON output does not end with a newline")
	}
	var back model.ProcessListing
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(back, observedListing()) {
		t.Errorf("JSON did not round-trip:\n got %+v\nwant %+v", back, observedListing())
	}
}

// --- Matrix: write failure -----------------------------------------

func TestListWriteErrorIsReturned(t *testing.T) {
	if err := TextList(errWriter{}, observedListing(), false); err == nil {
		t.Error("TextList swallowed a write error")
	}
	if err := TextList(errWriter{}, observedListing(), true); err == nil {
		t.Error("TextList (colour) swallowed a write error")
	}
	if err := TextList(errWriter{}, degradedListing(), false); err == nil {
		t.Error("TextList swallowed a write error on the non-observed path")
	}
	if err := JSONList(errWriter{}, observedListing()); err == nil {
		t.Error("JSONList swallowed a write error")
	}
}

// --- Matrix: determinism -----------------------------------------

func TestListRenderersAreDeterministic(t *testing.T) {
	if !bytes.Equal(renderTextList(t, observedListing(), false), renderTextList(t, observedListing(), false)) {
		t.Error("TextList is not deterministic")
	}
	if !bytes.Equal(renderTextList(t, observedListing(), true), renderTextList(t, observedListing(), true)) {
		t.Error("TextList (colour) is not deterministic")
	}
	var a, b bytes.Buffer
	_ = JSONList(&a, observedListing())
	_ = JSONList(&b, observedListing())
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("JSONList is not deterministic")
	}
}

// --- Order is taken as given, never re-sorted (AD-6) -----------------

func TestTextListDoesNotReorder(t *testing.T) {
	l := observedListing()
	l.Processes[0], l.Processes[1] = l.Processes[1], l.Processes[0]
	out := renderTextList(t, l, false)
	firstRow := bytes.Split(out, []byte("\n"))[1]
	if !bytes.HasPrefix(firstRow, []byte("42 ")) {
		t.Errorf("TextList re-sorted the rows; first data row = %q, want it to start with 42", firstRow)
	}
}
