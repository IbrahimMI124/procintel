package render

import (
	"bytes"
	"embed"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/IbrahimMI124/procintel/internal/model"
)

//go:embed testdata/snapshot_observed.json.golden
var snapshotGoldenFS embed.FS

func wantSnapshotGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := snapshotGoldenFS.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return data
}

// --- Matrix: fully-observed snapshot, golden + round-trip --------------

func TestJSONSnapshotObservedGolden(t *testing.T) {
	var b bytes.Buffer
	if err := JSONSnapshot(&b, observedSnapshot()); err != nil {
		t.Fatalf("JSONSnapshot: %v", err)
	}
	out := b.Bytes()

	if !bytes.Equal(out, wantSnapshotGolden(t, "snapshot_observed.json.golden")) {
		t.Errorf("JSON output mismatch\n--- got ---\n%s", out)
	}
	if out[len(out)-1] != '\n' {
		t.Error("JSONSnapshot output does not end with a newline")
	}
	if bytes.Contains(out, []byte("\x1b[")) {
		t.Error("JSONSnapshot output contains an escape sequence")
	}
	var back model.Snapshot
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(back, observedSnapshot()) {
		t.Errorf("JSONSnapshot did not round-trip:\n got %+v\nwant %+v", back, observedSnapshot())
	}
}

// --- Matrix: zero Snapshot -------------------------------------------

func TestJSONSnapshotZeroValue(t *testing.T) {
	var b bytes.Buffer
	if err := JSONSnapshot(&b, model.Snapshot{}); err != nil {
		t.Fatalf("JSONSnapshot on zero Snapshot: %v", err)
	}
	out := b.Bytes()
	if out[len(out)-1] != '\n' {
		t.Error("JSONSnapshot output does not end with a newline")
	}
	var back model.Snapshot
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("zero Snapshot JSON is not valid: %v", err)
	}
	if !reflect.DeepEqual(back, model.Snapshot{}) {
		t.Errorf("zero Snapshot did not round-trip: got %+v", back)
	}
}

// --- Matrix: write failure -----------------------------------------

func TestJSONSnapshotWriteErrorIsReturned(t *testing.T) {
	if err := JSONSnapshot(errWriter{}, observedSnapshot()); err == nil {
		t.Error("JSONSnapshot swallowed a write error")
	}
}

// --- Matrix: determinism -----------------------------------------

func TestJSONSnapshotIsDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	_ = JSONSnapshot(&a, observedSnapshot())
	_ = JSONSnapshot(&b, observedSnapshot())
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("JSONSnapshot is not deterministic")
	}
}
