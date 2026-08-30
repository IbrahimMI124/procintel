package render

import (
	"bytes"
	"embed"
	"testing"

	"github.com/IbrahimMI124/procintel/internal/model"
)

//go:embed testdata/view_tree.txt.golden
//go:embed testdata/view_files.txt.golden
//go:embed testdata/view_network.txt.golden
//go:embed testdata/view_security.txt.golden
//go:embed testdata/view_security.color.golden
//go:embed testdata/view_network_degraded.txt.golden
var viewsGoldenFS embed.FS

func wantViewGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := viewsGoldenFS.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return data
}

// viewCase pairs a filtered-view renderer with its section name and the
// SectionAvailability field the view gates on.
var viewCases = []struct {
	name   string
	golden string
	render func(w *bytes.Buffer, r model.Report, color bool) error
	setAv  func(a *model.SectionAvailability, v model.Availability)
	label  string // the section header prefix a header-only render must carry
}{
	{
		name:   "tree",
		golden: "view_tree.txt.golden",
		render: func(w *bytes.Buffer, r model.Report, c bool) error { return TreeText(w, r, c) },
		setAv:  func(a *model.SectionAvailability, v model.Availability) { a.Children = v },
		label:  "  children   ",
	},
	{
		name:   "files",
		golden: "view_files.txt.golden",
		render: func(w *bytes.Buffer, r model.Report, c bool) error { return FilesText(w, r, c) },
		setAv:  func(a *model.SectionAvailability, v model.Availability) { a.Files = v },
		label:  "  files      ",
	},
	{
		name:   "network",
		golden: "view_network.txt.golden",
		render: func(w *bytes.Buffer, r model.Report, c bool) error { return NetworkText(w, r, c) },
		setAv:  func(a *model.SectionAvailability, v model.Availability) { a.Sockets = v },
		label:  "  sockets    ",
	},
	{
		name:   "security",
		golden: "view_security.txt.golden",
		render: func(w *bytes.Buffer, r model.Report, c bool) error { return SecurityText(w, r, c) },
		setAv:  func(a *model.SectionAvailability, v model.Availability) { a.Security = v },
		label:  "  security   ",
	},
}

// --- Matrix: fully-observed, no colour, one section per view ------------

func TestViewsObservedGolden(t *testing.T) {
	for _, tc := range viewCases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := tc.render(&b, observedReport(), false); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if !bytes.Equal(b.Bytes(), wantViewGolden(t, tc.golden)) {
				t.Errorf("%s output mismatch\n--- got ---\n%s", tc.name, b.Bytes())
			}
			if bytes.Contains(b.Bytes(), []byte("\x1b[")) {
				t.Errorf("%s: color=false output contains an escape sequence", tc.name)
			}
			// A view is one section: the header line plus exactly this section.
			if !bytes.HasPrefix(b.Bytes(), []byte("PID 7312  update  [S]\n")) {
				t.Errorf("%s: missing the shared header line", tc.name)
			}
			for _, other := range []string{"FACTS", "SIGNALS", "ASSESSMENT"} {
				if bytes.Contains(b.Bytes(), []byte(other)) {
					t.Errorf("%s: leaked the %s block header", tc.name, other)
				}
			}
		})
	}
}

// --- Matrix: section not observed → header line only, still success ----

func TestViewsHeaderOnlyWhenNotObserved(t *testing.T) {
	for _, tc := range viewCases {
		for _, av := range []model.Availability{
			model.AvailabilityDenied,
			model.AvailabilityUnsupported,
			model.AvailabilityAbsent,
			model.AvailabilityRaced,
		} {
			t.Run(tc.name+"/"+string(av), func(t *testing.T) {
				r := observedReport()
				tc.setAv(&r.Facts.Availability, av)
				var b bytes.Buffer
				if err := tc.render(&b, r, false); err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				lines := bytes.Split(bytes.TrimRight(b.Bytes(), "\n"), []byte("\n"))
				if len(lines) != 2 {
					t.Fatalf("%s: want header + one section line, got %d lines:\n%s", tc.name, len(lines), b.Bytes())
				}
				want := tc.label + string(av)
				if string(lines[1]) != want {
					t.Errorf("%s: section line = %q, want %q", tc.name, lines[1], want)
				}
			})
		}
	}
}

// --- Matrix: colour golden -------------------------------------------

func TestViewsColorGolden(t *testing.T) {
	var b bytes.Buffer
	if err := SecurityText(&b, observedReport(), true); err != nil {
		t.Fatalf("SecurityText colour: %v", err)
	}
	if !bytes.Equal(b.Bytes(), wantViewGolden(t, "view_security.color.golden")) {
		t.Errorf("colour output mismatch\n--- got ---\n%s", b.Bytes())
	}
	stripped := sgrPattern.ReplaceAll(b.Bytes(), nil)
	var plain bytes.Buffer
	_ = SecurityText(&plain, observedReport(), false)
	if !bytes.Equal(stripped, plain.Bytes()) {
		t.Errorf("stripping SGR from the coloured view did not yield the plain view\n--- stripped ---\n%s", stripped)
	}
}

// A header-only view still carries the availability word in colour and no body.
func TestViewsHeaderOnlyColorHasNoBody(t *testing.T) {
	r := observedReport()
	r.Facts.Availability.Sockets = model.AvailabilityUnsupported
	var b bytes.Buffer
	if err := NetworkText(&b, r, true); err != nil {
		t.Fatalf("NetworkText: %v", err)
	}
	if bytes.Count(b.Bytes(), []byte("\n")) != 2 {
		t.Errorf("header-only view emitted more than the header + section line:\n%s", b.Bytes())
	}
	if !bytes.Equal(sgrPattern.ReplaceAll(b.Bytes(), nil), wantViewGolden(t, "view_network_degraded.txt.golden")) {
		t.Errorf("stripped header-only view = %q", sgrPattern.ReplaceAll(b.Bytes(), nil))
	}
}

// --- Matrix: write failure -----------------------------------------

func TestViewsWriteErrorIsReturned(t *testing.T) {
	renderers := map[string]func(w interface {
		Write([]byte) (int, error)
	}) error{
		"tree":     func(w interface{ Write([]byte) (int, error) }) error { return TreeText(w, observedReport(), false) },
		"files":    func(w interface{ Write([]byte) (int, error) }) error { return FilesText(w, observedReport(), false) },
		"network":  func(w interface{ Write([]byte) (int, error) }) error { return NetworkText(w, observedReport(), false) },
		"security": func(w interface{ Write([]byte) (int, error) }) error { return SecurityText(w, observedReport(), false) },
	}
	for name, fn := range renderers {
		if err := fn(errWriter{}); err == nil {
			t.Errorf("%s swallowed a write error", name)
		}
	}
}

// --- Matrix: determinism -----------------------------------------

func TestViewsAreDeterministic(t *testing.T) {
	for _, tc := range viewCases {
		var a, b bytes.Buffer
		_ = tc.render(&a, observedReport(), false)
		_ = tc.render(&b, observedReport(), false)
		if !bytes.Equal(a.Bytes(), b.Bytes()) {
			t.Errorf("%s is not deterministic", tc.name)
		}
		var ca, cb bytes.Buffer
		_ = tc.render(&ca, observedReport(), true)
		_ = tc.render(&cb, observedReport(), true)
		if !bytes.Equal(ca.Bytes(), cb.Bytes()) {
			t.Errorf("%s (colour) is not deterministic", tc.name)
		}
	}
}
