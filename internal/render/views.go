package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// TreeText, FilesText, NetworkText and SecurityText are filtered views over
// one model.Report: the same header line render.Text writes, followed by a
// single FACTS section instead of all seven.
//
// Each is a pure function of (io.Writer, model.Report, bool): it builds once
// into a strings.Builder, reuses the matching hoisted section writer over
// r.Facts, and writes the result. Slice order is taken as given and never
// re-sorted (AD-6); the socket join and process lineage are not re-derived
// (AD-15/16). color == false emits no escape byte. A section whose
// Availability is not observed renders exactly its header line and no body —
// which section() already enforces — and that is success, not an error.
//
// There is no JSON counterpart by design: inspect --json already marshals
// the whole Snapshot, so a per-view projection would be a second
// construction path (AD-12).

func viewHeader(b *strings.Builder, r model.Report) {
	fmt.Fprintf(b, "PID %d  %s  [%s]\n", r.Facts.PID, r.Facts.Comm, r.Facts.State)
}

// TreeText renders the header line and the children (ancestors/descendants)
// section only.
func TreeText(w io.Writer, r model.Report, color bool) error {
	var b strings.Builder
	viewHeader(&b, r)
	writeChildrenSection(&b, r.Facts, color)
	_, err := w.Write([]byte(b.String()))
	return err
}

// FilesText renders the header line and the open file descriptor section only.
func FilesText(w io.Writer, r model.Report, color bool) error {
	var b strings.Builder
	viewHeader(&b, r)
	writeFilesSection(&b, r.Facts, color)
	_, err := w.Write([]byte(b.String()))
	return err
}

// NetworkText renders the header line and the sockets section only.
func NetworkText(w io.Writer, r model.Report, color bool) error {
	var b strings.Builder
	viewHeader(&b, r)
	writeSocketsSection(&b, r.Facts, color)
	_, err := w.Write([]byte(b.String()))
	return err
}

// SecurityText renders the header line and the security context section only.
func SecurityText(w io.Writer, r model.Report, color bool) error {
	var b strings.Builder
	viewHeader(&b, r)
	writeSecuritySection(&b, r.Facts, color)
	_, err := w.Write([]byte(b.String()))
	return err
}
