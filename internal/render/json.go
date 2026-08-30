package render

import (
	"encoding/json"
	"io"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// JSON writes r as indented JSON followed by a single newline.
//
// It is the machine-readable half of AD-12: the exact same model.Report the
// text renderer consumes, serialised with encoding/json. Struct-field order
// is the declaration order in internal/model, so the output is deterministic
// without any map iteration (AD-6), and it round-trips — json.Unmarshal of
// this output reproduces the Report.
func JSON(w io.Writer, r model.Report) error {
	encoded, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if _, err := w.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return nil
}

// JSONSnapshot writes s as indented JSON followed by a single newline.
//
// It is byte-shape identical to JSON — 2-space MarshalIndent, one trailing
// newline, both errors propagated unwrapped — but over a bare model.Snapshot
// rather than a model.Report. This is the on-the-wire form the differ reads
// as its "explicit files" provenance (AD-7): `snapshot -o a.json`, later
// `diff a.json b.json`. The serialised value is exactly what procfs produced
// — schema_version already stamped, CPU time in ticks and no percentage
// (AD-10), no nested Snapshot (AD-16). Struct-field order is the declaration
// order in internal/model, so the output is deterministic without any map
// iteration (AD-6) and round-trips — json.Unmarshal of this output
// reproduces the Snapshot.
func JSONSnapshot(w io.Writer, s model.Snapshot) error {
	encoded, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if _, err := w.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return nil
}
