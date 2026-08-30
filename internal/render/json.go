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
