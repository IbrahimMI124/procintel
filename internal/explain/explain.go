package explain

import (
	"time"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// Explain builds the one model.Report the renderers consume (AD-12).
//
// This block fills the FACTS half only: Facts carries the snapshot by value
// — the single place a Snapshot is nested in a Report (AD-16) — and nothing
// is reformatted, reordered or reinterpreted on the way through (AD-4, AD-6).
// Changes, Behaviors, Signals and Assessment stay at their zero values until
// the diff (Block 3) and behavior/rules/correlate (Block 5) layers are wired;
// an empty Changes list is a single-snapshot inspect, not an error.
func Explain(snapshot model.Snapshot) model.Report {
	return model.Report{
		SchemaVersion: model.SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Facts:         snapshot,
	}
}
