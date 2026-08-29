// Package diff turns two snapshots into an ordered event stream.
//
// Compare(a, b model.Snapshot) []model.Event is total and pure: it knows
// nothing about where either snapshot came from, keeps no cache and owns no
// state directory (AD-7). Two snapshots are comparable only when pid and
// start_time both match; a recycled PID yields a single PROCESS_REPLACED
// event rather than a fabricated diff. CPU percentage and memory deltas are
// computed here and only here, from the wall-clock delta between two
// snapshots (AD-10). Event ordering is deterministic (AD-6).
//
// Populated in Block 3 of IMPLEMENTATION-SEQUENCE.md.
package diff
