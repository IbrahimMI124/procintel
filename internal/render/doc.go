// Package render presents one model.Report as text, JSON or a TUI.
//
// All formatting, unit conversion, colour and truncation live here and
// nowhere below (AD-12). Renderers are pure functions over the report value:
// they never read /proc, never re-derive the socket join, and never import
// os, syscall or os/exec (AD-1, AD-2, AD-15) — the caller supplies the
// writer and the colour decision. Ordering is taken as given from the layers
// below and never re-sorted through a map (AD-6).
//
// Populated in Blocks 2 and 6 of IMPLEMENTATION-SEQUENCE.md.
package render
