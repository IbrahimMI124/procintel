// Package explain assembles the one report the renderers consume.
//
// It produces exactly one model.Report holding FACTS, SIGNALS and ASSESSMENT
// as separate values; text, JSON and TUI are three renderers over that same
// value, never a parallel construction path (AD-12). The three sections are
// kept visibly separate in every output, including JSON, so inference is
// never presented as fact (AD-5). Values stay raw here — bytes, ticks, ints,
// enums; formatting belongs to a renderer.
//
// Populated in Blocks 2 and 6 of IMPLEMENTATION-SEQUENCE.md.
package explain
