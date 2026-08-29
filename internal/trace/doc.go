// Package trace is the severable P2 syscall-reporting arm.
//
// Trace-sourced observations may only add model.Event values to the existing
// event stream, using the existing type. No stage may require a
// trace-sourced event to produce correct output, so deleting this package
// must leave a compiling, passing, demonstrable product (AD-14). Historical
// syscall streaming is explicitly not built.
//
// Populated in Block 9 of IMPLEMENTATION-SEQUENCE.md, if at all.
package trace
