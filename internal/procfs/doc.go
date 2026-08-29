// Package procfs is the sole adapter at the kernel boundary.
//
// It is the only package in procintel permitted to touch the filesystem or
// make a syscall (AD-1). Every reader resolves relative to a configurable
// root so the parsers are fixture-testable (AD-3), and no absolute /proc
// literal appears anywhere. Observation gaps are returned as
// [model.Availability] values, never as errors (AD-4). The
// fd -> socket-inode -> connection join is performed here, exactly once, and
// Snapshot.Sockets is the authoritative result (AD-15).
//
// Populated in Block 1 of IMPLEMENTATION-SEQUENCE.md.
package procfs
