// Package demo hosts the deterministic, harmless demo process.
//
// The demo program opens files, reads a sensitive-looking path from a
// fixture root, writes a temporary file, spawns a child and a shell, opens a
// local listening socket and makes a loopback connection — all locally, with
// no malware sample and no outbound internet (AD-9). It does triple duty as
// the demo-video script, an integration-test fixture and the README worked
// example.
//
// Populated in Block 4 of IMPLEMENTATION-SEQUENCE.md.
package demo
