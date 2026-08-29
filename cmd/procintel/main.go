// Command procintel is the entrypoint: flag parsing, subcommand dispatch,
// exit codes and wiring, and nothing else.
//
// Every layer below it is a pure function over internal/model values; the
// only code permitted to touch the kernel is internal/procfs (AD-1). Exit
// codes are fixed by the spine: 0 success, 1 usage or flag error, 2 PID not
// found — never non-zero for a partial result (AD-4). Nothing is written to
// disk unless the user names the path (AD-8), and there is no config file.
//
// The subcommand surface — inspect, list, snapshot, diff, watch — is wired
// in Blocks 2 and 3 of IMPLEMENTATION-SEQUENCE.md. Block 0 ships the
// entrypoint only, so that the one build command produces a runnable
// artifact from the first commit.
package main

import "fmt"

func main() {
	fmt.Println("procintel: Linux process intelligence. No subcommands are wired yet (Block 0).")
}
