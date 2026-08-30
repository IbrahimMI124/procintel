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

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/IbrahimMI124/procintel/internal/explain"
	"github.com/IbrahimMI124/procintel/internal/model"
	"github.com/IbrahimMI124/procintel/internal/procfs"
	"github.com/IbrahimMI124/procintel/internal/render"
)

// usageLine is the block printed on any usage or flag error, and as the help
// text. The subcommand surface is `inspect <pid>` and `list`; the inspect line
// is kept verbatim from the block that introduced it.
const usageLine = "usage: procintel inspect <pid> [--json] [--verbose] [--no-color] [--root <path>]\n" +
	"       procintel list [--json] [--verbose] [--no-color] [--root <path>]"

func main() {
	color := isCharDevice(os.Stdout) && os.Getenv("NO_COLOR") == ""
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, color))
}

// isCharDevice reports whether f is a character device (a terminal). A Stat
// error is treated as "not a terminal".
func isCharDevice(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// run is the whole behavioural surface: it dispatches on the subcommand,
// wires the pipeline and maps every outcome to an exit code. It never calls
// os.Exit and never touches os.Stdout/os.Stderr/env directly.
func run(args []string, stdout, stderr io.Writer, colorDefault bool) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usageLine)
		return 1
	}
	switch args[0] {
	case "inspect":
		return runInspect(args[1:], stdout, stderr, colorDefault)
	case "list":
		return runList(args[1:], stdout, stderr, colorDefault)
	case "-h", "--help":
		fmt.Fprintln(stdout, usageLine)
		return 0
	default:
		fmt.Fprintln(stderr, usageLine)
		return 1
	}
}

// runInspect owns the inspect flag set and the procfs → explain → render
// pipeline. It returns 0 on success (including a fully degraded snapshot), 1
// on a usage/flag or render-write error, and 2 iff the PID does not exist.
func runInspect(args []string, stdout, stderr io.Writer, colorDefault bool) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "render the report as JSON")
	verbose := fs.Bool("verbose", false, "write diagnostics to stderr")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	root := fs.String("root", "/proc", "procfs root to resolve reads under")

	// The pid is the sole positional argument and leads the subcommand;
	// stdlib flag stops at the first non-flag token, so the pid is peeled off
	// here and only the flags are handed to Parse.
	var pidArg string
	flagArgs := args
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		pidArg = args[0]
		flagArgs = args[1:]
	}

	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, usageLine)
			return 0
		}
		return 1
	}

	if pidArg == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, usageLine)
		return 1
	}
	pid, err := strconv.Atoi(pidArg)
	if err != nil || pid <= 0 {
		fmt.Fprintln(stderr, usageLine)
		return 1
	}

	reader := procfs.New(*root)

	if *verbose {
		fmt.Fprintf(stderr, "root: %s\n", reader.Root())
		fmt.Fprintf(stderr, "pid: %d\n", pid)
	}

	snapshot, err := reader.Snapshot(pid)
	if err != nil {
		if errors.Is(err, procfs.ErrProcessNotFound) {
			fmt.Fprintf(stderr, "inspect: pid %d not found under %s\n", pid, reader.Root())
			return 2
		}
		fmt.Fprintf(stderr, "inspect: %v\n", err)
		return 1
	}

	if *verbose {
		writeNonObservedSections(stderr, snapshot.Availability)
	}

	report := explain.Explain(snapshot)

	color := colorDefault && !*noColor

	var werr error
	if *jsonOut {
		werr = render.JSON(stdout, report)
	} else {
		werr = render.Text(stdout, report, color)
	}
	if werr != nil {
		fmt.Fprintf(stderr, "inspect: %v\n", werr)
		return 1
	}
	return 0
}

// runList owns the list flag set and the procfs → render pipeline. It walks
// the proc root once, renders the flat listing, and returns 0 on success —
// including an empty or non-observed listing, which is Availability, not an
// error (AD-4). It returns 1 only for a usage/flag or a render-write error;
// there is no single-PID abort here, so exit 2 cannot occur.
func runList(args []string, stdout, stderr io.Writer, colorDefault bool) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "render the listing as JSON")
	verbose := fs.Bool("verbose", false, "write diagnostics to stderr")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	root := fs.String("root", "/proc", "procfs root to resolve reads under")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, usageLine)
			return 0
		}
		return 1
	}

	// list takes no positional argument: it enumerates the whole root.
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, usageLine)
		return 1
	}

	reader := procfs.New(*root)

	if *verbose {
		fmt.Fprintf(stderr, "root: %s\n", reader.Root())
	}

	listing := reader.List()

	if *verbose && listing.Availability != model.AvailabilityObserved {
		fmt.Fprintf(stderr, "availability: %s\n", listing.Availability)
	}

	color := colorDefault && !*noColor

	var werr error
	if *jsonOut {
		werr = render.JSONList(stdout, listing)
	} else {
		werr = render.TextList(stdout, listing, color)
	}
	if werr != nil {
		fmt.Fprintf(stderr, "list: %v\n", werr)
		return 1
	}
	return 0
}

// writeNonObservedSections writes one plain `name: availability` line to w for
// every Snapshot section whose Availability is not observed, in
// SectionAvailability field order. It carries no severity or formatting logic
// — it is a direct reflection of the snapshot's section availability.
func writeNonObservedSections(w io.Writer, a model.SectionAvailability) {
	sections := []struct {
		name string
		got  model.Availability
	}{
		{"identity", a.Identity},
		{"resources", a.Resources},
		{"files", a.Files},
		{"sockets", a.Sockets},
		{"children", a.Children},
		{"security", a.Security},
		{"kernel", a.Kernel},
	}
	for _, s := range sections {
		if s.got != model.AvailabilityObserved {
			fmt.Fprintf(w, "%s: %s\n", s.name, s.got)
		}
	}
}
