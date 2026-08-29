package procfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// ErrProcessNotFound is the single Go error this package produces.
//
// AD-4 makes every observation gap data — an [model.Availability] carried
// beside the value — so the one condition that aborts an inspection is a PID
// that does not exist at all. Callers match it with [errors.Is] and map it to
// exit code 2.
var ErrProcessNotFound = errors.New("process not found")

// Reader observes processes under one configurable root (AD-3).
//
// Every read this package performs resolves inside the root, so the parsers
// are exercised against fixture trees under testdata/proc/<case>/ rather than
// only against the author's live machine. No absolute /proc literal appears
// anywhere in this package; the caller supplies the root.
//
// A Reader holds no open descriptor and no mutable state: it is a value the
// caller may keep for the life of the process and share freely.
type Reader struct {
	root string
	// pageSize converts stat's resident-set page count to bytes. It is a
	// field rather than a call to os.Getpagesize inside the parser so the
	// same fixture bytes yield the same Snapshot on a 4 KiB x86 host and a
	// 16 KiB arm64 one — which the golden-file tests above this layer
	// depend on.
	pageSize uint64
}

// New returns a Reader that resolves every read under root.
//
// The root is not validated here. A root that does not exist, or that this
// user may not open, surfaces as an [model.Availability] on each read rather
// than as a constructor error, which keeps the AD-4 contract in one place.
func New(root string) *Reader {
	return &Reader{root: root, pageSize: uint64(os.Getpagesize())}
}

// Root returns the path every read resolves under.
func (r *Reader) Root() string {
	return r.root
}

// interface names, so no read site spells a path fragment twice.
const (
	interfaceStat     = "stat"
	interfaceStatus   = "status"
	interfaceCmdline  = "cmdline"
	interfaceComm     = "comm"
	interfaceIO       = "io"
	interfaceOOMScore = "oom_score"
	interfaceExe      = "exe"
	interfaceCwd      = "cwd"
	interfaceRoot     = "root"
	interfaceFD       = "fd"
	interfaceFDInfo   = "fdinfo"
)

// entry builds the root-relative path of one per-process interface.
//
// pid is an int and name is a package constant, so neither can carry a path
// separator or a "..", and [os.Root] rejects an escape regardless.
func entry(pid int, name string) string {
	return filepath.Join(strconv.Itoa(pid), name)
}

// read returns the bytes of one per-process interface, paired with the
// availability that describes how the read went (AD-4).
//
// missingMeans is the classification for an ENOENT on a PID that is still
// present: for a regular interface file that is [model.AvailabilityUnsupported]
// — the kernel does not provide this interface — while for a symlink node it
// is [model.AvailabilityAbsent], because the node always exists and an ENOENT
// means only that this process has no target for it.
//
// An empty body is reported as observed: whether emptiness means "absent" is
// a per-interface judgement, and each parser makes it.
func (r *Reader) read(pid int, name string, missingMeans model.Availability) ([]byte, model.Availability) {
	root, err := os.OpenRoot(r.root)
	if err != nil {
		return nil, classifyRootError(err)
	}
	defer root.Close()

	data, err := root.ReadFile(entry(pid, name))
	if err != nil {
		return nil, classify(root, pid, err, missingMeans)
	}
	return data, model.AvailabilityObserved
}

// readlink returns the target of one per-process symlink.
//
// Only the link is read: the target is never Stat'd or opened, which would
// resolve a path the Reader's root does not contain (AD-3). A dangling or
// absolute target is therefore returned verbatim, exactly as the kernel
// reports it.
func (r *Reader) readlink(pid int, name string) (string, model.Availability) {
	root, err := os.OpenRoot(r.root)
	if err != nil {
		return "", classifyRootError(err)
	}
	defer root.Close()

	target, err := root.Readlink(entry(pid, name))
	if err != nil {
		return "", classify(root, pid, err, model.AvailabilityAbsent)
	}
	if strings.TrimSpace(target) == "" {
		return "", model.AvailabilityAbsent
	}
	return target, model.AvailabilityObserved
}

// readdir lists the numerically named entries of one per-process directory
// interface, paired with the availability of the directory read itself.
//
// The kernel names every entry of fd/ and fdinfo/ with a descriptor number,
// so a name that is not a decimal integer did not come from the kernel — a
// stray file in a fixture tree, or a future entry this parser does not know.
// Skipping it here keeps that judgement in one place instead of in each
// caller's loop. The names are returned in the order the directory yielded
// them; ordering the values they resolve to is the caller's job (AD-6).
//
// An empty directory is reported as observed: whether "no entries" means
// absent is a per-interface judgement, and each parser makes it, exactly as
// with an empty file body in read.
func (r *Reader) readdir(pid int, name string) ([]string, model.Availability) {
	root, err := os.OpenRoot(r.root)
	if err != nil {
		return nil, classifyRootError(err)
	}
	defer root.Close()

	directory, err := root.Open(entry(pid, name))
	if err != nil {
		// A per-process directory interface missing under a live PID is
		// classified the same way read classifies a missing regular
		// interface file: the kernel does not offer it.
		return nil, classify(root, pid, err, model.AvailabilityUnsupported)
	}
	defer directory.Close()

	entries, err := directory.Readdirnames(-1)
	if err != nil {
		return nil, classify(root, pid, err, model.AvailabilityUnsupported)
	}

	numeric := make([]string, 0, len(entries))
	for _, candidate := range entries {
		if !isDecimalFDName(candidate) {
			continue
		}
		numeric = append(numeric, candidate)
	}
	return numeric, model.AvailabilityObserved
}

// isDecimalFDName reports whether name is composed entirely of one or more
// ASCII digits — the only shape the kernel writes for an fd or fdinfo entry
// name.
//
// strconv.Atoi alone is not a sufficient filter: it also accepts signed
// forms like "-1" or "+5", which readdir never yields on a live kernel, so a
// candidate must be checked here before it is treated as trustworthy input
// to Atoi.
func isDecimalFDName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

// exists reports whether the PID directory is present under the root.
//
// A permission failure counts as present: hidepid hides the contents of a
// directory that is still there, and reporting the process as gone would turn
// a denial into a fabricated exit. That applies to the root itself — an
// unreadable root says nothing about whether the process is running, so only
// a root that is genuinely not there makes the answer no.
func (r *Reader) exists(pid int) bool {
	if pid <= 0 {
		return false
	}
	root, err := os.OpenRoot(r.root)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	defer root.Close()
	return processExists(root, pid)
}

func processExists(root *os.Root, pid int) bool {
	if _, err := root.Stat(strconv.Itoa(pid)); err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	return true
}

// classify maps a failed read on a live Reader to one Availability.
//
// This is the only place in procintel that decides what a filesystem error
// means, so the five later observers cannot each invent their own rules.
//
//	EACCES / EPERM                  -> denied
//	ESRCH, or the PID directory gone -> raced
//	ENOENT with the PID still there  -> missingMeans
//	anything else                    -> absent
func classify(root *os.Root, pid int, err error, missingMeans model.Availability) model.Availability {
	switch {
	case err == nil:
		return model.AvailabilityObserved
	case errors.Is(err, fs.ErrPermission):
		return model.AvailabilityDenied
	case errors.Is(err, syscall.ESRCH):
		return model.AvailabilityRaced
	}
	// The process may have exited between the inspection starting and this
	// read. Re-checking the PID directory is what separates "it went away"
	// from "this interface genuinely holds nothing".
	if !processExists(root, pid) {
		return model.AvailabilityRaced
	}
	if errors.Is(err, fs.ErrNotExist) {
		return missingMeans
	}
	return model.AvailabilityAbsent
}

// classifyRootError handles the case where the root itself could not be
// opened, so there is no handle left to re-check the PID directory with.
func classifyRootError(err error) model.Availability {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return model.AvailabilityDenied
	case errors.Is(err, fs.ErrNotExist):
		return model.AvailabilityUnsupported
	default:
		return model.AvailabilityAbsent
	}
}

// availabilityPrecedence orders the non-observed values from strongest claim
// to weakest, so a section that draws on several sources reports the most
// specific reason it is not fully observed.
var availabilityPrecedence = [...]model.Availability{
	model.AvailabilityDenied,
	model.AvailabilityRaced,
	model.AvailabilityUnsupported,
	model.AvailabilityAbsent,
}

// weakest combines the availabilities of one section's sources (AD-4).
//
// All sources observed yields observed; otherwise the first value present in
// the precedence denied > raced > unsupported > absent wins. A value outside
// the closed set — including the zero value — counts as absent, so a section
// can never be talked up to observed by a source that reported nothing legal.
// No sources at all is absent, not observed: nothing was looked at.
func weakest(sources ...model.Availability) model.Availability {
	if len(sources) == 0 {
		return model.AvailabilityAbsent
	}
	for _, want := range availabilityPrecedence {
		for _, got := range sources {
			if got == want {
				return want
			}
		}
	}
	for _, got := range sources {
		if got != model.AvailabilityObserved {
			return model.AvailabilityAbsent
		}
	}
	return model.AvailabilityObserved
}
