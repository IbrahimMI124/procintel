package procfs

import (
	"strconv"
	"strings"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// statFields is the subset of /proc/<pid>/stat this block consumes.
//
// CPU times and the start time stay in USER_HZ ticks; memory is raw bytes
// (AD-10). Nothing here is scaled, humanised or turned into a rate — that is
// a diff-layer and renderer concern.
type statFields struct {
	PID   int
	Comm  string
	State string
	PPID  int
	// UserTime and SystemTime are cumulative, in USER_HZ ticks.
	UserTime    uint64
	SystemTime  uint64
	Priority    int
	Nice        int
	ThreadCount int
	// StartTime is ticks since boot; with PID it is the diff key (AD-7).
	StartTime     uint64
	VirtualBytes  uint64
	ResidentBytes uint64
}

// Positions in the whitespace-separated remainder that follows the closing
// parenthesis of field 2. rest[0] is field 3, so a stat field number n sits at
// rest[n-3].
const (
	statRestState       = 0  // field 3
	statRestPPID        = 1  // field 4
	statRestUserTime    = 11 // field 14
	statRestSystemTime  = 12 // field 15
	statRestPriority    = 15 // field 18
	statRestNice        = 16 // field 19
	statRestThreadCount = 17 // field 20
	statRestStartTime   = 19 // field 22
	statRestVirtualSize = 20 // field 23
	statRestResidentSet = 21 // field 24

	// statRestMinimum is one past the last position read, so a truncated
	// line is rejected before any positional index is taken.
	statRestMinimum = statRestResidentSet + 1
)

// stat reads and parses /proc/<pid>/stat.
//
// A line this parser cannot make sense of yields the zero statFields and
// absent: a stat line is parsed as a whole or not at all, so no caller ever
// sees a half-populated identity where the missing half reads as fact (AD-4).
func (r *Reader) stat(pid int) (statFields, model.Availability) {
	data, availability := r.read(pid, interfaceStat, model.AvailabilityUnsupported)
	if availability != model.AvailabilityObserved {
		return statFields{}, availability
	}
	fields, ok := parseStat(data, r.pageSize)
	if !ok {
		return statFields{}, model.AvailabilityAbsent
	}
	return fields, model.AvailabilityObserved
}

// parseStat parses one /proc/<pid>/stat line, reporting whether it succeeded.
//
// Field 2 is the executable name as the kernel holds it, wrapped in
// parentheses and neither escaped nor length-limited in a way that helps: it
// may contain spaces and further parentheses, so a process named
// "my (odd) proc" produces "1234 (my (odd) proc) S 1 ...". Splitting on
// whitespace, or on the first ')', misreads every field after it. The only
// correct split is the LAST ')' in the line, which is why this is a function
// of its own with a table of its own rather than three lines inside the
// reader.
func parseStat(data []byte, pageSize uint64) (statFields, bool) {
	line := strings.TrimSpace(string(data))
	if line == "" {
		return statFields{}, false
	}

	open := strings.IndexByte(line, '(')
	closing := strings.LastIndexByte(line, ')')
	if open < 0 || closing < open {
		return statFields{}, false
	}

	var fields statFields
	ok := true

	fields.PID = parseInt(strings.TrimSpace(line[:open]), &ok)
	fields.Comm = line[open+1 : closing]

	rest := strings.Fields(line[closing+1:])
	if len(rest) < statRestMinimum {
		return statFields{}, false
	}

	fields.State = rest[statRestState]
	if len(fields.State) != 1 {
		return statFields{}, false
	}
	fields.PPID = parseInt(rest[statRestPPID], &ok)
	fields.UserTime = parseUint(rest[statRestUserTime], &ok)
	fields.SystemTime = parseUint(rest[statRestSystemTime], &ok)
	fields.Priority = parseInt(rest[statRestPriority], &ok)
	fields.Nice = parseInt(rest[statRestNice], &ok)
	fields.ThreadCount = parseInt(rest[statRestThreadCount], &ok)
	fields.StartTime = parseUint(rest[statRestStartTime], &ok)
	fields.VirtualBytes = parseUint(rest[statRestVirtualSize], &ok)

	// Field 24 is the resident set in pages, not bytes. The page size comes
	// from the Reader rather than from os.Getpagesize here, so identical
	// fixture bytes produce an identical Snapshot on any architecture.
	residentPages := parseUint(rest[statRestResidentSet], &ok)
	fields.ResidentBytes = residentPages * pageSize

	if !ok {
		return statFields{}, false
	}
	return fields, true
}

// parseInt and parseUint clear ok on the first unparsable field and return
// zero, so a caller checks one flag instead of ten errors.
func parseInt(text string, ok *bool) int {
	value, err := strconv.Atoi(text)
	if err != nil {
		*ok = false
		return 0
	}
	return value
}

func parseUint(text string, ok *bool) uint64 {
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		*ok = false
		return 0
	}
	return value
}
