package procfs

import (
	"strconv"
	"strings"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// ioCounters are the two /proc/<pid>/io fields the model carries.
//
// read_bytes and write_bytes are the counters that actually reached the
// storage layer, as opposed to rchar/wchar which count bytes passed to the
// syscall and include cache hits. The model names them ReadBytes and
// WriteBytes.
type ioCounters struct {
	ReadBytes  uint64
	WriteBytes uint64
}

// io reads and parses /proc/<pid>/io.
//
// This read requires PTRACE_MODE_READ and is denied for another user's
// process on almost every configuration, which is routine rather than
// exceptional: it degrades the resources section to denied and never aborts
// the inspection (AD-4). Reporting zero bytes read would be a fabricated
// fact, which is precisely what the Availability model exists to prevent.
func (r *Reader) io(pid int) (ioCounters, model.Availability) {
	data, availability := r.read(pid, interfaceIO, model.AvailabilityUnsupported)
	if availability != model.AvailabilityObserved {
		return ioCounters{}, availability
	}
	counters, ok := parseIO(data)
	if !ok {
		return ioCounters{}, model.AvailabilityAbsent
	}
	return counters, model.AvailabilityObserved
}

// parseIO extracts read_bytes and write_bytes, reporting whether both were
// found and parsable. A file missing either key yields nothing at all: half
// the counters is not a usable observation, and the missing half would read
// as a zero.
func parseIO(data []byte) (ioCounters, bool) {
	var counters ioCounters
	var sawRead, sawWrite bool

	for _, line := range strings.Split(string(data), "\n") {
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		if key != "read_bytes" && key != "write_bytes" {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(line[colon+1:]), 10, 64)
		if err != nil {
			return ioCounters{}, false
		}
		if key == "read_bytes" {
			counters.ReadBytes, sawRead = value, true
		} else {
			counters.WriteBytes, sawWrite = value, true
		}
	}
	if !sawRead || !sawWrite {
		return ioCounters{}, false
	}
	return counters, true
}

// oomScore reads /proc/<pid>/oom_score, the kernel section's one populated
// field in this block.
func (r *Reader) oomScore(pid int) (int, model.Availability) {
	data, availability := r.read(pid, interfaceOOMScore, model.AvailabilityUnsupported)
	if availability != model.AvailabilityObserved {
		return 0, availability
	}
	score, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, model.AvailabilityAbsent
	}
	return score, model.AvailabilityObserved
}
