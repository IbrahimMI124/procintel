package procfs

import (
	"sort"
	"strconv"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// List enumerates every process under the proc root, one stat read per PID.
//
// It is the sole enumeration entry point: readProcRoot yields the numeric PID
// directories, then one r.stat per PID fills a row. Per-entry tolerance
// mirrors lineage — a PID whose stat is not observed is dropped silently, with
// no penalty to the listing (AD-4). The returned Availability is exactly
// readProcRoot's: observed on a readable root, denied/unsupported/absent
// otherwise, with Processes empty.
//
// There is no error return: procfs's one Go error, ErrProcessNotFound, is a
// single-PID concept with no analogue for a whole-root walk. An unreadable
// root is Availability, not an error (AD-4).
//
// Processes is sorted by PID ascending before it is returned; no layer above
// re-sorts it (AD-6).
func (r *Reader) List() model.ProcessListing {
	names, availability := r.readProcRoot()
	if availability != model.AvailabilityObserved {
		return model.ProcessListing{Availability: availability}
	}

	processes := make([]model.ProcessSummary, 0, len(names))
	for _, name := range names {
		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		fields, status := r.stat(pid)
		if status != model.AvailabilityObserved {
			// Per-entry tolerance: a PID this user cannot stat is omitted
			// from the listing with no penalty to the section, exactly as
			// lineage drops an unreadable sibling.
			continue
		}
		processes = append(processes, model.ProcessSummary{
			PID:           fields.PID,
			PPID:          fields.PPID,
			Comm:          fields.Comm,
			State:         fields.State,
			ThreadCount:   fields.ThreadCount,
			ResidentBytes: fields.ResidentBytes,
			UserTicks:     fields.UserTime,
			SystemTicks:   fields.SystemTime,
			StartTime:     fields.StartTime,
		})
	}

	sort.Slice(processes, func(i, j int) bool { return processes[i].PID < processes[j].PID })

	return model.ProcessListing{Processes: processes, Availability: availability}
}
