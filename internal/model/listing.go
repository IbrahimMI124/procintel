package model

// ProcessSummary is one row of a single-shot process listing.
//
// Every field is a raw value straight from /proc/<pid>/stat: memory in bytes,
// CPU and start time in USER_HZ ticks. Nothing here is humanised, summed, or
// turned into a rate — that is a renderer's job (AD-12), and a single-snapshot
// listing carries CPU *time*, never CPU *percent* (AD-10). It mirrors
// [ProcessRef]: a flat value, no nested Snapshot.
type ProcessSummary struct {
	PID  int `json:"pid"`
	PPID int `json:"ppid"`
	// Comm is the kernel's short name from stat field 2, at most 15 bytes and
	// not the executable path.
	Comm string `json:"comm"`
	// State is the single-letter process state from stat: R, S, D, Z, T.
	State string `json:"state"`
	// ThreadCount is stat field 20 (num_threads).
	ThreadCount int `json:"thread_count"`
	// ResidentBytes is the resident set, converted from stat's page count to
	// bytes by the reader so identical fixture bytes yield an identical value
	// on any architecture.
	ResidentBytes uint64 `json:"resident_bytes"`
	// UserTicks and SystemTicks are cumulative CPU time in USER_HZ ticks,
	// carried separately rather than summed (AD-12).
	UserTicks   uint64 `json:"utime_ticks"`
	SystemTicks uint64 `json:"stime_ticks"`
	// StartTime is the process start time in USER_HZ ticks since boot.
	StartTime uint64 `json:"start_time"`
}

// ProcessListing is the whole-root enumeration [ProcessSummary] rows plus the
// availability of the proc-root walk that produced them.
//
// Availability is exactly the proc-root listing's own status: observed on a
// readable root, and denied/unsupported/absent otherwise — in which case
// Processes is empty. A non-observed listing is not an error; it renders and
// exits 0 (AD-4). Processes is sorted by PID ascending before it leaves
// procfs; no layer above re-sorts it (AD-6).
type ProcessListing struct {
	Processes    []ProcessSummary `json:"processes"`
	Availability Availability     `json:"availability"`
}
