package procfs

import (
	"fmt"
	"time"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// Snapshot observes one process and returns it as a model.Snapshot.
//
// This block populates the identity, resources, files, sockets and kernel
// sections. The children and security sections are left at their zero
// Availability — which model.Availability.Valid reports as invalid, and which
// therefore can never be mistaken for observed — until Blocks 1d and 1e fill
// them. Saying "absent" or "unsupported" for a section this build simply does
// not look at would be a false claim about the kernel (AD-4).
//
// The only error this method returns is ErrProcessNotFound. Every other
// failure to see something is carried as an Availability on the section it
// affects: a partial answer is always better than an aborted inspection.
//
// Reads are sequential. AD-13's concurrent observation lands with the rest of
// the observers, once there is more than one file's worth of latency to hide.
func (r *Reader) Snapshot(pid int) (model.Snapshot, error) {
	if !r.exists(pid) {
		return model.Snapshot{}, fmt.Errorf("pid %d under %s: %w", pid, r.root, ErrProcessNotFound)
	}

	snapshot := model.Snapshot{
		SchemaVersion:  model.SchemaVersion,
		CapturedAt:     time.Now().UTC(),
		CurrentSyscall: -1,
	}

	statFields, statStatus := r.stat(pid)
	statusFile, statusStatus := r.status(pid)
	name, commStatus := r.comm(pid)
	arguments, cmdlineStatus := r.cmdline(pid)
	resolved := r.links(pid)
	counters, ioStatus := r.io(pid)
	score, oomStatus := r.oomScore(pid)
	descriptors, filesStatus := r.fileDescriptors(pid)
	sockets, netStatus := r.sockets(pid, descriptors)

	// Identity. comm is the kernel's own short name and the most direct
	// source; stat's field 2 carries the same string, so it serves when the
	// comm file itself is unreadable.
	identitySources := append([]model.Availability{
		statStatus, commStatus, cmdlineStatus,
	}, resolved.availabilities()...)
	identity := weakest(identitySources...)

	// A degraded source lowers the section's Availability; it never erases
	// what another source read successfully. /proc/<pid>/stat is
	// world-readable, so a denied exe readlink must not take the pid, comm
	// and state down with it — that would leave the tool blank for every
	// process the user does not own, which is the case it is designed for.
	// Each field below holds what its own source returned, or zero if that
	// source failed. Availability is the honesty signal (AD-4).
	snapshot.PID = pid
	snapshot.PPID = statFields.PPID
	snapshot.State = statFields.State
	snapshot.StartTime = statFields.StartTime
	snapshot.Comm = firstNonEmpty(name, statFields.Comm)
	snapshot.CommandLine = arguments
	snapshot.Executable = resolved.Executable
	snapshot.WorkingDirectory = resolved.WorkingDirectory
	snapshot.RootDirectory = resolved.RootDirectory

	// stat naming a different process than the one asked for means the
	// entry was recycled underneath the read.
	if statStatus == model.AvailabilityObserved && statFields.PID != pid {
		identity = model.AvailabilityRaced
	}

	// Resources. A section is only as good as its weakest source, so a
	// denied /proc/<pid>/io or status — routine on another user's process —
	// marks the section denied. The counters it could not read stay zero
	// and the section's Availability says why; no rule may fire on them
	// (AD-4).
	resources := weakest(statStatus, statusStatus, ioStatus)
	snapshot.UserTime = statFields.UserTime
	snapshot.SystemTime = statFields.SystemTime
	snapshot.ResidentBytes = statFields.ResidentBytes
	snapshot.VirtualBytes = statFields.VirtualBytes
	snapshot.ThreadCount = threadCount(statusFile, statFields)
	snapshot.Priority = statFields.Priority
	snapshot.Nice = statFields.Nice
	snapshot.ReadBytes = counters.ReadBytes
	snapshot.WriteBytes = counters.WriteBytes

	// Files. The section's Availability describes the fd/ directory read
	// itself: denied under hidepid or on another user's process, raced when
	// the PID went away, absent when the directory is there and empty. A
	// socket descriptor carries only its inode; the join into Sockets below
	// is the only place a connection is ever assembled (AD-15).
	snapshot.FileDescriptors = descriptors

	// Sockets. The join happens exactly once, here, over Block 1b's
	// already-classified descriptors (AD-15). The section can never read
	// observed unless the fd side of the join (Files) also reached at least
	// the state needed to see every socket-kind descriptor, so the section's
	// Availability folds in filesStatus alongside each /proc/net/* file's
	// own read outcome, via the same weakest precedence every other section
	// uses.
	socketsAvailability := weakest(filesStatus, netStatus)
	snapshot.Sockets = sockets

	// Kernel. CurrentSyscall stays at -1: /proc/<pid>/syscall is P2 and
	// this block does not read it, so the field means "not observed here"
	// rather than "not in a syscall".
	kernel := weakest(oomStatus)
	snapshot.OOMScore = score

	snapshot.Availability = model.SectionAvailability{
		Identity:  identity,
		Resources: resources,
		Files:     filesStatus,
		Sockets:   socketsAvailability,
		Kernel:    kernel,
	}
	return snapshot, nil
}

// threadCount prefers status's Threads key over stat's field 20.
//
// They are the same number, but status names it, so a kernel that reorders
// stat's positional fields — which has happened — cannot silently shift a
// thread count into the wrong slot.
func threadCount(parsed statusFile, fields statFields) int {
	if threads, ok := parsed.LookupUint("Threads"); ok {
		return int(threads)
	}
	return fields.ThreadCount
}

// firstNonEmpty returns the first non-empty candidate, or "".
func firstNonEmpty(candidates ...string) string {
	for _, candidate := range candidates {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}
