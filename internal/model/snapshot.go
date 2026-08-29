package model

import "time"

// SchemaVersion is the wire version stamped onto every serialised
// [Snapshot] and [Report].
//
// The differ refuses a mismatch with a clear message rather than misreading
// old fields (AD-7). Bump it whenever a field is removed, renamed, or
// changes meaning.
const SchemaVersion = 1

// UserHZ is the number of clock ticks per second that /proc reports
// utime, stime and starttime in.
//
// The correct way to read it is sysconf(_SC_CLK_TCK), which requires cgo and
// is therefore unavailable under CGO_ENABLED=0. 100 is the kernel's fixed
// USER_HZ userspace ABI value on every architecture this product targets.
// This is a stated limitation, documented in README.md and STDLIB.md rather
// than hidden.
const UserHZ = 100

// ProcessRef is a flat reference to another process in this process's
// lineage.
//
// A [Snapshot] never contains another Snapshot: ancestors and descendants
// are ProcessRef values, so lineage cost and serialised size stay bounded
// and the differ has a shape it can compare (AD-16). Inspecting a child in
// full is a separate invocation.
type ProcessRef struct {
	PID int `json:"pid"`
	// PPID is the parent PID, or 0 for PID 1.
	PPID int `json:"ppid"`
	// Comm is the kernel's short name for the process, from
	// /proc/<pid>/comm — at most 15 bytes, and not the executable path.
	Comm string `json:"comm"`
	// Executable is the resolved /proc/<pid>/exe target, empty when the
	// readlink was denied or the process is a kernel thread.
	Executable string `json:"exe"`
	// StartTime is the process start time in USER_HZ ticks since boot.
	// Together with PID it is the identity a diff is keyed on (AD-7).
	StartTime uint64 `json:"start_time"`
	// Depth is the distance from the inspected process: 0 for the process
	// itself, 1 for its direct children, and so on. Ancestors leave it at
	// 0; only descendant lists carry it (AD-16).
	Depth int `json:"depth"`
}

// FileDescriptorKind classifies an open descriptor.
//
// The legal values are the FileDescriptorKind* constants below. It is a
// descriptive label rather than a closed enum in the AD-11 sense: it gates
// no rule and carries no severity.
type FileDescriptorKind string

// The descriptor classifications produced by the procfs adapter.
const (
	FileDescriptorKindFile      FileDescriptorKind = "file"
	FileDescriptorKindDirectory FileDescriptorKind = "directory"
	FileDescriptorKindPipe      FileDescriptorKind = "pipe"
	FileDescriptorKindSocket    FileDescriptorKind = "socket"
	FileDescriptorKindAnonymous FileDescriptorKind = "anon_inode"
	FileDescriptorKindCharacter FileDescriptorKind = "character_device"
	FileDescriptorKindUnknown   FileDescriptorKind = "unknown"
)

// FileDescriptor is one entry of /proc/<pid>/fd, normalised.
//
// A descriptor of kind socket carries only its inode reference — never a
// duplicated address, port, protocol or state. The fd to socket-inode to
// connection join is performed once, in procfs, and [Snapshot.Sockets] owns
// the result (AD-15).
type FileDescriptor struct {
	// Number is the descriptor number: 0, 1, 2 and upward.
	Number int                `json:"fd"`
	Kind   FileDescriptorKind `json:"kind"`
	// Target is the readlink target: a path, or a pipe:[inode] /
	// socket:[inode] / anon_inode:[...] pseudo-target.
	Target string `json:"target"`
	// SocketInode is the socket inode this descriptor refers to, and is
	// zero for every kind other than socket. It is the only network
	// information a descriptor carries (AD-15).
	SocketInode uint64 `json:"socket_inode"`
	// Deleted reports the "(deleted)" suffix the kernel appends when the
	// backing file has been unlinked while still open.
	Deleted bool `json:"deleted"`
}

// Socket is one network or unix-domain connection owned by the process.
//
// Snapshot.Sockets is the single authoritative connection list; nothing
// above procfs re-derives the join (AD-15). Addresses are raw values —
// parsed from the little-endian hex of /proc/net/* by one shared parser —
// and are formatted only inside a renderer.
type Socket struct {
	// Protocol is one of tcp, tcp6, udp, udp6, unix.
	Protocol string `json:"protocol"`
	// LocalAddress and RemoteAddress are textual IP addresses; both are
	// empty for a unix-domain socket, which uses Path instead.
	LocalAddress string `json:"local_address"`
	LocalPort    int    `json:"local_port"`
	// RemoteAddress is empty and RemotePort zero for a listening socket.
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
	// State is the kernel's connection state, e.g. LISTEN, ESTABLISHED.
	State string `json:"state"`
	// Path is the filesystem path of a unix-domain socket, empty for the
	// IP protocols.
	Path string `json:"path"`
	// Inode is the socket inode that joined this connection to a
	// descriptor.
	Inode uint64 `json:"inode"`
	// FileDescriptor is the number of the descriptor that owns this
	// socket, so the join is traceable from either side (AD-15).
	FileDescriptor int `json:"fd"`
}

// Namespace is one entry of /proc/<pid>/ns/, as a kind and an identifier.
//
// It is a slice element rather than a map entry because no map may be
// iterated on an output path (AD-6).
type Namespace struct {
	// Kind is the namespace type: mnt, pid, net, ipc, uts, user, cgroup,
	// time.
	Kind string `json:"kind"`
	// Identifier is the readlink target, e.g. "net:[4026531840]". Two
	// processes sharing a namespace share this string.
	Identifier string `json:"identifier"`
}

// SecurityContext is the process's privilege and confinement state.
//
// Every field here resolves through the security section's [Availability];
// none resolves through a default. Absence is never a security claim:
// "seccomp unreadable" is not "seccomp disabled" (AD-4).
type SecurityContext struct {
	UID          int `json:"uid"`
	EffectiveUID int `json:"effective_uid"`
	GID          int `json:"gid"`
	EffectiveGID int `json:"effective_gid"`
	// CapabilityEffective is the raw CapEff hex mask from
	// /proc/<pid>/status, unexpanded. Decoding to capability names is a
	// renderer's job.
	CapabilityEffective string `json:"capability_effective"`
	// NoNewPrivileges is the NoNewPrivs bit from /proc/<pid>/status.
	NoNewPrivileges bool `json:"no_new_privileges"`
	// SeccompMode is the raw Seccomp value: 0 disabled, 1 strict, 2
	// filter. It is meaningful only when the security section was
	// observed.
	SeccompMode int `json:"seccomp_mode"`
	// Namespaces is ordered by Kind for deterministic output (AD-6).
	Namespaces []Namespace `json:"namespaces"`
	// CgroupPath is the unified-hierarchy path from /proc/<pid>/cgroup.
	CgroupPath string `json:"cgroup_path"`
	// SecurityLabel is the SELinux or AppArmor label from
	// /proc/<pid>/attr/current, empty where no LSM is enabled — in which
	// case the section availability is unsupported, not absent.
	SecurityLabel string `json:"security_label"`
}

// SectionAvailability carries one [Availability] per section of a
// [Snapshot].
//
// One flag for the whole snapshot would make an empty list
// indistinguishable from an unreadable one, so availability is per section
// and never aggregated (AD-4).
type SectionAvailability struct {
	Identity  Availability `json:"identity"`
	Resources Availability `json:"resources"`
	Files     Availability `json:"files"`
	Sockets   Availability `json:"sockets"`
	Children  Availability `json:"children"`
	Security  Availability `json:"security"`
	Kernel    Availability `json:"kernel"`
}

// Snapshot is the normalised state of one process at one instant.
//
// It is the product's central value: procfs assembles it, the differ
// compares two of them, the rules read it, and it serialises to and from
// JSON unchanged. It never contains another Snapshot (AD-16), it carries
// cumulative CPU time in ticks and no CPU percentage (AD-10), and it stamps
// its own schema version so a stale file is refused rather than misread
// (AD-7).
type Snapshot struct {
	SchemaVersion int `json:"schema_version"`
	// CapturedAt is the snapshot's wall clock, captured once per snapshot
	// and serialised as RFC 3339 in UTC.
	CapturedAt time.Time `json:"captured_at"`

	// Identity section.
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Comm string `json:"comm"`
	// CommandLine is the NUL-separated /proc/<pid>/cmdline split into
	// arguments; empty for kernel threads and zombies.
	CommandLine []string `json:"command_line"`
	Executable  string   `json:"exe"`
	// WorkingDirectory and RootDirectory are the /proc/<pid>/cwd and
	// /proc/<pid>/root readlink targets.
	WorkingDirectory string `json:"cwd"`
	RootDirectory    string `json:"root"`
	// State is the single-letter process state from /proc/<pid>/stat: R,
	// S, D, Z, T and so on.
	State string `json:"state"`
	// StartTime is the process start time in USER_HZ ticks since boot.
	// With PID it forms the comparability key for a diff (AD-7).
	StartTime uint64 `json:"start_time"`

	// Resources section. Cumulative CPU time stays in USER_HZ ticks all
	// the way to the diff layer, which is the only place a percentage is
	// ever computed (AD-10).
	UserTime      uint64 `json:"utime"`
	SystemTime    uint64 `json:"stime"`
	ResidentBytes uint64 `json:"resident_bytes"`
	VirtualBytes  uint64 `json:"virtual_bytes"`
	ThreadCount   int    `json:"thread_count"`
	Priority      int    `json:"priority"`
	Nice          int    `json:"nice"`
	// ReadBytes and WriteBytes are the /proc/<pid>/io counters, which
	// require PTRACE_MODE_READ and are commonly denied.
	ReadBytes  uint64 `json:"read_bytes"`
	WriteBytes uint64 `json:"write_bytes"`

	// Files section, sorted by descriptor number (AD-6).
	FileDescriptors []FileDescriptor `json:"file_descriptors"`

	// Sockets section, sorted by (protocol, local_port, remote_address)
	// (AD-6). This is the authoritative connection list (AD-15).
	Sockets []Socket `json:"sockets"`

	// Children section. Ancestors are walked to PID 1, nearest first;
	// Descendants is a flat, depth-tagged, bounded list (AD-16).
	Ancestors   []ProcessRef `json:"ancestors"`
	Descendants []ProcessRef `json:"descendants"`

	// Security section.
	Security SecurityContext `json:"security"`

	// Kernel section.
	OOMScore int `json:"oom_score"`
	// CurrentSyscall is the syscall number from /proc/<pid>/syscall, or
	// -1 when the process is not in a syscall. It is P2 and optional; the
	// kernel section's availability governs whether it means anything.
	CurrentSyscall int `json:"current_syscall"`

	// Availability is the per-section observation status (AD-4).
	Availability SectionAvailability `json:"availability"`
}

// Comparable reports whether two snapshots describe the same run of the same
// process, and may therefore be diffed field by field.
//
// A PID recycled onto a different process fails this check, and the differ
// must emit a single PROCESS_REPLACED event rather than a fabricated diff
// (AD-7). A zero PID is never comparable to anything: two zero-value
// snapshots trivially agree on both keys, and declaring them diffable would
// produce exactly the fabricated diff this check exists to prevent.
func (s Snapshot) Comparable(other Snapshot) bool {
	return s.PID > 0 && s.PID == other.PID && s.StartTime == other.StartTime
}
