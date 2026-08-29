package procfs

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// The pseudo-target prefixes the kernel writes for a descriptor that has no
// path. Everything else /proc/<pid>/fd/<n> can point at is an absolute path.
const (
	targetPrefixSocket    = "socket:["
	targetPrefixPipe      = "pipe:["
	targetPrefixAnonymous = "anon_inode:"
	// deletedSuffix is appended by the kernel when the backing file has
	// been unlinked while the descriptor is still open. It is stripped
	// before classification and recorded as a flag.
	deletedSuffix = " (deleted)"
)

// oDirectory is O_DIRECTORY, the one open flag this block reads.
//
// It is 0200000 on every architecture procintel targets (linux/amd64,
// linux/arm64). Hardcoding it follows the same disclosed-limitation
// convention as USER_HZ: it is an ABI constant on the supported platforms,
// stated here rather than hidden.
const oDirectory = 0o200000

// fileDescriptors enumerates and classifies /proc/<pid>/fd (AD-15).
//
// Classification is readlink-text-first and fdinfo-second, never the reverse:
// the link target alone decides socket, pipe and anon_inode, so those
// descriptors never open an fdinfo file at all. Only a descriptor whose
// target is a path consults /proc/<pid>/fdinfo/<n>, and only to split
// directory from file.
//
// The target is read and never resolved. Stat'ing or opening it would follow
// a path outside the Reader's root — a path the inspected process chose
// (AD-3) — so a descriptor's kind is decided from text the kernel already
// gave us.
//
// A socket descriptor carries only its inode. The join to a connection is
// performed once, by the socket observer, and Snapshot.Sockets owns the
// result (AD-15); nothing here duplicates an address, port or state.
//
// Enumeration is tolerant per entry rather than per file: an entry whose
// readlink fails while the process is still present was closed between the
// directory read and the link read, and is dropped from the list instead of
// aborting the section. The list is sorted by descriptor number (AD-6).
func (r *Reader) fileDescriptors(pid int) ([]model.FileDescriptor, model.Availability) {
	names, availability := r.readdir(pid, interfaceFD)
	if availability != model.AvailabilityObserved {
		return nil, availability
	}

	candidates := make([]fdCandidate, 0, len(names))
	for _, name := range names {
		if !isDecimalFDName(name) {
			// readdir already filtered these; belt and braces.
			continue
		}
		number, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		target, entryAvailability := r.readlink(pid, filepath.Join(interfaceFD, name))
		candidates = append(candidates, fdCandidate{
			number:       number,
			name:         name,
			target:       target,
			availability: entryAvailability,
		})
	}

	return combineFDCandidates(candidates, func(number int, name, target string) model.FileDescriptor {
		return r.classifyDescriptor(pid, number, name, target)
	})
}

// fdCandidate is one fd/ directory entry paired with the outcome of reading
// its link target — the raw material [combineFDCandidates] turns into the
// section's descriptors and Availability.
type fdCandidate struct {
	number       int
	name         string
	target       string
	availability model.Availability
}

// combineFDCandidates turns a set of per-entry read outcomes into the final
// descriptor list and the section's Availability.
//
// It is a pure function over its arguments — no filesystem access — so the
// per-entry combination rule (a vanished entry is dropped silently, a denied
// one is dropped but counted against the section) is exercisable with
// synthetic candidates, independent of readlink or a real fixture tree.
//
// A descriptor that vanished under the enumeration is genuinely no longer
// open, so the list stays accurate without it and the section stays
// observed. A denial is different: the descriptor is there and we were not
// allowed to see it, which is a gap the section must confess (AD-4) — the
// descriptors that were read stay in the list, but the section's Availability
// reports the denial rather than observed.
func combineFDCandidates(candidates []fdCandidate, classify func(number int, name, target string) model.FileDescriptor) ([]model.FileDescriptor, model.Availability) {
	descriptors := make([]model.FileDescriptor, 0, len(candidates))
	// Sources feeding the section's availability: the directory read (always
	// observed, since the caller only reaches here after confirming that)
	// plus any per-entry read that failed for a reason that hides a fact.
	sources := []model.Availability{model.AvailabilityObserved}

	for _, candidate := range candidates {
		if candidate.availability != model.AvailabilityObserved {
			if candidate.availability == model.AvailabilityDenied {
				sources = append(sources, candidate.availability)
			}
			continue
		}
		descriptors = append(descriptors, classify(candidate.number, candidate.name, candidate.target))
	}

	if len(descriptors) == 0 {
		if len(sources) == 1 {
			// The directory was readable and held nothing — a fully reaped
			// zombie, for instance. Observing nothing is absent, not an
			// observed empty list.
			return nil, model.AvailabilityAbsent
		}
		return nil, weakest(sources...)
	}
	sort.Slice(descriptors, func(i, j int) bool {
		return descriptors[i].Number < descriptors[j].Number
	})
	return descriptors, weakest(sources...)
}

// classifyDescriptor turns one fd number and its raw link target into a
// model.FileDescriptor.
//
// name is the entry name as the kernel spelled it, used to address the
// matching fdinfo file; number is the same value parsed.
func (r *Reader) classifyDescriptor(pid, number int, name, rawTarget string) model.FileDescriptor {
	target, deleted := strings.CutSuffix(rawTarget, deletedSuffix)

	descriptor := model.FileDescriptor{
		Number:  number,
		Target:  target,
		Deleted: deleted,
	}

	switch {
	case strings.HasPrefix(target, targetPrefixSocket):
		descriptor.Kind = model.FileDescriptorKindSocket
		descriptor.SocketInode, _ = parseBracketedInode(target, targetPrefixSocket)
	case strings.HasPrefix(target, targetPrefixPipe):
		descriptor.Kind = model.FileDescriptorKindPipe
	case strings.HasPrefix(target, targetPrefixAnonymous):
		descriptor.Kind = model.FileDescriptorKindAnonymous
	default:
		// A path target. It is a file unless fdinfo says the descriptor was
		// opened with O_DIRECTORY.
		//
		// Stated limitation: a directory opened without that flag — and a
		// descriptor whose fdinfo is missing, denied or unparsable — is
		// reported as a file. The alternative is to stat the target, which
		// AD-3 forbids. FileDescriptorKindCharacter and
		// FileDescriptorKindUnknown are likewise never produced here: no
		// signal available without stating the target distinguishes them.
		descriptor.Kind = model.FileDescriptorKindFile
		if flags, ok := r.fdinfoFlags(pid, name); ok && flags&oDirectory != 0 {
			descriptor.Kind = model.FileDescriptorKindDirectory
		}
	}
	return descriptor
}

// parseBracketedInode extracts N from a "prefix[N]" pseudo-target.
//
// A target that carries the prefix but no parsable inode — a shape the
// kernel does not emit, but which a malformed fixture or a future format
// could — yields no inode rather than a fabricated zero-as-fact, and the
// caller keeps the descriptor with its raw target intact.
func parseBracketedInode(target, prefix string) (uint64, bool) {
	digits, ok := strings.CutPrefix(target, prefix)
	if !ok {
		return 0, false
	}
	digits, ok = strings.CutSuffix(digits, "]")
	if !ok {
		return 0, false
	}
	inode, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, false
	}
	return inode, true
}

// fdinfoFlags reads the flags: line of /proc/<pid>/fdinfo/<n>.
//
// It reports whether the line was present AND parsable, in the same guarded
// shape as statusFile.LookupUint: a present-but-malformed value is reported
// as missing rather than as zero, so a caller can never read a malformed
// field as a set or cleared bit. An unreadable fdinfo is not an observation
// gap the section reports — the descriptor itself was observed, only the
// file/directory refinement was unavailable — so no availability is returned.
func (r *Reader) fdinfoFlags(pid int, name string) (uint64, bool) {
	data, availability := r.read(pid, filepath.Join(interfaceFDInfo, name), model.AvailabilityUnsupported)
	if availability != model.AvailabilityObserved {
		return 0, false
	}
	return parseFDInfoFlags(data)
}

// parseFDInfoFlags finds the flags: key and parses its octal value.
//
// The kernel writes it as octal without a leading 0o, e.g. "flags:\t02100000",
// so the base is fixed at 8 rather than inferred.
func parseFDInfoFlags(data []byte) (uint64, bool) {
	for line := range strings.SplitSeq(string(data), "\n") {
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		if strings.TrimSpace(line[:colon]) != "flags" {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) == 0 {
			return 0, false
		}
		flags, err := strconv.ParseUint(fields[0], 8, 64)
		if err != nil {
			return 0, false
		}
		return flags, true
	}
	return 0, false
}
