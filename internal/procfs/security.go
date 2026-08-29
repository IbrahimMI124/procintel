package procfs

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// security assembles the process's privilege and confinement state from four
// sources: /proc/<pid>/status (uid/gid/caps/no-new-privs/seccomp — reusing the
// statusFile already read in Snapshot), a fixed set of /proc/<pid>/ns/<kind>
// readlinks, /proc/<pid>/cgroup (the cgroup-v2 unified line) and
// /proc/<pid>/attr/current (the LSM label).
//
// Every field resolves through the section Availability, never a default
// (AD-4): a field left at its zero value is not a security claim — the
// Availability carries that.
//
// The section folds its sources through weakest with two deliberate per-source
// tolerances (Design Notes). A namespace kind the kernel does not have
// (ns/time ENOENT -> absent) is the process genuinely having no such
// namespace, so it is skipped rather than folded. A missing attr/current (no
// label-based LSM, routine on containers and minimal distros) is skipped too,
// so uid / caps / seccomp / ns / cgroup stay usable by Block 5. A denied read
// of either — the node is present and we were refused — still folds in.
func (r *Reader) security(pid int, status statusFile, statusStatus model.Availability) (model.SecurityContext, model.Availability) {
	var context model.SecurityContext

	// uid/gid/caps/seccomp/no-new-privs come out of the status already read
	// for the resources section. A key absent from an otherwise-observed
	// status leaves its field at the zero value — the supported-kernel floor
	// (spine: Linux 4.x+) guarantees these keys exist, and the section
	// Availability is the honesty signal, not the field.
	if statusStatus == model.AvailabilityObserved {
		if value, ok := status.Lookup("Uid"); ok {
			if id, effective, ok := parseUIDLine(value); ok {
				context.UID = id
				context.EffectiveUID = effective
			}
		}
		if value, ok := status.Lookup("Gid"); ok {
			if id, effective, ok := parseUIDLine(value); ok {
				context.GID = id
				context.EffectiveGID = effective
			}
		}
		if value, ok := status.Lookup("CapEff"); ok {
			// The raw CapEff mask, verbatim: no 0x, unexpanded. A renderer
			// decodes it to capability names.
			context.CapabilityEffective = value
		}
		if value, ok := status.LookupUint("NoNewPrivs"); ok {
			context.NoNewPrivileges = value == 1
		}
		if value, ok := status.LookupUint("Seccomp"); ok {
			context.SeccompMode = int(value)
		}
	}

	// Namespaces: a fixed, alphabetically ordered set of ns/<kind> readlinks,
	// never a directory listing, so the slice is deterministic without a sort
	// (AD-6). Only a denied or raced outcome folds into the section; an absent
	// link (the kernel lacks this namespace kind) is skipped.
	var nsSources []model.Availability
	for _, kind := range namespaceKinds {
		target, availability := r.readlink(pid, filepath.Join(interfaceNS, kind))
		if availability == model.AvailabilityObserved {
			context.Namespaces = append(context.Namespaces, model.Namespace{
				Kind:       kind,
				Identifier: target,
			})
			continue
		}
		if availability == model.AvailabilityDenied || availability == model.AvailabilityRaced {
			nsSources = append(nsSources, availability)
		}
	}

	// Cgroup: the cgroup-v2 unified line only. No such line — a v1-only host —
	// leaves CgroupPath empty with the section still observed. The read
	// availability folds in unconditionally.
	cgroupData, cgroupStatus := r.read(pid, interfaceCgroup, model.AvailabilityUnsupported)
	if cgroupStatus == model.AvailabilityObserved {
		context.CgroupPath = parseUnifiedCgroup(cgroupData)
	}

	// LSM label: attr/current trimmed of trailing NUL / newline / space.
	// Present-but-empty (a kernel thread, "unconfined") is kept as read. A
	// missing attr/current (unsupported) is skipped, not folded.
	labelData, labelStatus := r.read(pid, interfaceAttrCurrent, model.AvailabilityUnsupported)
	if labelStatus == model.AvailabilityObserved {
		context.SecurityLabel = strings.TrimRight(string(labelData), "\x00\n ")
	}

	sources := []model.Availability{statusStatus, cgroupStatus}
	sources = append(sources, nsSources...)
	if labelStatus != model.AvailabilityUnsupported {
		sources = append(sources, labelStatus)
	}
	return context, weakest(sources...)
}

// parseUIDLine splits a status Uid:/Gid: value into its real and effective
// ids. The kernel layout is "real effective saved fs", tab-separated, so the
// effective id is field 2 (index 1) — which is what a setuid binary that has
// not dropped privilege shows differing from field 1.
//
// A value with fewer than two fields, or a non-numeric one, yields ok=false
// and leaves both ids at zero: a malformed field is never read as a value.
func parseUIDLine(value string) (id, effective int, ok bool) {
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return 0, 0, false
	}
	real, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, 0, false
	}
	eff, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, false
	}
	return real, eff, true
}

// parseUnifiedCgroup returns the path of the cgroup-v2 unified line: the line
// whose first ':'-field is "0" and whose second is empty ("0::/some/path").
// A host with only v1 controllers has no such line and yields "".
//
// The path itself may contain ':', so the split keeps three fields at most and
// the remainder is the path verbatim.
func parseUnifiedCgroup(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			return parts[2]
		}
	}
	return ""
}
