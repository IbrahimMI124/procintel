package procfs

import (
	"sort"
	"strconv"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// Lineage bounds. Descendant collection stops silently on reaching either one
// (AD-4 reserves Availability for read failures, and a deliberate cap is not
// one): the section keeps whatever the reads earned.
const (
	// maxAncestorDepth caps the parent walk. A live PPID chain reaches PID 1
	// in well under this many steps; the cap only ever bites on a fixture or
	// a kernel that has produced a chain no sane process tree contains.
	maxAncestorDepth = 64
	// maxDescendantDepth is the deepest level buildDescendants records: a ref
	// at this depth is kept, its children are not explored.
	maxDescendantDepth = 32
	// maxDescendantRefs caps the flat descendant list.
	maxDescendantRefs = 4096
)

// lineageEntry is one process seen by the proc-root scan, reduced to the four
// fields a ProcessRef needs. It is the pure input buildDescendants works over,
// so the BFS is exercisable without a fixture tree.
type lineageEntry struct {
	PID       int
	PPID      int
	Comm      string
	StartTime uint64
}

// lineage observes the target's ancestors and descendants and folds both
// halves into the single Children availability (AD-16).
//
// Ancestors walk the PPID chain from the target toward PID 1, nearest first,
// each ancestor's exe readlink resolved. Descendants come from a single scan
// of the proc root — every numeric directory stat'd once for (pid, ppid,
// comm, starttime) — then a depth-tagged BFS from the target.
//
// The availability split is asymmetric (Design Notes). A broken ancestor
// chain is a specific gap in a claim about the target, so it lowers the
// section. An unreadable unrelated process is not a claim about the target,
// so it is dropped from the tree with no penalty — exactly as
// combineFDCandidates drops a vanished fd. Only failure to enumerate the proc
// root at all lowers the section from the descendant side.
func (r *Reader) lineage(pid int, self statFields, selfStatus model.Availability) (ancestors, descendants []model.ProcessRef, availability model.Availability) {
	// Without the target's own stat there is no PPID to walk from and no
	// identity to exclude from the scan, so the section can be no better
	// than that read (I/O matrix: "Target stat unobserved").
	if selfStatus != model.AvailabilityObserved {
		return nil, nil, selfStatus
	}

	observed := make(map[int]statFields)
	next := func(ancestorPID int) (statFields, model.Availability) {
		fields, status := r.stat(ancestorPID)
		if status == model.AvailabilityObserved {
			observed[ancestorPID] = fields
		}
		return fields, status
	}

	ancestorPIDs, walkStatus := walkAncestors(self.PPID, next)
	for _, ancestorPID := range ancestorPIDs {
		fields := observed[ancestorPID]
		ref := model.ProcessRef{
			PID:       fields.PID,
			PPID:      fields.PPID,
			Comm:      fields.Comm,
			StartTime: fields.StartTime,
		}
		if fields.PID == 1 {
			// The topmost process reached: its parent is reported as 0
			// regardless of what field 4 of its stat holds.
			ref.PPID = 0
		}
		if exe, exeStatus := r.readlink(ancestorPID, interfaceExe); exeStatus == model.AvailabilityObserved {
			ref.Executable = exe
		}
		ancestors = append(ancestors, ref)
	}

	names, rootStatus := r.readProcRoot()
	entries := make([]lineageEntry, 0, len(names))
	for _, name := range names {
		otherPID, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		fields, status := r.stat(otherPID)
		if status != model.AvailabilityObserved {
			// Per-entry tolerance: an unrelated process this user cannot
			// read is omitted from the tree with no penalty to the section
			// (I/O matrix: "Unrelated process unreadable").
			continue
		}
		entries = append(entries, lineageEntry{
			PID:       fields.PID,
			PPID:      fields.PPID,
			Comm:      fields.Comm,
			StartTime: fields.StartTime,
		})
	}
	descendants = buildDescendants(pid, entries)

	return ancestors, descendants, weakest(selfStatus, walkStatus, rootStatus)
}

// walkAncestors follows the PPID chain from startPPID toward PID 1, nearest
// first, and returns the PID at each step.
//
// next reads one PID's stat; it is a parameter so the walk's termination
// rules — a visited-set breaking a PPID cycle, a hard depth cap, PID 1
// ending the climb, and a raced/denied read stopping it — are testable with
// synthetic inputs.
//
// A read that is not observed stops the walk at the last readable ancestor
// and returns that read's availability: a parent named in the chain that has
// gone away raced under the inspection, and the section must confess the
// broken chain rather than present a truncated lineage as complete.
func walkAncestors(startPPID int, next func(pid int) (statFields, model.Availability)) ([]int, model.Availability) {
	visited := make(map[int]bool)
	var chain []int

	current := startPPID
	for depth := 0; depth < maxAncestorDepth; depth++ {
		if current <= 0 {
			// PID 1's parent is 0, or the target was itself PID 1 and
			// startPPID is 0: a complete walk with nothing above it.
			return chain, model.AvailabilityObserved
		}
		if visited[current] {
			// A PPID cycle. Terminate this branch; what was collected
			// before the repeat stands (I/O matrix: "PPID cycle").
			return chain, model.AvailabilityObserved
		}
		visited[current] = true

		fields, status := next(current)
		if status != model.AvailabilityObserved {
			return chain, status
		}
		chain = append(chain, current)
		if current == 1 {
			return chain, model.AvailabilityObserved
		}
		current = fields.PPID
	}
	return chain, model.AvailabilityObserved
}

// buildDescendants runs a depth-tagged BFS from target over the adjacency the
// proc-root scan produced, returning a flat list sorted (Depth asc, PID asc)
// (AD-6).
//
// It is pure: the cycle guard, the depth and count caps, and the ordering are
// all exercisable with synthetic entries, independent of any fixture.
// Collection stops silently at maxDescendantDepth or maxDescendantRefs — a
// cap is a deliberate bound, not a read gap.
func buildDescendants(target int, entries []lineageEntry) []model.ProcessRef {
	// Adjacency is built from a PID-sorted copy so the BFS visits children
	// in ascending PID order at every level and never depends on the scan's
	// readdir order or on map iteration (AD-6).
	sorted := append([]lineageEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PID < sorted[j].PID })

	childrenOf := make(map[int][]lineageEntry)
	for _, entry := range sorted {
		childrenOf[entry.PPID] = append(childrenOf[entry.PPID], entry)
	}

	type queued struct {
		entry lineageEntry
		depth int
	}
	visited := map[int]bool{target: true}
	var queue []queued
	enqueueChildren := func(parent, depth int) {
		if depth > maxDescendantDepth {
			return
		}
		for _, child := range childrenOf[parent] {
			if visited[child.PID] {
				continue
			}
			visited[child.PID] = true
			queue = append(queue, queued{entry: child, depth: depth})
		}
	}

	var refs []model.ProcessRef
	enqueueChildren(target, 1)
	for len(queue) > 0 {
		if len(refs) >= maxDescendantRefs {
			break
		}
		item := queue[0]
		queue = queue[1:]
		refs = append(refs, model.ProcessRef{
			PID:       item.entry.PID,
			PPID:      item.entry.PPID,
			Comm:      item.entry.Comm,
			StartTime: item.entry.StartTime,
			Depth:     item.depth,
		})
		enqueueChildren(item.entry.PID, item.depth+1)
	}

	if len(refs) == 0 {
		return nil
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Depth != refs[j].Depth {
			return refs[i].Depth < refs[j].Depth
		}
		return refs[i].PID < refs[j].PID
	})
	return refs
}
