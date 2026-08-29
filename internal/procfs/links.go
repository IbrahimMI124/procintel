package procfs

import "github.com/IbrahimMI124/procintel/internal/model"

// processLinks are the three per-process symlinks this block resolves, each
// with the availability of its own readlink.
//
// They are separate availabilities rather than one because they fail
// independently: a kernel thread has no exe but does have a cwd, and an
// unprivileged reader is denied all three on another user's process.
type processLinks struct {
	Executable       string
	ExecutableStatus model.Availability

	WorkingDirectory       string
	WorkingDirectoryStatus model.Availability

	RootDirectory       string
	RootDirectoryStatus model.Availability
}

// links resolves /proc/<pid>/{exe,cwd,root}.
//
// Only the link is read. The target is never Stat'd or opened: doing so would
// resolve a path outside the Reader's root, which would both break fixture
// isolation (AD-3) and, on a live /proc, follow a path the inspected process
// controls. A dangling target — a deleted executable, a fixture symlink
// pointing at a path that does not exist here — is returned verbatim, which
// is exactly the value a later block needs to flag a deleted binary.
func (r *Reader) links(pid int) processLinks {
	var resolved processLinks
	resolved.Executable, resolved.ExecutableStatus = r.readlink(pid, interfaceExe)
	resolved.WorkingDirectory, resolved.WorkingDirectoryStatus = r.readlink(pid, interfaceCwd)
	resolved.RootDirectory, resolved.RootDirectoryStatus = r.readlink(pid, interfaceRoot)
	return resolved
}

// availabilities returns the three link statuses for section combination.
func (p processLinks) availabilities() []model.Availability {
	return []model.Availability{
		p.ExecutableStatus,
		p.WorkingDirectoryStatus,
		p.RootDirectoryStatus,
	}
}
