package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// Text writes r as a human-readable report: the three AD-5 blocks FACTS,
// SIGNALS and ASSESSMENT, always separate, never merged.
//
// Every FACTS sub-section is gated on its own section Availability: one that
// is not observed prints its status and nothing else, so an unreadable
// section is never dressed up as observed fact (AD-4). All unit conversion
// and colour live here (AD-12); slice order is taken as given and never
// re-sorted (AD-6). color == false emits no escape bytes at all; color ==
// true adds SGR sequences only around block headers and availability words,
// so stripping \x1b[...m from the coloured output yields the plain output.
func Text(w io.Writer, r model.Report, color bool) error {
	var b strings.Builder

	fmt.Fprintf(&b, "PID %d  %s  [%s]\n", r.Facts.PID, r.Facts.Comm, r.Facts.State)

	b.WriteString("\n")
	b.WriteString(sgr(sgrBold, "FACTS", color))
	b.WriteString("\n\n")
	writeFacts(&b, r.Facts, color)

	b.WriteString("\n")
	b.WriteString(sgr(sgrBold, "SIGNALS", color))
	b.WriteString("\n\n")
	if len(r.Behaviors) == 0 && len(r.Signals) == 0 {
		b.WriteString("  (none)\n")
	}

	b.WriteString("\n")
	b.WriteString(sgr(sgrBold, "ASSESSMENT", color))
	b.WriteString("\n\n")
	if r.Assessment.Summary == "" {
		b.WriteString("  (none)\n")
	}

	_, err := w.Write([]byte(b.String()))
	return err
}

// writeFacts renders the seven Snapshot sections in SectionAvailability field
// order. A section that is not observed contributes only its header line.
//
// Each section is one named writer so the same section can be rendered on its
// own by a filtered view (views.go) without duplicating its body.
func writeFacts(b *strings.Builder, s model.Snapshot, color bool) {
	writeIdentitySection(b, s, color)
	writeResourcesSection(b, s, color)
	writeFilesSection(b, s, color)
	writeSocketsSection(b, s, color)
	writeChildrenSection(b, s, color)
	writeSecuritySection(b, s, color)
	writeKernelSection(b, s, color)
}

func writeIdentitySection(b *strings.Builder, s model.Snapshot, color bool) {
	section(b, "identity", s.Availability.Identity, color, func() {
		field(b, "pid", fmt.Sprintf("%d", s.PID))
		field(b, "ppid", fmt.Sprintf("%d", s.PPID))
		field(b, "comm", s.Comm)
		field(b, "command", strings.Join(s.CommandLine, " "))
		field(b, "executable", s.Executable)
		field(b, "cwd", s.WorkingDirectory)
		field(b, "root", s.RootDirectory)
		field(b, "state", s.State)
		field(b, "start_time", fmt.Sprintf("%d", s.StartTime))
	})
}

func writeResourcesSection(b *strings.Builder, s model.Snapshot, color bool) {
	section(b, "resources", s.Availability.Resources, color, func() {
		field(b, "cpu_time", fmt.Sprintf("%s user  %s system",
			ticksToSeconds(s.UserTime), ticksToSeconds(s.SystemTime)))
		field(b, "memory", fmt.Sprintf("%s resident  %s virtual",
			humanBytes(s.ResidentBytes), humanBytes(s.VirtualBytes)))
		field(b, "threads", fmt.Sprintf("%d", s.ThreadCount))
		field(b, "priority", fmt.Sprintf("%d  nice %d", s.Priority, s.Nice))
		field(b, "io", fmt.Sprintf("%s read  %s written",
			humanBytes(s.ReadBytes), humanBytes(s.WriteBytes)))
	})
}

func writeFilesSection(b *strings.Builder, s model.Snapshot, color bool) {
	section(b, "files", s.Availability.Files, color, func() {
		if len(s.FileDescriptors) == 0 {
			field(b, "", "(none)")
			return
		}
		fmt.Fprintf(b, "    %-4s %-16s %s\n", "FD", "TYPE", "TARGET")
		for _, fd := range s.FileDescriptors {
			target := fd.Target
			if fd.Deleted {
				target += " (deleted)"
			}
			fmt.Fprintf(b, "    %-4d %-16s %s\n", fd.Number, fd.Kind, target)
		}
	})
}

func writeSocketsSection(b *strings.Builder, s model.Snapshot, color bool) {
	section(b, "sockets", s.Availability.Sockets, color, func() {
		if len(s.Sockets) == 0 {
			field(b, "", "(none)")
			return
		}
		fmt.Fprintf(b, "    %-6s %-22s %-22s %s\n", "PROTO", "LOCAL", "REMOTE", "STATE")
		for _, sock := range s.Sockets {
			fmt.Fprintf(b, "    %-6s %-22s %-22s %s\n",
				sock.Protocol, socketLocal(sock), socketRemote(sock), sock.State)
		}
	})
}

func writeChildrenSection(b *strings.Builder, s model.Snapshot, color bool) {
	section(b, "children", s.Availability.Children, color, func() {
		field(b, "ancestors", refsInline(s.Ancestors))
		if len(s.Descendants) == 0 {
			field(b, "descendants", "(none)")
			return
		}
		field(b, "descendants", "")
		for _, ref := range s.Descendants {
			fmt.Fprintf(b, "      %s (%d) depth %d\n", ref.Comm, ref.PID, ref.Depth)
		}
	})
}

func writeSecuritySection(b *strings.Builder, s model.Snapshot, color bool) {
	section(b, "security", s.Availability.Security, color, func() {
		field(b, "uid", fmt.Sprintf("%d  euid %d", s.Security.UID, s.Security.EffectiveUID))
		field(b, "gid", fmt.Sprintf("%d  egid %d", s.Security.GID, s.Security.EffectiveGID))
		field(b, "capabilities", s.Security.CapabilityEffective)
		field(b, "no_new_privs", fmt.Sprintf("%t", s.Security.NoNewPrivileges))
		field(b, "seccomp", fmt.Sprintf("%d", s.Security.SeccompMode))
		field(b, "namespaces", namespacesInline(s.Security.Namespaces))
		field(b, "cgroup", s.Security.CgroupPath)
		field(b, "label", s.Security.SecurityLabel)
	})
}

func writeKernelSection(b *strings.Builder, s model.Snapshot, color bool) {
	section(b, "kernel", s.Availability.Kernel, color, func() {
		field(b, "oom_score", fmt.Sprintf("%d", s.OOMScore))
	})
}

// section writes one FACTS sub-section header with its availability, and runs
// body only when the section was observed.
func section(b *strings.Builder, name string, a model.Availability, color bool, body func()) {
	fmt.Fprintf(b, "  %-10s %s\n", name, sgr(availabilityColor(a), availabilityLabel(a), color))
	if a == model.AvailabilityObserved {
		body()
	}
}

// field writes one indented "key   value" line. An empty key indents the
// value alone (a "(none)" placeholder or a list heading); an empty value
// prints the key alone with no trailing space.
func field(b *strings.Builder, key, value string) {
	switch {
	case key == "":
		fmt.Fprintf(b, "    %s\n", value)
	case value == "":
		fmt.Fprintf(b, "    %s\n", key)
	default:
		fmt.Fprintf(b, "    %-14s %s\n", key, value)
	}
}

func refsInline(refs []model.ProcessRef) string {
	if len(refs) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(refs))
	for _, ref := range refs {
		parts = append(parts, fmt.Sprintf("%s (%d)", ref.Comm, ref.PID))
	}
	return strings.Join(parts, "  ")
}

func namespacesInline(ns []model.Namespace) string {
	if len(ns) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(ns))
	for _, n := range ns {
		parts = append(parts, n.Identifier)
	}
	return strings.Join(parts, "  ")
}

func socketLocal(s model.Socket) string {
	if s.Path != "" {
		return s.Path
	}
	return fmt.Sprintf("%s:%d", s.LocalAddress, s.LocalPort)
}

func socketRemote(s model.Socket) string {
	if s.Path != "" {
		return "-"
	}
	return fmt.Sprintf("%s:%d", s.RemoteAddress, s.RemotePort)
}

func availabilityLabel(a model.Availability) string {
	if a == "" {
		return "not observed"
	}
	return string(a)
}
