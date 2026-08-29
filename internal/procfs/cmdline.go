package procfs

import (
	"strings"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// cmdline reads /proc/<pid>/cmdline as the argument vector.
//
// The kernel writes the arguments NUL-separated with a trailing NUL, so a
// naive split leaves an empty final element. An empty file is the normal
// state of a kernel thread and of a zombie, and is reported as absent rather
// than as an observed empty vector: "this process has no command line" and
// "this process's command line could not be read" must stay distinguishable
// (AD-4).
func (r *Reader) cmdline(pid int) ([]string, model.Availability) {
	data, availability := r.read(pid, interfaceCmdline, model.AvailabilityUnsupported)
	if availability != model.AvailabilityObserved {
		return nil, availability
	}
	arguments := splitNUL(data)
	if len(arguments) == 0 {
		return nil, model.AvailabilityAbsent
	}
	return arguments, model.AvailabilityObserved
}

// splitNUL splits the kernel's NUL-separated argument vector.
//
// Only the element after the kernel's trailing NUL is discarded. An interior
// empty element is a real argument — execve permits an empty string, and a
// shell passes one for an empty -c operand — so filtering every empty element
// would silently shift each later index and misreport the command line.
func splitNUL(data []byte) []string {
	body := strings.TrimSuffix(string(data), "\x00")
	if body == "" {
		return nil
	}
	return strings.Split(body, "\x00")
}

// comm reads /proc/<pid>/comm, the kernel's short name for the process.
//
// It is at most 15 bytes and is not the executable path: a process that
// exec'd /usr/bin/python3 shows "python3", and one that set its own name
// shows whatever it set. The trailing newline the kernel appends is stripped.
func (r *Reader) comm(pid int) (string, model.Availability) {
	data, availability := r.read(pid, interfaceComm, model.AvailabilityUnsupported)
	if availability != model.AvailabilityObserved {
		return "", availability
	}
	name := strings.TrimRight(string(data), "\n")
	if name == "" {
		return "", model.AvailabilityAbsent
	}
	return name, model.AvailabilityObserved
}
