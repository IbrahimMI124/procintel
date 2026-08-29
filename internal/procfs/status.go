package procfs

import (
	"strconv"
	"strings"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// statusEntry is one "Key:\tvalue" line of /proc/<pid>/status.
//
// The file is kept as an ordered slice rather than a map: no map may be
// iterated on an output path (AD-6), and preserving kernel order keeps a
// dump of the parsed file diffable against the original.
type statusEntry struct {
	Key   string
	Value string
}

// statusFile is a parsed /proc/<pid>/status.
//
// It is deliberately generic. Block 1e reads the security fields — Uid, Gid,
// CapEff, NoNewPrivs, Seccomp — out of this same value, so this reader must
// not be specialised to the fields Block 1a happens to want.
type statusFile []statusEntry

// Lookup returns the value of the first entry with the given key.
//
// Keys are matched case-sensitively, as the kernel spells them. A key that
// appears twice — which the kernel does not currently do, but is not
// forbidden from doing — resolves to its first occurrence.
func (s statusFile) Lookup(key string) (string, bool) {
	for _, entry := range s {
		if entry.Key == key {
			return entry.Value, true
		}
	}
	return "", false
}

// LookupUint returns a key's value parsed as an unsigned decimal, reporting
// whether the key was present AND parsable. A present-but-unparsable key is
// reported as missing rather than as zero, so a caller can never read a
// malformed field as a value.
func (s statusFile) LookupUint(key string) (uint64, bool) {
	text, found := s.Lookup(key)
	if !found {
		return 0, false
	}
	// A key with a blank value — real /proc emits several, such as
	// Groups: for a process with no supplementary groups — leaves Fields
	// empty, so the first field cannot be indexed unguarded.
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return 0, false
	}
	value, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// status reads and parses /proc/<pid>/status.
//
// Unlike stat, this file is a set of independent lines: one unrecognisable
// line says nothing about the rest, so parsing is tolerant and drops only
// what it cannot split. A file with no parsable line at all is absent.
func (r *Reader) status(pid int) (statusFile, model.Availability) {
	data, availability := r.read(pid, interfaceStatus, model.AvailabilityUnsupported)
	if availability != model.AvailabilityObserved {
		return nil, availability
	}
	parsed := parseStatus(data)
	if len(parsed) == 0 {
		return nil, model.AvailabilityAbsent
	}
	return parsed, model.AvailabilityObserved
}

// parseStatus splits the file into ordered key/value entries.
//
// Values keep their internal whitespace — "Uid:\t1000\t1000\t1000\t1000" is
// four fields the caller splits for itself — but lose the leading tab the
// kernel writes after the colon.
func parseStatus(data []byte) statusFile {
	lines := strings.Split(string(data), "\n")
	parsed := make(statusFile, 0, len(lines))
	for _, line := range lines {
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		if key == "" {
			continue
		}
		parsed = append(parsed, statusEntry{
			Key:   key,
			Value: strings.TrimSpace(line[colon+1:]),
		})
	}
	if len(parsed) == 0 {
		return nil
	}
	return parsed
}
