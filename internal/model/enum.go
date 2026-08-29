package model

// Availability records why a piece of observed state is or is not present.
//
// It is the project's answer to partial failure: every observer returns a
// value paired with an Availability, and Availability is carried per section
// of a [Snapshot] rather than once for the whole snapshot, so an empty list
// is always distinguishable from an unreadable one (AD-4). An unreadable
// field is never rendered, scored or reasoned about as a safe value.
type Availability string

// The closed set of Availability values. No other value is legal.
const (
	// AvailabilityObserved means the value was read successfully.
	AvailabilityObserved Availability = "observed"
	// AvailabilityDenied means the read failed on permissions (EACCES,
	// EPERM, hidepid). The value exists; this user may not read it.
	AvailabilityDenied Availability = "denied"
	// AvailabilityUnsupported means the kernel or configuration does not
	// provide this interface at all — an absent LSM, a kernel built
	// without the required option.
	AvailabilityUnsupported Availability = "unsupported"
	// AvailabilityAbsent means the interface exists but holds nothing for
	// this process — an empty cmdline on a kernel thread, for instance.
	AvailabilityAbsent Availability = "absent"
	// AvailabilityRaced means the process changed underneath the read: it
	// exited, exec'd, or closed the descriptor mid-inspection.
	AvailabilityRaced Availability = "raced"
)

// Valid reports whether a is one of the five legal Availability values.
func (a Availability) Valid() bool {
	switch a {
	case AvailabilityObserved,
		AvailabilityDenied,
		AvailabilityUnsupported,
		AvailabilityAbsent,
		AvailabilityRaced:
		return true
	default:
		return false
	}
}

// Severity is the closed severity scale a [Finding] is emitted at (AD-11).
type Severity string

// The closed set of Severity values. No other value is legal.
const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
)

// Valid reports whether s is one of the three legal Severity values.
func (s Severity) Valid() bool {
	switch s {
	case SeverityHigh, SeverityMedium, SeverityLow:
		return true
	default:
		return false
	}
}

// Rank returns a sort key ordering severities from most to least severe, so
// findings can be sorted by (severity desc, rule_id asc) without a map
// lookup on an output path (AD-6). An invalid severity ranks last.
func (s Severity) Rank() int {
	switch s {
	case SeverityHigh:
		return 0
	case SeverityMedium:
		return 1
	case SeverityLow:
		return 2
	default:
		return 3
	}
}

// Confidence is the closed confidence scale a [Finding] is emitted at.
//
// Confidence is reduced — never suppressed — when a finding draws on a
// section whose [Availability] is not observed (AD-4).
type Confidence string

// The closed set of Confidence values. No other value is legal.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Valid reports whether c is one of the three legal Confidence values.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	default:
		return false
	}
}

// Reduce returns the next confidence level down, used when evidence rests on
// a section that was not observed (AD-4). Low is the floor.
func (c Confidence) Reduce() Confidence {
	switch c {
	case ConfidenceHigh:
		return ConfidenceMedium
	case ConfidenceMedium:
		return ConfidenceLow
	default:
		return ConfidenceLow
	}
}
