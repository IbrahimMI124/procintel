package model

import (
	"strings"
	"time"
)

// EventType names a change the differ found between two snapshots.
//
// Identifiers are SCREAMING_SNAKE_CASE, stable, and drawn from the diff
// event catalogue. They are declared here because both the differ that
// produces them and the behavior layer that consumes them must agree on the
// spelling, and neither may import the other (AD-2).
type EventType string

// The diff event catalogue.
const (
	EventFileOpened               EventType = "FILE_OPENED"
	EventFileClosed               EventType = "FILE_CLOSED"
	EventNetworkConnectionCreated EventType = "NETWORK_CONNECTION_CREATED"
	EventNetworkConnectionClosed  EventType = "NETWORK_CONNECTION_CLOSED"
	EventListeningPortAppeared    EventType = "LISTENING_PORT_APPEARED"
	EventChildCreated             EventType = "CHILD_CREATED"
	EventChildExited              EventType = "CHILD_EXITED"
	EventExecutableChanged        EventType = "EXECUTABLE_CHANGED"
	EventWorkingDirectoryChanged  EventType = "CWD_CHANGED"
	EventSensitiveFileAccessed    EventType = "SENSITIVE_FILE_ACCESSED"
	EventCPUSpike                 EventType = "CPU_SPIKE"
	EventMemorySpike              EventType = "MEMORY_SPIKE"
	// EventProcessReplaced is the single event emitted when two snapshots
	// share a PID but not a start time — a recycled PID, not a diff
	// (AD-7).
	EventProcessReplaced EventType = "PROCESS_REPLACED"
)

// Event is one change between two snapshots.
//
// Events are produced only by the diff layer and, additively and optionally,
// by the severable trace arm (AD-14). They sort by (timestamp, event_type,
// subject) for deterministic output (AD-6).
type Event struct {
	Type EventType `json:"event_type"`
	// Timestamp is the CapturedAt of the later of the two snapshots, in
	// UTC.
	Timestamp time.Time `json:"timestamp"`
	PID       int       `json:"pid"`
	// Subject is what the event is about: a path, an address:port, a
	// child PID. It is part of the sort key, so it is always set.
	Subject string `json:"subject"`
	// PreviousValue and CurrentValue carry the two sides of a change
	// event, and are empty for pure appearance or disappearance events.
	PreviousValue string `json:"previous_value"`
	CurrentValue  string `json:"current_value"`
	// Availability is the status of the snapshot section this event was
	// derived from. An event from a section that was not observed may not
	// feed a rule at full confidence (AD-4).
	Availability Availability `json:"availability"`
}

// BehaviorKind is the coarse taxonomy an individual behavior belongs to.
type BehaviorKind string

// The behavior taxonomy that raw observations are lifted into.
const (
	BehaviorKindFileRead              BehaviorKind = "FILE_READ_ACTIVITY"
	BehaviorKindFileWrite             BehaviorKind = "FILE_WRITE_ACTIVITY"
	BehaviorKindNetwork               BehaviorKind = "NETWORK_ACTIVITY"
	BehaviorKindProcessCreation       BehaviorKind = "PROCESS_CREATION"
	BehaviorKindExecution             BehaviorKind = "EXECUTION_ACTIVITY"
	BehaviorKindPrivilege             BehaviorKind = "PRIVILEGE_ACTIVITY"
	BehaviorKindSensitiveFile         BehaviorKind = "SENSITIVE_FILE_ACTIVITY"
	BehaviorKindTemporaryDirectoryRun BehaviorKind = "TEMPORARY_DIRECTORY_EXECUTION"
)

// Behavior is a named, interpreted pattern lifted from events and snapshot
// state.
//
// Rules read behaviors and snapshot state, never raw events; no rule may
// skip this layer (AD-11). Behaviors are inference, not fact, and are
// rendered under SIGNALS rather than FACTS (AD-5).
type Behavior struct {
	// Name is the lowercase hyphenated behavior name, e.g.
	// "sensitive-file-access", "outbound-network", "shell-spawn".
	Name string       `json:"name"`
	Kind BehaviorKind `json:"kind"`
	// Evidence is the concrete observations this behavior was lifted
	// from, in the order they were found. Never empty.
	Evidence []string `json:"evidence"`
	// Availability is the weakest availability among the sections this
	// behavior rests on, which caps the confidence of any finding built
	// on it (AD-4).
	Availability Availability `json:"availability"`
}

// Finding is one security signal, with everything needed to justify it.
//
// All five fields are mandatory and none may be empty: a finding that cannot
// be explained is a correctness failure, not a cosmetic one (AD-11). Finding
// language never asserts identity — "exhibits behavior associated with", not
// "is malware".
type Finding struct {
	// RuleID is the SCREAMING_SNAKE_CASE identifier of the rule that
	// produced this finding, e.g. EXECUTABLE_FROM_TEMP_DIRECTORY.
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	// Evidence is the specific observed facts supporting the finding.
	Evidence []string `json:"evidence"`
	// Reason explains why those facts matter, in plain language.
	Reason     string     `json:"reason"`
	Confidence Confidence `json:"confidence"`
}

// Complete reports whether every one of the five mandatory finding fields is
// populated with a legal value (AD-11).
//
// Blank counts as absent: a whitespace-only reason, or an evidence list
// holding nothing but empty strings, is a finding that cannot be justified,
// which AD-11 classes as a correctness failure rather than a cosmetic one.
func (f Finding) Complete() bool {
	hasEvidence := false
	for _, evidence := range f.Evidence {
		if strings.TrimSpace(evidence) != "" {
			hasEvidence = true
			break
		}
	}
	return strings.TrimSpace(f.RuleID) != "" &&
		f.Severity.Valid() &&
		hasEvidence &&
		strings.TrimSpace(f.Reason) != "" &&
		f.Confidence.Valid()
}

// Assessment is the single correlated judgement over a set of findings.
//
// Single signals are weak; combinations are strong. Exactly one Assessment
// is produced per report, and it is inference throughout — it never appears
// in the same block as observed fact (AD-5).
type Assessment struct {
	// Summary is the human-readable judgement, phrased as behavior
	// observed rather than identity asserted.
	Summary  string   `json:"summary"`
	Severity Severity `json:"severity"`
	// Score is the weighted evidence total. The weights are tuning owned
	// by the correlate package; only the shape is fixed here.
	Score      int        `json:"score"`
	Confidence Confidence `json:"confidence"`
	// ContributingRuleIDs lists the rule identifiers that fed this
	// assessment, in the registry's execution order (AD-6).
	ContributingRuleIDs []string `json:"contributing_rule_ids"`
}

// Report is the one value the renderers consume.
//
// The explain package produces exactly one Report; text, JSON and TUI are
// three renderers over it, never a parallel construction path (AD-12). Its
// three parts are kept structurally separate so that FACTS, SIGNALS and
// ASSESSMENT never blur into one block in any output, JSON included (AD-5).
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`

	// Facts is the observed state — the FACTS block. It holds a Snapshot
	// by value; this is the one place a Snapshot is nested, and a
	// Snapshot still never nests another (AD-16).
	Facts Snapshot `json:"facts"`
	// Changes are the diff events since the previous snapshot, empty for
	// a single-snapshot inspect. They are observed fact, not inference.
	Changes []Event `json:"changes"`

	// Behaviors and Signals together are the SIGNALS block: interpreted
	// behavior and the rule findings drawn from it.
	Behaviors []Behavior `json:"behaviors"`
	Signals   []Finding  `json:"signals"`

	// Assessment is the ASSESSMENT block, and is inference throughout.
	Assessment Assessment `json:"assessment"`
}
