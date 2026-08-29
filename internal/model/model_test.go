package model

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// snakeCase matches the JSON key convention: lowercase words joined by
// single underscores, no leading or trailing underscore, no camelCase.
var snakeCase = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// populatedSnapshot returns a Snapshot with every field set to a
// distinguishable non-zero value, so a dropped or mistyped tag shows up as a
// round-trip inequality rather than passing silently.
func populatedSnapshot() Snapshot {
	return Snapshot{
		SchemaVersion:    SchemaVersion,
		CapturedAt:       time.Date(2026, 8, 29, 12, 34, 56, 0, time.UTC),
		PID:              7312,
		PPID:             1401,
		Comm:             "update",
		CommandLine:      []string{"/tmp/update", "--quiet"},
		Executable:       "/tmp/update",
		WorkingDirectory: "/tmp",
		RootDirectory:    "/",
		State:            "S",
		StartTime:        980412,
		UserTime:         1234,
		SystemTime:       567,
		ResidentBytes:    52 * 1024 * 1024,
		VirtualBytes:     310 * 1024 * 1024,
		ThreadCount:      4,
		Priority:         20,
		Nice:             0,
		ReadBytes:        88123,
		WriteBytes:       4096,
		FileDescriptors: []FileDescriptor{
			{Number: 0, Kind: FileDescriptorKindCharacter, Target: "/dev/pts/2"},
			{Number: 3, Kind: FileDescriptorKindFile, Target: "/etc/passwd"},
			{Number: 4, Kind: FileDescriptorKindSocket, Target: "socket:[884213]", SocketInode: 884213},
			{Number: 5, Kind: FileDescriptorKindFile, Target: "/tmp/payload", Deleted: true},
		},
		Sockets: []Socket{
			{
				Protocol:       "tcp",
				LocalAddress:   "10.0.0.4",
				LocalPort:      51422,
				RemoteAddress:  "185.10.20.30",
				RemotePort:     443,
				State:          "ESTABLISHED",
				Inode:          884213,
				FileDescriptor: 4,
			},
			{
				Protocol:       "unix",
				State:          "LISTEN",
				Path:           "/run/example.sock",
				Inode:          884990,
				FileDescriptor: 6,
			},
		},
		Ancestors: []ProcessRef{
			{PID: 1401, PPID: 1, Comm: "nginx", Executable: "/usr/sbin/nginx", StartTime: 4120},
			{PID: 1, PPID: 0, Comm: "systemd", Executable: "/usr/lib/systemd/systemd", StartTime: 12},
		},
		Descendants: []ProcessRef{
			{PID: 7401, PPID: 7312, Comm: "sh", Executable: "/bin/sh", StartTime: 980500, Depth: 1},
		},
		Security: SecurityContext{
			UID:                 0,
			EffectiveUID:        0,
			GID:                 0,
			EffectiveGID:        0,
			CapabilityEffective: "000001ffffffffff",
			NoNewPrivileges:     false,
			SeccompMode:         0,
			Namespaces: []Namespace{
				{Kind: "mnt", Identifier: "mnt:[4026531840]"},
				{Kind: "net", Identifier: "net:[4026531992]"},
			},
			CgroupPath:    "/system.slice/nginx.service",
			SecurityLabel: "unconfined",
		},
		OOMScore:       17,
		CurrentSyscall: -1,
		Availability: SectionAvailability{
			Identity:  AvailabilityObserved,
			Resources: AvailabilityObserved,
			Files:     AvailabilityObserved,
			Sockets:   AvailabilityObserved,
			Children:  AvailabilityObserved,
			Security:  AvailabilityDenied,
			Kernel:    AvailabilityUnsupported,
		},
	}
}

func populatedReport() Report {
	return Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Date(2026, 8, 29, 12, 35, 0, 0, time.UTC),
		Facts:         populatedSnapshot(),
		Changes: []Event{{
			Type:          EventChildCreated,
			Timestamp:     time.Date(2026, 8, 29, 12, 34, 59, 0, time.UTC),
			PID:           7312,
			Subject:       "/bin/sh",
			PreviousValue: "",
			CurrentValue:  "7401",
			Availability:  AvailabilityObserved,
		}},
		Behaviors: []Behavior{{
			Name:         "shell-spawn",
			Kind:         BehaviorKindProcessCreation,
			Evidence:     []string{"PID 7312 (/tmp/update) spawned /bin/sh"},
			Availability: AvailabilityObserved,
		}},
		Signals: []Finding{{
			RuleID:     "PROCESS_SPAWNED_SHELL",
			Severity:   SeverityHigh,
			Evidence:   []string{"PID 7312 (/tmp/update) spawned /bin/sh"},
			Reason:     "Executables running from temporary directories spawning shells can indicate post-exploitation activity.",
			Confidence: ConfidenceMedium,
		}},
		Assessment: Assessment{
			Summary:             "Exhibits behavior associated with post-exploitation activity.",
			Severity:            SeverityHigh,
			Score:               7,
			Confidence:          ConfidenceMedium,
			ContributingRuleIDs: []string{"EXECUTABLE_FROM_TEMP_DIRECTORY", "PROCESS_SPAWNED_SHELL"},
		},
	}
}

// TestJSONRoundTrip marshals each contract value and unmarshals it back,
// asserting equality. It is the guard on every struct tag in the package.
func TestJSONRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		value any
		into  func() any
	}{
		{"snapshot zero", Snapshot{}, func() any { return new(Snapshot) }},
		{"snapshot populated", populatedSnapshot(), func() any { return new(Snapshot) }},
		{"report zero", Report{}, func() any { return new(Report) }},
		{"report populated", populatedReport(), func() any { return new(Report) }},
		{"process ref", ProcessRef{PID: 2, PPID: 1, Comm: "kthreadd", StartTime: 9, Depth: 3}, func() any { return new(ProcessRef) }},
		{"file descriptor", FileDescriptor{Number: 4, Kind: FileDescriptorKindSocket, Target: "socket:[1]", SocketInode: 1}, func() any { return new(FileDescriptor) }},
		{"socket", Socket{Protocol: "tcp6", LocalAddress: "::1", LocalPort: 8080, State: "LISTEN", Inode: 3, FileDescriptor: 9}, func() any { return new(Socket) }},
		{"security context", populatedSnapshot().Security, func() any { return new(SecurityContext) }},
		{"event", populatedReport().Changes[0], func() any { return new(Event) }},
		{"behavior", populatedReport().Behaviors[0], func() any { return new(Behavior) }},
		{"finding", populatedReport().Signals[0], func() any { return new(Finding) }},
		{"assessment", populatedReport().Assessment, func() any { return new(Assessment) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			target := tt.into()
			if err := json.Unmarshal(encoded, target); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			decoded := reflect.ValueOf(target).Elem().Interface()
			if !reflect.DeepEqual(tt.value, decoded) {
				t.Errorf("round trip changed the value\n before: %#v\n  after: %#v", tt.value, decoded)
			}
		})
	}
}

// TestJSONKeysAreSnakeCase walks every contract struct and asserts that each
// exported field carries an explicit snake_case tag. No key may be left to
// Go's field-name default.
func TestJSONKeysAreSnakeCase(t *testing.T) {
	roots := []any{
		Snapshot{}, Report{}, ProcessRef{}, FileDescriptor{}, Socket{},
		Namespace{}, SecurityContext{}, SectionAvailability{}, Event{},
		Behavior{}, Finding{}, Assessment{},
	}

	seen := map[reflect.Type]bool{}
	var walk func(t *testing.T, typ reflect.Type)
	walk = func(t *testing.T, typ reflect.Type) {
		for typ.Kind() == reflect.Slice || typ.Kind() == reflect.Ptr {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		if typ.PkgPath() != reflect.TypeOf(Snapshot{}).PkgPath() {
			return // time.Time and friends define their own encoding.
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			tag, ok := field.Tag.Lookup("json")
			if !ok {
				t.Errorf("%s.%s has no json tag", typ.Name(), field.Name)
				continue
			}
			key, _, _ := strings.Cut(tag, ",")
			if key == "-" {
				// A field deliberately kept off the wire. It carries
				// no key, so there is no convention to check — but
				// anything it reaches is still on the wire nowhere,
				// so there is nothing to walk either.
				continue
			}
			if !snakeCase.MatchString(key) {
				t.Errorf("%s.%s json key %q is not snake_case", typ.Name(), field.Name, key)
			}
			walk(t, field.Type)
		}
	}

	for _, root := range roots {
		walk(t, reflect.TypeOf(root))
	}
}

// TestSnapshotCarriesSchemaVersionAndNoCPUPercent guards AD-7 and AD-10 on
// the wire, where a later block would notice a violation too late.
func TestSnapshotCarriesSchemaVersionAndNoCPUPercent(t *testing.T) {
	encoded, err := json.Marshal(populatedSnapshot())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	text := string(encoded)
	if !strings.Contains(text, `"schema_version":1`) {
		t.Errorf("serialised snapshot is missing schema_version: %s", text)
	}
	for _, forbidden := range []string{"cpu_percent", "cpu_percentage", "cpu_usage"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("snapshot carries %q; CPU percentage is a diff-layer concept (AD-10)", forbidden)
		}
	}
	if !strings.Contains(text, `"utime":`) || !strings.Contains(text, `"stime":`) {
		t.Errorf("snapshot must carry cumulative utime/stime in ticks: %s", text)
	}
}

// TestSnapshotIsNotRecursive guards AD-16: lineage is flat ProcessRef
// values, and a Snapshot never reaches another Snapshot.
func TestSnapshotIsNotRecursive(t *testing.T) {
	snapshotType := reflect.TypeOf(Snapshot{})
	visited := map[reflect.Type]bool{}

	var reaches func(typ reflect.Type) bool
	reaches = func(typ reflect.Type) bool {
		for typ.Kind() == reflect.Slice || typ.Kind() == reflect.Ptr || typ.Kind() == reflect.Array {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || visited[typ] {
			return false
		}
		visited[typ] = true
		for i := 0; i < typ.NumField(); i++ {
			fieldType := typ.Field(i).Type
			for fieldType.Kind() == reflect.Slice || fieldType.Kind() == reflect.Ptr || fieldType.Kind() == reflect.Array {
				fieldType = fieldType.Elem()
			}
			if fieldType == snapshotType || reaches(fieldType) {
				return true
			}
		}
		return false
	}

	if reaches(snapshotType) {
		t.Error("Snapshot transitively contains another Snapshot; lineage must be flat ProcessRef values (AD-16)")
	}
}

func TestAvailabilityValues(t *testing.T) {
	tests := []struct {
		value Availability
		wire  string
		valid bool
	}{
		{AvailabilityObserved, "observed", true},
		{AvailabilityDenied, "denied", true},
		{AvailabilityUnsupported, "unsupported", true},
		{AvailabilityAbsent, "absent", true},
		{AvailabilityRaced, "raced", true},
		{Availability(""), "", false},
		{Availability("OBSERVED"), "OBSERVED", false},
		{Availability("unknown"), "unknown", false},
	}
	for _, tt := range tests {
		t.Run(tt.wire, func(t *testing.T) {
			if string(tt.value) != tt.wire {
				t.Errorf("wire value = %q, want %q", string(tt.value), tt.wire)
			}
			if got := tt.value.Valid(); got != tt.valid {
				t.Errorf("Valid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestSeverityValues(t *testing.T) {
	tests := []struct {
		value Severity
		wire  string
		valid bool
		rank  int
	}{
		{SeverityHigh, "HIGH", true, 0},
		{SeverityMedium, "MEDIUM", true, 1},
		{SeverityLow, "LOW", true, 2},
		{Severity("high"), "high", false, 3},
		{Severity("CRITICAL"), "CRITICAL", false, 3},
		{Severity(""), "", false, 3},
	}
	for _, tt := range tests {
		t.Run(tt.wire, func(t *testing.T) {
			if string(tt.value) != tt.wire {
				t.Errorf("wire value = %q, want %q", string(tt.value), tt.wire)
			}
			if got := tt.value.Valid(); got != tt.valid {
				t.Errorf("Valid() = %v, want %v", got, tt.valid)
			}
			if got := tt.value.Rank(); got != tt.rank {
				t.Errorf("Rank() = %d, want %d", got, tt.rank)
			}
		})
	}
}

func TestConfidenceValues(t *testing.T) {
	tests := []struct {
		value   Confidence
		wire    string
		valid   bool
		reduced Confidence
	}{
		{ConfidenceHigh, "high", true, ConfidenceMedium},
		{ConfidenceMedium, "medium", true, ConfidenceLow},
		{ConfidenceLow, "low", true, ConfidenceLow},
		{Confidence("HIGH"), "HIGH", false, ConfidenceLow},
		{Confidence(""), "", false, ConfidenceLow},
	}
	for _, tt := range tests {
		t.Run(tt.wire, func(t *testing.T) {
			if string(tt.value) != tt.wire {
				t.Errorf("wire value = %q, want %q", string(tt.value), tt.wire)
			}
			if got := tt.value.Valid(); got != tt.valid {
				t.Errorf("Valid() = %v, want %v", got, tt.valid)
			}
			if got := tt.value.Reduce(); got != tt.reduced {
				t.Errorf("Reduce() = %q, want %q", got, tt.reduced)
			}
		})
	}
}

func TestFindingCompleteRequiresAllFiveFields(t *testing.T) {
	complete := Finding{
		RuleID:     "SENSITIVE_FILE_ACCESS",
		Severity:   SeverityMedium,
		Evidence:   []string{"opened /etc/passwd"},
		Reason:     "Reading credential files is unusual for this process.",
		Confidence: ConfidenceLow,
	}
	if !complete.Complete() {
		t.Fatalf("a fully populated finding must be complete: %#v", complete)
	}
	mixed := complete
	mixed.Evidence = []string{"", "opened /etc/passwd"}
	if !mixed.Complete() {
		t.Errorf("one real evidence entry is enough, even beside a blank one: %#v", mixed)
	}

	missing := func(mutate func(*Finding)) Finding {
		f := complete
		mutate(&f)
		return f
	}
	tests := []struct {
		name    string
		finding Finding
	}{
		{"no rule id", missing(func(f *Finding) { f.RuleID = "" })},
		{"no severity", missing(func(f *Finding) { f.Severity = "" })},
		{"invalid severity", missing(func(f *Finding) { f.Severity = Severity("CRITICAL") })},
		{"blank rule id", missing(func(f *Finding) { f.RuleID = "   " })},
		{"no evidence", missing(func(f *Finding) { f.Evidence = nil })},
		{"empty evidence", missing(func(f *Finding) { f.Evidence = []string{} })},
		{"only empty evidence strings", missing(func(f *Finding) { f.Evidence = []string{""} })},
		{"only blank evidence strings", missing(func(f *Finding) { f.Evidence = []string{"", "  \t "} })},
		{"no reason", missing(func(f *Finding) { f.Reason = "" })},
		{"blank reason", missing(func(f *Finding) { f.Reason = " \t\n " })},
		{"no confidence", missing(func(f *Finding) { f.Confidence = "" })},
		{"invalid confidence", missing(func(f *Finding) { f.Confidence = Confidence("certain") })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.finding.Complete() {
				t.Errorf("finding with %s must not be complete (AD-11)", tt.name)
			}
		})
	}
}

func TestSnapshotComparable(t *testing.T) {
	base := Snapshot{PID: 7312, StartTime: 980412}
	tests := []struct {
		name  string
		other Snapshot
		want  bool
	}{
		{"same pid and start time", Snapshot{PID: 7312, StartTime: 980412}, true},
		{"recycled pid", Snapshot{PID: 7312, StartTime: 991000}, false},
		{"different pid", Snapshot{PID: 7313, StartTime: 980412}, false},
		{"zero value", Snapshot{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := base.Comparable(tt.other); got != tt.want {
				t.Errorf("Comparable() = %v, want %v", got, tt.want)
			}
		})
	}

	// A zero PID is not an identity. Two zero-value snapshots agree on
	// both keys, and calling them diffable would produce precisely the
	// fabricated diff AD-7 forbids.
	zeroTests := []struct {
		name  string
		left  Snapshot
		right Snapshot
	}{
		{"zero against zero", Snapshot{}, Snapshot{}},
		{"zero against populated", Snapshot{}, base},
		{"populated against zero", base, Snapshot{}},
		{"zero pid with equal start times", Snapshot{StartTime: 42}, Snapshot{StartTime: 42}},
		{"negative pid", Snapshot{PID: -1}, Snapshot{PID: -1}},
	}
	for _, tt := range zeroTests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.left.Comparable(tt.right) {
				t.Errorf("Comparable() = true, want false for %s", tt.name)
			}
		})
	}
}

// TestEventTypeIdentifiers pins the wire spelling of the diff event
// catalogue; the differ and the behavior layer both depend on it.
func TestEventTypeIdentifiers(t *testing.T) {
	catalogue := []EventType{
		EventFileOpened, EventFileClosed,
		EventNetworkConnectionCreated, EventNetworkConnectionClosed,
		EventListeningPortAppeared, EventChildCreated, EventChildExited,
		EventExecutableChanged, EventWorkingDirectoryChanged,
		EventSensitiveFileAccessed, EventCPUSpike, EventMemorySpike,
		EventProcessReplaced,
	}
	screaming := regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$`)
	seen := map[EventType]bool{}
	for _, eventType := range catalogue {
		if !screaming.MatchString(string(eventType)) {
			t.Errorf("event type %q is not SCREAMING_SNAKE_CASE", eventType)
		}
		if seen[eventType] {
			t.Errorf("event type %q is declared twice", eventType)
		}
		seen[eventType] = true
	}
}
