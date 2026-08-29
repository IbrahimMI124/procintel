package procfs

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// --- parseHexAddress / parseHexPort ----------------------------------------

// The classic bug this block exists to get right: an address is
// little-endian per 32-bit word, not one big-endian blob, and IPv6 repeats
// that per word rather than reversing the whole sixteen bytes at once.
func TestParseHexAddress(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want string
		ok   bool
	}{
		{"loopback", "0100007F", "127.0.0.1", true},
		{"second loopback-family address", "0200007F", "127.0.0.2", true},
		{"unspecified IPv4", "00000000", "0.0.0.0", true},
		{"a real routable address", "0101A8C0", "192.168.1.1", true},
		{"IPv6 loopback", "00000000000000000000000001000000", "::1", true},
		{"IPv6 unspecified", "00000000000000000000000000000000", "::", true},
		{"odd length is invalid", "0100007", "", false},
		{"non-hex characters", "GGGGGGGG", "", false},
		{"empty string", "", "", false},
		{"wrong byte count (12 bytes)", "010203040506070809101112", "", false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := parseHexAddress(testCase.hex)
			if ok != testCase.ok {
				t.Fatalf("parseHexAddress(%q) ok = %v, want %v", testCase.hex, ok, testCase.ok)
			}
			if !ok {
				return
			}
			if got.String() != testCase.want {
				t.Errorf("parseHexAddress(%q) = %q, want %q", testCase.hex, got.String(), testCase.want)
			}
		})
	}
}

// A real, non-degenerate IPv6 address exercises all four words, not just an
// all-zero-but-one-byte case: 2001:db8::1 word-reversed per 32-bit word.
//
//	Word 0: 2001:0db8 -> bytes 20 01 0d b8 -> reversed b8 0d 01 20
//	Word 1: 0000:0000 -> 00000000
//	Word 2: 0000:0000 -> 00000000
//	Word 3: 0000:0001 -> bytes 00 00 00 01 -> reversed 01 00 00 00
func TestParseHexAddressIPv6NonTrivial(t *testing.T) {
	hexAddress := "B80D0120" + "00000000" + "00000000" + "01000000"
	got, ok := parseHexAddress(hexAddress)
	if !ok {
		t.Fatalf("parseHexAddress(%q) failed", hexAddress)
	}
	if want := "2001:db8::1"; got.String() != want {
		t.Errorf("parseHexAddress(%q) = %q, want %q", hexAddress, got.String(), want)
	}
}

func TestParseHexPort(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want int
		ok   bool
	}{
		{"http", "0050", 80, true},
		{"high port", "1F90", 8080, true},
		{"max port", "FFFF", 65535, true},
		{"zero", "0000", 0, true},
		{"lowercase hex", "c350", 50000, true},
		{"wrong length (short)", "50", 0, false},
		{"wrong length (long)", "00050", 0, false},
		{"non-hex", "ZZZZ", 0, false},
		{"empty", "", 0, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := parseHexPort(testCase.hex)
			if ok != testCase.ok || got != testCase.want {
				t.Errorf("parseHexPort(%q) = %d/%v, want %d/%v", testCase.hex, got, ok, testCase.want, testCase.ok)
			}
		})
	}
}

// The port half never goes through the address's word-endianness handling:
// the same four characters are a valid port but not a valid address (they
// decode to an odd byte count), proving the two are independent code paths
// rather than one shared routine misapplied to both fields.
func TestParseHexPortDoesNotReuseAddressDecoding(t *testing.T) {
	if _, ok := parseHexAddress("1F90"); ok {
		t.Errorf("parseHexAddress(%q) unexpectedly succeeded", "1F90")
	}
	if port, ok := parseHexPort("1F90"); !ok || port != 8080 {
		t.Errorf("parseHexPort(%q) = %d/%v, want 8080/true", "1F90", port, ok)
	}
}

// --- parseTCPLine / parseUDPLine -------------------------------------------

// ipSocketLineWant is the string-keyed shape TestParseTCPLine compares
// against, so a case table can be written in dotted-decimal / literal state
// text instead of a hand-built net.IP value (whose IPv4 and IPv6 forms are
// different byte lengths and awkward to compare with reflect.DeepEqual).
type ipSocketLineWant struct {
	localAddress, remoteAddress string
	localPort, remotePort       int
	state                       string
	inode                       uint64
}

func checkIPSocketLine(t *testing.T, got ipSocketLine, want ipSocketLineWant) {
	t.Helper()
	if got.localAddress.String() != want.localAddress {
		t.Errorf("localAddress = %q, want %q", got.localAddress.String(), want.localAddress)
	}
	if got.localPort != want.localPort {
		t.Errorf("localPort = %d, want %d", got.localPort, want.localPort)
	}
	if got.remoteAddress.String() != want.remoteAddress {
		t.Errorf("remoteAddress = %q, want %q", got.remoteAddress.String(), want.remoteAddress)
	}
	if got.remotePort != want.remotePort {
		t.Errorf("remotePort = %d, want %d", got.remotePort, want.remotePort)
	}
	if got.state != want.state {
		t.Errorf("state = %q, want %q", got.state, want.state)
	}
	if got.inode != want.inode {
		t.Errorf("inode = %d, want %d", got.inode, want.inode)
	}
}

func TestParseTCPLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		want ipSocketLineWant
		ok   bool
	}{
		{
			name: "listening",
			line: "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 654321 1 0000000000000000 100 0 0 10 0",
			want: ipSocketLineWant{localAddress: "127.0.0.1", localPort: 8080, remoteAddress: "0.0.0.0", remotePort: 0, state: "LISTEN", inode: 654321},
			ok:   true,
		},
		{
			name: "established",
			line: "   1: 0100007F:1F91 0200007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 700002 1 0000000000000000 100 0 0 10 0",
			want: ipSocketLineWant{localAddress: "127.0.0.1", localPort: 8081, remoteAddress: "127.0.0.2", remotePort: 50000, state: "ESTABLISHED", inode: 700002},
			ok:   true,
		},
		{
			name: "unknown state code renders as the literal hex",
			line: "   2: 0100007F:2328 00000000:0000 0F 00000000:00000000 00:00000000 00000000     0        0 800002 1 0000000000000000 100 0 0 10 0",
			want: ipSocketLineWant{localAddress: "127.0.0.1", localPort: 9000, remoteAddress: "0.0.0.0", remotePort: 0, state: "0F", inode: 800002},
			ok:   true,
		},
		{
			name: "header line is not data",
			line: "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
			ok:   false,
		},
		{name: "blank line", line: "", ok: false},
		{name: "too few fields", line: "0: 0100007F:1F90 00000000:0000 0A", ok: false},
		{
			name: "unparsable inode",
			line: "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 notanumber 1 0000000000000000 100 0 0 10 0",
			ok:   false,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := parseTCPLine(testCase.line)
			if ok != testCase.ok {
				t.Fatalf("parseTCPLine ok = %v, want %v", ok, testCase.ok)
			}
			if !ok {
				return
			}
			checkIPSocketLine(t, got, testCase.want)
		})
	}
}

// tcp and udp share one layout and one state table; parseUDPLine is a
// distinct named entry point over the same parser (Design Notes), pinned
// separately so a future divergence between the two files is caught here.
func TestParseUDPLine(t *testing.T) {
	line := "   0: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 700200 2 0000000000000000 0"
	got, ok := parseUDPLine(line)
	if !ok {
		t.Fatalf("parseUDPLine failed on %q", line)
	}
	checkIPSocketLine(t, got, ipSocketLineWant{localAddress: "0.0.0.0", localPort: 5353, remoteAddress: "0.0.0.0", remotePort: 0, state: "CLOSE", inode: 700200})
}

// IPv6 addresses must decode through the same four-word path as any other
// tcp6/udp6 row, not be mangled as if they were IPv4 (I/O matrix: "IPv6
// address").
func TestParseTCPLineIPv6(t *testing.T) {
	line := "   0: 00000000000000000000000001000000:2382 00000000000000000000000001000000:2383 01 00000000:00000000 00:00000000 00000000     0        0 700100 1 0000000000000000 100 0 0 10 0"
	got, ok := parseTCPLine(line)
	if !ok {
		t.Fatalf("parseTCPLine failed on %q", line)
	}
	checkIPSocketLine(t, got, ipSocketLineWant{localAddress: "::1", localPort: 9090, remoteAddress: "::1", remotePort: 9091, state: "ESTABLISHED", inode: 700100})
}

// --- parseUnixLine -----------------------------------------------------

func TestParseUnixLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		want unixSocketLine
		ok   bool
	}{
		{
			name: "path socket",
			line: "0000000000000000: 00000002 00000000 00000000 0001 03 800001 /run/app.sock",
			want: unixSocketLine{state: "CONNECTED", path: "/run/app.sock", inode: 800001},
			ok:   true,
		},
		{
			name: "abstract socket path kept verbatim, including the @",
			line: "0000000000000000: 00000003 00000000 00010000 0001 01 800003 @myabstract",
			want: unixSocketLine{state: "LISTENING", path: "@myabstract", inode: 800003},
			ok:   true,
		},
		{
			name: "no path",
			line: "0000000000000000: 00000002 00000000 00000000 0001 02 700400",
			want: unixSocketLine{state: "CONNECTING", path: "", inode: 700400},
			ok:   true,
		},
		{
			name: "listening flag wins regardless of St",
			line: "0000000000000000: 00000002 00000000 00010000 0001 04 700500",
			want: unixSocketLine{state: "LISTENING", path: "", inode: 700500},
			ok:   true,
		},
		{
			name: "unknown St falls back to the literal value",
			line: "0000000000000000: 00000002 00000000 00000000 0001 FF 700600",
			want: unixSocketLine{state: "FF", path: "", inode: 700600},
			ok:   true,
		},
		{
			name: "header line is not data",
			line: "Num       RefCount Protocol Flags    Type St Inode Path",
			ok:   false,
		},
		{name: "too few fields", line: "0: 1 2 3", ok: false},
		{
			name: "unparsable inode",
			line: "0000000000000000: 00000002 00000000 00000000 0001 03 notanumber /run/app.sock",
			ok:   false,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := parseUnixLine(testCase.line)
			if ok != testCase.ok {
				t.Fatalf("parseUnixLine ok = %v, want %v", ok, testCase.ok)
			}
			if !ok {
				return
			}
			if !reflect.DeepEqual(got, testCase.want) {
				t.Errorf("parseUnixLine =\n%+v\nwant\n%+v", got, testCase.want)
			}
		})
	}
}

// --- splitFields ------------------------------------------------------

// The Path column is taken verbatim from whatever remains after the seventh
// field — never re-joined from a Fields() split, which would normalise
// internal spacing out from under it.
func TestSplitFieldsPreservesRemainderVerbatim(t *testing.T) {
	fields, rest := splitFields("a b c d e f g   spaced   remainder", 7)
	wantFields := []string{"a", "b", "c", "d", "e", "f", "g"}
	if !reflect.DeepEqual(fields, wantFields) {
		t.Errorf("fields = %v, want %v", fields, wantFields)
	}
	if rest != "spaced   remainder" {
		t.Errorf("rest = %q, want %q", rest, "spaced   remainder")
	}
}

func TestSplitFieldsTooFewFields(t *testing.T) {
	fields, rest := splitFields("a b c", 7)
	if len(fields) >= 7 {
		t.Errorf("fields = %v, want fewer than 7", fields)
	}
	if rest != "" {
		t.Errorf("rest = %q, want empty", rest)
	}
}

// --- the join: (*Reader).sockets -------------------------------------

// I/O matrix: "Listening TCP socket". The acceptance criterion this block
// exists to satisfy: the normal/1234 fixture's one socket-kind fd joins to
// exactly the tcp entry that shares its inode.
func TestSnapshotJoinsListeningTCPSocket(t *testing.T) {
	snapshot, err := New(fixtureRoot("normal")).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	if snapshot.Availability.Sockets != model.AvailabilityObserved {
		t.Fatalf("Availability.Sockets = %q, want observed", snapshot.Availability.Sockets)
	}
	want := []model.Socket{
		{
			Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 8080,
			RemoteAddress: "", RemotePort: 0, State: "LISTEN",
			Inode: 654321, FileDescriptor: 2,
		},
	}
	if !reflect.DeepEqual(snapshot.Sockets, want) {
		t.Errorf("Sockets =\n%+v\nwant\n%+v", snapshot.Sockets, want)
	}
}

// The second fixture PID (4444) exercises everything the first fixture's
// single socket fd cannot: an established connection actually joined to a
// descriptor, a udp and a udp6 socket, a unix-domain socket with a path, an
// abstract unix socket, an unknown state code, and a socket fd with no
// matching /proc/net/* entry at all.
func TestSocketsJoinAcrossProtocols(t *testing.T) {
	reader := New(fixtureRoot("normal"))
	descriptors, filesAvailability := reader.fileDescriptors(4444)
	if filesAvailability != model.AvailabilityObserved {
		t.Fatalf("files availability = %q, want observed", filesAvailability)
	}

	sockets, availability := reader.sockets(4444, descriptors)
	if availability != model.AvailabilityObserved {
		t.Fatalf("sockets availability = %q, want observed", availability)
	}

	want := []model.Socket{
		{
			Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 8081,
			RemoteAddress: "127.0.0.2", RemotePort: 50000, State: "ESTABLISHED",
			Inode: 700002, FileDescriptor: 2,
		},
		{
			Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 9000,
			RemoteAddress: "", RemotePort: 0, State: "0F",
			Inode: 800002, FileDescriptor: 4,
		},
		{
			// net/udp's one row: 0.0.0.0:0x14E9 (5353), st 07 -> CLOSE, the
			// state a bound-but-unconnected UDP socket carries.
			Protocol: "udp", LocalAddress: "0.0.0.0", LocalPort: 5353,
			RemoteAddress: "", RemotePort: 0, State: "CLOSE",
			Inode: 700200, FileDescriptor: 7,
		},
		{
			// net/udp6's one row: [::]:0x0203 (515), same shared state table
			// as udp — proves udp6 is joined through its own protocol label
			// and file, not silently merged into udp or tcp6.
			Protocol: "udp6", LocalAddress: "::", LocalPort: 515,
			RemoteAddress: "", RemotePort: 0, State: "CLOSE",
			Inode: 700300, FileDescriptor: 8,
		},
		{
			Protocol: "unix", Path: "/run/app.sock", State: "CONNECTED",
			Inode: 800001, FileDescriptor: 3,
		},
		{
			Protocol: "unix", Path: "@myabstract", State: "LISTENING",
			Inode: 800003, FileDescriptor: 5,
		},
	}
	if !reflect.DeepEqual(sockets, want) {
		t.Errorf("sockets =\n%+v\nwant\n%+v", sockets, want)
	}

	// fd 6 (socket:[999999]) matches no /proc/net/* entry at all and must be
	// omitted, never fabricated with empty fields (I/O matrix: "Socket fd
	// with no net match").
	for _, socket := range sockets {
		if socket.FileDescriptor == 6 {
			t.Errorf("fd 6 unexpectedly present in sockets: %+v", socket)
		}
	}
}

// I/O matrix: "Unmatched net entry". net/tcp's fourth row (inode 700003) and
// net/unix's third row (inode 700400) are claimed by no fd in either fixture
// PID, and must simply be absent from every joined result rather than
// erroring.
func TestUnmatchedNetEntriesAreExcluded(t *testing.T) {
	reader := New(fixtureRoot("normal"))
	for _, pid := range []int{1234, 4444} {
		descriptors, _ := reader.fileDescriptors(pid)
		sockets, _ := reader.sockets(pid, descriptors)
		for _, socket := range sockets {
			if socket.Inode == 700003 || socket.Inode == 700400 {
				t.Errorf("pid %d: unmatched inode %d unexpectedly joined: %+v", pid, socket.Inode, socket)
			}
		}
	}
}

// I/O matrix: "net/tcp6 unsupported". Removing tcp6 from a copy of the
// fixture must not abort the section: the IPv4 entries still join, and the
// section degrades rather than erroring.
func TestMissingTCP6DegradesWithoutAborting(t *testing.T) {
	root := copyFixture(t, "normal")
	if err := os.Remove(filepath.Join(root, "net", "tcp6")); err != nil {
		t.Fatalf("removing net/tcp6: %v", err)
	}

	snapshot, err := New(root).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	if snapshot.Availability.Sockets != model.AvailabilityUnsupported {
		t.Errorf("Availability.Sockets = %q, want unsupported", snapshot.Availability.Sockets)
	}
	want := []model.Socket{
		{
			Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 8080,
			RemoteAddress: "", RemotePort: 0, State: "LISTEN",
			Inode: 654321, FileDescriptor: 2,
		},
	}
	if !reflect.DeepEqual(snapshot.Sockets, want) {
		t.Errorf("Sockets =\n%+v\nwant\n%+v — tcp/unix must still join with tcp6 gone", snapshot.Sockets, want)
	}
}

// The udp/udp6 counterpart to TestMissingTCP6DegradesWithoutAborting: before
// this test, nothing ever exercised the udp/udp6 read-and-join path past the
// standalone line parser, so swapping a protocol label or file argument in
// buildSocketLookup's readIP calls, or dropping either call entirely, would
// have passed every test in this file unchanged. Using pid 4444 rather than
// 1234 matters here — 1234 carries no udp/udp6 fd at all, so removing either
// file against that fixture would prove nothing about the join.
func TestMissingUDPDegradesWithoutAborting(t *testing.T) {
	root := copyFixture(t, "normal")
	if err := os.Remove(filepath.Join(root, "net", "udp")); err != nil {
		t.Fatalf("removing net/udp: %v", err)
	}

	reader := New(root)
	descriptors, _ := reader.fileDescriptors(4444)
	sockets, availability := reader.sockets(4444, descriptors)
	if availability != model.AvailabilityUnsupported {
		t.Errorf("sockets availability = %q, want unsupported", availability)
	}
	for _, socket := range sockets {
		if socket.Protocol == "udp" {
			t.Errorf("udp socket %+v present after net/udp was removed", socket)
		}
	}
	var sawTCP, sawUDP6, sawUnix bool
	for _, socket := range sockets {
		switch socket.Protocol {
		case "tcp":
			sawTCP = true
		case "udp6":
			sawUDP6 = true
		case "unix":
			sawUnix = true
		}
	}
	if !sawTCP || !sawUDP6 || !sawUnix {
		t.Errorf("sockets =\n%+v\nwant tcp, udp6 and unix entries still joined with only net/udp gone", sockets)
	}
}

// The udp6 counterpart, removing net/udp6 instead. Proves udp and udp6 are
// two independent read/join calls rather than one call covering both files.
func TestMissingUDP6DegradesWithoutAborting(t *testing.T) {
	root := copyFixture(t, "normal")
	if err := os.Remove(filepath.Join(root, "net", "udp6")); err != nil {
		t.Fatalf("removing net/udp6: %v", err)
	}

	reader := New(root)
	descriptors, _ := reader.fileDescriptors(4444)
	sockets, availability := reader.sockets(4444, descriptors)
	if availability != model.AvailabilityUnsupported {
		t.Errorf("sockets availability = %q, want unsupported", availability)
	}
	for _, socket := range sockets {
		if socket.Protocol == "udp6" {
			t.Errorf("udp6 socket %+v present after net/udp6 was removed", socket)
		}
	}
	var sawTCP, sawUDP, sawUnix bool
	for _, socket := range sockets {
		switch socket.Protocol {
		case "tcp":
			sawTCP = true
		case "udp":
			sawUDP = true
		case "unix":
			sawUnix = true
		}
	}
	if !sawTCP || !sawUDP || !sawUnix {
		t.Errorf("sockets =\n%+v\nwant tcp, udp and unix entries still joined with only net/udp6 gone", sockets)
	}
}

// I/O matrix: "Files section denied". The fd side of the join could not be
// seen at all, so the section can never claim observed regardless of what
// /proc/net/* itself said.
func TestDeniedFilesSectionDeniesSockets(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions, so a chmod cannot produce EACCES")
	}
	root := copyFixture(t, "normal")
	directory := filepath.Join(root, "1234", interfaceFD)
	if err := os.Chmod(directory, 0o000); err != nil {
		t.Fatalf("chmod fd directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o755) })

	snapshot, err := New(root).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	if snapshot.Availability.Files != model.AvailabilityDenied {
		t.Fatalf("Availability.Files = %q, want denied", snapshot.Availability.Files)
	}
	if snapshot.Availability.Sockets != model.AvailabilityDenied {
		t.Errorf("Availability.Sockets = %q, want denied — the fd side of the join was unreadable",
			snapshot.Availability.Sockets)
	}
	if snapshot.Sockets != nil {
		t.Errorf("Sockets = %+v, want none — a denied fd side has nothing to join", snapshot.Sockets)
	}
}

// The complementary case: /proc/net/unix itself denied, exercising the
// /proc/net/* half of the combiner rather than the Files half. One bad
// source lowers the section, but the tcp entry another source read
// successfully is still returned.
func TestDeniedNetFileDeniesSockets(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions, so a chmod cannot produce EACCES")
	}
	root := copyFixture(t, "normal")
	unixFile := filepath.Join(root, "net", "unix")
	if err := os.Chmod(unixFile, 0o000); err != nil {
		t.Fatalf("chmod net/unix: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(unixFile, 0o644) })

	snapshot, err := New(root).Snapshot(1234)
	if err != nil {
		t.Fatalf("Snapshot(1234): %v", err)
	}
	if snapshot.Availability.Sockets != model.AvailabilityDenied {
		t.Errorf("Availability.Sockets = %q, want denied", snapshot.Availability.Sockets)
	}
	want := []model.Socket{
		{
			Protocol: "tcp", LocalAddress: "127.0.0.1", LocalPort: 8080,
			RemoteAddress: "", RemotePort: 0, State: "LISTEN",
			Inode: 654321, FileDescriptor: 2,
		},
	}
	if !reflect.DeepEqual(snapshot.Sockets, want) {
		t.Errorf("Sockets =\n%+v\nwant\n%+v", snapshot.Sockets, want)
	}
}
