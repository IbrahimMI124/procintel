package procfs

import (
	"encoding/hex"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// The five /proc/net/* interfaces the socket observer parses, and the
// protocol label each contributes to a joined [model.Socket].
const (
	netFileTCP  = "tcp"
	netFileTCP6 = "tcp6"
	netFileUDP  = "udp"
	netFileUDP6 = "udp6"
	netFileUnix = "unix"
)

// unixListeningFlag is SO_ACCEPTCON, the /proc/net/unix Flags bit that marks
// a socket as listening regardless of its St value (Design Notes).
const unixListeningFlag = 0x10000

// ipStateNames is the shared TCP/UDP connection-state table both IP protocol
// families read their st column against. A code outside this table is
// reported as the literal hex string it was, never guessed (I/O matrix:
// "Unknown state code").
var ipStateNames = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
	"0C": "NEW_SYN_RECV",
}

// ipStateName maps a /proc/net/{tcp,tcp6,udp,udp6} st code to its name, or
// returns the code itself, unmodified, when it is not one of the table's
// twelve known values.
func ipStateName(code string) string {
	if name, ok := ipStateNames[strings.ToUpper(code)]; ok {
		return name
	}
	return code
}

// unixStateNames is /proc/net/unix's own small St fallback table, consulted
// only when the Flags word does not already mark the socket LISTENING
// (Design Notes).
var unixStateNames = map[string]string{
	"01": "UNCONNECTED",
	"02": "CONNECTING",
	"03": "CONNECTED",
	"04": "DISCONNECTING",
}

// unixStateName maps a /proc/net/unix Flags/St pair to a state name, falling
// back to the literal St value when it is not one of the four known codes.
func unixStateName(flags uint64, st string) string {
	if flags&unixListeningFlag != 0 {
		return "LISTENING"
	}
	if name, ok := unixStateNames[strings.ToUpper(st)]; ok {
		return name
	}
	return st
}

// parseHexAddress decodes the little-endian hex address half of a
// /proc/net/{tcp,tcp6,udp,udp6} address:port field into a [net.IP].
//
// The bytes are little-endian per 32-bit word (spine convention): one word
// for an 8-hex-digit IPv4 address, four words for a 32-hex-digit IPv6
// address. Each word is reversed independently — a naive whole-buffer
// reverse would scramble a multi-word IPv6 address, which is the classic bug
// this parser exists to avoid (Design Notes).
//
//	"0100007F" -> the word 7F 00 00 01 read low-to-high -> 127.0.0.1
func parseHexAddress(hexAddress string) (net.IP, bool) {
	raw, err := hex.DecodeString(hexAddress)
	if err != nil {
		return nil, false
	}
	switch len(raw) {
	case 4:
		return reverseWord(raw), true
	case 16:
		ip := make(net.IP, 0, 16)
		for word := 0; word < 4; word++ {
			ip = append(ip, reverseWord(raw[word*4:word*4+4])...)
		}
		return ip, true
	default:
		return nil, false
	}
}

// reverseWord returns a copy of one 4-byte little-endian word with its bytes
// reversed into big-endian (network/text) order.
func reverseWord(word []byte) []byte {
	reversed := make([]byte, len(word))
	for i, b := range word {
		reversed[len(word)-1-i] = b
	}
	return reversed
}

// parseHexPort decodes the port half of a /proc/net/* address:port field.
//
// Unlike the address half, the port is plain big-endian 4-hex-digit text —
// it does not go through the address's word-endianness handling (Design
// Notes).
func parseHexPort(hexPort string) (int, bool) {
	if len(hexPort) != 4 {
		return 0, false
	}
	value, err := strconv.ParseUint(hexPort, 16, 32)
	if err != nil {
		return 0, false
	}
	return int(value), true
}

// parseHexAddrPort splits and decodes one "HEXADDR:HEXPORT" field, the shape
// both the local_address and rem_address columns share.
func parseHexAddrPort(field string) (net.IP, int, bool) {
	addr, port, ok := strings.Cut(field, ":")
	if !ok {
		return nil, 0, false
	}
	ip, ok := parseHexAddress(addr)
	if !ok {
		return nil, 0, false
	}
	portNumber, ok := parseHexPort(port)
	if !ok {
		return nil, 0, false
	}
	return ip, portNumber, true
}

// ipSocketLine is one successfully parsed row of /proc/net/{tcp,tcp6,udp,udp6}.
type ipSocketLine struct {
	localAddress  net.IP
	localPort     int
	remoteAddress net.IP
	remotePort    int
	state         string
	inode         uint64
}

// parseIPLine parses one whitespace-separated data row shared by
// /proc/net/tcp, tcp6, udp and udp6:
//
//	sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
//
// A header line, a blank line, or any row this package cannot fully parse
// reports false rather than a partial or fabricated result; the caller skips
// it and moves on (never a fabricated Socket entry).
func parseIPLine(line string) (ipSocketLine, bool) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return ipSocketLine{}, false
	}
	localAddress, localPort, ok := parseHexAddrPort(fields[1])
	if !ok {
		return ipSocketLine{}, false
	}
	remoteAddress, remotePort, ok := parseHexAddrPort(fields[2])
	if !ok {
		return ipSocketLine{}, false
	}
	inode, err := strconv.ParseUint(fields[9], 10, 64)
	if err != nil {
		return ipSocketLine{}, false
	}
	return ipSocketLine{
		localAddress:  localAddress,
		localPort:     localPort,
		remoteAddress: remoteAddress,
		remotePort:    remotePort,
		state:         ipStateName(fields[3]),
		inode:         inode,
	}, true
}

// parseTCPLine parses one /proc/net/tcp or /proc/net/tcp6 data row.
//
// tcp, tcp6, udp and udp6 share one field layout and one state table
// (Design Notes); parseTCPLine and parseUDPLine are kept as separate named
// entry points, one per file kind, so a call site never has to remember
// which protocol family a bare "parseIPLine" call was reading.
func parseTCPLine(line string) (ipSocketLine, bool) {
	return parseIPLine(line)
}

// parseUDPLine parses one /proc/net/udp or /proc/net/udp6 data row, sharing
// parseTCPLine's layout and state table (Design Notes).
func parseUDPLine(line string) (ipSocketLine, bool) {
	return parseIPLine(line)
}

// unixSocketLine is one successfully parsed row of /proc/net/unix.
type unixSocketLine struct {
	state string
	path  string
	inode uint64
}

// parseUnixLine parses one /proc/net/unix data row:
//
//	Num RefCount Protocol Flags Type St Inode [Path]
//
// Path is whatever text remains after the seventh field, taken verbatim —
// including a leading "@" for an abstract socket — and is never stripped or
// reinterpreted. It is read by locating the byte offset after the seventh
// field rather than by re-joining a Fields() split, so internal spacing (were
// it ever to matter) is never normalised out from under it.
func parseUnixLine(line string) (unixSocketLine, bool) {
	fields, rest := splitFields(line, 7)
	if len(fields) < 7 {
		return unixSocketLine{}, false
	}
	flags, err := strconv.ParseUint(fields[3], 16, 64)
	if err != nil {
		return unixSocketLine{}, false
	}
	inode, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return unixSocketLine{}, false
	}
	return unixSocketLine{
		state: unixStateName(flags, fields[5]),
		path:  rest,
		inode: inode,
	}, true
}

// splitFields splits line into at most n whitespace-separated leading
// fields, and returns whatever text remains after the nth field, with
// exactly its own leading whitespace trimmed and nothing else — the
// remainder is returned byte-for-byte otherwise.
//
// If line holds fewer than n fields, fields is shorter than n and rest is
// empty; the caller treats that as a parse failure.
func splitFields(line string, n int) (fields []string, rest string) {
	index := 0
	for len(fields) < n {
		for index < len(line) && isASCIISpace(line[index]) {
			index++
		}
		start := index
		for index < len(line) && !isASCIISpace(line[index]) {
			index++
		}
		if start == index {
			return fields, ""
		}
		fields = append(fields, line[start:index])
	}
	for index < len(line) && isASCIISpace(line[index]) {
		index++
	}
	return fields, line[index:]
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r'
}

// socketRecord is one /proc/net/* entry keyed by inode, ready to be joined
// against a socket-kind file descriptor.
type socketRecord struct {
	protocol      string
	localAddress  string
	localPort     int
	remoteAddress string
	remotePort    int
	state         string
	path          string
}

// buildSocketLookup reads all five /proc/net/* files once and returns them
// keyed by socket inode, alongside the weakest availability among the files
// that were actually consulted.
//
// A file that is simply absent on this kernel (e.g. tcp6 with IPv6 disabled)
// degrades only its own contribution to the section's availability — the
// other four files still join normally (I/O matrix: "net/tcp6 unsupported").
func (r *Reader) buildSocketLookup() (map[uint64]socketRecord, model.Availability) {
	lookup := make(map[uint64]socketRecord)
	sources := make([]model.Availability, 0, 5)

	readIP := func(name, protocol string, parse func(string) (ipSocketLine, bool)) {
		data, availability := r.readNet(name)
		sources = append(sources, availability)
		if availability != model.AvailabilityObserved {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			parsed, ok := parse(line)
			if !ok {
				continue
			}
			record := socketRecord{
				protocol:     protocol,
				localAddress: parsed.localAddress.String(),
				localPort:    parsed.localPort,
				state:        parsed.state,
			}
			// A listening or unconnected entry's remote half is the zero
			// address on port 0; reporting that as a literal "0.0.0.0" or
			// "::" would read as a real peer, so port 0 collapses the
			// remote address to empty too (I/O matrix: "Listening TCP
			// socket").
			if parsed.remotePort != 0 {
				record.remoteAddress = parsed.remoteAddress.String()
				record.remotePort = parsed.remotePort
			}
			lookup[parsed.inode] = record
		}
	}

	readIP(netFileTCP, "tcp", parseTCPLine)
	readIP(netFileTCP6, "tcp6", parseTCPLine)
	readIP(netFileUDP, "udp", parseUDPLine)
	readIP(netFileUDP6, "udp6", parseUDPLine)

	unixData, unixAvailability := r.readNet(netFileUnix)
	sources = append(sources, unixAvailability)
	if unixAvailability == model.AvailabilityObserved {
		for _, line := range strings.Split(string(unixData), "\n") {
			parsed, ok := parseUnixLine(line)
			if !ok {
				continue
			}
			lookup[parsed.inode] = socketRecord{
				protocol: netFileUnix,
				state:    parsed.state,
				path:     parsed.path,
			}
		}
	}

	return lookup, weakest(sources...)
}

// sockets performs the fd -> socket-inode -> connection join (AD-15).
//
// descriptors is Block 1b's already-classified, already-sorted list — read
// only, never re-derived. Every socket-kind entry is looked up by its
// SocketInode against a lookup built once from all five /proc/net/* files;
// an entry with no match (closed between the fd read and the net read, or
// living in a different network namespace) is simply omitted, never
// fabricated with partial fields. The result is sorted by
// (Protocol, LocalPort, RemoteAddress) (AD-6).
//
// The returned Availability reflects only the /proc/net/* reads themselves;
// folding in the Files section's own availability is the caller's job
// (weakest is the combiner for both halves of the join).
func (r *Reader) sockets(pid int, descriptors []model.FileDescriptor) ([]model.Socket, model.Availability) {
	lookup, availability := r.buildSocketLookup()

	sockets := make([]model.Socket, 0, len(descriptors))
	for _, descriptor := range descriptors {
		if descriptor.Kind != model.FileDescriptorKindSocket {
			continue
		}
		record, ok := lookup[descriptor.SocketInode]
		if !ok {
			continue
		}
		sockets = append(sockets, model.Socket{
			Protocol:       record.protocol,
			LocalAddress:   record.localAddress,
			LocalPort:      record.localPort,
			RemoteAddress:  record.remoteAddress,
			RemotePort:     record.remotePort,
			State:          record.state,
			Path:           record.path,
			Inode:          descriptor.SocketInode,
			FileDescriptor: descriptor.Number,
		})
	}

	// SliceStable, not Slice: two sockets that tie on every sort key (e.g.
	// two unix-domain sockets, which carry no port) must still resolve to a
	// deterministic order (AD-6) rather than whatever an unstable sort
	// happens to leave them in. The pre-sort order here is fd number
	// ascending, since descriptors already is.
	sort.SliceStable(sockets, func(i, j int) bool {
		if sockets[i].Protocol != sockets[j].Protocol {
			return sockets[i].Protocol < sockets[j].Protocol
		}
		if sockets[i].LocalPort != sockets[j].LocalPort {
			return sockets[i].LocalPort < sockets[j].LocalPort
		}
		return sockets[i].RemoteAddress < sockets[j].RemoteAddress
	})

	if len(sockets) == 0 {
		sockets = nil
	}
	return sockets, availability
}
