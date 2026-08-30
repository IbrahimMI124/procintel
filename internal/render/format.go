package render

import (
	"fmt"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// SGR parameter codes used by the text renderer. Only these three appear in
// output, and each is emitted as "\x1b[<code>m ... \x1b[0m", so a caller can
// strip colour with the single regexp \x1b\[[0-9;]*m.
const (
	sgrBold = "1"
	sgrDim  = "2"
	sgrGrn  = "32"
	sgrYel  = "33"
)

// sgr wraps s in an SGR sequence when color is true and code is non-empty,
// and returns s untouched otherwise — so color == false yields byte-for-byte
// plain text.
func sgr(code, s string, color bool) string {
	if !color || code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// availabilityColor maps a section availability to its SGR colour: observed
// is green, a permission or race failure is yellow, and everything else
// (unsupported, absent, the empty zero value) is dim.
func availabilityColor(a model.Availability) string {
	switch a {
	case model.AvailabilityObserved:
		return sgrGrn
	case model.AvailabilityDenied, model.AvailabilityRaced:
		return sgrYel
	default:
		return sgrDim
	}
}

// ticksToSeconds converts a USER_HZ tick count to a fixed-precision seconds
// string. USER_HZ is the hardcoded 100 (model.UserHZ) because sysconf needs
// cgo, which CGO_ENABLED=0 rules out — a stated limitation, not a guess.
func ticksToSeconds(ticks uint64) string {
	return fmt.Sprintf("%.3fs", float64(ticks)/float64(model.UserHZ))
}

// humanBytes formats a byte count in binary units with one decimal place,
// or plain bytes below 1 KiB.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB", "PiB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f EiB", value/unit)
}
