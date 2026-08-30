package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/IbrahimMI124/procintel/internal/model"
)

// listColumns is the single-shot listing header, hand-rolled into fixed-width
// columns like text.go's fd and socket tables rather than through tabwriter.
const listColumns = "%-8s %-8s %-16s %-5s %-7s %-11s %s"

// TextList writes a process listing as a PID-ascending table.
//
// Slice order is taken as given and never re-sorted here (AD-6); all unit
// conversion — stat's page-derived bytes to a human size, USER_HZ ticks to
// seconds — lives here (AD-12). CPU is cumulative user+system *time*, never a
// percentage, because a single snapshot cannot express a rate (AD-10).
// color == false emits no escape byte at all. When the listing's Availability
// is not observed the table is replaced by one "not observed" status line and
// no rows.
func TextList(w io.Writer, l model.ProcessListing, color bool) error {
	var b strings.Builder

	if l.Availability != model.AvailabilityObserved {
		fmt.Fprintf(&b, "%s\n",
			sgr(availabilityColor(l.Availability), availabilityLabel(l.Availability), color))
		_, err := w.Write([]byte(b.String()))
		return err
	}

	header := fmt.Sprintf(listColumns, "PID", "PPID", "COMM", "STATE", "THREADS", "RSS", "CPU")
	b.WriteString(sgr(sgrBold, header, color))
	b.WriteString("\n")
	for _, p := range l.Processes {
		fmt.Fprintf(&b, "%-8d %-8d %-16s %-5s %-7d %-11s %s\n",
			p.PID, p.PPID, p.Comm, p.State, p.ThreadCount,
			humanBytes(p.ResidentBytes),
			ticksToSeconds(p.UserTicks+p.SystemTicks))
	}

	_, err := w.Write([]byte(b.String()))
	return err
}

// JSONList writes a process listing as indented JSON followed by one newline.
//
// It is the machine half of AD-12 over the same model.ProcessListing the text
// renderer consumes. Struct-field order is the declaration order in
// internal/model, so the output is deterministic without any map iteration
// (AD-6) and round-trips through json.Unmarshal.
func JSONList(w io.Writer, l model.ProcessListing) error {
	encoded, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(encoded, '\n'))
	return err
}
