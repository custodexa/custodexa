package sensitivescan

import (
	"sort"
	"strings"
)

const RedactionPlaceholder = "[REDACTED]"

// Redact replaces matched spans completely. Count is the number of replacements,
// including zero on a scanned, unchanged value. Callers must persist this count
// in their own return ledger. Host output recordings stay untouched; the added
// agent blocked-input evidence line is explicitly redacted before recording.
func (r *Rules) Redact(text string) (string, int) {
	hits := r.Scan(text)
	if len(hits) == 0 {
		return text, 0
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Start < hits[j].Start })
	var b strings.Builder
	pos, count := int64(0), 0
	for i := 0; i < len(hits); {
		start, end := hits[i].Start, hits[i].End
		i++
		for i < len(hits) && hits[i].Start < end {
			if hits[i].End > end {
				end = hits[i].End
			}
			i++
		}
		b.WriteString(text[pos:start])
		b.WriteString(RedactionPlaceholder)
		pos = end
		count++
	}
	b.WriteString(text[pos:])
	return b.String(), count
}
