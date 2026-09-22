// Package sensitivescan scans literal text bytes. It does not decode encodings
// or render terminal control sequences. Matches mean "possibly contains".
package sensitivescan

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/custodexa/backend/internal/model"
)

const (
	CardPattern       = `[0-9](?:[ \t-]?[0-9]){12,18}`
	PrivateKeyPattern = `-----BEGIN (?:(?:[A-Z0-9]{1,16} ){0,3}PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----`
	// OverlapBytes exceeds the longest builtin candidate, including boundaries.
	// Custom patterns requiring more history are outside this bounded window.
	OverlapBytes = 256
)

// Luhn validates 13–19 digits; spaces, tabs and hyphens are not checksum input.
func Luhn(text string) bool {
	digits := make([]byte, 0, 19)
	for i := 0; i < len(text); i++ {
		c := text[i]
		if separator(c) {
			continue
		}
		if !digit(c) {
			return false
		}
		digits = append(digits, c-'0')
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i])
		if (len(digits)-1-i)%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

func digit(c byte) bool     { return c >= '0' && c <= '9' }
func separator(c byte) bool { return c == ' ' || c == '\t' || c == '-' }
func word(c byte) bool      { return digit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' }

func cardCandidate(text string, start, end int) bool {
	if start > 0 && word(text[start-1]) || end < len(text) && word(text[end]) {
		return false
	}
	if start > 1 && separator(text[start-1]) && digit(text[start-2]) {
		return false
	}
	if end+1 < len(text) && separator(text[end]) && digit(text[end+1]) {
		return false
	}
	candidate := text[start:end]
	if !Luhn(candidate) {
		return false
	}
	// Repeated and cyclic ascending numeric placeholders are not card candidates.
	var digits []byte
	for i := range candidate {
		if digit(candidate[i]) {
			digits = append(digits, candidate[i])
		}
	}
	same, ascending := true, true
	for i := 1; i < len(digits); i++ {
		same = same && digits[i] == digits[0]
		ascending = ascending && digits[i]-'0' == (digits[i-1]-'0'+1)%10
	}
	return !same && !ascending
}

type compiledRule struct {
	rule model.AlertRule
	re   *regexp.Regexp
	card bool
}

// Rules is an immutable compiled set, shared by text and stream scanners.
type Rules struct{ rules []compiledRule }

// Compile selects enabled output rules for a textual protocol. The builtin
// card pattern identifies candidates requiring Luhn rather than regex alone.
func Compile(rules []model.AlertRule, protocol string) (*Rules, error) {
	out := &Rules{}
	switch protocol {
	case "ssh", "k8s", "mysql", "postgres", "mssql", "redis":
	default:
		return out, nil
	}
	for _, rule := range rules {
		if !rule.Enabled || rule.Direction != model.DirectionOutput {
			continue
		}
		applies := rule.Protocols == ""
		for _, p := range strings.Split(rule.Protocols, ",") {
			applies = applies || strings.TrimSpace(p) == protocol
		}
		if !applies {
			continue
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile output rule %d: %w", rule.ID, err)
		}
		out.rules = append(out.rules, compiledRule{rule, re, rule.Pattern == CardPattern})
	}
	return out, nil
}

// Match contains byte positions only, never the matching text. End is exclusive.
type Match struct {
	RuleID uint
	Start  int64
	End    int64
}

func (r *Rules) scan(text string, base int64, final bool, emit func(int, Match)) {
	if r == nil {
		return
	}
	for i, rule := range r.rules {
		for _, loc := range rule.re.FindAllStringIndex(text, -1) {
			start, end := loc[0], loc[1]
			// A retained window may begin inside a token. Require its left context.
			if base > 0 && start < 2 {
				continue
			}
			if rule.card {
				// A frame boundary is not a token boundary; wait for up to two lookahead
				// bytes (a separator plus the next digit), or an explicit Flush at EOF.
				if !final && (end == len(text) || end+1 == len(text) && separator(text[end])) {
					continue
				}
				if !cardCandidate(text, start, end) {
					continue
				}
			}
			emit(i, Match{rule.rule.ID, base + int64(start), base + int64(end)})
		}
	}
}

// Scan scans a complete text value.
func (r *Rules) Scan(text string) []Match {
	var matches []Match
	r.scan(text, 0, true, func(_ int, m Match) { matches = append(matches, m) })
	return matches
}

// StreamScanner is single-owner per session. Retained text is bounded; offsets
// and one last emitted position per rule suppress overlap duplicates.
type StreamScanner struct {
	rules   *Rules
	tail    string
	offset  int64
	lastEnd []int64
}

func NewStreamScanner(rules *Rules) *StreamScanner {
	s := &StreamScanner{rules: rules}
	if rules != nil {
		s.lastEnd = make([]int64, len(rules.rules))
	}
	return s
}

// Write scans a frame. Call Flush at end of stream to resolve trailing digits.
func (s *StreamScanner) Write(data []byte) []Match {
	if s.rules == nil || len(s.rules.rules) == 0 || len(data) == 0 {
		return nil
	}
	text := s.tail + string(data)
	base := s.offset - int64(len(s.tail))
	s.offset += int64(len(data))
	matches := s.scan(text, base, false)
	start := len(text) - OverlapBytes
	if start < 0 {
		start = 0
	}
	s.tail = strings.Clone(text[start:])
	return matches
}

func (s *StreamScanner) scan(text string, base int64, final bool) []Match {
	var matches []Match
	s.rules.scan(text, base, final, func(i int, m Match) {
		if m.End <= s.lastEnd[i] {
			return
		}
		s.lastEnd[i] = m.End
		matches = append(matches, m)
	})
	return matches
}

// Flush resolves candidates at the end of the stream. Repeated calls are safe.
func (s *StreamScanner) Flush() []Match {
	if s.rules == nil || len(s.rules.rules) == 0 {
		return nil
	}
	return s.scan(s.tail, s.offset-int64(len(s.tail)), true)
}
