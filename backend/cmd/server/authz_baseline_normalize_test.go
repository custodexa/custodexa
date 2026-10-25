package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Authorization decision baseline: normalization rules (single source).
//
// Only values that are not deterministic across runs are masked: wall-clock
// timestamps, random identifiers, tokens and nonces, hash-chain and signature
// material, and durations. Auto-increment IDs are NOT masked: every scenario
// starts from the same template, so IDs are deterministic. The comparator
// self-test (TestAuthzBaselineApprovedDiffs) proves the masks are not so wide
// that a difference in an unmasked field disappears.

// maskedKeyExact keys whose values are always masked (case-insensitive).
var maskedKeyExact = map[string]string{
	"token": "token", "access_token": "token", "refresh_token": "token", "id_token": "token",
	"ticket": "token", "grant": "token", "session_token": "token", "scoped_token": "token",
	"connect_token": "token", "monitor_token": "token", "share_token": "token", "recording_token": "token",
	"nonce": "nonce", "code_verifier": "nonce", "pkce_verifier": "nonce",
	"jti": "nonce", "request_id": "nonce", "correlation_id": "nonce", "trace_id": "nonce",
	"secret": "secret", "otpauth_url": "secret", "qr_code": "secret", "totp_secret": "secret",
	"uptime": "duration", "uptime_seconds": "duration", "elapsed_ms": "duration",
	"duration_ms": "duration", "latency_ms": "duration", "age_seconds": "duration", "duration_seconds": "duration",
	"unsealed_at": "time", "server_time": "time", "now": "time",
	"duration": "duration", "diagnostic_id": "nonce", "public_key": "key", "public_key_pem": "key",
}

// maskedKeySubstrings keys containing any of these are masked.
var maskedKeySubstrings = map[string]string{
	"hash":        "digest",
	"signature":   "digest",
	"_mac":        "digest",
	"hmac":        "digest",
	"fingerprint": "digest",
}

// alwaysKeepKeys keys never masked by the substring rule (they carry
// deterministic, decision-relevant data).
var alwaysKeepKeys = map[string]bool{
	"hash_algorithm": true,
}

var (
	reTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?( [+-]\d{4} \w+)?$`)
	reJWT       = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
	reUUID      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reBcrypt    = regexp.MustCompile(`^\$2[aby]\$\d\d\$`)
	reLongHex   = regexp.MustCompile(`^[0-9a-fA-F]{32,}$`)
	reEmbedTime = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?`)
	reEmbedJWT  = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)
	reEmbedUUID = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reEmbedHex  = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)
	// Runtime session identifiers embed a nanosecond clock reading
	// ("sess_<unix nanos>_<user id>"); the user id part is kept.
	reSessionID = regexp.MustCompile(`\bsess_\d{16,}_`)
	// Unix timestamps in seconds or milliseconds (2001..2286).
	reEpochKey = regexp.MustCompile(`(^|_)(exp|iat|nbf|ts|epoch)$`)
)

// bodySummaryThreshold bodies larger than this are recorded as a summary.
const bodySummaryThreshold = 16 * 1024

// normalizeValue applies the masking rules recursively. key is the map key
// under which v was found ("" at top level).
func normalizeValue(key string, v any) any {
	lk := strings.ToLower(key)
	// Connectivity-probe latency is wall-clock dependent, yet the golden files record
	// it as 0 in every row. Clamp to 0 rather than mask or drop so the existing golden
	// stays byte-identical while a loaded machine no longer produces a timing-only diff.
	if lk == "last_test_latency_ms" {
		if f, ok := v.(float64); ok && f != 0 {
			return float64(0)
		}
	}
	if kind, ok := maskedKeyExact[lk]; ok && !isEmptyValue(v) {
		return "<" + kind + ">"
	}
	if !alwaysKeepKeys[lk] {
		for sub, kind := range maskedKeySubstrings {
			if strings.Contains(lk, sub) && !isEmptyValue(v) {
				return "<" + kind + ">"
			}
		}
	}
	if reEpochKey.MatchString(lk) {
		if f, ok := v.(float64); ok && f > 1e9 {
			return "<time>"
		}
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			// Durations are dropped rather than masked: a zero duration is
			// often omitted from the payload, so masking would still leave
			// key presence varying with timing.
			if maskedKeyExact[strings.ToLower(k)] == "duration" {
				continue
			}
			out[k] = normalizeValue(k, val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = normalizeValue(key, val)
		}
		return out
	case string:
		return normalizeString(x)
	default:
		return v
	}
}

func isEmptyValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	}
	return false
}

// baselinePathMasks per-run temporary directories, replaced by "<tmp>".
var baselinePathMasks []string

// normalizeString masks volatile strings and recurses into embedded JSON.
func normalizeString(s string) any {
	for _, p := range baselinePathMasks {
		if p != "" {
			s = strings.ReplaceAll(s, p, "<tmp>")
		}
	}
	switch {
	case reBcrypt.MatchString(s):
		return "<bcrypt>"
	case strings.HasPrefix(s, "enc:"):
		return "<enc>"
	case reTimestamp.MatchString(s):
		return "<time>"
	case reJWT.MatchString(s):
		return "<jwt>"
	case reUUID.MatchString(s):
		return "<uuid>"
	case reLongHex.MatchString(s):
		return "<hex>"
	}
	s = reSessionID.ReplaceAllString(s, "sess_<clock>_")
	t := strings.TrimSpace(s)
	if len(t) > 1 && (t[0] == '{' || t[0] == '[') {
		var inner any
		if json.Unmarshal([]byte(t), &inner) == nil {
			// The embedded document is normalized value by value, and each string in it is
			// date-shifted on its own; shifting the raw text here as well would move the dates
			// twice.
			b, _ := json.Marshal(normalizeValue("", inner))
			return "json:" + string(b)
		}
	}
	// A "json:" string is the output of an earlier normalization pass (its dates were shifted
	// while it was built); shifting it again would move them twice.
	if !strings.HasPrefix(s, "json:") {
		s = shiftBaselineDates(s)
	}
	if len(s) > 20 {
		s = reEmbedJWT.ReplaceAllString(s, "<jwt>")
		s = reEmbedTime.ReplaceAllString(s, "<time>")
		s = reEmbedUUID.ReplaceAllString(s, "<uuid>")
		s = reEmbedHex.ReplaceAllString(s, "<hex>")
	}
	return s
}

// normalizeRow normalizes a DB row (column -> value); timestamps stored as
// driver time values are rendered as strings first.
func normalizeRow(row map[string]any) map[string]any {
	out := make(map[string]any, len(row))
	for k, v := range row {
		if maskedKeyExact[strings.ToLower(k)] == "duration" {
			continue
		}
		switch x := v.(type) {
		case int64:
			out[k] = normalizeValue(k, float64(x))
		case float64, bool, nil, string:
			out[k] = normalizeValue(k, x)
		default:
			out[k] = normalizeValue(k, fmt.Sprint(x))
		}
	}
	return out
}

// summarizeBody replaces an oversized normalized body with a digest, the
// top-level keys, array lengths and count fields.
func summarizeBody(v any) any {
	raw, _ := json.Marshal(v)
	if len(raw) <= bodySummaryThreshold {
		return v
	}
	return summaryOf(v, raw)
}

// forceSummarizeBody summarizes a body whatever its size. The comparator
// uses it to compare a body captured in full against a golden that holds the
// same route's body as a summary.
func forceSummarizeBody(v any) any {
	raw, _ := json.Marshal(v)
	return summaryOf(v, raw)
}

// isBodySummary reports whether a (decoded) body is a summary made by
// summarizeBody.
func isBodySummary(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	_, sha := m["summary_sha256"]
	_, n := m["bytes"]
	return sha && n
}

func summaryOf(v any, raw []byte) any {
	sum := sha256.Sum256(raw)
	s := map[string]any{"summary_sha256": hex.EncodeToString(sum[:]), "bytes": len(raw)}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		lengths := map[string]any{}
		for k, val := range x {
			keys = append(keys, k)
			if arr, ok := val.([]any); ok {
				lengths[k] = len(arr)
			}
			if lk := strings.ToLower(k); lk == "total" || lk == "count" || strings.HasSuffix(lk, "_count") {
				s[k] = val
			}
		}
		sort.Strings(keys)
		s["keys"] = keys
		if len(lengths) > 0 {
			s["array_lengths"] = lengths
		}
	case []any:
		s["array_length"] = len(x)
	}
	return s
}

// tokenKinds lists which credential-like fields a response carried.
func tokenKinds(v any, cookies []string) []string {
	seen := map[string]bool{}
	var walk func(any)
	walk = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			for k, val := range x {
				if _, ok := maskedKeyExact[strings.ToLower(k)]; ok {
					if s, ok := val.(string); ok && s != "" && maskedKeyExact[strings.ToLower(k)] == "token" {
						seen["body:"+k] = true
					}
				}
				walk(val)
			}
		case []any:
			for _, val := range x {
				walk(val)
			}
		}
	}
	walk(v)
	for _, c := range cookies {
		seen["cookie:"+c] = true
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- date freezing ----
//
// The product derives many response fields from "today" (pending review days, statistics
// windows, recording dates, compliance evaluation dates, and request paths built from the
// scenario date objects). The golden records were captured on one UTC date, so a run on a
// later date differs for that reason alone. Fresh output is therefore shifted back by the
// number of days between today and the capture date before it is summarised and compared:
// every bare YYYY-MM-DD inside [capture-45d, capture+1d] after shifting is mapped back.
// On the capture date the shift is 0. The golden files are never rewritten.

var reBareDate = regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)

// baselineClock returns "today" (UTC midnight) for the comparison; AUTHZ_BASELINE_DATE pins it.
func baselineClock() time.Time {
	if pinned := os.Getenv("AUTHZ_BASELINE_DATE"); pinned != "" {
		if d, err := time.Parse("2006-01-02", pinned); err == nil {
			return d
		}
	}
	n := time.Now().UTC()
	return time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC)
}

var (
	captureDateOnce sync.Once
	captureDate     time.Time
)

func baselineCaptureDate() (time.Time, bool) {
	captureDateOnce.Do(func() {
		if m, err := loadManifest(); err == nil {
			if d, err := time.Parse("2006-01-02", m.CapturedAt); err == nil {
				captureDate = d
			}
		}
	})
	return captureDate, !captureDate.IsZero()
}

// shiftBaselineDatesBy maps dates in the window [capture+shift-45d, capture+shift+1d] back by
// shift days. Dates outside the window are fixed values and stay as they are.
func shiftBaselineDatesBy(s string, capture time.Time, shiftDays int) string {
	if shiftDays == 0 {
		return s
	}
	lo := capture.AddDate(0, 0, shiftDays-45)
	hi := capture.AddDate(0, 0, shiftDays+1)
	return reBareDate.ReplaceAllStringFunc(s, func(m string) string {
		d, err := time.Parse("2006-01-02", m)
		if err != nil || d.Before(lo) || d.After(hi) {
			return m
		}
		return d.AddDate(0, 0, -shiftDays).Format("2006-01-02")
	})
}

func shiftBaselineDates(s string) string {
	capture, ok := baselineCaptureDate()
	if !ok {
		return s
	}
	shift := int(baselineClock().Sub(capture).Hours() / 24)
	if shift <= 0 {
		return s
	}
	return shiftBaselineDatesBy(s, capture, shift)
}
