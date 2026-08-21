// Package apierror is the neutral home for the machine-readable API error-code
// system (i18n-backend-error-codes). It depends on neither internal/api nor
// internal/middleware, so both can import it without an import cycle.
//
// The envelope is {"error": <zh fallback>, "code": <machine code>, "params": <controlled>}.
// error is always present (legacy fallback for non-code-aware clients); code and
// params are optional. Codes are registered here with a zh-TW fallback template
// and a param schema; a completeness test binds each code to three-language
// frontend translations (apiError.*).
package apierror

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/notifycat"
)

// ErrCode is a stable, machine-readable error code. Values MUST be created via
// register (so they are in the registry and match CodeGrammar); constructing an
// ErrCode from a bare string literal is forbidden and caught by the AST test.
type ErrCode string

// CodeGrammar constrains code spelling: uppercase start, then uppercase/digit/underscore.
var CodeGrammar = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// placeholderRe extracts {key} interpolation placeholders from a ZhFallback template.
var placeholderRe = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

// reservedEnvelopeKeys cannot be carried by Meta (they are set by Write itself).
var reservedEnvelopeKeys = map[string]bool{"error": true, "code": true, "params": true}

// ParamKind enumerates allowed param value kinds.
type ParamKind int

const (
	// ParamEnum is a semantic ID (e.g. "asset", "admin") resolved to a label on
	// the frontend via an enum getter; ZhLabels supplies the zh wire fallback.
	ParamEnum ParamKind = iota
	// ParamInt is a numeric value passed through verbatim.
	ParamInt
	// ParamOpaque is a free string whose value domain cannot be enumerated (a
	// signer's display name, a rejected-because-unknown key). It is NOT
	// translated and NOT semantically validated: the value is passed through
	// SanitizeOpaque (escape-sequence stripping, control-char folding, rune cap)
	// and then travels verbatim on the wire. Content is never a reason to drop
	// the params — sanitizing, not rejecting, is the contract (mirrors
	// notifycat.KindOpaque, which supplies the shared sanitize implementation).
	//
	// Prefer ParamEnum whenever the value domain is closed; ParamOpaque exists
	// for the cases where an allowlist is impossible by construction.
	ParamOpaque
)

// ParamSpec declares one interpolation parameter of a code. It is the executable
// contract that keeps params to controlled values (New-C3): the writer rejects
// unknown keys, wrong kinds, and enum values outside ZhLabels.
type ParamSpec struct {
	Key      string
	Kind     ParamKind
	EnumNS   string            // frontend enum namespace (informational; e.g. "resource", "role")
	ZhLabels map[string]string // enum value -> zh label for the wire fallback; nil means use the raw value
}

// Descriptor is the registry entry for a code. ZhFallback is a template with
// {key} placeholders (same syntax as vue-i18n and the frontend apiError.zh-TW
// value, so the bijection test compares them as templates).
type Descriptor struct {
	ZhFallback string
	Params     []ParamSpec
}

// registry is the single source of truth. Unexported so it cannot be mutated
// from outside the package (M1); read access is via the accessors below.
var registry = map[ErrCode]Descriptor{}

// register adds a code to the registry, enforcing grammar and uniqueness at
// package-load time (so a bad code panics during tests, not in production).
func register(code ErrCode, d Descriptor) ErrCode {
	s := string(code)
	if !CodeGrammar.MatchString(s) {
		panic("apierror: code violates grammar: " + s)
	}
	if _, dup := registry[code]; dup {
		panic("apierror: duplicate code: " + s)
	}
	// param schema integrity (I2): every ParamEnum MUST carry a ZhLabels allowlist
	// so no arbitrary string can ever be interpolated; every param key must be
	// non-empty; and the template placeholders must exactly match the ParamSpec
	// keys (no orphan {placeholder}, no unused spec).
	specKeys := map[string]bool{}
	for _, p := range d.Params {
		if p.Key == "" {
			panic("apierror: empty param key for code " + s)
		}
		if specKeys[p.Key] {
			panic("apierror: duplicate param key " + p.Key + " for code " + s)
		}
		if p.Kind != ParamEnum && p.Kind != ParamInt && p.Kind != ParamOpaque {
			panic("apierror: param " + p.Key + " for code " + s + " has invalid ParamKind")
		}
		if p.Kind == ParamEnum && len(p.ZhLabels) == 0 {
			panic("apierror: enum param " + p.Key + " for code " + s + " requires a non-empty ZhLabels allowlist")
		}
		// an opaque param has no closed value domain, so labels/namespace would be
		// dead weight that reads as an allowlist it is not (I2 legibility).
		if p.Kind == ParamOpaque && (len(p.ZhLabels) > 0 || p.EnumNS != "") {
			panic("apierror: opaque param " + p.Key + " for code " + s + " must not declare ZhLabels/EnumNS")
		}
		specKeys[p.Key] = true
	}
	placeholders := map[string]bool{}
	for _, m := range placeholderRe.FindAllStringSubmatch(d.ZhFallback, -1) {
		placeholders[m[1]] = true
	}
	for k := range placeholders {
		if !specKeys[k] {
			panic("apierror: code " + s + " template has placeholder {" + k + "} with no ParamSpec")
		}
	}
	for k := range specKeys {
		if !placeholders[k] {
			panic("apierror: code " + s + " ParamSpec " + k + " has no {" + k + "} placeholder in template")
		}
	}
	registry[code] = d
	return code
}

// IsRegistered reports whether code is in the registry.
func IsRegistered(code ErrCode) bool {
	_, ok := registry[code]
	return ok
}

// DescriptorOf returns the descriptor for code as an immutable copy (M1): the
// Params slice is deep-copied so callers cannot mutate the registry's internals.
func DescriptorOf(code ErrCode) (Descriptor, bool) {
	d, ok := registry[code]
	if !ok {
		return Descriptor{}, false
	}
	cp := Descriptor{ZhFallback: d.ZhFallback}
	if d.Params != nil {
		cp.Params = make([]ParamSpec, len(d.Params))
		for i, p := range d.Params {
			cp.Params[i] = p
			if p.ZhLabels != nil {
				labels := make(map[string]string, len(p.ZhLabels))
				for k, v := range p.ZhLabels {
					labels[k] = v
				}
				cp.Params[i].ZhLabels = labels
			}
		}
	}
	return cp, true
}

// AllCodes returns a sorted copy of every registered code (immutable view, M1).
func AllCodes() []ErrCode {
	out := make([]ErrCode, 0, len(registry))
	for c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ErrorResponse is the structured input to Write. Code is required; Params and
// Meta are optional. Meta carries non-text structured metadata that coexists
// with error (e.g. required_permission); it MUST NOT carry error text.
type ErrorResponse struct {
	Code   ErrCode
	Params map[string]any
	Meta   map[string]any
}

// Write emits the unified envelope. error comes from the code's ZhFallback
// (rendered with Params); an unregistered code degrades to a generic 500 in
// production (the AST test prevents this statically). Invalid params are
// dropped (never leaked) after logging.
func Write(c *gin.Context, status int, r ErrorResponse) {
	d, ok := registry[r.Code]
	if !ok {
		log.Printf("[apierror] unregistered code %q (path=%s)", logSafe(string(r.Code)), c.FullPath())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "系統發生錯誤，請稍後再試"})
		return
	}
	params := r.Params
	if err := validateParams(d, params); err != nil {
		// 訊息含被拒的 param 值（請求可控）：淨化＋截斷＋%q 引用後才進日誌，
		// 否則一個帶換行的值就能在 log 裡偽造整行「另一則事件」，帶 ESC 的值
		// 還能操縱讀 log 的終端（C4）。
		log.Printf("[apierror] param validation failed for %q: %q (path=%s)",
			logSafe(string(r.Code)), logSafe(err.Error()), c.FullPath())
		params = nil
	} else {
		// opaque values are sanitized here (not in validateParams, which must stay
		// side-effect free): the sanitized form is what both the wire params and
		// the zh fallback render carry.
		params = sanitizeParams(d, params)
	}
	body := gin.H{
		"error": renderZh(d, params),
		"code":  string(r.Code),
	}
	if len(params) > 0 {
		body["params"] = params
	}
	// Meta carries non-text metadata only; it MUST NOT overwrite the reserved
	// envelope fields (error/code/params) that Write itself owns (I2).
	for k, v := range r.Meta {
		if reservedEnvelopeKeys[k] {
			log.Printf("[apierror] dropped Meta key %q colliding with reserved field (code=%s)", k, r.Code)
			continue
		}
		body[k] = v
	}
	c.JSON(status, body)
}

// Respond is the common case: a status, a code, and optional params.
func Respond(c *gin.Context, status int, code ErrCode, params map[string]any) {
	Write(c, status, ErrorResponse{Code: code, Params: params})
}

// RespondInternal logs the raw cause server-side and returns a generalized,
// code-tagged message. status may be 500 or 502 so sanitizing a leak does not
// change the original error class.
func RespondInternal(c *gin.Context, status int, code ErrCode, cause error) {
	userID, _ := c.Get("userID")
	log.Printf("[apierror] internal %s: %v (path=%s user=%v)", code, cause, c.FullPath(), userID)
	Write(c, status, ErrorResponse{Code: code})
}

// validateParams enforces the code's ParamSpec (I2): every declared param MUST
// be present (so no raw {placeholder} survives), only declared keys are allowed,
// int params must be numeric, and enum params must be a string within the
// mandatory ZhLabels allowlist (register guarantees ZhLabels is non-empty).
func validateParams(d Descriptor, params map[string]any) error {
	specs := map[string]ParamSpec{}
	for _, p := range d.Params {
		specs[p.Key] = p
	}
	for key := range specs {
		if _, ok := params[key]; !ok {
			return &paramError{"missing required param: " + key}
		}
	}
	for k, v := range params {
		spec, ok := specs[k]
		if !ok {
			return &paramError{"unknown param key: " + k}
		}
		switch spec.Kind {
		case ParamInt:
			if !isNumber(v) {
				return &paramError{"param " + k + " must be numeric"}
			}
		case ParamEnum:
			s, ok := v.(string)
			if !ok {
				return &paramError{"param " + k + " must be a string enum id"}
			}
			if _, allowed := spec.ZhLabels[s]; !allowed {
				return &paramError{"param " + k + " value not in allowlist: " + s}
			}
		case ParamOpaque:
			// only the Go type is checked; the content is sanitized (sanitizeParams),
			// never rejected — an opaque value that failed validation would drop the
			// whole param set and silently gut the message it was added to carry.
			if _, ok := v.(string); !ok {
				return &paramError{"param " + k + " must be a string"}
			}
		default:
			return &paramError{"param " + k + " has unknown kind"}
		}
	}
	return nil
}

// sanitizeParams returns a copy of params with every ParamOpaque value passed
// through the shared sanitize contract (notifycat.SanitizeOpaque: ANSI/ESC
// sequences stripped, control characters folded, capped at MaxOpaqueRunes).
// Non-opaque values are copied verbatim; the caller's map is never mutated.
func sanitizeParams(d Descriptor, params map[string]any) map[string]any {
	if len(params) == 0 {
		return params
	}
	opaque := map[string]bool{}
	for _, p := range d.Params {
		if p.Kind == ParamOpaque {
			opaque[p.Key] = true
		}
	}
	if len(opaque) == 0 {
		return params
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		if s, ok := v.(string); ok && opaque[k] {
			out[k] = notifycat.SanitizeOpaque(s)
			continue
		}
		out[k] = v
	}
	return out
}

// renderZh substitutes {key} placeholders in the fallback template with param
// values (enum params use ZhLabels when available, else the raw id). Any
// placeholder left unfilled (e.g. when params were dropped after a validation
// failure) is stripped so a raw {key} never reaches the client (I2); such cases
// are always logged loudly by Write.
// Substitution is a single pass over the template's placeholders (not a
// ReplaceAll per param followed by a strip): a substituted value that itself
// contains {text} must never be re-scanned as a placeholder and erased, which
// matters now that ParamOpaque puts free strings on this path.
func renderZh(d Descriptor, params map[string]any) string {
	if len(d.Params) == 0 {
		return d.ZhFallback
	}
	specs := map[string]ParamSpec{}
	for _, p := range d.Params {
		specs[p.Key] = p
	}
	return placeholderRe.ReplaceAllStringFunc(d.ZhFallback, func(m string) string {
		key := m[1 : len(m)-1]
		v, ok := params[key]
		if !ok {
			return "" // unfilled placeholder: stripped, never leaked raw (I2)
		}
		return stringifyParam(specs[key], v)
	})
}

func stringifyParam(spec ParamSpec, v any) string {
	if s, ok := v.(string); ok {
		if spec.Kind == ParamEnum && spec.ZhLabels != nil {
			if label, ok := spec.ZhLabels[s]; ok {
				return label
			}
		}
		return s
	}
	return fmt.Sprintf("%v", v)
}

// logSafe 淨化要寫進伺服端日誌的請求可控字串（C4）。
//
// 與出站淨化共用 notifycat.SanitizeOpaque：ESC 序列移除、換行與 U+2028/9
// 折成空白、控制字元與零寬/bidi 移除，並截斷至 MaxOpaqueRunes（128，
// 遠低於「日誌單值 ≤200 rune」的上限，不另設第二道截斷）。
// 單行性由淨化保證，呼叫端再一律以 %q 引用加碼：即使日後淨化規則放寬，
// %q 仍會把殘餘特殊字元轉為逸出寫法，不讓它以原形進入日誌檔。
func logSafe(s string) string {
	return notifycat.SanitizeOpaque(s)
}

type paramError struct{ msg string }

func (e *paramError) Error() string { return e.msg }

func isNumber(v any) bool {
	switch v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return true
	}
	return false
}
