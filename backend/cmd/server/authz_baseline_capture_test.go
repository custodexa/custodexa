package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Authorization decision baseline: scenario execution and output capture.

// baselineRecord is the observable outcome of one scenario.
type baselineRecord struct {
	ID     string                    `json:"id"`
	Status int                       `json:"status"`
	Error  map[string]any            `json:"error,omitempty"`
	Body   any                       `json:"body,omitempty"`
	DB     map[string]map[string]any `json:"db,omitempty"`
	FS     map[string]string         `json:"fs,omitempty"`
	Audit  []map[string]any          `json:"audit,omitempty"`
	Alerts []map[string]any          `json:"alerts,omitempty"`
	Remote []string                  `json:"remote,omitempty"`
	Tokens []string                  `json:"tokens,omitempty"`
	Steps  []flowStep                `json:"steps,omitempty"` // flow groups only
}

// baselineAuditTables rows added here go to the audit field.
var baselineAuditTables = map[string]bool{"audit_logs": true}

// baselineAlertTables rows added here go to the alerts field.
var baselineAlertTables = map[string]bool{
	"command_alerts": true, "audit_failure_events": true, "notification_deliveries": true,
	"alert_events": true, "security_events": true,
}

// baselineRequest is a resolved request ready to send.
type baselineRequest struct {
	Method      string
	Path        string // already substituted, with query
	Body        []byte
	ContentType string
	WS          bool
	Settle      time.Duration
	Headers     map[string]string
	// FullBody keeps the body unsummarized whatever its size (body_mode
	// "complete").
	FullBody bool
}

// bodyModeComplete routes.json body_mode for routes whose body is recorded in
// full rather than as a digest once it passes the summary threshold, so a
// difference shows which item changed.
const bodyModeComplete = "complete"

// run executes one scenario as subject and captures its record. The DB,
// filesystem and in-process state are restored before it returns.
func (e *baselineEnv) run(id string, subj *baselineSubject, br baselineRequest) baselineRecord {
	e.recv.take() // discard anything not attributable to this scenario
	var body *bytes.Reader
	if br.Body != nil {
		body = bytes.NewReader(br.Body)
	} else {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(br.Method, br.Path, body)
	if br.ContentType != "" {
		req.Header.Set("Content-Type", br.ContentType)
	}
	if br.WS {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	}
	for k, v := range br.Headers {
		req.Header.Set(k, v)
	}
	subj.authorize(req)
	w := e.serve(req)
	if br.Settle > 0 {
		time.Sleep(br.Settle)
	}
	awaitBackground(e.t)
	rec := baselineRecord{ID: id, Status: w.Code}
	captureBody(&rec, w, br.FullBody)

	touched := e.touched()
	diff := e.diffTables(touched)
	rec.FS = e.fsDiff()
	rec.Remote = remoteList(e.recv.take())
	e.splitDiff(&rec, diff)

	e.resetTables(touched)
	if rec.FS != nil {
		e.resetFS()
	}
	e.resetInProcess(touched)
	return rec
}

// captureBody fills status-dependent body fields.
func captureBody(rec *baselineRecord, w *httptest.ResponseRecorder, full bool) {
	var cookies []string
	for _, c := range w.Result().Cookies() {
		cookies = append(cookies, c.Name)
	}
	ct := w.Header().Get("Content-Type")
	raw := w.Body.Bytes()
	var parsed any
	isJSON := len(raw) > 0 && json.Unmarshal(raw, &parsed) == nil
	rec.Tokens = tokenKinds(parsed, cookies)
	if !isJSON {
		if len(raw) > 0 || ct != "" {
			mt := ct
			if i := strings.Index(mt, ";"); i >= 0 {
				mt = mt[:i]
			}
			rec.Body = map[string]any{"non_json": true, "content_type": mt, "empty": len(raw) == 0}
		}
		return
	}
	norm := normalizeValue("", parsed)
	if rec.Status >= 400 {
		if m, ok := norm.(map[string]any); ok {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			shape := map[string]any{"keys": keys}
			if c, ok := m["code"]; ok {
				shape["code"] = c
			}
			if msg, ok := m["error"]; ok {
				shape["message"] = msg
			}
			rest := map[string]any{}
			for k, v := range m {
				if k != "code" && k != "error" {
					rest[k] = v
				}
			}
			if len(rest) > 0 {
				shape["detail"] = summarizeBody(rest)
			}
			rec.Error = shape
			return
		}
	}
	if full {
		rec.Body = norm
		return
	}
	rec.Body = summarizeBody(norm)
}

// splitDiff routes normalized table diffs to db / audit / alerts.
func (e *baselineEnv) splitDiff(rec *baselineRecord, diff map[string]*rowDiff) {
	for tbl, d := range diff {
		added := normalizeRows(d.Added)
		if baselineAuditTables[tbl] && len(d.Removed) == 0 && len(d.Modified) == 0 {
			rec.Audit = append(rec.Audit, added...)
			continue
		}
		if baselineAlertTables[tbl] && len(d.Removed) == 0 && len(d.Modified) == 0 {
			for _, r := range added {
				r["@table"] = tbl
				rec.Alerts = append(rec.Alerts, r)
			}
			continue
		}
		entry := map[string]any{}
		if len(added) > 0 {
			entry["added"] = added
		}
		if rm := normalizeRows(d.Removed); len(rm) > 0 {
			entry["removed"] = rm
		}
		var mods []any
		for _, m := range d.Modified {
			nm := map[string]any{}
			for col, pair := range m {
				nm[col] = []any{normalizeValue(col, rowScalar(pair[0])), normalizeValue(col, rowScalar(pair[1]))}
			}
			mods = append(mods, nm)
		}
		sortAny(mods)
		if len(mods) > 0 {
			entry["modified"] = mods
		}
		if len(entry) == 0 {
			continue
		}
		if rec.DB == nil {
			rec.DB = map[string]map[string]any{}
		}
		rec.DB[tbl] = entry
	}
	sortRows(rec.Audit)
	sortRows(rec.Alerts)
}

func rowScalar(v any) any {
	switch x := v.(type) {
	case int64:
		return float64(x)
	case nil, float64, bool, string:
		return x
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func normalizeRows(rows []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, normalizeRow(r))
	}
	sortRows(out)
	return out
}

func sortRows(rows []map[string]any) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, _ := json.Marshal(rows[i])
		b, _ := json.Marshal(rows[j])
		return string(a) < string(b)
	})
}

func sortAny(xs []any) {
	sort.SliceStable(xs, func(i, j int) bool {
		a, _ := json.Marshal(xs[i])
		b, _ := json.Marshal(xs[j])
		return string(a) < string(b)
	})
}

// routeEntry is one row of testdata/authz-baseline/routes.json.
type routeEntry struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Params      map[string]any    `json:"params,omitempty"`
	Query       map[string]any    `json:"query,omitempty"`
	Body        json.RawMessage   `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Multipart   *multipartSpec    `json:"multipart,omitempty"`
	WS          bool              `json:"ws,omitempty"`
	SubjectHint string            `json:"subject_hint,omitempty"`
	BodyMode    string            `json:"body_mode"`
	Reason      string            `json:"reason,omitempty"`
	Note        string            `json:"note,omitempty"`
	SettleMS    int               `json:"settle_ms,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type multipartSpec struct {
	Fields map[string]string `json:"fields,omitempty"`
	Files  map[string]struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	} `json:"files,omitempty"`
}

// request resolves a catalog entry into a concrete request.
func (e *baselineEnv) request(r routeEntry) baselineRequest {
	path := r.Path
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, ":") {
			v, ok := r.Params[s[1:]]
			if !ok {
				e.t.Fatalf("routes.json %s %s: no value for path param %s", r.Method, r.Path, s)
			}
			segs[i] = url.PathEscape(toString(e.resolveValue(v)))
		}
	}
	path = strings.Join(segs, "/")
	if len(r.Query) > 0 {
		q := url.Values{}
		for k, v := range r.Query {
			if arr, ok := v.([]any); ok {
				for _, x := range arr {
					q.Add(k, toString(e.resolveValue(x)))
				}
				continue
			}
			q.Set(k, toString(e.resolveValue(v)))
		}
		path += "?" + q.Encode()
	}
	br := baselineRequest{Method: r.Method, Path: path, WS: r.WS, Settle: time.Duration(r.SettleMS) * time.Millisecond, Headers: r.Headers,
		FullBody: r.BodyMode == bodyModeComplete}
	switch {
	case r.Multipart != nil:
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.SetBoundary("authzbaselineboundary")
		keys := make([]string, 0, len(r.Multipart.Fields))
		for k := range r.Multipart.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_ = mw.WriteField(k, e.substitute(r.Multipart.Fields[k]))
		}
		fkeys := make([]string, 0, len(r.Multipart.Files))
		for k := range r.Multipart.Files {
			fkeys = append(fkeys, k)
		}
		sort.Strings(fkeys)
		for _, k := range fkeys {
			f := r.Multipart.Files[k]
			fw, _ := mw.CreateFormFile(k, f.Name)
			_, _ = fw.Write([]byte(e.substitute(f.Content)))
		}
		_ = mw.Close()
		br.Body = buf.Bytes()
		br.ContentType = mw.FormDataContentType()
	case len(r.Body) > 0 && string(r.Body) != "null":
		var v any
		if err := json.Unmarshal(r.Body, &v); err != nil {
			e.t.Fatalf("routes.json %s %s: body: %v", r.Method, r.Path, err)
		}
		b, _ := json.Marshal(e.resolveValue(v))
		br.Body = b
		br.ContentType = "application/json"
	}
	return br
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		b, _ := json.Marshal(x)
		return string(b)
	default:
		b, _ := json.Marshal(x)
		s := string(b)
		return strings.Trim(s, `"`)
	}
}

var _ = http.MethodGet
