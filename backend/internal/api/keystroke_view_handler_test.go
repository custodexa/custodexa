package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/gin-gonic/gin"
)

type fakeKeystrokeViewer struct {
	metaErr, viewErr error
	viewCalls        int
	lastReason       string
}

func (f *fakeKeystrokeViewer) Meta(uint) (*session.KeystrokeMeta, error) {
	if f.metaErr != nil {
		return nil, f.metaErr
	}
	return &session.KeystrokeMeta{State: "complete", Viewable: true}, nil
}

func (f *fakeKeystrokeViewer) View(_ context.Context, id uint, req session.KeystrokeViewRequest,
	_ session.KeystrokeViewOperator) (*session.KeystrokeView, error) {
	f.viewCalls++
	f.lastReason = req.Reason
	if f.viewErr != nil {
		return nil, f.viewErr
	}
	return &session.KeystrokeView{Integrity: "complete", RecordStatus: "complete", RecordID: 5, SessionID: id,
		Events: []session.KeystrokeViewEvent{{Seq: 0, Kind: 1, Source: "user", DataB64: "bHM="}}}, nil
}

type fakeReveal struct{ in []audit.SensitiveRevealInput }

func (f *fakeReveal) Report(_ context.Context, in audit.SensitiveRevealInput) { f.in = append(f.in, in) }

func ksRouter(v *fakeKeystrokeViewer, rv *fakeReveal) *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := NewKeystrokeViewHandler(v)
	if rv != nil {
		h.SetSensitiveRevealReporter(rv)
	}
	r := gin.New()
	r.GET("/sessions/:id/keystrokes", h.Meta)
	r.POST("/sessions/:id/keystrokes/view", h.View)
	return r
}

func ksPost(r *gin.Engine, url, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func errCode(w *httptest.ResponseRecorder) string {
	var out struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out.Code
}

func TestKeystrokeViewReasonValidation(t *testing.T) {
	cjk := func(n int) string { return strings.Repeat("理", n) }
	cases := []struct {
		name, body, code string
		status           int
		calls            int
	}{
		{"缺少理由", `{}`, "VALIDATION_KEYSTROKE_REASON_REQUIRED", 400, 0},
		{"空白理由", `{"reason":"   \n\t "}`, "VALIDATION_KEYSTROKE_REASON_REQUIRED", 400, 0},
		{"本文非 JSON", `not json`, "VALIDATION_KEYSTROKE_REASON_REQUIRED", 400, 0},
		{"1000 個中文字通過", `{"reason":"` + cjk(1000) + `"}`, "", 200, 1},
		{"1001 個中文字超長", `{"reason":"` + cjk(1001) + `"}`, "VALIDATION_KEYSTROKE_REASON_TOO_LONG", 400, 0},
		{"前後空白不計入", `{"reason":"  ` + cjk(1000) + `  "}`, "", 200, 1},
	}
	for _, c := range cases {
		v := &fakeKeystrokeViewer{}
		w := ksPost(ksRouter(v, nil), "/sessions/11/keystrokes/view", c.body)
		if w.Code != c.status || v.viewCalls != c.calls || (c.code != "" && errCode(w) != c.code) {
			t.Errorf("%s: status=%d code=%s calls=%d", c.name, w.Code, errCode(w), v.viewCalls)
		}
	}
}

func TestKeystrokeViewQueryReasonNotAdopted(t *testing.T) {
	v := &fakeKeystrokeViewer{}
	w := ksPost(ksRouter(v, nil), "/sessions/11/keystrokes/view?reason=from-url", `{}`)
	if w.Code != 400 || v.viewCalls != 0 {
		t.Fatalf("查詢字串帶理由不得被採用: status=%d calls=%d", w.Code, v.viewCalls)
	}
	v = &fakeKeystrokeViewer{}
	w = ksPost(ksRouter(v, nil), "/sessions/11/keystrokes/view?reason=from-url", `{"reason":"body-reason"}`)
	if w.Code != 200 || v.lastReason != "body-reason" {
		t.Fatalf("理由應取自本文: status=%d reason=%q", w.Code, v.lastReason)
	}
}

func TestKeystrokeViewErrorMapping(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{session.ErrSessionNotFound, 404, "NOTFOUND_SESSION"},
		{&session.KeystrokeNotViewableError{State: "purged"}, 404, "RESOURCE_KEYSTROKE_NOT_VIEWABLE"},
		{session.ErrKeystrokeVaultSealed, 503, "RULE_KEYSTROKE_VAULT_SEALED"},
		{session.ErrKeystrokeRecordRejected, 422, "RULE_KEYSTROKE_RECORD_REJECTED"},
		{session.ErrKeystrokeAuditUnavailable, 500, "INTERNAL_KEYSTROKE_VIEW"},
	}
	for _, c := range cases {
		rv := &fakeReveal{}
		w := ksPost(ksRouter(&fakeKeystrokeViewer{viewErr: c.err}, rv), "/sessions/11/keystrokes/view", `{"reason":"x"}`)
		if w.Code != c.status || errCode(w) != c.code {
			t.Errorf("%v: status=%d code=%s", c.err, w.Code, errCode(w))
		}
		if len(rv.in) != 0 {
			t.Errorf("%v: 失敗時不得發揭露告警", c.err)
		}
	}
}

func TestKeystrokeViewSuccessReportsRevealAndNoContentInAlert(t *testing.T) {
	rv := &fakeReveal{}
	w := ksPost(ksRouter(&fakeKeystrokeViewer{}, rv), "/sessions/11/keystrokes/view", `{"reason":"工單 1"}`)
	if w.Code != 200 || len(rv.in) != 1 {
		t.Fatalf("status=%d reveals=%d", w.Code, len(rv.in))
	}
	if rv.in[0].SourceType != "keystroke_record" || rv.in[0].SessionID != 11 || rv.in[0].Reason != "工單 1" {
		t.Fatalf("揭露告警欄位不符: %+v", rv.in[0])
	}
}

func TestKeystrokeMetaHandler(t *testing.T) {
	r := ksRouter(&fakeKeystrokeViewer{}, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/sessions/11/keystrokes", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	ksRouter(&fakeKeystrokeViewer{metaErr: session.ErrSessionNotFound}, nil).ServeHTTP(w, httptest.NewRequest("GET", "/sessions/11/keystrokes", nil))
	if w.Code != 404 || errCode(w) != "NOTFOUND_SESSION" {
		t.Fatalf("會話不存在應回既有 404: %d %s", w.Code, errCode(w))
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/sessions/abc/keystrokes", nil))
	if w.Code != 400 {
		t.Fatalf("非法 id: %d", w.Code)
	}
}

func TestKeystrokeViewResponseIsNoStore(t *testing.T) {
	w := ksPost(ksRouter(&fakeKeystrokeViewer{}, nil), "/sessions/5/keystrokes/view", `{"reason":"調查工單 42"}`)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache-control=%q", w.Code, w.Header().Get("Cache-Control"))
	}
}
