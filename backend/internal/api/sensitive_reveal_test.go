package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const revealPlaintext = "private clipboard 4111111111111111"

type revealTestCodec struct{}

func (revealTestCodec) EncryptFor(_ context.Context, _ crypto.CipherRef, plain string) (string, error) {
	return "sealed:" + plain, nil
}
func (revealTestCodec) DecryptFor(_ context.Context, _ crypto.CipherRef, sealed string) (string, error) {
	return strings.TrimPrefix(sealed, "sealed:"), nil
}

type revealTestFailures struct{ causes []string }

func (f *revealTestFailures) Report(_, cause string, _ map[string]string) {
	f.causes = append(f.causes, cause)
}

type revealTestEnv struct {
	*policyTestEnv
	failures *revealTestFailures
}

func newSensitiveRevealEnv(t *testing.T, enabled bool) *revealTestEnv {
	t.Helper()
	env := newPolicyTestEnv(t)
	if err := env.db.AutoMigrate(&model.Session{}, &model.ClipboardEvent{}, &model.CommandAlert{}); err != nil {
		t.Fatal(err)
	}
	asset, task := uint(42), uint(91)
	if err := env.db.Create(&model.Session{ID: 73, SessionID: "reveal-session", UserID: 1, Protocol: model.ProtocolRDP, Status: model.SessionStatusClosed, AssetID: &asset, AccessRequestID: &task}).Error; err != nil {
		t.Fatal(err)
	}
	if err := env.db.Create(&model.ClipboardEvent{ID: 5, SessionID: 73, Direction: "send", ContentStatus: model.ClipboardContentAvailable, ContentLength: len(revealPlaintext), ContentEnc: "sealed:" + revealPlaintext}).Error; err != nil {
		t.Fatal(err)
	}
	if enabled {
		if _, err := env.service.Update(policy.PolicyAlertOnSensitiveReveal, "true", "admin"); err != nil {
			t.Fatal(err)
		}
	}
	failures := &revealTestFailures{}
	reader := session.NewClipboardContentService(env.db, revealTestCodec{}, audit.NewTxSink(), failures)
	h := NewClipboardEventHandler(&stubClipboardLister{}, reader)
	h.SetSensitiveRevealReporter(audit.NewSensitiveRevealService(env.service, audit.NewAlertRecorder(env.db), failures))
	env.router.GET("/api/v1/sessions/:id/clipboard-events/:eventID/content", func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "auditor")
		c.Set("request_id", "reveal-request")
		c.Next()
	}, h.GetContent)
	return &revealTestEnv{policyTestEnv: env, failures: failures}
}
func (e *revealTestEnv) read(t *testing.T, suffix string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, "GET", "/api/v1/sessions/73/clipboard-events/5/content"+suffix, model.RoleAuditor, nil)
}
func revealRowCount(t *testing.T, db *gorm.DB, table string) int64 {
	t.Helper()
	var n int64
	if err := db.Table(table).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}
func TestSensitiveRevealClipboardEnabled(t *testing.T) {
	env := newSensitiveRevealEnv(t, true)
	w := env.read(t, "?reason="+url.QueryEscape("  investigation <incident-7>  "))
	if w.Code != 200 || !strings.Contains(w.Body.String(), revealPlaintext) {
		t.Fatalf("delivery: %d %s", w.Code, w.Body)
	}
	if n := revealRowCount(t, env.db, "audit_logs"); n != 1 {
		t.Fatalf("audit rows=%d", n)
	}
	if n := revealRowCount(t, env.db, "command_alerts"); n != 1 {
		t.Fatalf("alerts=%d", n)
	}
	var row model.CommandAlert
	if err := env.db.Select("id,kind,rule_id,rule_name,reason_code,severity,command,session_id,user_id,asset_id,disposition,note").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Kind != model.AlertKindSensitiveReveal || row.RuleID != nil || row.RuleName != row.Kind || row.ReasonCode != row.Kind || row.Severity != "medium" || row.Command != "" || row.SessionID != 73 || row.UserID != 9 || row.AssetID == nil || *row.AssetID != 42 || row.Disposition != model.AlertDispositionPending {
		t.Fatalf("alert=%+v", row)
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(row.Note), &meta); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{"source_type": "clipboard_event", "source_id": float64(5), "session_id": float64(73), "user_id": float64(9), "username": "auditor", "access_request_id": float64(91), "reason": "investigation <incident-7>", "request_id": "reveal-request"} {
		if meta[key] != want {
			t.Errorf("%s=%v want %v", key, meta[key], want)
		}
	}
	var log model.AuditLog
	if err := env.db.First(&log).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.Details, "investigation ") || log.RequestID != "reveal-request" {
		t.Fatalf("reveal reason/correlation missing: %+v", log)
	}
	// Each audited delivery, including the same event, gets its own alert.
	if w = env.read(t, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if n := revealRowCount(t, env.db, "command_alerts"); n != 2 {
		t.Fatalf("repeated reveal alerts=%d", n)
	}
}
func TestSensitiveRevealClipboardDisabled(t *testing.T) {
	env := newSensitiveRevealEnv(t, false)
	w := env.read(t, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), revealPlaintext) {
		t.Fatalf("delivery: %d %s", w.Code, w.Body)
	}
	if n := revealRowCount(t, env.db, "command_alerts"); n != 0 {
		t.Fatalf("disabled policy wrote %d alerts", n)
	}
	if n := revealRowCount(t, env.db, "audit_logs"); n != 1 {
		t.Fatalf("audit rows=%d", n)
	}
}
func TestSensitiveRevealClipboardAlertContainsNoPlaintext(t *testing.T) {
	env := newSensitiveRevealEnv(t, true)
	if w := env.read(t, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var rows []map[string]any
	if err := env.db.Table("command_alerts").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || strings.Contains(string(raw), revealPlaintext) || strings.Contains(string(raw), "4111111111111111") {
		t.Fatalf("plaintext in alert: %s", raw)
	}
}
func TestSensitiveRevealClipboardAlertFailureStillDelivers(t *testing.T) {
	env := newSensitiveRevealEnv(t, true)
	if err := env.db.Migrator().DropTable(&model.CommandAlert{}); err != nil {
		t.Fatal(err)
	}
	w := env.read(t, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), revealPlaintext) {
		t.Fatalf("alert failure revoked delivery: %d %s", w.Code, w.Body)
	}
	if n := revealRowCount(t, env.db, "audit_logs"); n != 1 {
		t.Fatalf("audit rows=%d", n)
	}
	if len(env.failures.causes) != 1 || env.failures.causes[0] != model.CauseSensitiveRevealAlertWriteFailed {
		t.Fatalf("failure chain=%v", env.failures.causes)
	}
}
func TestSensitiveRevealClipboardAuditFailureDoesNotAlert(t *testing.T) {
	env := newSensitiveRevealEnv(t, true)
	if err := env.db.Migrator().DropTable(&model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	w := env.read(t, "")
	if w.Code != 500 || strings.Contains(w.Body.String(), revealPlaintext) {
		t.Fatalf("fail-close: %d %s", w.Code, w.Body)
	}
	if n := revealRowCount(t, env.db, "command_alerts"); n != 0 {
		t.Fatalf("failed audit wrote %d alerts", n)
	}
}
func TestSensitiveRevealClipboardGapAndInvalidReason(t *testing.T) {
	env := newSensitiveRevealEnv(t, true)
	w := env.read(t, "?reason="+strings.Repeat("a", 1001))
	if w.Code != 400 {
		t.Fatalf("oversize reason: %d", w.Code)
	}
	if n := revealRowCount(t, env.db, "audit_logs"); n != 0 {
		t.Fatalf("invalid reason audited/decrypted: %d", n)
	}
	if err := env.db.Model(&model.ClipboardEvent{}).Where("id=5").Update("content_status", model.ClipboardContentFailed).Error; err != nil {
		t.Fatal(err)
	}
	w = env.read(t, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), `"content":`) {
		t.Fatalf("gap: %d %s", w.Code, w.Body)
	}
	if n := revealRowCount(t, env.db, "command_alerts"); n != 0 {
		t.Fatalf("gap wrote %d alerts", n)
	}
}
func TestSensitiveRevealPolicyAPI(t *testing.T) {
	env := newPolicyTestEnv(t)
	w := env.do(t, "GET", "/api/v1/security-policies", model.RoleAdmin, nil)
	if w.Code != 200 {
		t.Fatalf("GET security-policies: %d %s", w.Code, w.Body)
	}
	var body struct {
		Data []securityPolicyItem `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, v := range body.Data {
		if v.Key == policy.PolicyAlertOnSensitiveReveal {
			if v.Type != policy.PolicyTypeBool || v.Value != "false" {
				t.Fatalf("policy=%+v", v)
			}
			t.Logf("GET /api/v1/security-policies: key=%s type=%s value=%s", v.Key, v.Type, v.Value)
			return
		}
	}
	t.Fatal("sensitive reveal policy missing from API")
}
