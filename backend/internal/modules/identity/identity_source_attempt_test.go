package identity_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 檢核面板「最近一次登入嘗試」的測試：取自稽核、依 provider_id 精確比對、
// 原因碼與受控子碼、提供者自報說明的截斷。

// seedProviderWithID 以指定識別碼建一列 provider（測前綴誤配要 5 與 50 並存）
func seedProviderWithID(t *testing.T, db *gorm.DB, id uint) *model.OIDCProvider {
	t.Helper()
	row := &model.OIDCProvider{
		ID: id, Name: "p", Issuer: "https://idp.example.com/" + strings.Repeat("x", int(id%7)),
		ClientID: "cid", Scopes: "openid", GroupsClaim: "groups", Enabled: true,
		AdmissionMode: model.AdmissionPreboundOnly, ClientSecretEnc: "enc",
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed provider %d: %v", id, err)
	}
	return row
}

// seedLoginAudit 寫一列登入稽核（resource=auth、action=login）
func seedLoginAudit(t *testing.T, db *gorm.DB, at time.Time, status model.AuditStatus,
	userID uint, username string, details map[string]any) {
	t.Helper()
	seedAuditRow(t, db, at, model.ResourceAuth, model.ActionLogin, status, userID, username, "", details)
}

func seedAuditRow(t *testing.T, db *gorm.DB, at time.Time, resource model.AuditResource,
	action model.AuditAction, status model.AuditStatus, userID uint, username, errMsg string,
	details map[string]any) {
	t.Helper()
	payload, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	row := &model.AuditLog{
		CreatedAt: at, Action: action, Resource: resource, Status: status,
		UserID: userID, Username: username, ErrorMsg: errMsg, Details: string(payload),
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed audit: %v", err)
	}
}

func providerStatus(t *testing.T, db *gorm.DB, id uint) *identity.SourceStatus {
	t.Helper()
	svc := mappingService(db, audit.NewTxSink())
	st, err := svc.ProviderStatus(id)
	if err != nil {
		t.Fatalf("狀態彙總: %v", err)
	}
	return st
}

// TestLastAttemptReasonCodes 原因碼對照表每一列與兩組子碼白名單逐一一案。
func TestLastAttemptReasonCodes(t *testing.T) {
	type tc struct {
		name       string
		status     model.AuditStatus
		details    map[string]any
		wantCode   string
		wantOut    string
		wantDetail string
		wantEvent  string
	}
	ev := func(event string, kv ...string) map[string]any {
		m := map[string]any{"event": event, "provider_id": 5}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	cases := []tc{
		{"成功", model.StatusSuccess, ev("oidc_login", "stage", ""), "success", "success", "", ""},
		{"第二因素完成點的成功列", model.StatusSuccess,
			map[string]any{"provider_id": 5, "auth_method": "oidc", "provider_name": "p"}, "success", "success", "", ""},
		{"等待第二因素", model.StatusSuccess, ev("oidc_login", "stage", "mfa_pending"), "pending_mfa", "pending", "", ""},
		{"等待註冊第二因素", model.StatusSuccess, ev("oidc_login", "stage", "mfa_enrollment_required"), "pending_mfa_enrollment", "pending", "", ""},
		{"等待變更密碼", model.StatusSuccess, ev("oidc_login", "stage", "password_change_required"), "pending_password_change", "pending", "", ""},
		{"來源位址拒絕", model.StatusDenied, ev("oidc_login", "stage", "source_denied"), "source_denied", "denied", "", ""},
		{"租戶不符", model.StatusDenied, ev("oidc_admission_denied", "failed_rule", "tid"), "admission_tid", "denied", "", ""},
		{"組織網域", model.StatusDenied, ev("oidc_admission_denied", "failed_rule", "hd"), "admission_hd", "denied", "", ""},
		{"email 網域", model.StatusDenied, ev("oidc_admission_denied", "failed_rule", "email_domain"), "admission_email_domain", "denied", "", ""},
		{"email 未驗證", model.StatusDenied, ev("oidc_admission_denied", "failed_rule", "email_verified"), "admission_email_verified", "denied", "", ""},
		{"未預先綁定", model.StatusDenied, ev("oidc_admission_denied", "failed_rule", "not_prebound"), "admission_not_prebound", "denied", "", ""},
		{"換權杖失敗", model.StatusFailure, ev("oidc_flow_error", "reason", "code_exchange_failed"), "code_exchange_failed", "failed", "", ""},
		{"身分權杖缺失", model.StatusFailure, ev("oidc_flow_error", "reason", "id_token_missing"), "id_token_missing", "failed", "", ""},
		{"身分權杖無效", model.StatusFailure, ev("oidc_flow_error", "reason", "id_token_invalid"), "id_token_invalid", "failed", "", ""},
		{"登入中來源不可用", model.StatusFailure, ev("oidc_flow_error", "reason", "provider_unavailable"), "provider_unavailable", "failed", "", ""},
		{"查帳號錯誤", model.StatusFailure, ev("oidc_flow_error", "reason", "identity_lookup_failed"), "internal_error", "failed", "", ""},
		{"帳號名稱衝突", model.StatusDenied, ev("oidc_username_conflict"), "username_conflict", "denied", "", ""},
		{"帳號已刪除", model.StatusDenied, ev("oidc_account_removed"), "account_removed", "denied", "", ""},
		{"帳號已停用", model.StatusDenied, ev("oidc_user_inactive"), "user_inactive", "denied", "", ""},
		{"未知事件帶合法事件名", model.StatusFailure, ev("oidc_future_event"), "unknown", "failed", "", "oidc_future_event"},
		{"未知事件含大寫", model.StatusFailure, ev("Oidc_Future"), "unknown", "failed", "", ""},
		{"未知事件超長", model.StatusFailure, ev(strings.Repeat("a", 65)), "unknown", "failed", "", ""},
	}
	for _, sub := range identity.AttemptRulesNoncompliantDetails {
		if sub == identity.AttemptDetailOther {
			continue
		}
		cases = append(cases, tc{"規則不合規：" + sub, model.StatusDenied,
			ev("oidc_admission_denied", "failed_rule", "rules_noncompliant:"+sub),
			"admission_rules_noncompliant", "denied", sub, ""})
	}
	cases = append(cases, tc{"規則不合規：名單外", model.StatusDenied,
		ev("oidc_admission_denied", "failed_rule", "rules_noncompliant:brand_new"),
		"admission_rules_noncompliant", "denied", "other", ""})
	for _, code := range identity.AttemptProviderErrorDetails {
		if code == identity.AttemptDetailOther {
			continue
		}
		cases = append(cases, tc{"提供者錯誤：" + code, model.StatusDenied,
			ev("oidc_provider_denied", "provider_error", code), "provider_error", "denied", code, ""})
	}
	cases = append(cases, tc{"提供者錯誤：名單外", model.StatusDenied,
		ev("oidc_provider_denied", "provider_error", "invalid_request"), "provider_error", "denied", "other", ""})
	if got := len(identity.AttemptRulesNoncompliantDetails); got != 7 {
		t.Fatalf("准入不合規子碼白名單 %d 項，want 6＋other", got)
	}
	if got := len(identity.AttemptProviderErrorDetails); got != 9 {
		t.Fatalf("提供者錯誤白名單 %d 項，want 8＋other", got)
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db := setupMappingDB(t)
			seedProviderWithID(t, db, 5)
			seedLoginAudit(t, db, time.Now().Add(-time.Hour), c.status, 7, "alice", c.details)
			a := providerStatus(t, db, 5).LastAttempt
			if a == nil {
				t.Fatal("last_attempt = null，want 有值")
			}
			if a.ReasonCode != c.wantCode || a.Outcome != c.wantOut {
				t.Fatalf("reason_code／outcome = %s／%s，want %s／%s", a.ReasonCode, a.Outcome, c.wantCode, c.wantOut)
			}
			if a.ReasonDetail != c.wantDetail || a.Event != c.wantEvent {
				t.Fatalf("reason_detail／event = %q／%q，want %q／%q", a.ReasonDetail, a.Event, c.wantDetail, c.wantEvent)
			}
			if a.Username != "alice" || a.WindowDays != 30 {
				t.Fatalf("username／window_days = %q／%d", a.Username, a.WindowDays)
			}
			raw, err := json.Marshal(a)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if c.wantDetail != "" && !strings.Contains(string(raw), `"reason_detail":"`+c.wantDetail+`"`) {
				t.Fatalf("JSON 欄位名應為 reason_detail：%s", raw)
			}
			if c.wantEvent != "" && !strings.Contains(string(raw), `"event":"`+c.wantEvent+`"`) {
				t.Fatalf("JSON 欄位名應為 event：%s", raw)
			}
			if c.wantEvent == "" && strings.Contains(string(raw), `"event"`) {
				t.Fatalf("不合格式或非 unknown 時應省略 event：%s", raw)
			}
		})
	}
}

// TestLastAttemptPrefixProviderIsolated provider 5 與 50 並存時只取 5 的；
// 50 有超過一批的較新列時，仍回 5 那一筆較舊的列而不是 null。
func TestLastAttemptPrefixProviderIsolated(t *testing.T) {
	db := setupMappingDB(t)
	seedProviderWithID(t, db, 5)
	seedProviderWithID(t, db, 50)
	base := time.Now().Add(-48 * time.Hour)
	seedLoginAudit(t, db, base, model.StatusDenied, 7, "five",
		map[string]any{"event": "oidc_admission_denied", "provider_id": 5, "failed_rule": "tid"})
	for i := 0; i < 250; i++ {
		seedLoginAudit(t, db, base.Add(time.Duration(i+1)*time.Minute), model.StatusSuccess, 8, "fifty",
			map[string]any{"event": "oidc_login", "stage": "", "provider_id": 50})
	}
	a := providerStatus(t, db, 5).LastAttempt
	if a == nil {
		t.Fatal("provider 50 的大量較新列不得讓 provider 5 被判成查無")
	}
	if a.Username != "five" || a.ReasonCode != "admission_tid" {
		t.Fatalf("取到 %s／%s，want provider 5 的 five／admission_tid", a.Username, a.ReasonCode)
	}
	if b := providerStatus(t, db, 50).LastAttempt; b == nil || b.Username != "fifty" {
		t.Fatalf("provider 50 應取到自己的列：%+v", b)
	}
}

// TestLastAttemptSuccessSeparateFromAttempt 最近一筆是拒絕、較早一筆是本地帳號的成功登入時，
// last_attempt 為拒絕、last_success 的 mapping_eligible=false。
func TestLastAttemptSuccessSeparateFromAttempt(t *testing.T) {
	db := setupMappingDB(t)
	seedProviderWithID(t, db, 5)
	local := &model.User{Username: "hybrid", Password: "x", Active: true}
	if err := db.Create(local).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	now := time.Now()
	seedLoginAudit(t, db, now.Add(-2*time.Hour), model.StatusSuccess, local.ID, "hybrid",
		map[string]any{"event": "oidc_login", "stage": "", "provider_id": 5})
	seedLoginAudit(t, db, now.Add(-time.Hour), model.StatusDenied, 0, "",
		map[string]any{"event": "oidc_admission_denied", "provider_id": 5, "failed_rule": "tid"})
	st := providerStatus(t, db, 5)
	if st.LastAttempt == nil || st.LastAttempt.ReasonCode != "admission_tid" {
		t.Fatalf("last_attempt = %+v，want 拒絕", st.LastAttempt)
	}
	if st.LastSuccess == nil {
		t.Fatal("last_success = null，want 較早的成功登入")
	}
	if st.LastSuccess.MappingEligible {
		t.Fatal("本地帳號綁外部身分者 mapping_eligible 應為 false")
	}
	if !st.LastSuccess.At.Before(st.LastAttempt.At) {
		t.Fatalf("last_success.at %v 應早於 last_attempt.at %v", st.LastSuccess.At, st.LastAttempt.At)
	}
}

// TestLastAttemptSuccessAccountRemoved 最近一次成功登入的帳號已刪除：
// account_removed=true、mapping_eligible=false；帳號仍在時 account_removed=false。
func TestLastAttemptSuccessAccountRemoved(t *testing.T) {
	db := setupMappingDB(t)
	seedProviderWithID(t, db, 5)
	jit := &model.User{Username: "jit-user", Password: "x", Active: true}
	if err := db.Create(jit).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	seedLoginAudit(t, db, time.Now().Add(-time.Hour), model.StatusSuccess, jit.ID, "jit-user",
		map[string]any{"event": "oidc_login", "stage": "", "provider_id": 5})
	if st := providerStatus(t, db, 5); st.LastSuccess == nil || st.LastSuccess.AccountRemoved {
		t.Fatalf("帳號仍在時 last_success = %+v，want account_removed=false", st.LastSuccess)
	}
	if err := db.Delete(jit).Error; err != nil {
		t.Fatalf("delete user: %v", err)
	}
	st := providerStatus(t, db, 5)
	if st.LastSuccess == nil || !st.LastSuccess.AccountRemoved || st.LastSuccess.MappingEligible {
		t.Fatalf("帳號已刪除時 last_success = %+v，want account_removed=true、mapping_eligible=false", st.LastSuccess)
	}
	raw, err := json.Marshal(st.LastSuccess)
	if err != nil || !strings.Contains(string(raw), `"account_removed":true`) {
		t.Fatalf("欄位名應為 account_removed，實得 %s（err=%v）", raw, err)
	}
}

// TestLastAttemptOutsideWindow 30 天前的列不取，回 null。
func TestLastAttemptOutsideWindow(t *testing.T) {
	db := setupMappingDB(t)
	seedProviderWithID(t, db, 5)
	seedLoginAudit(t, db, time.Now().AddDate(0, 0, -31), model.StatusSuccess, 7, "old",
		map[string]any{"event": "oidc_login", "stage": "", "provider_id": 5})
	st := providerStatus(t, db, 5)
	if st.LastAttempt != nil || st.LastSuccess != nil {
		t.Fatalf("窗外的列不得取：last_attempt=%+v last_success=%+v", st.LastAttempt, st.LastSuccess)
	}
}

// TestLastAttemptMFACompletedAfterPending mfa_pending 之後的成功列取成功；
// oidc_user_provisioned（resource=user）不被取。
func TestLastAttemptMFACompletedAfterPending(t *testing.T) {
	db := setupMappingDB(t)
	seedProviderWithID(t, db, 5)
	now := time.Now()
	seedLoginAudit(t, db, now.Add(-3*time.Minute), model.StatusSuccess, 7, "alice",
		map[string]any{"event": "oidc_login", "stage": "mfa_pending", "provider_id": 5})
	seedLoginAudit(t, db, now.Add(-2*time.Minute), model.StatusSuccess, 7, "alice",
		map[string]any{"provider_id": 5, "provider_name": "p", "auth_method": "oidc"})
	seedAuditRow(t, db, now.Add(-time.Minute), model.ResourceUser, model.ActionCreate,
		model.StatusSuccess, 7, "alice", "",
		map[string]any{"event": "oidc_user_provisioned", "provider_id": 5})
	a := providerStatus(t, db, 5).LastAttempt
	if a == nil || a.ReasonCode != "success" || a.Outcome != "success" {
		t.Fatalf("last_attempt = %+v，want 第二因素完成後的成功", a)
	}
}

// TestLastAttemptProviderDescriptionTruncated 提供者自報說明以字元截為 200，仍為合法 UTF-8。
func TestLastAttemptProviderDescriptionTruncated(t *testing.T) {
	db := setupMappingDB(t)
	seedProviderWithID(t, db, 5)
	long := strings.Repeat("錯", 300)
	seedLoginAudit(t, db, time.Now().Add(-time.Minute), model.StatusDenied, 0, "",
		map[string]any{"event": "oidc_provider_denied", "provider_id": 5,
			"provider_error": "access_denied", "provider_error_description": long})
	a := providerStatus(t, db, 5).LastAttempt
	if a == nil {
		t.Fatal("last_attempt = null")
	}
	if n := utf8.RuneCountInString(a.ProviderErrorDescription); n != 200 {
		t.Fatalf("說明長 %d 字元，want 200", n)
	}
	if !utf8.ValidString(a.ProviderErrorDescription) {
		t.Fatal("截斷後不是合法 UTF-8")
	}
}
