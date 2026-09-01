package api

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/custodexa/backend/pkg/crypto"
)

// 離機儲存管理 API 的**設定面**守衛：拒因對照表三軸、角色閘、設定 CRUD 一條龍、
// write-only 讀取、逐拒因的機器碼。裝配見 offsite_storage_fixture_test.go。

// ── A. 拒因對照表的三軸窮盡守衛 ───────────────────────────────────────────

// TestOffsiteReasonCodeTablesExhaustive 服務層的靜態拒因與 HTTP 對照表**三軸**齊全。
//
// 三軸缺一即只驗到一半：
//
//	(A) AllSettingsReasons() 的每一項在 offsiteReasonCodes 有出口，且該碼已註冊
//	(B) offsiteReasonCodes 的每一項都在 AllSettingsReasons() 內（反向：死條目）
//	(C) **AST 掃 profile_settings.go 的 Reason* 常數 ⊆ AllSettingsReasons()**
//	    ——缺 (C) 則「新增常數但漏加進 AllSettingsReasons」不會紅，因為 (A)/(B)
//	    兩軸都以 AllSettingsReasons() 為事實源，漏登記時兩邊會一起漏。
//
// 另加第四項：offsiteReasonStatus 的每個鍵都必須是合法拒因（拼錯的死條目會讓
// 該拒因靜默退回預設 400，而它可能本該是 409）。
//
// **AST 掃描沿用 scanLDAPReasonConstants／ldapReasonBackendRoot**（同 package、
// 以 prefix 參數化、掃描根以 go.mod module 行為錨）：這套機械只該有一份實作。
func TestOffsiteReasonCodeTablesExhaustive(t *testing.T) {
	all := offsite.AllSettingsReasons()
	if len(all) == 0 {
		t.Fatal("AllSettingsReasons() 為空——守衛已在空集合下假綠")
	}
	allSet := map[string]bool{}
	for _, r := range all {
		if allSet[r] {
			t.Errorf("AllSettingsReasons() 有重複項 %q", r)
		}
		allSet[r] = true
	}

	// (A) 服務層 → HTTP 出口，且該碼經 apierror registry 註冊
	for _, reason := range all {
		code, ok := offsiteReasonCodes[reason]
		if !ok {
			t.Errorf("拒因 %q 未登記 HTTP 機器碼——新增拒因須同步 offsiteReasonCodes", reason)
			continue
		}
		if _, registered := apierror.DescriptorOf(code); !registered {
			t.Errorf("拒因 %q 對應的碼 %q 未登記於 apierror registry", reason, code)
		}
	}

	// (B) HTTP 對照表 → 服務層（死條目：對照表有、服務層無）
	for reason := range offsiteReasonCodes {
		if !allSet[reason] {
			t.Errorf("offsiteReasonCodes 有死條目 %q：服務層無此拒因常數", reason)
		}
	}

	// (C) 原始碼常數 → AllSettingsReasons()（漏登記即紅）
	settingsFile := filepath.Join(ldapReasonBackendRoot(t), "internal", "offsite", "profile_settings.go")
	consts := scanLDAPReasonConstants(t, settingsFile, "Reason")
	if len(consts) == 0 {
		t.Fatalf("%s 未掃到任何 Reason* 常數——守衛已在空集合下假綠", settingsFile)
	}
	for name, value := range consts {
		if !allSet[value] {
			t.Errorf("profile_settings.go 的 %s（值 %q）不在 AllSettingsReasons() 內"+
				"——新增拒因常數須同步該函式，否則對照表守衛整組失去射程", name, value)
		}
	}

	// (D) HTTP 狀態表的鍵必須是合法拒因（拼錯即靜默退回預設 400）
	for reason := range offsiteReasonStatus {
		if !allSet[reason] {
			t.Errorf("offsiteReasonStatus 有死條目 %q：服務層無此拒因常數"+
				"（該拒因會靜默退回預設 400）", reason)
		}
	}
}

// ── B. 端點行為 ───────────────────────────────────────────────────────────

// offsiteRoutes 11 條路由的完整清單（角色閘與未認證閘逐條檢查用）。
func offsiteRoutes() []struct {
	method string
	path   string
	body   any
} {
	return []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/v1/offsite-storage/status", nil},
		{http.MethodGet, "/api/v1/offsite-storage/failures", nil},
		{http.MethodPost, "/api/v1/offsite-storage/test", map[string]any{"bucket": "b"}},
		{http.MethodPost, "/api/v1/offsite-storage/retry-failed", map[string]any{}},
		{http.MethodPost, "/api/v1/offsite-storage/objects/1/retry", map[string]any{}},
		{http.MethodGet, "/api/v1/offsite-storage/settings", nil},
		{http.MethodPut, "/api/v1/offsite-storage/settings", map[string]any{"bucket": "b"}},
		{http.MethodPost, "/api/v1/offsite-storage/settings/confirm", map[string]any{"bucket": "b"}},
		{http.MethodPost, "/api/v1/offsite-storage/settings/disable", map[string]any{}},
		{http.MethodGet, "/api/v1/offsite-storage/profiles", nil},
		{http.MethodPost, "/api/v1/offsite-storage/profiles/1/revoke-credentials", map[string]any{}},
	}
}

// TestOffsiteStorageRoutesRequireAdmin 11 條路由全數 admin-only。
//
// **逐條逐角色檢查**：只驗 GET 會讓「PUT 忘了掛角色閘」這種最危險的形態溜過
// ——而這批端點的 PUT／POST 正是憑證寫入與世代切換的入口。
func TestOffsiteStorageRoutesRequireAdmin(t *testing.T) {
	env := newOffsiteAPIEnv(t)
	env.seedUser(t, 300, "someone")

	routes := offsiteRoutes()
	if len(routes) != 11 {
		t.Fatalf("路由清單有 %d 條，RegisterRoutes 註冊 11 條：清單已與實作脫節", len(routes))
	}

	for _, role := range []string{"user", "auditor", "approver"} {
		token, err := env.mgr.GenerateToken(300, "someone", "u@example.com", role, crypto.AuthContext{})
		if err != nil {
			t.Fatalf("簽發 token: %v", err)
		}
		for _, rt := range routes {
			w := env.do(t, rt.method, rt.path, token, rt.body)
			if w.Code != http.StatusForbidden {
				t.Fatalf("role=%s %s %s 應 403，實得 %d (%s)",
					role, rt.method, rt.path, w.Code, w.Body.String())
			}
		}
	}
	// 未帶 token 一律 401（不是 404，也不是靜默放行）
	for _, rt := range routes {
		w := env.do(t, rt.method, rt.path, "", rt.body)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s 未帶 token 應 401，實得 %d (%s)",
				rt.method, rt.path, w.Code, w.Body.String())
		}
	}
}

// TestOffsiteSettingsLifecycle 設定 CRUD 的一條龍（全語義）。
//
// 未設定 → 首次儲存 → 讀回一致 → 有存量時改落點回「需確認」且**零寫入** →
// confirm 切世代 → 歷史世代列表出現新舊兩代 → 過期 confirm 被拒且不回顯現況 →
// 停用（零現行世代而歷史面照常）→ 撤銷憑證。
func TestOffsiteSettingsLifecycle(t *testing.T) {
	env := newOffsiteAPIEnv(t)
	token := env.adminToken(t, 301)

	// (1) 未設定：configured:false 而非 404——「還沒設定」是本資源的正常狀態
	w := env.do(t, http.MethodGet, "/api/v1/offsite-storage/settings", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET 未設定應 200，實得 %d (%s)", w.Code, w.Body.String())
	}
	if body := offsiteBody(t, w); body["configured"] != false {
		t.Fatalf("未設定應回 configured:false: %s", w.Body.String())
	}

	// (2) 首次儲存
	w = env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token,
		env.s3Payload("evidence-bucket-one"))
	if w.Code != http.StatusOK {
		t.Fatalf("首次 PUT 應 200，實得 %d (%s)", w.Code, w.Body.String())
	}
	saved := offsiteBody(t, w)
	if saved["needs_confirmation"] != false || saved["configured"] != true ||
		saved["has_credentials"] != true || saved["credential_mode"] != "stored" {
		t.Fatalf("首次 PUT 回應欄位不符: %s", w.Body.String())
	}
	gen1 := uint(saved["generation_id"].(float64))
	if gen1 == 0 {
		t.Fatalf("首次 PUT 未回世代識別: %s", w.Body.String())
	}

	// (3) GET 反映 PUT
	w = env.do(t, http.MethodGet, "/api/v1/offsite-storage/settings", token, nil)
	got := offsiteBody(t, w)
	if got["bucket"] != "evidence-bucket-one" || got["generation_id"] != saved["generation_id"] ||
		got["endpoint_origin"] != "https://"+offsiteEndpointHost {
		t.Fatalf("GET 未反映 PUT: %s", w.Body.String())
	}

	// (4) 造出存量物件後改落點 → 需確認，且**未做任何寫入**
	env.seedObject(t, gen1, 9001, offsite.StateUploaded)
	moved := env.s3Payload("evidence-bucket-two")
	w = env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token, moved)
	if w.Code != http.StatusOK {
		t.Fatalf("有存量時改落點應 200＋需確認，實得 %d (%s)", w.Code, w.Body.String())
	}
	confirmHint := offsiteBody(t, w)
	if confirmHint["needs_confirmation"] != true {
		t.Fatalf("有存量時改落點應回 needs_confirmation:true: %s", w.Body.String())
	}
	if int64(confirmHint["object_count"].(float64)) != 1 {
		t.Fatalf("需確認回應的 object_count 應為 1: %s", w.Body.String())
	}
	if uint(confirmHint["expected_current_generation_id"].(float64)) != gen1 {
		t.Fatalf("需確認回應的 expected_current_generation_id 應為 %d: %s", gen1, w.Body.String())
	}
	digest, _ := confirmHint["settings_digest"].(string)
	if digest == "" {
		t.Fatalf("需確認回應須帶 settings_digest: %s", w.Body.String())
	}
	// 零寫入的實證：現行設定仍是舊 bucket，且世代表仍只有一列
	w = env.do(t, http.MethodGet, "/api/v1/offsite-storage/settings", token, nil)
	if offsiteBody(t, w)["bucket"] != "evidence-bucket-one" {
		t.Fatalf("「需確認」不得寫入任何東西，現行設定已被改動: %s", w.Body.String())
	}
	var profileRows int64
	if err := env.db.Model(&model.OffsiteProfile{}).Count(&profileRows).Error; err != nil {
		t.Fatalf("計數世代: %v", err)
	}
	if profileRows != 1 {
		t.Fatalf("「需確認」不得建列，世代表現有 %d 列", profileRows)
	}

	// (5) confirm 攜回兩者 → 世代切換成功
	confirmReq := env.s3Payload("evidence-bucket-two")
	confirmReq["expected_current_generation_id"] = gen1
	confirmReq["settings_digest"] = digest
	w = env.do(t, http.MethodPost, "/api/v1/offsite-storage/settings/confirm", token, confirmReq)
	if w.Code != http.StatusOK {
		t.Fatalf("confirm 應 200，實得 %d (%s)", w.Code, w.Body.String())
	}
	switched := offsiteBody(t, w)
	gen2 := uint(switched["generation_id"].(float64))
	if gen2 == gen1 || switched["bucket"] != "evidence-bucket-two" {
		t.Fatalf("confirm 後應是新世代與新落點: %s", w.Body.String())
	}

	// (6) 歷史世代列表出現新舊兩代
	w = env.do(t, http.MethodGet, "/api/v1/offsite-storage/profiles", token, nil)
	profiles := offsiteBody(t, w)
	if int(profiles["total"].(float64)) != 2 {
		t.Fatalf("歷史世代列表應有兩代: %s", w.Body.String())
	}
	items := profiles["data"].([]any)
	seen := map[uint]bool{}
	for _, it := range items {
		m := it.(map[string]any)
		seen[uint(m["generation_id"].(float64))] = true
	}
	if !seen[gen1] || !seen[gen2] {
		t.Fatalf("歷史世代列表應同時含 %d 與 %d: %s", gen1, gen2, w.Body.String())
	}

	// (7) 以**過期的** expected 再 confirm → 靜態拒因，且回應不回顯現況
	staleReq := env.s3Payload("evidence-bucket-two")
	staleReq["expected_current_generation_id"] = gen1
	staleReq["settings_digest"] = digest
	w = env.do(t, http.MethodPost, "/api/v1/offsite-storage/settings/confirm", token, staleReq)
	if w.Code != http.StatusConflict {
		t.Fatalf("過期 confirm 應 409，實得 %d (%s)", w.Code, w.Body.String())
	}
	if code := offsiteErrCode(t, w); code != string(apierror.CodeConflictOffsiteSettingsStaleConfirmation) {
		t.Fatalf("過期 confirm 的機器碼應為 %s，實得 %s",
			apierror.CodeConflictOffsiteSettingsStaleConfirmation, code)
	}
	assertNoSecret(t, "過期 confirm 回應", w.Body.String(),
		[]string{"evidence-bucket-two", "evidence-bucket-one", offsiteEndpointHost, offsiteEndpointPathToken})

	// (8) 停止離機：現行世代歸零，歷史面照常
	w = env.do(t, http.MethodPost, "/api/v1/offsite-storage/settings/disable", token, map[string]any{})
	if w.Code != http.StatusOK {
		t.Fatalf("disable 應 200，實得 %d (%s)", w.Code, w.Body.String())
	}
	w = env.do(t, http.MethodGet, "/api/v1/offsite-storage/settings", token, nil)
	disabled := offsiteBody(t, w)
	if disabled["configured"] != true || disabled["disabled"] != true {
		t.Fatalf("停用態應為 configured:true／disabled:true（與「從未設定」分立）: %s", w.Body.String())
	}
	if n := env.currentGenerationCount(t); n != 0 {
		t.Fatalf("停用後現行世代應為 0 列，實得 %d", n)
	}
	w = env.do(t, http.MethodGet, "/api/v1/offsite-storage/profiles", token, nil)
	if int(offsiteBody(t, w)["total"].(float64)) != 2 {
		t.Fatalf("停用不得影響歷史世代列表: %s", w.Body.String())
	}

	// (9) 撤銷某世代憑證：模式轉 revoked、清除時刻非空、入審計
	before := len(env.journal.all())
	w = env.do(t, http.MethodPost,
		fmt.Sprintf("/api/v1/offsite-storage/profiles/%d/revoke-credentials", gen2), token, map[string]any{})
	if w.Code != http.StatusNoContent {
		t.Fatalf("撤銷憑證應 204，實得 %d (%s)", w.Code, w.Body.String())
	}
	w = env.do(t, http.MethodGet, "/api/v1/offsite-storage/profiles", token, nil)
	var revoked map[string]any
	for _, it := range offsiteBody(t, w)["data"].([]any) {
		m := it.(map[string]any)
		if uint(m["generation_id"].(float64)) == gen2 {
			revoked = m
		}
	}
	if revoked == nil {
		t.Fatalf("撤銷後世代 %d 自列表消失: %s", gen2, w.Body.String())
	}
	if revoked["credential_mode"] != "revoked" {
		t.Fatalf("撤銷後 credential_mode 應為 revoked: %v", revoked)
	}
	if revoked["credentials_cleared_at"] == nil || revoked["credentials_cleared_at"] == "" {
		t.Fatalf("撤銷後 credentials_cleared_at 應非空: %v", revoked)
	}
	if revoked["has_credentials"] != false {
		t.Fatalf("撤銷後 has_credentials 應為 false: %v", revoked)
	}
	// 保管鏈事件（同交易審計面）
	events := env.journal.all()
	if len(events) <= before {
		t.Fatal("撤銷憑證未寫保管鏈事件")
	}
	last := events[len(events)-1]
	if last.Action != offsite.CustodyActionCredRevoke {
		t.Fatalf("撤銷事件的 Action 應為 %s，實得 %s", offsite.CustodyActionCredRevoke, last.Action)
	}
	if uint(last.Details["generation_id"].(uint)) != gen2 {
		t.Fatalf("撤銷事件的 generation_id 應為 %d: %v", gen2, last.Details)
	}
	// 中介層審計面：該次動作在 audit_logs 留得下痕
	revokePath := fmt.Sprintf("/api/v1/offsite-storage/profiles/%d/revoke-credentials", gen2)
	var auditRows []model.AuditLog
	if err := env.db.Where("path = ?", revokePath).Find(&auditRows).Error; err != nil {
		t.Fatalf("讀 audit_logs: %v", err)
	}
	if len(auditRows) == 0 {
		t.Fatalf("撤銷憑證未在 audit_logs 留痕（path=%s）", revokePath)
	}
	if auditRows[0].Resource != model.ResourceOffsiteStorage {
		t.Fatalf("撤銷審計列的 resource 應為 %s，實得 %s",
			model.ResourceOffsiteStorage, auditRows[0].Resource)
	}
}

// TestOffsiteReadEndpointsNeverExposeCredentials 三個讀取端點的 write-only 斷言。
//
// **連遮罩形態都不得出現**：`AKIA****` 說出了這是 AWS 靜態金鑰，`***`＋長度提示
// 說出了 secret 有多長；write-only DTO 要求的是「沒有值、也沒有遮罩」。
// 連帶斷言端點只以 origin 出現——path 段（反向代理前綴）不顯示、不入日誌。
func TestOffsiteReadEndpointsNeverExposeCredentials(t *testing.T) {
	env := newOffsiteAPIEnv(t)
	token := env.adminToken(t, 302)

	// s3 世代（access key 兩欄）
	if w := env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token,
		env.s3Payload("evidence-bucket-one")); w.Code != http.StatusOK {
		t.Fatalf("前置：s3 設定失敗 %d (%s)", w.Code, w.Body.String())
	}
	// gcs 世代（service account JSON：client_email 與私鑰 PEM）
	gcs := map[string]any{
		"provider":             "gcs",
		"bucket":               "evidence-bucket-gcs",
		"prefix":               "custodexa",
		"service_account_json": offsiteFakeSAJSON(),
	}
	if w := env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token, gcs); w.Code != http.StatusOK {
		t.Fatalf("前置：gcs 設定失敗 %d (%s)", w.Code, w.Body.String())
	}

	needles := append(offsiteSecretNeedles(), offsiteMaskNeedles()...)
	for _, path := range []string{
		"/api/v1/offsite-storage/settings",
		"/api/v1/offsite-storage/profiles",
		"/api/v1/offsite-storage/status",
	} {
		w := env.do(t, http.MethodGet, path, token, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s 應 200，實得 %d (%s)", path, w.Code, w.Body.String())
		}
		assertNoSecret(t, "GET "+path+" 回應體", w.Body.String(), needles)
	}

	// 正向控制：端點確實以 **origin** 出現在歷史世代列表裡。
	// 少了這一條，「端點整個沒回」也會讓上面的 path 段斷言通過——那不是
	// 端點紀律要的（origin 是設定頁與稽核唯一該看見的端點形態，不是「什麼都別看見」）。
	w := env.do(t, http.MethodGet, "/api/v1/offsite-storage/profiles", token, nil)
	if !strings.Contains(w.Body.String(), "https://"+offsiteEndpointHost) {
		t.Fatalf("歷史世代列表未帶端點 origin——path 段的斷言因此是空的: %s", w.Body.String())
	}

	// 反向斷言：回應確實還帶得出可稽核的非機密事實，否則「回空字串」也會過
	w = env.do(t, http.MethodGet, "/api/v1/offsite-storage/settings", token, nil)
	view := offsiteBody(t, w)
	if view["bucket"] != "evidence-bucket-gcs" || view["provider"] != "gcs" ||
		view["has_credentials"] != true || view["credential_mode"] != "stored" {
		t.Fatalf("write-only DTO 仍須答得出落點與憑證三態: %s", w.Body.String())
	}
}

// TestOffsiteSaveSettingsRejectionCodes PUT 的靜態拒因逐一出得了門，
// 且**不被併成一支泛碼**——逐因給碼是刻意的（前端要據以指向出錯的欄位）。
func TestOffsiteSaveSettingsRejectionCodes(t *testing.T) {
	env := newOffsiteAPIEnv(t)
	token := env.adminToken(t, 303)

	// 前置：先有一個帶憑證的現行世代（落點變更拒沿用的規則需要既存憑證）
	if w := env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token,
		env.s3Payload("evidence-bucket-one")); w.Code != http.StatusOK {
		t.Fatalf("前置設定失敗: %d (%s)", w.Code, w.Body.String())
	}

	cases := []struct {
		name    string
		payload map[string]any
		status  int
		code    apierror.ErrCode
	}{
		{
			name: "落點變更而憑證留空",
			payload: map[string]any{
				"provider": "s3", "endpoint": "https://" + offsiteEndpointHost,
				"bucket": "attacker-controlled-bucket", "region": "us-east-1",
			},
			status: http.StatusConflict,
			code:   apierror.CodeRuleOffsiteCredentialReuseOnMove,
		},
		{
			name: "端點含 userinfo",
			payload: map[string]any{
				"provider": "s3",
				"endpoint": "https://" + offsiteFakeAccessKey + ":" + offsiteFakeSecret + "@" + offsiteEndpointHost,
				"bucket":   "evidence-bucket-one", "region": "us-east-1",
				"access_key_id": offsiteFakeAccessKey, "secret_access_key": offsiteFakeSecret,
			},
			status: http.StatusBadRequest,
			code:   apierror.CodeValidationOffsiteEndpointHasSecrets,
		},
		{
			name: "端點含 query",
			payload: map[string]any{
				"provider": "s3",
				"endpoint": "https://" + offsiteEndpointHost + "/?X-Amz-Security-Token=" + offsiteFakeSecret,
				"bucket":   "evidence-bucket-one", "region": "us-east-1",
				"access_key_id": offsiteFakeAccessKey, "secret_access_key": offsiteFakeSecret,
			},
			status: http.StatusBadRequest,
			code:   apierror.CodeValidationOffsiteEndpointHasSecrets,
		},
		{
			name: "bucket 空",
			payload: map[string]any{
				"provider": "s3", "endpoint": "https://" + offsiteEndpointHost, "bucket": "",
				"region":        "us-east-1",
				"access_key_id": offsiteFakeAccessKey, "secret_access_key": offsiteFakeSecret,
			},
			status: http.StatusBadRequest,
			code:   apierror.CodeValidationOffsiteBucketRequired,
		},
		{
			name: "provider 非法",
			payload: map[string]any{
				"provider": "azure-blob", "endpoint": "https://" + offsiteEndpointHost,
				"bucket": "evidence-bucket-one", "region": "us-east-1",
			},
			status: http.StatusBadRequest,
			code:   apierror.CodeValidationOffsiteProviderInvalid,
		},
		{
			name: "憑證半套",
			payload: map[string]any{
				"provider": "s3", "endpoint": "https://" + offsiteEndpointHost,
				"bucket": "evidence-bucket-one", "region": "us-east-1",
				"access_key_id": offsiteFakeAccessKey,
			},
			status: http.StatusBadRequest,
			code:   apierror.CodeValidationOffsiteCredentialHalfSet,
		},
		{
			name: "憑證衝突（同時給值與清除旗標）",
			payload: map[string]any{
				"provider": "s3", "endpoint": "https://" + offsiteEndpointHost,
				"bucket": "evidence-bucket-one", "region": "us-east-1",
				"access_key_id": offsiteFakeAccessKey, "secret_access_key": offsiteFakeSecret,
				"clear_credentials": true,
			},
			status: http.StatusBadRequest,
			code:   apierror.CodeValidationOffsiteCredentialConflict,
		},
		{
			name: "s3 端點與 region 皆空",
			payload: map[string]any{
				"provider": "s3", "bucket": "evidence-bucket-one",
				"access_key_id": offsiteFakeAccessKey, "secret_access_key": offsiteFakeSecret,
			},
			status: http.StatusBadRequest,
			code:   apierror.CodeValidationOffsiteRegionOrEndpointRequired,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getLog := captureOperationalLog(t)
			w := env.do(t, http.MethodPut, "/api/v1/offsite-storage/settings", token, tc.payload)
			if w.Code != tc.status {
				t.Fatalf("應 %d，實得 %d (%s)", tc.status, w.Code, w.Body.String())
			}
			if got := offsiteErrCode(t, w); got != string(tc.code) {
				t.Fatalf("機器碼應為 %s，實得 %s (%s)", tc.code, got, w.Body.String())
			}
			// 端點被拒的兩格：回應與 operational log 都不得回顯端點裡那個值
			if strings.Contains(tc.name, "端點含") {
				assertNoSecret(t, "拒絕回應", w.Body.String(), offsiteSecretNeedles())
				assertNoSecret(t, "operational log", getLog(), offsiteSecretNeedles())
			}
		})
	}

	// 反向斷言：前置的現行世代未被任何一次拒絕改動
	w := env.do(t, http.MethodGet, "/api/v1/offsite-storage/settings", token, nil)
	if offsiteBody(t, w)["bucket"] != "evidence-bucket-one" {
		t.Fatalf("被拒的請求不得改動現行設定: %s", w.Body.String())
	}
}
