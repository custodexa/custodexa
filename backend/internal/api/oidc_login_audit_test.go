package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// OIDC 登入留痕。
//
// # 本檔釘的是什麼
//
// 實測基準：OIDC 成功登入**零審計列**（兩輪實走 max(audit_logs.id) 不動，
// 而 users.last_login_at 確實更新——登入真的發生了，只是無痕），JIT 首登建帳號
// 同樣無痕，失敗列則 client_ip／path／method／status_code 四欄全空、resource 標成
// `user`。共同根因是留痕全由 `oidc_login_service.go` 承擔，而該層**結構上拿不到
// `*gin.Context`**，那四欄不可能填。
//
// 修法是把落地點移到 handler：service 交回審計意向，handler 補請求脈絡後寫入。
// 故本檔驗的是「意向真的變成了列，且列上有只有 handler 才拿得到的東西」——
// service 層的意向內容（狀態語義、事件名、不含 claim 明文）由
// `internal/modules/identity/oidc_flow_error_audit_test.go` 與 `oidc_provision_test.go` 承擔。
//
// # 突變自檢（三者互不掩蓋）
//
//  1. 移除 `Exchange` 的 `h.auditOIDCLogin(c, resp)` → 成功列不見
//     → TestOIDCExchangeSuccessIsAudited 紅（其餘兩格全綠）。
//  2. `oidc_login_service.go` 的 `resp.AuthProviderID/Name` 兩行拿掉（或 handler 的
//     Details 不帶 provider）→ TestOIDCExchangeSuccessIsAudited 的 provider 斷言紅。
//  3. 移除 `Callback` 失敗路徑的 `h.writeOIDCAudit(...)` → TestOIDCCallbackFailureRowCarriesRequestContext 紅。
//
// 另：把 service 的 `trail.flowError` 狀態由 failure 改回 denied、或把
// `trail.admissionDenied` 的 denied 改成 failure，皆由 identity 包的兩支測試轉紅——
// 狀態語義的分流不在本檔重複斷言，避免兩處各自演化。

const oidcAuditRemoteAddr = "203.0.113.9:51515"

type oidcAuditEnv struct {
	h        *OIDCHandler
	db       *gorm.DB
	provider *model.OIDCProvider
	user     *model.User
}

func setupOIDCAuditEnv(t *testing.T) *oidcAuditEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// 單連線：ff51836 的「單獨跑綠、整包跑紅」防護
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.RefreshToken{},
		&model.SecurityPolicy{}, &model.PasswordHistory{}, &model.OIDCProvider{},
		&model.UserExternalIdentity{}, &model.OIDCFlowState{}, &model.OIDCLoginTicket{},
		&model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS user_roles (
		user_id INTEGER NOT NULL, role_id INTEGER NOT NULL)`).Error; err != nil {
		t.Fatalf("user_roles: %v", err)
	}
	if err := db.Create(&model.Role{Name: model.RoleUser, Description: "一般使用者"}).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	auth := identity.NewAuthService("oidc-audit-secret", 15*time.Minute)
	auth.SetSecurityPolicies(policy.NewSecurityPolicyService(db))
	// codec／egress 為 nil：本檔不觸及密鑰解密與出站政策（provider secret 留空）
	providers := identity.NewOIDCProviderService(db, nil, nil, nil, "https://bastion.example.com")
	login := identity.NewOIDCLoginService(db, providers, nil, auth, nil)

	// 同步落地（AsyncAuditEnabled=false）：非同步 sink 有 worker 與 flush 週期，
	// 測試只能等，等不到也證明不了「沒有落」
	auditService := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	h := NewOIDCHandler(providers, login, "https://bastion.example.com", auditService)
	h.SetSourcePolicyReader(unrestrictedSourcePolicy())

	p := &model.OIDCProvider{
		Name: "corp-idp", Issuer: "https://idp.example.com", ClientID: "cid-1",
		Scopes: "openid profile email", AdmissionMode: model.AdmissionPreboundOnly,
		Enabled: true, AuthEpoch: 3, // 非零起始，使世代比對不是與零值相符
	}
	if err := db.Create(p).Error; err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if err := db.Model(&model.OIDCProvider{}).Where("id = ?", p.ID).
		Update("enabled", true).Error; err != nil {
		t.Fatalf("set enabled: %v", err)
	}

	u := &model.User{
		Username: "sso-user", Password: "x", Active: true,
		ProvisioningOrigin: model.AuthSourceOIDC, ExternalCredential: true,
		CredentialEpoch: 2,
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Exec("DELETE FROM audit_logs").Error; err != nil {
		t.Fatalf("清空 seed 期審計列: %v", err)
	}
	return &oidcAuditEnv{h: h, db: db, provider: p, user: u}
}

// issueTicket 直接落一張合法交棒憑證（世代取自現況）。
// 不走 callback：本檔驗的是 exchange 成功之後有沒有留痕，前段的 IdP 往返與此無關
func (e *oidcAuditEnv) issueTicket(t *testing.T) string {
	t.Helper()
	plain := "ticket-" + hex.EncodeToString([]byte("fixed-seed-value"))
	sum := sha256.Sum256([]byte(plain))
	ticket := model.OIDCLoginTicket{
		TokenHash: hex.EncodeToString(sum[:]), UserID: e.user.ID, ProviderID: e.provider.ID,
		AuthEpoch: e.provider.AuthEpoch, CredEpoch: e.user.CredentialEpoch,
		AuthMethod: crypto.AuthMethodOIDC,
		ExpiresAt:  time.Now().Add(time.Minute),
	}
	if err := e.db.Create(&ticket).Error; err != nil {
		t.Fatalf("seed ticket: %v", err)
	}
	return plain
}

func (e *oidcAuditEnv) postExchange(t *testing.T, ticket string) int {
	t.Helper()
	r := gin.New()
	r.POST("/api/v1/auth/oidc/exchange", e.h.Exchange)
	body, _ := json.Marshal(map[string]string{"ticket": ticket})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = oidcAuditRemoteAddr
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// loginRows 取出 audit_logs 內的登入類列（新到舊無關，本檔每格都清空後起算）
func (e *oidcAuditEnv) rows(t *testing.T) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatalf("讀審計列: %v", err)
	}
	return rows
}

// assertRequestContext 四欄非空且與本次請求相符——**這四欄是 service 層寫不出來的**，
// 也是把留痕移到 handler 的全部理由。任何「把留痕搬回 service」的回退都會在此轉紅
func assertRequestContext(t *testing.T, row model.AuditLog, wantPath string, wantStatus int) {
	t.Helper()
	if row.ClientIP != "203.0.113.9" {
		t.Errorf("client_ip = %q, want 203.0.113.9（來源位址取自連線對端）", row.ClientIP)
	}
	if row.Path != wantPath {
		t.Errorf("path = %q, want %q", row.Path, wantPath)
	}
	if row.Method == "" {
		t.Error("method 不得為空")
	}
	if row.StatusCode != wantStatus {
		t.Errorf("status_code = %d, want %d", row.StatusCode, wantStatus)
	}
}

// TestOIDCExchangeSuccessIsAudited 交換成功即產生一筆成功登入列（實測基準是零列）
func TestOIDCExchangeSuccessIsAudited(t *testing.T) {
	env := setupOIDCAuditEnv(t)
	ticket := env.issueTicket(t)

	if code := env.postExchange(t, ticket); code != http.StatusOK {
		t.Fatalf("exchange 應成功，實得 %d", code)
	}

	rows := env.rows(t)
	if len(rows) != 1 {
		t.Fatalf("成功登入應恰產生 1 筆審計列，實得 %d 筆: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.Action != model.ActionLogin || row.Resource != model.ResourceAuth ||
		row.Status != model.StatusSuccess {
		t.Errorf("應為 action=login／resource=auth／status=success，實得 %q／%q／%q",
			row.Action, row.Resource, row.Status)
	}
	if row.UserID != env.user.ID || row.Username != env.user.Username {
		t.Errorf("歸屬應為 %d/%s，實得 %d/%s",
			env.user.ID, env.user.Username, row.UserID, row.Username)
	}
	assertRequestContext(t, row, "/api/v1/auth/oidc/exchange", http.StatusOK)

	// 認證方式與 provider 標註（spec「標註認證方式為 OIDC 並帶出 provider 識別」）。
	// 少了它，SSO 登入在審計上與本地密碼登入無法區分，也查不出是哪個 IdP 放行的
	if !strings.Contains(row.ErrorMsg, "source="+crypto.AuthMethodOIDC) {
		t.Errorf("應標註認證方式（source=oidc），實得 ErrorMsg=%q", row.ErrorMsg)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
		t.Fatalf("Details 應為合法 JSON，實得 %q: %v", row.Details, err)
	}
	if id, _ := details["provider_id"].(float64); uint(id) != env.provider.ID {
		t.Errorf("provider_id = %v, want %d（Details=%s）", details["provider_id"], env.provider.ID, row.Details)
	}
	if name, _ := details["provider_name"].(string); name != env.provider.Name {
		t.Errorf("provider_name = %q, want %q（Details=%s）", name, env.provider.Name, row.Details)
	}
}

// TestOIDCExchangeMFAPendingIsNotCountedAsSuccessfulLogin MFA 分支只記待驗證。
//
// 正式會話尚未發出（回應無 token），此刻若記一筆與正常成功列無異的列，
// 稽核上「一次登入」會變成兩次；反之完全不記，第一因子通過的事實就消失了
func TestOIDCExchangeMFAPendingIsNotCountedAsSuccessfulLogin(t *testing.T) {
	env := setupOIDCAuditEnv(t)
	if err := env.db.Model(&model.User{}).Where("id = ?", env.user.ID).
		Updates(map[string]any{"totp_enabled": true, "totp_secret_enc": "SEED"}).Error; err != nil {
		t.Fatalf("啟用 TOTP: %v", err)
	}
	ticket := env.issueTicket(t)

	if code := env.postExchange(t, ticket); code != http.StatusOK {
		t.Fatalf("exchange 應回 200（MFA 第一階段），實得 %d", code)
	}

	rows := env.rows(t)
	if len(rows) != 1 {
		t.Fatalf("MFA 分支應恰產生 1 筆列（待驗證），實得 %d 筆: %+v", len(rows), rows)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(rows[0].Details), &details); err != nil {
		t.Fatalf("Details 應為合法 JSON: %v", err)
	}
	if stage, _ := details["stage"].(string); stage != "mfa_pending" {
		t.Errorf("MFA 分支的列應標註 stage=mfa_pending，實得 %q（Details=%s）", stage, rows[0].Details)
	}
	// 正式會話的成功列由 MFA 完成點寫出（auth_mfa_handler.go 的 MFAVerify），
	// 此處不得再有第二筆「無 stage」的成功列
	for _, row := range rows {
		var d map[string]any
		_ = json.Unmarshal([]byte(row.Details), &d)
		if stage, _ := d["stage"].(string); stage == "" && row.Status == model.StatusSuccess {
			t.Errorf("待驗證階段不得記正式會話成功列: %+v", row)
		}
	}
	assertRequestContext(t, rows[0], "/api/v1/auth/oidc/exchange", http.StatusOK)
}

// TestOIDCExchangeSourceDeniedWritesNoSuccessRow 被來源政策擋下的交換只留 denied 一列。
//
// 釘的是留痕與判定的**順序**：成功列若寫在來源閘之前，同一次被擋的交換會同時
// 產生 success 與 denied 兩列（實測相差數百微秒），稽核以 `status=success` 查 login
// 就會看到一次從未發生的成功登入——它沒有發出任何會話。本地登入路徑本來就是
// 「閘在前、成功列在後」（auth_handler.go 的 Login，實測只有 denied 一列），
// 本測試使兩條路徑的對稱性不再靠人盯。
//
// 突變自檢：把 `Exchange` 的 `h.auditOIDCLogin(c, resp)` 移回來源閘之前 → 本測試紅
//（列數 2、且其中一列 status=success），其餘各格全綠。
func TestOIDCExchangeSourceDeniedWritesNoSuccessRow(t *testing.T) {
	env := setupOIDCAuditEnv(t)
	// 清單不涵蓋本次請求來源（fixture 的 RemoteAddr 為 203.0.113.9）
	env.h.SetSourcePolicyReader(fixedSourcePolicy{raw: "10.0.0.0/8"})
	ticket := env.issueTicket(t)

	if code := env.postExchange(t, ticket); code != http.StatusForbidden {
		t.Fatalf("清單外的交換應回 403，實得 %d", code)
	}

	rows := env.rows(t)
	for _, row := range rows {
		if row.Status == model.StatusSuccess {
			t.Errorf("被擋下的交換寫出了成功登入列（稽核以 status=success 查 login 會看到"+
				"一次沒發生的登入）: %+v", row)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("應恰產生 1 筆 denied 列，實得 %d 筆: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.Action != model.ActionLogin || row.Resource != model.ResourceAuth ||
		row.Status != model.StatusDenied {
		t.Errorf("應為 action=login／resource=auth／status=denied，實得 %q／%q／%q",
			row.Action, row.Resource, row.Status)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
		t.Fatalf("Details 應為合法 JSON，實得 %q: %v", row.Details, err)
	}
	if stage, _ := details["stage"].(string); stage != "source_denied" {
		t.Errorf("拒絕列應標註 stage=source_denied，實得 %q（Details=%s）", stage, row.Details)
	}
	// 原因只進審計（對外回應不回顯位址與清單，由 source_policy_gate_test.go 承擔）
	if reason, _ := details["reason"].(string); !strings.Contains(reason, "203.0.113.9") {
		t.Errorf("拒絕列應在 details 記下被判的位址，實得 reason=%q", reason)
	}
	assertRequestContext(t, row, "/api/v1/auth/oidc/exchange", http.StatusForbidden)
}

// TestOIDCCallbackFailureRowCarriesRequestContext 失敗列補實四欄且 resource=auth。
//
// 情境取「流程期間 provider 世代已推進」（begin 之後 client_secret 被輪替）：
// 它不需要接觸 IdP 即可走到 service 的失敗留痕點，故能在單元層驗證
// 「service 交回的意向 → handler 補脈絡 → 真的落成一列」這條完整鏈路
func TestOIDCCallbackFailureRowCarriesRequestContext(t *testing.T) {
	env := setupOIDCAuditEnv(t)
	flow := model.OIDCFlowState{
		State: "state-stale", Nonce: "n", PKCEVerifier: "v",
		ProviderID: env.provider.ID,
		AuthEpoch:  env.provider.AuthEpoch - 1, // 在途流程的世代已落後
		ExpiresAt:  time.Now().Add(time.Minute),
	}
	if err := env.db.Create(&flow).Error; err != nil {
		t.Fatalf("seed flow: %v", err)
	}

	r := gin.New()
	r.GET("/api/v1/auth/oidc/callback", env.h.Callback)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/oidc/callback?state=state-stale&code=any", nil)
	req.RemoteAddr = oidcAuditRemoteAddr
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("callback 失敗應導回登入頁（302），實得 %d", w.Code)
	}

	rows := env.rows(t)
	if len(rows) != 1 {
		t.Fatalf("流程失敗應恰產生 1 筆審計列，實得 %d 筆: %+v", len(rows), rows)
	}
	row := rows[0]
	// resource 為 auth（原實作標成 user，使登入拒絕混進帳號管理視圖）
	if row.Resource != model.ResourceAuth {
		t.Errorf("resource = %q, want %q", row.Resource, model.ResourceAuth)
	}
	// 憑證不成立＝認證失敗；`denied` 是授權拒絕語義，不得混用
	if row.Status != model.StatusFailure {
		t.Errorf("status = %q, want %q", row.Status, model.StatusFailure)
	}
	assertRequestContext(t, row, "/api/v1/auth/oidc/callback", http.StatusFound)
	if !strings.Contains(row.Details, "provider_unavailable") {
		t.Errorf("Details 應可辨識失敗成因，實得 %s", row.Details)
	}
}

// TestOIDCAuditIgnoresForwardedHeaderWhenProxyUntrusted 未設可信代理時不採信轉送標頭。
//
// gin 在未呼叫 SetTrustedProxies 時信任任意 `X-Forwarded-For`。若審計直接取
// `c.ClientIP()`，攻擊者就能為自己那筆**成功登入列**指定任意來源位址——稽核事後
// 追人追到的會是他挑的那個 IP。與限流鍵同一條紀律（spec：未設定可信代理時
// 來源位址 SHALL 取自連線對端）
func TestOIDCAuditIgnoresForwardedHeaderWhenProxyUntrusted(t *testing.T) {
	env := setupOIDCAuditEnv(t)
	ticket := env.issueTicket(t)

	r := gin.New()
	r.POST("/api/v1/auth/oidc/exchange", env.h.Exchange)
	body, _ := json.Marshal(map[string]string{"ticket": ticket})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "198.51.100.77") // 偽造的來源
	req.RemoteAddr = oidcAuditRemoteAddr
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("exchange 應成功，實得 %d", w.Code)
	}

	rows := env.rows(t)
	if len(rows) != 1 {
		t.Fatalf("應恰產生 1 筆審計列，實得 %d", len(rows))
	}
	if rows[0].ClientIP != "203.0.113.9" {
		t.Errorf("client_ip = %q，應取連線對端 203.0.113.9 而非轉送標頭值", rows[0].ClientIP)
	}
}

// TestOIDCAuditDisabledWritesNothing 未注入審計服務時不得 panic、不得留痕。
// nil 是既有慣例（AuthHandler 的 auditService 同形），破壞它會讓最小化部署直接崩
func TestOIDCAuditDisabledWritesNothing(t *testing.T) {
	env := setupOIDCAuditEnv(t)
	env.h.audit = nil
	ticket := env.issueTicket(t)

	if code := env.postExchange(t, ticket); code != http.StatusOK {
		t.Fatalf("exchange 應成功，實得 %d", code)
	}
	if rows := env.rows(t); len(rows) != 0 {
		t.Fatalf("審計停用時不得寫入，實得 %d 筆", len(rows))
	}
}
