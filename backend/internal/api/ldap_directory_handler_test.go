package api

import (
	"bytes"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// LDAP 目錄設定 HTTP 面的守衛（ldap-settings-migration 3.1）。
//
// 全部經**完整 RegisterRoutes**（真 AuthMiddleware＋真 RequireRole＋真服務層＋
// sqlite），不 mock 服務層：本檔要證明的是「服務層既有的判定確實出得了 HTTP
// 這道門，且出來時是正確的狀態碼與機器碼」——對著假服務斷言只會證明測試自己。
//
// 連線測試的目標一律取 link-local（169.254.0.0/16）：出站政策對它是**無條件**
// 封鎖（loopback 允許清單也放行不了），故階梯必停在撥號階段、不發出任何封包、
// 不依賴容器網路狀態，且毫秒級返回。

// setupLDAPDirectoryEnv 建置經完整路由的測試環境。
//
// codec 傳 nil＝明文直通（服務層既有的單測建構路徑）；密碼的「write-only」
// 語義因此仍可驗——回應形狀與 has_bind_password 不因加密與否而異
func setupLDAPDirectoryEnv(t *testing.T) (*gin.Engine, *crypto.JWTManager, *policy.SecurityPolicyService, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// **檔案型 sqlite ＋多條連線**（沿 ldap_directory_service_test.go 的
	// TestLDAPDirectoryConcurrentUpsert 與 localAdminConcurrentDB 先例）：
	// `:memory:` 每條連線是各自獨立的庫，故只能配 SetMaxOpenConns(1)——但存檔閘
	// 於 Upsert 的交易**內**呼叫 TransmissionPolicyService.ChannelLevel，後者讀的是
	// 交易外的 db；單一連線被交易佔住時該讀取永遠等不到連線，測試自我死鎖。
	// 生產（postgres 連線池）沒有這一格，故此處是 fixture 的取捨而非行為差異
	dsn := filepath.Join(t.TempDir(), "ldapdir.db") + "?_pragma=busy_timeout(5000)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(4)
	if err := db.AutoMigrate(&model.LDAPDirectory{}, &model.AuditLog{},
		&model.SecurityPolicy{}, &model.User{}, &model.Role{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// AuthMiddleware 的憑證世代閘現查 database.DB（未注入即全數 401）
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	policies := policy.NewSecurityPolicyService(db)
	directories := identity.NewLDAPDirectoryService(db, nil, audit.NewTxSink())
	directories.SetTransmissionPolicy(policy.NewTransmissionPolicyService(policies, directories.RiskViewProvider()))

	r := gin.New()
	group := r.Group("/api/v1")
	NewLDAPDirectoryHandler(directories).RegisterRoutes(group,
		identity.NewAuthService("ldap-directory-test-secret", time.Minute))

	return r, crypto.NewJWTManager("ldap-directory-test-secret", time.Minute), policies, db
}

// ldapSeedUser 建出 token 對應的使用者列。
//
// **不可省**：AuthMiddleware 的憑證世代閘現查 DB，查無此人一律 401——
// 沒有這一步，全部斷言都會停在認證層而不是它們要驗的那件事
func ldapSeedUser(t *testing.T, db *gorm.DB, userID uint, username string) {
	t.Helper()
	user := &model.User{Username: username, Password: "hashed", Active: true}
	user.ID = userID
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("建立測試使用者: %v", err)
	}
}

// ldapAdminToken 簽發一枚 admin token 並建出對應使用者。userID 由呼叫端指定
// ——連線測試的限流以已認證的 actor 為鍵，共用 id 會使各測試互相吃額度
func ldapAdminToken(t *testing.T, mgr *crypto.JWTManager, db *gorm.DB, userID uint) string {
	t.Helper()
	username := "admin" + strconv.FormatUint(uint64(userID), 10)
	ldapSeedUser(t, db, userID, username)
	token, err := mgr.GenerateToken(userID, username, "admin@example.com", "admin", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("簽發 token: %v", err)
	}
	return token
}

func ldapRequest(t *testing.T, r *gin.Engine, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("序列化請求: %v", err)
		}
		reader = bytes.NewReader(payload)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ldapErrCode 取回應信封的機器碼
func ldapErrCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("回應無法解析: %v (body=%s)", err, w.Body.String())
	}
	return env.Code
}

// ldapView 解析 GET／PUT 的設定視圖
type ldapViewBody struct {
	Configured      bool   `json:"configured"`
	Name            string `json:"name"`
	URL             string `json:"url"`
	BindDN          string `json:"bind_dn"`
	BaseDN          string `json:"base_dn"`
	UserFilter      string `json:"user_filter"`
	Enabled         bool   `json:"enabled"`
	HasBindPassword bool   `json:"has_bind_password"`
}

func ldapView(t *testing.T, w *httptest.ResponseRecorder) ldapViewBody {
	t.Helper()
	var v ldapViewBody
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("設定視圖無法解析: %v (body=%s)", err, w.Body.String())
	}
	return v
}

// validLDAPPayload 一份通過啟用態驗證的請求（ldaps 以免撞上傳輸閘）
func validLDAPPayload() map[string]any {
	return map[string]any{
		"name":            "公司目錄",
		"url":             "ldaps://dir.example.com:636",
		"bind_dn":         "cn=svc-bind,dc=example,dc=com",
		"bind_password":   "s3cret",
		"base_dn":         "ou=users,dc=example,dc=com",
		"user_filter":     "(&(objectClass=user)(sAMAccountName=%s))",
		"attr_email":      "mail",
		"attr_fullname":   "displayName",
		"skip_tls_verify": false,
		"enabled":         true,
	}
}

// TestLDAPDirectoryGetUnconfigured 未設定回 configured:false 而非 404——
// 「還沒設定」是 singleton 資源的正常狀態
func TestLDAPDirectoryGetUnconfigured(t *testing.T) {
	r, mgr, _, db := setupLDAPDirectoryEnv(t)
	w := ldapRequest(t, r, http.MethodGet, "/api/v1/ldap-directory", ldapAdminToken(t, mgr, db, 101), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET 未設定應 200，實得 %d (%s)", w.Code, w.Body.String())
	}
	v := ldapView(t, w)
	if v.Configured || v.HasBindPassword {
		t.Fatalf("未設定應回 configured:false 且無密碼旗標: %s", w.Body.String())
	}
}

// TestLDAPDirectoryUpsertAndRead upsert 後讀取形狀一致，且**回應恆不含密碼**
func TestLDAPDirectoryUpsertAndRead(t *testing.T) {
	r, mgr, _, db := setupLDAPDirectoryEnv(t)
	token := ldapAdminToken(t, mgr, db, 102)

	w := ldapRequest(t, r, http.MethodPut, "/api/v1/ldap-directory", token, validLDAPPayload())
	if w.Code != http.StatusOK {
		t.Fatalf("PUT 應 200，實得 %d (%s)", w.Code, w.Body.String())
	}
	v := ldapView(t, w)
	if !v.Configured || !v.HasBindPassword || !v.Enabled {
		t.Fatalf("PUT 回應欄位不符: %s", w.Body.String())
	}
	// 密碼不得以任何形式出現在回應中（write-only 的實質檢查，非只看有無欄位）
	if bytes.Contains(w.Body.Bytes(), []byte("s3cret")) {
		t.Fatalf("回應洩漏 bind 密碼: %s", w.Body.String())
	}

	w = ldapRequest(t, r, http.MethodGet, "/api/v1/ldap-directory", token, nil)
	got := ldapView(t, w)
	if got.URL != v.URL || got.BindDN != v.BindDN || !got.HasBindPassword {
		t.Fatalf("GET 與 PUT 回應不一致: %s", w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("s3cret")) {
		t.Fatalf("GET 洩漏 bind 密碼: %s", w.Body.String())
	}

	var row model.LDAPDirectory
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀取資料列: %v", err)
	}
	if row.BindPasswordEnc == "" {
		t.Fatal("bind 密碼未落庫")
	}
}

// TestLDAPDirectoryBindPasswordRules 密碼三規則的 HTTP 面：
// 空=沿用、顯式清除、URL 變更須重供；以及新密碼＋清除旗標的衝突
func TestLDAPDirectoryBindPasswordRules(t *testing.T) {
	r, mgr, _, db := setupLDAPDirectoryEnv(t)
	token := ldapAdminToken(t, mgr, db, 103)

	if w := ldapRequest(t, r, http.MethodPut, "/api/v1/ldap-directory", token, validLDAPPayload()); w.Code != http.StatusOK {
		t.Fatalf("前置建立失敗: %d (%s)", w.Code, w.Body.String())
	}

	// (1) 空密碼＋URL 未變 ⇒ 沿用
	reuse := validLDAPPayload()
	reuse["bind_password"] = ""
	reuse["name"] = "改個名"
	w := ldapRequest(t, r, http.MethodPut, "/api/v1/ldap-directory", token, reuse)
	if w.Code != http.StatusOK || !ldapView(t, w).HasBindPassword {
		t.Fatalf("空密碼應沿用既存: %d (%s)", w.Code, w.Body.String())
	}

	// (2) 新密碼＋清除旗標 ⇒ 400（兩個互斥意圖，服務層無從裁決真意）
	conflict := validLDAPPayload()
	conflict["clear_bind_password"] = true
	w = ldapRequest(t, r, http.MethodPut, "/api/v1/ldap-directory", token, conflict)
	if w.Code != http.StatusBadRequest ||
		ldapErrCode(t, w) != string(apierror.CodeValidationLDAPBindPasswordConflict) {
		t.Fatalf("密碼衝突應 400＋專屬碼: %d %s", w.Code, w.Body.String())
	}

	// (3) URL 變更＋空密碼 ⇒ 400（既存憑證不得被沿用到新位址）
	moved := validLDAPPayload()
	moved["bind_password"] = ""
	moved["url"] = "ldaps://other.example.com:636"
	w = ldapRequest(t, r, http.MethodPut, "/api/v1/ldap-directory", token, moved)
	if w.Code != http.StatusBadRequest ||
		ldapErrCode(t, w) != string(apierror.CodeValidationLDAPBindPasswordRequired) {
		t.Fatalf("改 URL 留空密碼應 400＋專屬碼: %d %s", w.Code, w.Body.String())
	}

	// (4) 顯式清除 ⇒ has_bind_password 轉 false
	clear := validLDAPPayload()
	clear["bind_password"] = ""
	clear["clear_bind_password"] = true
	clear["enabled"] = false // 啟用態要求有密碼，清除後只能是草稿
	w = ldapRequest(t, r, http.MethodPut, "/api/v1/ldap-directory", token, clear)
	if w.Code != http.StatusOK || ldapView(t, w).HasBindPassword {
		t.Fatalf("顯式清除後應無密碼: %d (%s)", w.Code, w.Body.String())
	}
}

// TestLDAPDirectoryValidationCodes 存檔驗證的三類拒因各自出得了門，
// 且**不被併成一支泛碼**——逐因給碼是本批的設計裁決
func TestLDAPDirectoryValidationCodes(t *testing.T) {
	r, mgr, _, db := setupLDAPDirectoryEnv(t)
	token := ldapAdminToken(t, mgr, db, 104)

	cases := []struct {
		name   string
		mutate func(map[string]any)
		code   apierror.ErrCode
		field  string
	}{
		{"URL 內嵌憑證", func(p map[string]any) { p["url"] = "ldaps://user:secret@dir.example.com" },
			apierror.CodeValidationLDAPURLUserinfo, ""},
		{"URL 帶路徑", func(p map[string]any) { p["url"] = "ldaps://dir.example.com/ou=users" },
			apierror.CodeValidationLDAPURLPath, ""},
		{"URL scheme 不合法", func(p map[string]any) { p["url"] = "https://dir.example.com" },
			apierror.CodeValidationLDAPURLScheme, ""},
		{"filter 無 placeholder", func(p map[string]any) { p["user_filter"] = "(objectClass=person)" },
			apierror.CodeValidationLDAPFilterPlaceholderMissing, ""},
		{"filter OR 繞過", func(p map[string]any) { p["user_filter"] = "(|(uid=%s)(uid=svc-admin))" },
			apierror.CodeValidationLDAPFilterPlaceholderScope, ""},
		{"啟用態缺 base_dn", func(p map[string]any) { p["base_dn"] = "" },
			apierror.CodeValidationLDAPFieldRequired, "base_dn"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := validLDAPPayload()
			tc.mutate(payload)
			w := ldapRequest(t, r, http.MethodPut, "/api/v1/ldap-directory", token, payload)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("應 400，實得 %d (%s)", w.Code, w.Body.String())
			}
			if got := ldapErrCode(t, w); got != string(tc.code) {
				t.Fatalf("機器碼應為 %s，實得 %s (%s)", tc.code, got, w.Body.String())
			}
			if tc.field != "" {
				var env struct {
					Field string `json:"field"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil || env.Field != tc.field {
					t.Fatalf("欄位錯誤應以 Meta 帶 field=%s: %s", tc.field, w.Body.String())
				}
			}
		})
	}
}

// TestLDAPDirectorySaveGate 存檔閘沿用既有三通道契約：strict 拒存、
// warn 缺 risk_acknowledged 拒存、warn 帶確認放行。**形狀不得另起爐灶**
// （碼與 syslog／通知通道相同，risks 經 Meta 平鋪）
func TestLDAPDirectorySaveGate(t *testing.T) {
	r, mgr, policies, db := setupLDAPDirectoryEnv(t)
	token := ldapAdminToken(t, mgr, db, 105)

	plaintext := validLDAPPayload()
	plaintext["url"] = "ldap://dir.example.com:389" // 明文＝傳輸風險

	if _, err := policies.Update(policy.PolicyTransportLDAPLevel, policy.TransportLevelStrict, "admin"); err != nil {
		t.Fatalf("設定 strict: %v", err)
	}
	w := ldapRequest(t, r, http.MethodPut, "/api/v1/ldap-directory", token, plaintext)
	if w.Code != http.StatusBadRequest ||
		ldapErrCode(t, w) != string(apierror.CodeTransmissionSaveStrictReject) {
		t.Fatalf("strict 應拒存並回既有機器碼: %d %s", w.Code, w.Body.String())
	}
	// risks 為機器欄，前端據以列示確認框內容
	var strictEnv struct {
		Risks []map[string]any `json:"risks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &strictEnv); err != nil || len(strictEnv.Risks) == 0 {
		t.Fatalf("拒存回應應帶 risks: %s", w.Body.String())
	}

	if _, err := policies.Update(policy.PolicyTransportLDAPLevel, policy.TransportLevelWarn, "admin"); err != nil {
		t.Fatalf("設定 warn: %v", err)
	}
	w = ldapRequest(t, r, http.MethodPut, "/api/v1/ldap-directory", token, plaintext)
	if w.Code != http.StatusBadRequest ||
		ldapErrCode(t, w) != string(apierror.CodeTransmissionAckRequired) {
		t.Fatalf("warn 缺確認應拒存: %d %s", w.Code, w.Body.String())
	}

	acked := validLDAPPayload()
	acked["url"] = "ldap://dir.example.com:389"
	acked["risk_acknowledged"] = true
	if w = ldapRequest(t, r, http.MethodPut, "/api/v1/ldap-directory", token, acked); w.Code != http.StatusOK {
		t.Fatalf("warn 帶確認應放行: %d (%s)", w.Code, w.Body.String())
	}
}

// TestLDAPDirectoryTestLadderFailureIs200 階梯**已執行**即 200（含失敗）。
//
// 把「撥號被出站政策擋下」回成 4xx 會使前端無從呈現階梯的部分成功，
// 而分階段定位正是這個端點存在的理由
func TestLDAPDirectoryTestLadderFailureIs200(t *testing.T) {
	r, mgr, _, db := setupLDAPDirectoryEnv(t)
	token := ldapAdminToken(t, mgr, db, 106)

	payload := validLDAPPayload()
	// link-local（含雲端 metadata 段）：出站政策無條件封鎖，允許清單放行不了，
	// 故不發出任何封包、不依賴容器網路
	payload["url"] = "ldaps://169.254.169.254:636"

	w := ldapRequest(t, r, http.MethodPost, "/api/v1/ldap-directory/test", token, payload)
	if w.Code != http.StatusOK {
		t.Fatalf("階梯已執行應 200，實得 %d (%s)", w.Code, w.Body.String())
	}
	var result struct {
		Success      bool   `json:"success"`
		FailedStage  string `json:"failed_stage"`
		Code         string `json:"code"`
		DiagnosticID string `json:"diagnostic_id"`
		Target       string `json:"target"`
		Stages       []struct {
			Stage string `json:"stage"`
			OK    bool   `json:"ok"`
			Code  string `json:"code"`
		} `json:"stages"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("測試結果無法解析: %v (%s)", err, w.Body.String())
	}
	if result.Success {
		t.Fatalf("目標被出站政策封鎖，不該回成功: %s", w.Body.String())
	}
	if result.FailedStage != "dial" || result.Code != "egress_blocked" {
		t.Fatalf("應停在撥號階段並回 egress_blocked: %s", w.Body.String())
	}
	if result.DiagnosticID == "" {
		t.Fatalf("失敗回應必須帶 diagnostic_id（回應／審計／log 三處同值）: %s", w.Body.String())
	}
	if len(result.Stages) != 1 || result.Stages[0].OK {
		t.Fatalf("stages 應逐階段呈現且首階失敗: %s", w.Body.String())
	}

	// 成功與失敗皆入審計（diagnostic_id 三處同值的第二處）
	var audits int64
	db.Model(&model.AuditLog{}).Count(&audits)
	if audits == 0 {
		t.Fatal("測試失敗未入審計")
	}
}

// TestLDAPDirectoryTestRateLimited 逾越 per-actor 界線回 429。
//
// **回應不得洩漏限流參數**：門檻與剩餘額度會讓攻擊者把流量調到界線之下持續
// 消耗內網探測；此處連帶斷言無 Retry-After
func TestLDAPDirectoryTestRateLimited(t *testing.T) {
	r, mgr, _, db := setupLDAPDirectoryEnv(t)
	token := ldapAdminToken(t, mgr, db, 107)

	payload := validLDAPPayload()
	// 專屬目標：per-target 桶與其他測試隔離，避免互相吃額度造成偶發
	payload["url"] = "ldaps://169.254.7.7:636"

	limited := false
	for i := 0; i < 8; i++ {
		w := ldapRequest(t, r, http.MethodPost, "/api/v1/ldap-directory/test", token, payload)
		if w.Code == http.StatusTooManyRequests {
			if got := ldapErrCode(t, w); got != string(apierror.CodeRuleLDAPTestRateLimited) {
				t.Fatalf("429 機器碼應為 %s，實得 %s", apierror.CodeRuleLDAPTestRateLimited, got)
			}
			if w.Header().Get("Retry-After") != "" {
				t.Fatal("限流回應不得附 Retry-After（會洩漏界線參數）")
			}
			limited = true
			break
		}
		if w.Code != http.StatusOK {
			t.Fatalf("第 %d 次測試應為 200 或 429，實得 %d (%s)", i+1, w.Code, w.Body.String())
		}
	}
	if !limited {
		t.Fatal("連續測試未觸發限流——per-actor 界線未生效")
	}
}

// TestLDAPDirectoryTestGateNotNarrowedByEnabled 測試閘不受請求 enabled 限縮：
// 關掉表單開關不得成為「strict 下仍明文外送 bind 憑證」的旁路
func TestLDAPDirectoryTestGateNotNarrowedByEnabled(t *testing.T) {
	r, mgr, policies, db := setupLDAPDirectoryEnv(t)
	token := ldapAdminToken(t, mgr, db, 108)

	if _, err := policies.Update(policy.PolicyTransportLDAPLevel, policy.TransportLevelStrict, "admin"); err != nil {
		t.Fatalf("設定 strict: %v", err)
	}
	payload := validLDAPPayload()
	payload["url"] = "ldap://169.254.7.8:389"
	payload["enabled"] = false

	w := ldapRequest(t, r, http.MethodPost, "/api/v1/ldap-directory/test", token, payload)
	if w.Code != http.StatusBadRequest ||
		ldapErrCode(t, w) != string(apierror.CodeTransmissionSaveStrictReject) {
		t.Fatalf("strict 下 enabled=false 仍應拒測: %d %s", w.Code, w.Body.String())
	}
}

// TestLDAPDirectoryDelete 無列 404、有列 204，刪後回未設定
func TestLDAPDirectoryDelete(t *testing.T) {
	r, mgr, _, db := setupLDAPDirectoryEnv(t)
	token := ldapAdminToken(t, mgr, db, 109)

	w := ldapRequest(t, r, http.MethodDelete, "/api/v1/ldap-directory", token, nil)
	if w.Code != http.StatusNotFound || ldapErrCode(t, w) != string(apierror.CodeNotFoundLDAPDirectory) {
		t.Fatalf("無設定時刪除應 404＋專屬碼: %d %s", w.Code, w.Body.String())
	}

	if w = ldapRequest(t, r, http.MethodPut, "/api/v1/ldap-directory", token, validLDAPPayload()); w.Code != http.StatusOK {
		t.Fatalf("前置建立失敗: %d (%s)", w.Code, w.Body.String())
	}
	if w = ldapRequest(t, r, http.MethodDelete, "/api/v1/ldap-directory", token, nil); w.Code != http.StatusNoContent {
		t.Fatalf("刪除應 204，實得 %d (%s)", w.Code, w.Body.String())
	}
	w = ldapRequest(t, r, http.MethodGet, "/api/v1/ldap-directory", token, nil)
	if ldapView(t, w).Configured {
		t.Fatalf("刪除後應回未設定: %s", w.Body.String())
	}
}

// TestLDAPDirectoryRequiresAdmin 四條路由全數 admin-only。
//
// **逐條逐角色檢查**：只驗 GET 會讓「PUT 忘了掛角色閘」這種最危險的形態溜過
func TestLDAPDirectoryRequiresAdmin(t *testing.T) {
	r, mgr, _, db := setupLDAPDirectoryEnv(t)
	ldapSeedUser(t, db, 200, "someone")

	routes := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/v1/ldap-directory", nil},
		{http.MethodPut, "/api/v1/ldap-directory", validLDAPPayload()},
		{http.MethodDelete, "/api/v1/ldap-directory", nil},
		{http.MethodPost, "/api/v1/ldap-directory/test", validLDAPPayload()},
	}
	for _, role := range []string{"user", "auditor", "approver"} {
		token, err := mgr.GenerateToken(200, "someone", "u@example.com", role, crypto.AuthContext{})
		if err != nil {
			t.Fatalf("簽發 token: %v", err)
		}
		for _, rt := range routes {
			w := ldapRequest(t, r, rt.method, rt.path, token, rt.body)
			if w.Code != http.StatusForbidden {
				t.Fatalf("role=%s %s %s 應 403，實得 %d (%s)",
					role, rt.method, rt.path, w.Code, w.Body.String())
			}
		}
	}
	// 未帶 token 一律 401（不是 404，也不是靜默放行）
	for _, rt := range routes {
		req := httptest.NewRequest(rt.method, rt.path, bytes.NewReader(nil))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s 未帶 token 應 401，實得 %d", rt.method, rt.path, w.Code)
		}
	}
}

// TestLDAPReasonCodeTablesExhaustive 服務層每一個靜態拒因常數都必須在 HTTP
// 層有對應機器碼。
//
// **以 AST 掃描服務層原始碼取常數清單，而非在測試裡另抄一份**：抄一份的守衛
// 只能證明「我抄的那些有對應」——新增拒因時兩邊會一起漏，正是這類對照表最
// 典型的假綠形態。掃描使新增常數立刻紅
func TestLDAPReasonCodeTablesExhaustive(t *testing.T) {
	// **掃描根以 go.mod module 身分為錨，不用固定層數 `..`**
	// （modular-architecture W1 1.20／W8 9.9）：原本寫 `Dir(thisFile)/../service`，
	// LDAP 三檔於 W8 搬入 `internal/modules/identity` 後即指向不存在的目錄。
	// 失效方向是 t.Fatal（下方「未掃到任何常數」）而非恆綠，但修法仍不能只換字串。
	identityDir := filepath.Join(ldapReasonBackendRoot(t), "internal", "modules", "identity")

	tables := []struct {
		file   string
		prefix string
		table  map[string]apierror.ErrCode
	}{
		{"ldap_url.go", "LDAPURLReason", ldapURLReasonCodes},
		{"ldap_settings_validation.go", "LDAPFilterReason", ldapFilterReasonCodes},
		{"ldap_settings_validation.go", "LDAPFieldReason", ldapFieldReasonCodes},
	}
	for _, tc := range tables {
		reasons := scanLDAPReasonConstants(t, filepath.Join(identityDir, tc.file), tc.prefix)
		if len(reasons) == 0 {
			t.Fatalf("%s 未掃到任何 %s* 常數——守衛已在空集合下假綠", tc.file, tc.prefix)
		}
		for name, value := range reasons {
			code, ok := tc.table[value]
			if !ok {
				t.Errorf("%s.%s（值 %q）未登記 HTTP 機器碼——新增拒因須同步對照表", tc.file, name, value)
				continue
			}
			if _, registered := apierror.DescriptorOf(code); !registered {
				t.Errorf("%s 對應的碼 %q 未登記於 apierror registry", name, code)
			}
		}
	}
}

// scanLDAPReasonConstants 取檔案內指定前綴的 string 常數（名稱 → 值）
func scanLDAPReasonConstants(t *testing.T, path, prefix string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s: %v", path, err)
	}
	out := map[string]string{}
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			name := vs.Names[0].Name
			if len(name) <= len(prefix) || name[:len(prefix)] != prefix {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("解析常數 %s 的值: %v", name, err)
			}
			out[name] = value
		}
	}
	return out
}

// ldapReasonBackendRoot 定位 backend module 根：自本檔向上找 go.mod 並核對 module 行。
// 比照 notifycat／kms 守衛的作法——固定層數 `..` 與「本 package 住在第幾層」綁死。
func ldapReasonBackendRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("無法解析測試檔路徑")
	}
	dir := filepath.Dir(thisFile)
	const want = "module github.com/custodexa/backend"
	for {
		if body, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) == want {
					return dir
				}
			}
			t.Fatalf("%s/go.mod 的 module 行不是 %q：掃描根錨點失效", dir, want)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("自 %s 向上找不到 go.mod：掃描根無從定位", filepath.Dir(thisFile))
		}
		dir = parent
	}
}
