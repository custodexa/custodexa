package middleware

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// 審計紀錄查詢摘要的憑證遮蔽守衛。
//
// **釘子打在哪**：AuditLogMiddleware 對敏感資源的 GET 會把 raw query 整串寫進
// audit_logs.details。走 query string 的憑證（rtoken、connect_token、`token`＝
// monitor／share WS 的長效登入 JWT、password、OIDC 的 code／state／binding）
// 因此逐字入庫。這比 access log 的同型缺口嚴重一級：access log 會輪替、會過期，
// 而 audit_logs 受檢查點鏈保護——寫進去就刪不掉（刪了鏈驗證即失敗），等於憑證
// 明文被**永久封存在不可篡改的紀錄**裡。
//
// **斷言打在實際入庫的列上**（latestAuditRow 讀回 audit_logs），不是
// MaskCredentialQuery 的回傳值：缺口是「寫進去的那一列長什麼樣」，遮蔽點若被搬走
// 或呼叫被拿掉，函式單測仍會全綠，只有讀回實列的斷言會紅。
//
// 反向斷言同樣必要：只驗「明文不在」的話，「details 一律寫空字串」也會過，而那會
// 拆掉 PCI 10.2.1.3 要的「誰以什麼條件查了什麼」。故另有可稽核性斷言。
//
// **突變自證**（已實跑，見 change 紀錄）：把 audit_log.go 的
// `summary["query"] = MaskCredentialQuery(query)` 改回 `= query`
// → TestAuditDetailsNeverContainsCredentialPlaintext 全 8 個子案例轉紅。

// credentialAuditRouter 掛真的 AuditLogMiddleware ＋ 一支敏感資源的讀取路由。
// 沿用 audit_log_clipboard_guard_test.go 的 DB 裝設（同 package，單一寫者）。
func credentialAuditRouter(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := installClipboardAuditDB(t)

	svc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	r := gin.New()
	r.Use(AuditLogMiddleware(svc))
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(9))
		c.Set("username", "auditor")
		c.Next()
	})
	// audit-logs 屬 auditSensitiveResources，其 GET 才會寫查詢摘要
	r.GET("/api/v1/audit-logs", func(c *gin.Context) { c.JSON(200, gin.H{}) })
	return r, db
}

// auditDetailsQuery 讀回最後一列的 details 並取出查詢摘要字串。
// 回傳 (details 原文, summary["query"])——原文用於「明文不得出現在任何一個
// byte」的斷言，避免解析後才比對而漏掉鍵名或其他欄位夾帶。
func auditDetailsQuery(t *testing.T, db *gorm.DB) (string, string) {
	t.Helper()
	row := latestAuditRow(t, db)
	if row.Resource != model.ResourceAuditLog {
		t.Fatalf("resource = %s, want audit_log（釘子須打在會寫摘要的資源上）", row.Resource)
	}
	if row.Details == "" {
		t.Fatal("details 為空——摘要未產生，守衛失去觀測對象")
	}
	var summary map[string]string
	if err := json.Unmarshal([]byte(row.Details), &summary); err != nil {
		t.Fatalf("details 非 JSON 物件: %q (%v)", row.Details, err)
	}
	return row.Details, summary["query"]
}

// TestAuditDetailsNeverContainsCredentialPlaintext 憑證明文不得寫進 audit_logs。
//
// 涵蓋 access log 遮蔽盤點查出的全部 query string 憑證載體。
func TestAuditDetailsNeverContainsCredentialPlaintext(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		masked string // 遮蔽後應出現在摘要中的字面
	}{
		{"錄影取證 capability token", "rtoken=" + secretSentinel, "rtoken=" + QueryValueMask},
		{"一次性連線 token", "connect_token=" + secretSentinel, "connect_token=" + QueryValueMask},
		{"WebSocket 認證用長效 JWT", "token=" + secretSentinel, "token=" + QueryValueMask},
		{"連線收口防呆擋下的 password 參數", "password=" + secretSentinel, "password=" + QueryValueMask},
		{"OIDC 授權碼", "code=" + secretSentinel, "code=" + QueryValueMask},
		{"OIDC state（CSRF nonce）", "state=" + secretSentinel, "state=" + QueryValueMask},
		{"OIDC 裝置綁定雜湊", "binding=" + secretSentinel, "binding=" + QueryValueMask},
		{
			name:   "兩個憑證同時出現，不得只遮到第一個",
			query:  "code=" + secretSentinel + "&state=" + otherSecretSentinel,
			masked: "state=" + QueryValueMask,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, db := credentialAuditRouter(t)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/audit-logs?"+tc.query, nil))
			if w.Code != 200 {
				t.Fatalf("讀取應成功（釘子須打在真正被受理的請求上），得 %d", w.Code)
			}

			details, query := auditDetailsQuery(t, db)
			for _, sentinel := range []string{secretSentinel, otherSecretSentinel} {
				if strings.Contains(details, sentinel) {
					t.Fatalf("憑證明文寫進了 audit_logs.details——該表受檢查點鏈保護，"+
						"寫進去就刪不掉，等於憑證被永久封存\ndetails: %s", details)
				}
			}
			if !strings.Contains(query, tc.masked) {
				t.Errorf("摘要未見遮蔽後字面 %q；遮蔽必須是「遮值留鍵」，"+
					"不是讓參數整個消失\ndetails: %s", tc.masked, details)
			}
		})
	}
}

// TestAuditDetailsKeepsQueryAuditability 遮蔽不得把查詢摘要遮成廢物。
//
// PCI 10.2.1.3 要的是「誰以什麼條件查了什麼」。只驗「明文不在」會放行
// 「details 一律寫空字串」這種假修法，故此處逐條釘住可稽核維度：
// 時間範圍、對象、類別，以及非憑證參數的原值。
func TestAuditDetailsKeepsQueryAuditability(t *testing.T) {
	r, db := credentialAuditRouter(t)

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET",
		"/api/v1/audit-logs?start_time=2026-08-01&end_time=2026-08-12"+
			"&subject=user&subject_id=7&user_id=3&types=login,read&action=read"+
			"&q=alice&page=2&page_size=50&token="+secretSentinel, nil))

	details, query := auditDetailsQuery(t, db)
	if strings.Contains(details, secretSentinel) {
		t.Fatalf("憑證明文寫進了 audit_logs.details\ndetails: %s", details)
	}
	for _, want := range []string{
		"start_time=2026-08-01", "end_time=2026-08-12", // 時間範圍
		"subject=user", "subject_id=7", "user_id=3", // 對象
		"types=login,read", "action=read", // 類別
		"q=alice",                 // 對象搜尋字串：審計要答得出「他查的是誰」
		"page=2", "page_size=50",  // 其餘條件原樣保留
		"token=" + QueryValueMask, // 憑證：只有它被遮
	} {
		if !strings.Contains(query, want) {
			t.Errorf("查詢摘要遺失可稽核資訊 %q——遮蔽只該遮憑證值\ndetails: %s", want, details)
		}
	}
}

// TestAuditDetailsMaskingReusesAccessLogVocabulary 兩個遮蔽面共用同一組語彙。
//
// 缺口的成因是「憑證載體清單」散在各處；若審計端另立一套片段表，新增一種
// token 命名時就會出現「access log 遮了、審計沒遮」的漂移。此處釘住：凡
// access log 認定為憑證的參數名，審計端一律同判。
func TestAuditDetailsMaskingReusesAccessLogVocabulary(t *testing.T) {
	credentials := []string{
		"rtoken", "token", "connect_token", "refresh_token", "access_token",
		"password", "passwd", "passphrase", "private_key", "privateKey",
		"secret", "client_secret", "credential", "api_key", "otp", "signature",
		"code", "state", "binding",
	}
	for _, key := range credentials {
		if !IsCredentialQueryKey(key) {
			t.Errorf("query 參數 %q 未被認定為憑證——其值會逐字寫進 audit_logs.details", key)
		}
		if !IsSensitiveQueryKey(key) {
			t.Errorf("query 參數 %q 憑證判定與 access log 語彙不一致", key)
		}
		if got := MaskCredentialQuery(key + "=" + secretSentinel); strings.Contains(got, secretSentinel) {
			t.Errorf("MaskCredentialQuery 未遮蔽 %q 之值", key)
		}
	}

	// 個資類搜尋參數：access log 遮（會被收集系統帶走），審計 details 不遮
	//（PCI 10.2.1.3 的「對象」維度）。這條差異是刻意的，一併釘住以免被
	// 「統一成同一支判定」順手抹平。
	for _, key := range []string{"search", "keyword", "q"} {
		if IsCredentialQueryKey(key) {
			t.Errorf("%q 被歸入憑證——審計摘要會失去「他查的是誰」這一維", key)
		}
		if !IsSensitiveQueryKey(key) {
			t.Errorf("%q 未被 access log 判定為敏感——個資會進 access log", key)
		}
	}
}
