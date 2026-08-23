package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// 提權事件課責欄位的行為守衛。
//
// **釘子打在實際入庫的那一列**（讀回 audit_logs.request_body），不是
// `MaskSensitiveFields` 的回傳值：缺陷的形態是「審計列存在、內容全是遮罩標記」，
// 只驗函式回傳的話，遮罩呼叫被搬走或 middleware 換寫法時仍會全綠。
//
// 三個斷言方向缺一不可：
//   - 正向：升權後的角色、帳號啟停的方向必須在列上讀得出來
//   - 反向（機密）：同一個請求裡的密碼／權杖必須仍是遮罩，且明文不得出現在整列的
//     任何一個 byte——只驗「角色看得見」的話，把遮罩函式改成恆等也會過
//   - 反向（授權閘）：低權越權仍須 403 ＋ status=denied 留痕，且**未遂的提權企圖
//     同樣要留下他想升成什麼**（拒絕列的課責價值不低於成功列）

// privilegeAuditRouter 掛真的 AuditLogMiddleware ＋ 真的 RequireRole ＋ 提權路由。
//
// 路由字面與 UserHandler.RegisterRoutes 一致（路徑本身由 route golden 釘）。
// handler 只回 200——本守衛驗的是中介層寫出的那一列，不是 handler 的業務邏輯。
func privilegeAuditRouter(t *testing.T, role string) (*gin.Engine, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := installClipboardAuditDB(t)

	svc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	r := gin.New()
	r.Use(AuditLogMiddleware(svc))
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "admin-under-test")
		c.Set("role", role)
		c.Next()
	})
	users := r.Group("/api/v1/users")
	users.Use(RequireRole("admin"))
	{
		users.PUT("/:id/roles", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{}) })
		users.PUT("/:id/status", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{}) })
	}
	return r, db
}

// privilegeAuditBody 送出請求並讀回最後一列的 (整列原文, 解析後的 request_body)。
// 整列原文供「機密明文不得出現在任何 byte」的斷言使用。
func privilegeAuditBody(t *testing.T, r *gin.Engine, db *gorm.DB,
	method, path, body string) (model.AuditLog, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	row := latestAuditRow(t, db)
	if row.RequestBody == "" {
		t.Fatal("request_body 為空——中介層未寫出本文，守衛失去觀測對象")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(row.RequestBody), &parsed); err != nil {
		t.Fatalf("request_body 非 JSON 物件: %q (%v)", row.RequestBody, err)
	}
	return row, parsed
}

// TestRoleAssignmentAuditRecordsTargetRoles 升權可查明目標角色。
//
// 規格 scenario：升權可查明目標角色。
func TestRoleAssignmentAuditRecordsTargetRoles(t *testing.T) {
	r, db := privilegeAuditRouter(t, "admin")
	row, parsed := privilegeAuditBody(t, r, db,
		"PUT", "/api/v1/users/42/roles", `{"roles":["admin","auditor"]}`)

	if row.StatusCode != http.StatusOK {
		t.Fatalf("狀態碼 = %d，want 200（釘子須打在真正被受理的請求上）", row.StatusCode)
	}
	raw, ok := parsed["roles"]
	if !ok {
		t.Fatalf("request_body 沒有 roles 鍵: %s", row.RequestBody)
	}
	if s, isStr := raw.(string); isStr && strings.Contains(s, "MASKED") {
		t.Fatalf("roles 被遮成 %q——「升成什麼角色」無處可查，這正是要修的缺陷", s)
	}
	list, ok := raw.([]any)
	if !ok {
		t.Fatalf("roles 型別 %T，want 陣列: %s", raw, row.RequestBody)
	}
	got := make([]string, 0, len(list))
	for _, v := range list {
		got = append(got, v.(string))
	}
	if len(got) != 2 || got[0] != "admin" || got[1] != "auditor" {
		t.Fatalf("roles = %v，want [admin auditor]", got)
	}
}

// TestAccountStatusAuditRecordsDirection 帳號啟停可查明方向。
//
// 規格 scenario：帳號啟停可查明方向。停用與啟用**分別**斷言：只驗一個方向的話，
// 「恆寫 true」也會過，而那正好是「方向不可辨」的另一種形態。
func TestAccountStatusAuditRecordsDirection(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"停用帳號", `{"active":false}`, false},
		{"啟用帳號", `{"active":true}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, db := privilegeAuditRouter(t, "admin")
			row, parsed := privilegeAuditBody(t, r, db, "PUT", "/api/v1/users/42/status", tc.body)

			raw, ok := parsed["active"]
			if !ok {
				t.Fatalf("request_body 沒有 active 鍵: %s", row.RequestBody)
			}
			got, ok := raw.(bool)
			if !ok {
				t.Fatalf("active = %#v（型別 %T）——方向被遮或型別走樣，"+
					"稽核分不出這次是停用還是啟用: %s", raw, raw, row.RequestBody)
			}
			if got != tc.want {
				t.Fatalf("active = %v，want %v", got, tc.want)
			}
		})
	}
}

// TestPrivilegeAuditKeepsSecretsMasked 機密欄位不因課責而外洩。
//
// 規格 scenario：機密欄位不因課責而外洩。攻擊面很實在——請求本文是攻擊者可控的，
// 任何人都能在提權請求裡多塞一個 password／token 欄位；放行清單若被改成
// default-allow，那些值就會逐字寫進受檢查點鏈保護、刪不掉的審計列。
func TestPrivilegeAuditKeepsSecretsMasked(t *testing.T) {
	const leaked = "SENTINEL-must-never-reach-audit"
	r, db := privilegeAuditRouter(t, "admin")
	row, parsed := privilegeAuditBody(t, r, db, "PUT", "/api/v1/users/42/roles",
		`{"roles":["admin"],"password":"`+leaked+`","refresh_token":"`+leaked+
			`","client_secret":"`+leaked+`","private_key":"`+leaked+`"}`)

	if strings.Contains(row.RequestBody, leaked) {
		t.Fatalf("機密明文寫進了 audit_logs.request_body（該列受檢查點鏈保護，寫進去刪不掉）: %s",
			row.RequestBody)
	}
	for _, key := range []string{"password", "refresh_token", "client_secret", "private_key"} {
		if parsed[key] != "***MASKED***" {
			t.Errorf("%s = %#v，want ***MASKED***", key, parsed[key])
		}
	}
	// 反向：遮罩必須是**選擇性**的。整列全遮也能通過上面的斷言，
	// 而那就是這裡要防的缺陷本身
	if _, ok := parsed["roles"].([]any); !ok {
		t.Errorf("roles = %#v——課責欄位連同機密一起被遮，等於沒修", parsed["roles"])
	}
}

// TestDeniedPrivilegeEscalationStillRecordsAttempt 授權閘行為未受影響（反向斷言）。
//
// 兩件事一起釘：低權越權仍是 403 ＋ `status=denied` 留痕（既有行為，不得被動到），
// 且**未遂的提權企圖照樣留下他想升成什麼**——拒絕列少了這個欄位，稽核只知道
// 「有人被擋了」，答不出「他想幹什麼」。
func TestDeniedPrivilegeEscalationStillRecordsAttempt(t *testing.T) {
	r, db := privilegeAuditRouter(t, "user")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/v1/users/42/roles", strings.NewReader(`{"roles":["admin"]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("低權提權應被擋下（403），得 %d——授權閘行為已被改動影響", w.Code)
	}
	row := latestAuditRow(t, db)
	if row.Status != model.StatusDenied {
		t.Fatalf("status = %s，want %s（拒絕路徑的留痕分類不得漂移）", row.Status, model.StatusDenied)
	}
	if row.StatusCode != http.StatusForbidden {
		t.Fatalf("status_code = %d，want 403", row.StatusCode)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(row.RequestBody), &parsed); err != nil {
		t.Fatalf("request_body 非 JSON 物件: %q (%v)", row.RequestBody, err)
	}
	list, ok := parsed["roles"].([]any)
	if !ok || len(list) != 1 || list[0] != "admin" {
		t.Fatalf("被拒的提權企圖沒留下目標角色: %s", row.RequestBody)
	}
}
