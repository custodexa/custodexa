package api

import (
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
)

// 重包請求體不入審計的**回歸釘子**。
//
// **釘子打在哪很重要**：middleware 實際捕獲的欄位是 `audit_logs.request_body`
// （internal/middleware/audit_log.go 讀 body → MaskSensitiveFields → 寫入該欄），
// **不是 details**。打在 details 上的斷言是打空氣——那個欄位本來就不裝請求體。
//
// 現行 MaskSensitiveFields 已是 allowlist（`internal/service/audit_log_service.go`），
// new_kek／new_kek_confirm 不在白名單故今天就被遮罩。本測試不是新增排除，而是
// **釘住這個既有行為**：日後若有人把 new_kek 加進 allowlist、或把遮罩策略改成
// denylist，本測試先紅。

// setupRewrapAuditRouter 掛上真正的審計 middleware 與重包路由（同步寫入，
// 免除 worker 批次的時序不確定）
func setupRewrapAuditRouter(t *testing.T) (*gin.Engine, *KeyManagementHandler) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := newKeyMgmtTestHandler(t)
	if err := h.db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	prev := database.DB
	database.DB = h.db
	t.Cleanup(func() { database.DB = prev })

	audit := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(audit))
	// 審計 middleware 只在 context 有身分時記錄；此處補上假身分（認證本身不在射程內）
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "admin")
		c.Next()
	})
	r.POST("/api/v1/keys/rewrap", h.Rewrap)
	return r, h
}

// latestRequestBody 取最後一筆審計列的 request_body 實值
func latestRequestBody(t *testing.T, h *KeyManagementHandler) string {
	t.Helper()
	var rows []model.AuditLog
	if err := h.db.Order("id DESC").Limit(1).Find(&rows).Error; err != nil {
		t.Fatalf("讀 audit_logs: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("未產生任何審計列——回歸釘子失去觀測對象（middleware 未生效？）")
	}
	return rows[0].RequestBody
}

// TestRewrapRequestBodyMaskedInAudit 斷言打在 audit_logs.request_body 實值上：
// new_kek／new_kek_confirm 被遮罩、材料字面不出現於該欄
func TestRewrapRequestBodyMaskedInAudit(t *testing.T) {
	r, h := setupRewrapAuditRouter(t)
	material := apiTestKEKMaterial(11)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rewrap", strings.NewReader(localRewrapBody(material)))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("重包應成功（釘子須打在真正被受理的請求上），得 %d body=%s", w.Code, w.Body.String())
	}

	body := latestRequestBody(t, h)
	// 觀測對象非空：空字串會讓下面的「不含材料」變成恆真
	if body == "" {
		t.Fatal("audit_logs.request_body 為空——斷言將恆真，釘子無效")
	}
	if strings.Contains(body, material) {
		t.Fatalf("audit_logs.request_body 洩漏 KEK 明文: %s", body)
	}
	for _, field := range []string{"new_kek", "new_kek_confirm"} {
		want := fmt.Sprintf("%q:%q", field, "***MASKED***")
		if !strings.Contains(body, want) {
			t.Fatalf("欄位 %s 未被遮罩（allowlist 可能被放寬）: %s", field, body)
		}
	}
}

// TestAuditRequestBodyMaskingIsSelective 敏感度：同一筆請求裡的 allowlist 欄位
// （username）必須原值保留。若整個 request_body 被無條件清空或整包遮罩，
// 上一格的「不含材料」就是假綠——本格證明遮罩確實是**逐欄位**判定
func TestAuditRequestBodyMaskingIsSelective(t *testing.T) {
	r, h := setupRewrapAuditRouter(t)
	material := apiTestKEKMaterial(12)

	// 刻意帶未知欄位 username：請求會被 union 解析以 400 拒絕（fail-close 正確），
	// 但審計仍會記錄請求體——正是本格需要的觀測樣本
	payload := fmt.Sprintf(`{"mode":"local","new_kek":%q,"new_kek_confirm":%q,"confirm_saved":true,"username":"admin"}`,
		material, material)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rewrap", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("未知欄位應 fail-close 400，得 %d body=%s", w.Code, w.Body.String())
	}

	body := latestRequestBody(t, h)
	if !strings.Contains(body, `"username":"admin"`) {
		t.Fatalf("allowlist 欄位應原值保留（否則遮罩不是逐欄位判定）: %s", body)
	}
	if strings.Contains(body, material) {
		t.Fatalf("audit_logs.request_body 洩漏 KEK 明文: %s", body)
	}
}
