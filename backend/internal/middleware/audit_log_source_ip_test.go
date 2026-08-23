package middleware

// 已認證請求審計列的來源位址不可偽造。
//
// `/auth/login` 那條零憑證路徑已另行修掉；本檔守的是**覆蓋面最大的一處**——
// `AuditLogMiddleware` 為每一個已認證請求寫的那一列。它原本取 `c.ClientIP()`，
// 在未設 `TRUSTED_PROXIES` 的部署下由請求方的轉送標頭決定，故任何持有有效帳號者
// 送一個 `X-Forwarded-For`，就能把自己**全部操作**的來源位址寫成任選的值：
// 稽核事後追人，追到的是他挑的那個位址。
//
// 兩格缺一不可：
//   - 正向：六種轉送標頭全帶，列上仍是 socket 對端
//   - 反向：**已約定可信代理時才採信標頭**——沒有這格，「一律取 socket 對端」
//     與正確實作在測試上不可區分，可信代理的設定路徑等於悄悄失效

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// sourceIPSpoofHeaders 攻擊者可控的六種轉送標頭（含 gin RemoteIPHeaders 與 CDN 慣例）
var sourceIPSpoofHeaders = map[string]string{
	"X-Forwarded-For":  sourceIPSpoofValue,
	"X-Real-IP":        sourceIPSpoofValue,
	"Forwarded":        "for=" + sourceIPSpoofValue,
	"True-Client-IP":   sourceIPSpoofValue,
	"CF-Connecting-IP": sourceIPSpoofValue,
	"X-Client-IP":      sourceIPSpoofValue,
}

const (
	// sourceIPSpoofValue 攻擊者想寫進審計列的位址（TEST-NET-2，文件用保留段）
	sourceIPSpoofValue = "198.51.100.77"
	// sourceIPPeer httptest.NewRequest 的 socket 對端（TEST-NET-1）
	sourceIPPeer = "192.0.2.1"
)

// sourceIPAuditRouter 掛真的 AuditLogMiddleware ＋ 一條已認證路由。
//
// trustProxy 為真時同時做兩件事：告訴中介層「可信代理已約定」，並讓 gin engine
// 把 socket 對端列為可信代理——兩者缺一，`ClientIP()` 都不會採信標頭，反向格會
// 因為錯誤的理由而通過。
func sourceIPAuditRouter(t *testing.T, trustProxy bool) (*gin.Engine, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := installClipboardAuditDB(t)

	svc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})
	r := gin.New()
	if trustProxy {
		if err := r.SetTrustedProxies([]string{sourceIPPeer}); err != nil {
			t.Fatalf("SetTrustedProxies: %v", err)
		}
		r.Use(AuditLogMiddleware(svc, withTrustedProxyDecision(true)))
	} else {
		r.Use(AuditLogMiddleware(svc))
	}
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "operator-under-test")
		c.Set("role", "admin")
		c.Next()
	})
	r.POST("/api/v1/assets", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{}) })
	return r, db
}

// sourceIPAuditRow 帶六種轉送標頭送出一般操作，回傳寫下的那一列
func sourceIPAuditRow(t *testing.T, r *gin.Engine, db *gorm.DB) model.AuditLog {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assets", nil)
	for k, v := range sourceIPSpoofHeaders {
		req.Header.Set(k, v)
	}
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("狀態碼 = %d，want 200（釘子須打在真正被受理的請求上）", w.Code)
	}
	return latestAuditRow(t, db)
}

// TestAuthenticatedAuditIgnoresForwardedHeaders 未約定可信代理時，六種轉送標頭全數不採信。
func TestAuthenticatedAuditIgnoresForwardedHeaders(t *testing.T) {
	r, db := sourceIPAuditRouter(t, false)
	row := sourceIPAuditRow(t, r, db)

	if row.ClientIP == sourceIPSpoofValue {
		t.Fatalf("審計列的 client_ip = %q——正是請求自帶的轉送標頭值："+
			"任何持有有效帳號者都能為自己的全部操作指定來源位址，稽核追到的是他挑的位址",
			row.ClientIP)
	}
	if row.ClientIP != sourceIPPeer {
		t.Fatalf("審計列的 client_ip = %q，want %q（socket 對端）", row.ClientIP, sourceIPPeer)
	}
}

// TestAuthenticatedAuditHonorsForwardedHeaderWhenProxyTrusted 反向斷言：
// 可信代理**已顯式約定**（`TRUSTED_PROXIES`，非法即拒絕啟動）時才採信轉送標頭。
//
// 沒有這一格，把實作改成「永遠取 socket 對端」也會全綠，而那會讓所有部署在反向
// 代理後的系統把每一列都記成代理的位址——設定路徑形同不存在。
func TestAuthenticatedAuditHonorsForwardedHeaderWhenProxyTrusted(t *testing.T) {
	r, db := sourceIPAuditRouter(t, true)
	row := sourceIPAuditRow(t, r, db)

	if row.ClientIP != sourceIPSpoofValue {
		t.Fatalf("審計列的 client_ip = %q，want %q："+
			"已約定可信代理鏈時仍不採信轉送標頭，等於可信代理設定路徑失效",
			row.ClientIP, sourceIPSpoofValue)
	}
}
