package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 本地登入端點的來源限流（security-backlog-settlement 塊 3）。
//
// **與帳號級鎖定防的是不同攻擊**：既有的 `failed_login_attempts`＋`locked_until`
// 擋對單一帳號的暴力破解；本限流擋**換帳號輪流試**的密碼噴灑——每個帳號各試
// 三次即換下一個，永遠碰不到帳號門檻。只有帳號鎖定 SHALL NOT 視為已涵蓋此面。

// newLoginGuardRouter 以指定參數建一個只有 /auth/login 的 router。
//
// **必須接一個可用的 authService**：限流雖發生在解析 body 之前，但通過限流的
// 請求會一路走到憑證驗證——authService 為 nil 時那裡直接 panic，測試就分不出
// 「被限流擋下」與「程式壞了」。這裡接 sqlite in-memory 且不建任何使用者，
// 通過限流者一律落在「查無帳號」路徑回 401，與 429 清楚可辨
func newLoginGuardRouter(t *testing.T, params sourceGuardParams, sink sourceAbuseAuditSink) *gin.Engine {
	t.Helper()
	return newLoginRouterWithGuard(t, newSourceAbuseGuard(params, false, sink))
}

// newLoginRouterWithGuard 同上，但 guard 由呼叫端提供（可為 nil，驗未建構路徑）
func newLoginRouterWithGuard(t *testing.T, guard *sourceAbuseGuard) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	h := &AuthHandler{
		authService: identity.NewAuthService("login-guard-test-secret", time.Minute),
		loginGuard:  guard,
	}
	r := gin.New()
	r.POST("/api/v1/auth/login", h.Login)
	return r
}

func postLogin(t *testing.T, r *gin.Engine, ip, username string) *httptest.ResponseRecorder {
	t.Helper()
	body := bytes.NewBufferString(`{"username":"` + username + `","password":"guess"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":40000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// 密碼噴灑：同一來源對**不同帳號**連續嘗試，每個帳號都不會觸發帳號鎖定，
// 但來源限流會擋下
func TestLoginRateLimit_PasswordSprayingBlockedBySourceLimit(t *testing.T) {
	params := defaultLoginGuardParams()
	params.PerIPBurst = 3 // 縮小額度使測試不必送 60 次
	sink := &recordingAggSink{}
	r := newLoginGuardRouter(t, params, sink)

	const attacker = "203.0.113.7"

	// 額度內：不得回 429（每次都換一個帳號，模擬噴灑）
	for i := 0; i < 3; i++ {
		w := postLogin(t, r, attacker, "victim"+string(rune('a'+i)))
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("第 %d 次（額度內）不應被限流，實得 429", i+1)
		}
	}

	// 超出額度：擋下
	w := postLogin(t, r, attacker, "victim-x")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("超出來源額度應回 429，實得 %d——"+
			"密碼噴灑不受帳號鎖定約束，只有來源限流擋得住", w.Code)
	}
}

// 回應不得洩漏限流參數：門檻、剩餘額度與重試時間都會讓攻擊者把流量精確調到
// 門檻之下持續消耗（沿帳號鎖定「不透露剩餘時間與次數」的既有語義）
func TestLoginRateLimit_ResponseLeaksNoQuota(t *testing.T) {
	params := defaultLoginGuardParams()
	params.PerIPBurst = 1
	r := newLoginGuardRouter(t, params, &recordingAggSink{})

	const ip = "203.0.113.8"
	postLogin(t, r, ip, "someone")
	w := postLogin(t, r, ip, "someone")

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("應為 429，實得 %d", w.Code)
	}
	body := w.Body.String()
	if !bytes.Contains([]byte(body), []byte(string(apierror.CodeAuthLoginRateLimited))) {
		t.Errorf("回應應含機器碼 %s，實得 %s", apierror.CodeAuthLoginRateLimited, body)
	}
	for _, leak := range []string{"retry", "Retry", "remaining", "quota", "burst", "refill"} {
		if bytes.Contains([]byte(body), []byte(leak)) {
			t.Errorf("回應洩漏限流參數（含 %q）：%s", leak, body)
		}
	}
	if w.Header().Get("Retry-After") != "" {
		t.Errorf("不得回 Retry-After 標頭，實得 %q", w.Header().Get("Retry-After"))
	}
}

// 限流事件以**聚合**形式入審計：逐次一筆會讓偵測訊號本身變成無界寫入載體
// （攻擊者持續送請求＝持續寫 DB）
func TestLoginRateLimit_AuditIsAggregatedNotPerRequest(t *testing.T) {
	params := defaultLoginGuardParams()
	params.PerIPBurst = 1
	sink := &recordingAggSink{}
	r := newLoginGuardRouter(t, params, sink)

	const ip = "203.0.113.9"
	const floods = 50
	for i := 0; i < floods; i++ {
		postLogin(t, r, ip, "victim")
	}

	sink.mu.Lock()
	entries := append([]aggRecord(nil), sink.entries...)
	sink.mu.Unlock()

	// 窗未結束時尚未 flush 屬正常；重點是**不得**逐次一筆
	if len(entries) >= floods {
		t.Fatalf("審計列數 %d 與請求數 %d 同量級——限流事件必須聚合，"+
			"否則攻擊本身即成審計洪水", len(entries), floods)
	}
	for _, e := range entries {
		if e.event != loginEventThrottled {
			t.Errorf("聚合事件名 = %q, want %q", e.event, loginEventThrottled)
		}
		if e.status != model.StatusDenied {
			t.Errorf("限流屬政策拒絕（denied，與 RBAC 403 同語義），實得 %v", e.status)
		}
	}
}

// 不同來源各自計額：一個來源被擋不得波及其他來源
func TestLoginRateLimit_PerSourceIsolation(t *testing.T) {
	params := defaultLoginGuardParams()
	params.PerIPBurst = 1
	r := newLoginGuardRouter(t, params, &recordingAggSink{})

	postLogin(t, r, "203.0.113.10", "u1")
	if w := postLogin(t, r, "203.0.113.10", "u1"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("同來源第二次應被擋，實得 %d", w.Code)
	}
	if w := postLogin(t, r, "203.0.113.11", "u1"); w.Code == http.StatusTooManyRequests {
		t.Error("另一個來源不應受影響——per-IP 桶必須各自獨立")
	}
}

// 未建構 guard 的實例不 panic（測試與 sealgate 佔位路徑）
func TestLoginRateLimit_NilGuardIsSafe(t *testing.T) {
	r := newLoginRouterWithGuard(t, nil)

	w := postLogin(t, r, "203.0.113.12", "u1")
	if w.Code == http.StatusTooManyRequests {
		t.Errorf("無 guard 時不應限流，實得 %d", w.Code)
	}
}
