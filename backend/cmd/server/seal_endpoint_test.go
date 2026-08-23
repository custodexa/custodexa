package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/seal"
)

// 解封端點驗收。

// sealEndpointRouter 只掛解封端點（本檔驗的是端點語義，不是路由面）。
func sealEndpointRouter(t *testing.T, h *api.SealHandler) *gin.Engine {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"))
	return r
}

// postUnseal 送一次解封請求。sourceIP 為空時沿用 httptest 預設來源。
func postUnseal(r *gin.Engine, body, sourceIP string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/seal/unseal", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if sourceIP != "" {
		req.RemoteAddr = net.JoinHostPort(sourceIP, "40000")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// getStatus 取 /seal/status 的解析結果（沿用 httptest 預設來源）。
func getStatus(t *testing.T, r *gin.Engine) map[string]any {
	t.Helper()
	return getStatusFrom(t, r, "")
}

// getStatusFrom 自指定來源 IP 取 /seal/status。
// 狀態查詢與解封同受網段限制，故來源在此是必要參數而非細節。
func getStatusFrom(t *testing.T, r *gin.Engine, sourceIP string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/seal/status", nil)
	if sourceIP != "" {
		req.RemoteAddr = net.JoinHostPort(sourceIP, "40000")
	}
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("/seal/status 回 %d，期望 200", w.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析 /seal/status 失敗: %v", err)
	}
	return out
}

// testLimiter 是本檔共用的短參數限速結構：門檻小、時長短，使冷卻可被觀察。
func testLimiter() *seal.Limiter {
	return seal.NewLimiter(seal.LimiterConfig{
		BaseBackoff:       time.Second,
		MaxBackoff:        4 * time.Second,
		GlobalThreshold:   3,
		GlobalCooldown:    10 * time.Second,
		MaxGlobalCooldown: 20 * time.Second,
	})
}

// TestUnsealCooldownExpiresWithoutRestart 冷卻期滿自動恢復——證明不需重啟行程。
//
// 這是原設計「終局鎖定態」被移除的核心驗收：任何情況下都不得存在需重啟才能
// 解除的鎖定。
func TestUnsealCooldownExpiresWithoutRestart(t *testing.T) {
	clock := newFakeClock()
	_, h := newTestSealSetup(t, withLimiter(testLimiter()), withNow(clock.Now))
	r := sealEndpointRouter(t, h)

	// 連續材料失敗直到武裝全域冷卻。時鐘在**每次嘗試之前**推進以跨過該來源的
	// 退避期——若改成事後推進，最後一次失敗與觀察點之間就會多出一段時間，
	// 冷卻到期時間會恰好落在「現在」而使斷言失去意義。
	for i := 0; i < 3; i++ {
		if i > 0 {
			clock.Advance(10 * time.Second)
		}
		if w := postUnseal(r, `{"kek":"bad"}`, ""); w.Code != http.StatusBadRequest {
			t.Fatalf("第 %d 次材料失敗回 %d，期望 400", i+1, w.Code)
		}
	}

	status := getStatus(t, r)
	until, ok := status["cooldown_until"].(string)
	if !ok || until == "" {
		t.Fatalf("/seal/status 未暴露 cooldown_until（管理員與監控將只能猜測）：%v", status)
	}
	deadline, err := time.Parse(time.RFC3339, until)
	if err != nil {
		t.Fatalf("cooldown_until 不是 RFC3339：%q", until)
	}
	if !deadline.After(clock.Now()) {
		t.Fatalf("冷卻到期時間 %v 不在未來（現在 %v）", deadline, clock.Now())
	}

	// 冷卻期內：直接被拒、不驗證。
	w := postUnseal(r, `{"kek":"bad"}`, "")
	if w.Code != http.StatusTooManyRequests || bodyCode(t, w.Body.Bytes()) != string(apierror.CodeSealCooldownActive) {
		t.Fatalf("冷卻期內回 %d/%s，期望 429/SEAL_COOLDOWN_ACTIVE", w.Code, bodyCode(t, w.Body.Bytes()))
	}

	// 時間走到到期之後：自動恢復可嘗試（回到材料驗證，而非仍被冷卻拒絕）。
	advancePast(clock, deadline)
	w = postUnseal(r, `{"kek":"bad"}`, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("冷卻期滿後回 %d（碼 %s），期望 400 材料失敗——冷卻未自動解除即等於需重啟才能恢復",
			w.Code, bodyCode(t, w.Body.Bytes()))
	}
}

// TestUnsealCooldownNotExtendedByAttempts 冷卻期間持續嘗試，仍於原到期時間恢復。
//
// 缺此性質時，匿名攻擊者可持續送請求把到期時間不斷往後推，使可嘗試窗口永不
// 出現——等價於可持續 DoS，即使狀態機層已無「終局鎖定態」。
func TestUnsealCooldownNotExtendedByAttempts(t *testing.T) {
	clock := newFakeClock()
	_, h := newTestSealSetup(t, withLimiter(testLimiter()), withNow(clock.Now))
	r := sealEndpointRouter(t, h)

	for i := 0; i < 3; i++ {
		if i > 0 {
			clock.Advance(10 * time.Second)
		}
		postUnseal(r, `{"kek":"bad"}`, "")
	}
	first := getStatus(t, r)["cooldown_until"].(string)

	// 冷卻期間持續轟炸：每一次都應被直接拒絕，且不得刷新到期時間。
	for i := 0; i < 20; i++ {
		w := postUnseal(r, `{"kek":"bad"}`, "")
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("冷卻期第 %d 次嘗試回 %d，期望 429（不得進入驗證）", i+1, w.Code)
		}
		clock.Advance(100 * time.Millisecond)
		if now := getStatus(t, r)["cooldown_until"].(string); now != first {
			t.Fatalf("冷卻到期時間被嘗試延長：%s → %s", first, now)
		}
	}

	deadline, _ := time.Parse(time.RFC3339, first)
	advancePast(clock, deadline)
	if w := postUnseal(r, `{"kek":"bad"}`, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("原到期時間屆滿後回 %d，期望恢復受理（400 材料失敗）", w.Code)
	}
}

// TestUnsealBackoffIsCapped 退避成長有封頂：等待封頂時長即必然可再試。
func TestUnsealBackoffIsCapped(t *testing.T) {
	const maxBackoff = 4 * time.Second
	clock := newFakeClock()
	// 冷卻門檻拉高，使本測試只觀察 per-source 退避而不被全域冷卻干擾。
	limiter := seal.NewLimiter(seal.LimiterConfig{
		BaseBackoff: time.Second, MaxBackoff: maxBackoff,
		GlobalThreshold: 1000, GlobalCooldown: time.Minute, MaxGlobalCooldown: time.Minute,
	})
	_, h := newTestSealSetup(t, withLimiter(limiter), withNow(clock.Now))
	r := sealEndpointRouter(t, h)

	for i := 0; i < 12; i++ {
		w := postUnseal(r, `{"kek":"bad"}`, "203.0.113.9")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("第 %d 次嘗試在等待封頂時長後仍被退避拒絕（回 %d）——退避無上限即「等待即可再試」不成立",
				i+1, w.Code)
		}
		clock.Advance(maxBackoff + time.Millisecond)
	}
}

// TestAnonymousFailuresCannotLockOutAdmin 匿名連續失敗不得使正當管理員永久無法解封。
//
// 這是原終局鎖定設計的缺陷：攻擊者灌爆失敗次數即可讓正確材料也進不來，
// 重啟後再灌一次即可無限重複。
func TestAnonymousFailuresCannotLockOutAdmin(t *testing.T) {
	const goodMaterial = `{"kek":"good"}`
	clock := newFakeClock()
	_, h := newTestSealSetup(t,
		withLimiter(testLimiter()),
		withNow(clock.Now),
		withVerify(func(_ context.Context, material []byte) (seal.VerifiedMaterial, error) {
			if string(material) == goodMaterial {
				return seal.VerifiedMaterial{}, nil
			}
			return seal.VerifiedMaterial{}, errTestMaterial
		}))
	r := sealEndpointRouter(t, h)

	// 攻擊者（另一來源）連續灌爆到觸發全域冷卻。
	for i := 0; i < 8; i++ {
		if i > 0 {
			clock.Advance(30 * time.Second)
		}
		postUnseal(r, `{"kek":"attacker"}`, "198.51.100.7")
	}
	deadlineStr, ok := getStatus(t, r)["cooldown_until"].(string)
	if !ok {
		t.Fatal("攻擊未觸發全域冷卻，本測試的前提不成立")
	}
	deadline, _ := time.Parse(time.RFC3339, deadlineStr)

	// 冷卻期滿後，正當管理員以正確材料解封必須成功。
	advancePast(clock, deadline)
	w := postUnseal(r, goodMaterial, "192.0.2.50")
	if w.Code != http.StatusOK {
		t.Fatalf("冷卻期滿後正當管理員解封回 %d（碼 %s），期望 200——匿名失敗造成了永久鎖定",
			w.Code, bodyCode(t, w.Body.Bytes()))
	}
}

// TestPerSourceBackoffDegradesWithoutTrustedProxy 未設可信代理時 per-IP 退避降級為全域退避。
//
// 未設定可信代理鏈時，限速鍵可被轉送標頭污染而誤歸戶或繞過；寧可影響可用性
// 也不提供可繞過的假防線。
func TestPerSourceBackoffDegradesWithoutTrustedProxy(t *testing.T) {
	t.Run("未設可信代理：另一來源同樣被退避", func(t *testing.T) {
		clock := newFakeClock()
		_, h := newTestSealSetup(t, withLimiter(testLimiter()), withNow(clock.Now))
		h.SetSourceControls(false, nil, "")
		r := sealEndpointRouter(t, h)

		if w := postUnseal(r, `{"kek":"bad"}`, "203.0.113.1"); w.Code != http.StatusBadRequest {
			t.Fatalf("首次嘗試回 %d，期望 400", w.Code)
		}
		w := postUnseal(r, `{"kek":"bad"}`, "203.0.113.2")
		if w.Code != http.StatusTooManyRequests || bodyCode(t, w.Body.Bytes()) != string(apierror.CodeSealBackoffActive) {
			t.Fatalf("另一來源回 %d/%s，期望 429/SEAL_BACKOFF_ACTIVE（未降級為全域退避）",
				w.Code, bodyCode(t, w.Body.Bytes()))
		}
	})

	t.Run("已設可信代理：退避逐來源獨立", func(t *testing.T) {
		clock := newFakeClock()
		_, h := newTestSealSetup(t, withLimiter(testLimiter()), withNow(clock.Now))
		h.SetSourceControls(true, nil, "")
		r := sealEndpointRouter(t, h)

		if w := postUnseal(r, `{"kek":"bad"}`, "203.0.113.1"); w.Code != http.StatusBadRequest {
			t.Fatalf("首次嘗試回 %d，期望 400", w.Code)
		}
		if w := postUnseal(r, `{"kek":"bad"}`, "203.0.113.2"); w.Code != http.StatusBadRequest {
			t.Fatalf("另一來源回 %d，期望 400（可信代理已設定時不應被鄰居的退避牽連）", w.Code)
		}
	})
}

// TestUnsealSourceCIDRRestriction 解封端點的來源網段限制組態確實生效。
func TestUnsealSourceCIDRRestriction(t *testing.T) {
	_, h := newTestSealSetup(t)
	cfg := config.SealConfig{UnsealAllowedCIDRs: []string{"10.0.0.0/24", "192.0.2.77"}}
	nets, err := cfg.ParseAllowedCIDRs()
	if err != nil {
		t.Fatalf("解析允許網段失敗: %v", err)
	}
	h.SetSourceControls(false, nets, "127.0.0.1:8081")
	r := sealEndpointRouter(t, h)

	for _, ip := range []string{"10.0.0.5", "192.0.2.77"} {
		if w := postUnseal(r, `{"kek":"bad"}`, ip); w.Code == http.StatusForbidden {
			t.Errorf("允許網段內的來源 %s 被拒", ip)
		}
	}
	w := postUnseal(r, `{"kek":"bad"}`, "203.0.113.200")
	if w.Code != http.StatusForbidden || bodyCode(t, w.Body.Bytes()) != string(apierror.CodeSealSourceNotAllowed) {
		t.Fatalf("網段外來源回 %d/%s，期望 403/SEAL_SOURCE_NOT_ALLOWED",
			w.Code, bodyCode(t, w.Body.Bytes()))
	}

	// 繫結位址經 status 暴露，使部署方可確認組態真的生效。
	// **狀態查詢同樣受網段限制**（限制是端點群層級的），故須自允許網段內查詢。
	st := getStatusFrom(t, r, "10.0.0.5")
	if got := st["bind_addr"]; got != "127.0.0.1:8081" {
		t.Fatalf("/seal/status 的 bind_addr 為 %v，期望 127.0.0.1:8081", got)
	}
	if got := st["source_restricted"]; got != true {
		t.Fatalf("/seal/status 的 source_restricted 為 %v，期望 true", got)
	}
}

// TestSealConfigRejectsMalformedCIDR 網段組態打錯即整體 fail-close。
// 靜默忽略等於把一道顯式啟用的來源限制悄悄關掉。
func TestSealConfigRejectsMalformedCIDR(t *testing.T) {
	cfg := config.SealConfig{UnsealAllowedCIDRs: []string{"10.0.0.0/24", "not-an-ip"}}
	if _, err := cfg.ParseAllowedCIDRs(); err == nil {
		t.Fatal("含無法解析項目的網段組態竟被接受——打錯的網段會靜默失效")
	}
}

// TestUnsealFailureResponsesIndistinguishable 失敗回應**內容**不可區分。
//
// 承諾範圍限於回應內容；timing 差異誠實列於 Risks，不在本測試範圍。
func TestUnsealFailureResponsesIndistinguishable(t *testing.T) {
	clock := newFakeClock()
	// 退避關到最小，使四次嘗試都真的走到驗證。
	limiter := seal.NewLimiter(seal.LimiterConfig{
		BaseBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond,
		GlobalThreshold: 1000, GlobalCooldown: time.Minute, MaxGlobalCooldown: time.Minute,
	})
	_, h := newTestSealSetup(t, withLimiter(limiter), withNow(clock.Now),
		withVerify(func(_ context.Context, material []byte) (seal.VerifiedMaterial, error) {
			// 真實的 verify 對「格式錯」與「材料錯」走不同路徑，但回傳的
			// error 只作為 Cause——對外一律是同一個材料失敗碼。
			if _, err := api.DecodeSealMaterial(material); err != nil {
				return seal.VerifiedMaterial{}, err
			}
			return seal.VerifiedMaterial{}, errTestMaterial
		}))
	r := sealEndpointRouter(t, h)

	bodies := []string{
		`{"kek":"short"}`, // 格式不合
		`{"kek":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`, // 格式合但材料錯
		`not json at all`,               // 請求體無法解析
		`{"kek":"x","unknown_field":1}`, // 未知欄位
	}
	var first string
	for i, b := range bodies {
		clock.Advance(time.Second)
		w := postUnseal(r, b, "")
		got := w.Body.String()
		if w.Code != http.StatusBadRequest {
			t.Fatalf("第 %d 種失敗回 %d，期望 400", i+1, w.Code)
		}
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("第 %d 種失敗的回應內容與第 1 種不同，成因可被區分：\n  %s\n  %s", i+1, first, got)
		}
	}
}

// TestSealStatusExposesFaultAndTimeoutHint faulted 機器碼與逾時重試指引皆須可讀。
func TestSealStatusExposesFaultAndTimeoutHint(t *testing.T) {
	t.Run("段 2 失敗：狀態 sealed-faulted 且暴露機器碼", func(t *testing.T) {
		_, h := newTestSealSetup(t,
			withVerify(func(context.Context, []byte) (seal.VerifiedMaterial, error) {
				return seal.VerifiedMaterial{}, nil
			}),
			withStage2(func(context.Context, seal.VerifiedMaterial) (seal.ServiceGraph, error) {
				return nil, errTestMaterial
			}))
		r := sealEndpointRouter(t, h)
		if w := postUnseal(r, `{"kek":"x"}`, ""); w.Code != http.StatusInternalServerError {
			t.Fatalf("段 2 失敗回 %d，期望 500", w.Code)
		}
		st := getStatus(t, r)
		if st["state"] != string(seal.StateSealedFaulted) {
			t.Fatalf("狀態為 %v，期望 sealed-faulted", st["state"])
		}
		if st["fault_code"] != seal.CodeInitFailed {
			t.Fatalf("fault_code 為 %v，期望 %s", st["fault_code"], seal.CodeInitFailed)
		}
	})

	t.Run("段 2 逾時：狀態暴露逾時重試指引", func(t *testing.T) {
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		m, h := newTestSealSetup(t,
			withStage2Timeout(20*time.Millisecond),
			withVerify(func(context.Context, []byte) (seal.VerifiedMaterial, error) {
				return seal.VerifiedMaterial{}, nil
			}),
			withStage2(func(ctx context.Context, _ seal.VerifiedMaterial) (seal.ServiceGraph, error) {
				select {
				case <-ctx.Done():
				case <-release:
				}
				return &fakeGraph{}, ctx.Err()
			}))
		r := sealEndpointRouter(t, h)
		if w := postUnseal(r, `{"kek":"x"}`, ""); w.Code != http.StatusGatewayTimeout {
			t.Fatalf("段 2 逾時回 %d，期望 504", w.Code)
		}
		st := getStatus(t, r)
		if st["timeout_retry_hint_code"] != string(apierror.CodeSealStage2Timeout) {
			t.Fatalf("逾時後未暴露重試指引碼：%v\n"+
				"缺此提示時，管理員可能改用新材料重試而使第一把材料成為無人知曉的部署主 KEK", st)
		}
		m.WaitCleanup()
	})
}

// TestUnsealRejectsWhenAlreadyUnsealed 已解封時回 409 且不重跑初始化。
func TestUnsealRejectsWhenAlreadyUnsealed(t *testing.T) {
	m := seal.NewUnsealed(&fakeGraph{})
	h := api.NewSealHandler(m, nil)
	r := sealEndpointRouter(t, h)

	w := postUnseal(r, `{"kek":"x"}`, "")
	if w.Code != http.StatusConflict || bodyCode(t, w.Body.Bytes()) != string(apierror.CodeSealAlreadyUnsealed) {
		t.Fatalf("已解封時回 %d/%s，期望 409/SEAL_ALREADY_UNSEALED",
			w.Code, bodyCode(t, w.Body.Bytes()))
	}
	if st := getStatus(t, r); st["state"] != string(seal.StateUnsealed) {
		t.Fatalf("A／C 模式狀態為 %v，期望恆 unsealed", st["state"])
	}
}

// advancePast 把時鐘推進到 deadline 之後。已經過了就不動——負向推進會把時鐘
// 倒退回冷卻期內，讓測試以相反的理由變紅。
func advancePast(clock *fakeClock, deadline time.Time) {
	if d := deadline.Sub(clock.Now()) + time.Second; d > 0 {
		clock.Advance(d)
	}
}
