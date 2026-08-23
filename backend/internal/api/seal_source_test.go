package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/seal"
)

// 解封端點的來源控管驗收。

// sourceTestRouter 建一個只掛 seal 端點的 router。
func sourceTestRouter(t *testing.T, h *SealHandler) *gin.Engine {
	t.Helper()
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(prev) })
	r := gin.New()
	h.RegisterRoutes(r.Group("/api/v1"))
	return r
}

// mustCIDRs 解析測試用網段。
func mustCIDRs(t *testing.T, items ...string) []*net.IPNet {
	t.Helper()
	out := make([]*net.IPNet, 0, len(items))
	for _, s := range items {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("解析網段 %q 失敗: %v", s, err)
		}
		out = append(out, n)
	}
	return out
}

// sealRequest 送一次請求，peer 為 socket 對端、forwarded 為偽造的轉送標頭。
func sealRequest(r *gin.Engine, method, path, peer, forwarded string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(`{"kek":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = net.JoinHostPort(peer, "51234")
	if forwarded != "" {
		req.Header.Set("X-Forwarded-For", forwarded)
		req.Header.Set("X-Real-IP", forwarded)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func sourceBodyCode(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "<非 JSON 回應>"
	}
	return env.Code
}

// TestUnsealCIDRIgnoresForwardedHeadersWithoutTrustedProxy 未設可信代理時，
// 轉送標頭不得影響網段白名單判定。
//
// 缺此性質時，SEAL_UNSEAL_ALLOWED_CIDRS 形同虛設：攻擊者從任意位置送一個
// `X-Forwarded-For: 10.0.0.5` 就自稱位於管理網段——而 gin 的預設正是信任
// 全部代理，故「未設定可信代理」恰恰是最容易被繞過的組態。
func TestUnsealCIDRIgnoresForwardedHeadersWithoutTrustedProxy(t *testing.T) {
	h := NewSealHandler(seal.NewUnsealed(nil), nil)
	h.SetSourceControls(false, mustCIDRs(t, "10.0.0.0/24"), "")
	r := sourceTestRouter(t, h)

	// 網段外的 peer 偽造轉送標頭：必須仍被拒。
	w := sealRequest(r, http.MethodPost, "/api/v1/seal/unseal", "203.0.113.9", "10.0.0.5")
	if w.Code != http.StatusForbidden ||
		sourceBodyCode(t, w.Body.Bytes()) != string(apierror.CodeSealSourceNotAllowed) {
		t.Fatalf("偽造轉送標頭的網段外來源回 %d/%s，期望 403/SEAL_SOURCE_NOT_ALLOWED——網段白名單可被標頭繞過",
			w.Code, sourceBodyCode(t, w.Body.Bytes()))
	}

	// 網段內的 peer 即使帶著網段外的轉送標頭，也不得被誤擋。
	w = sealRequest(r, http.MethodPost, "/api/v1/seal/unseal", "10.0.0.5", "203.0.113.9")
	if w.Code == http.StatusForbidden {
		t.Fatal("網段內的 socket 對端被轉送標頭誤擋——來源判定採信了不該採信的來源")
	}
}

// TestUnsealCIDRUsesClientIPWhenTrustedProxyConfigured 已約定可信代理時才採信轉送標頭。
//
// 這是降級的另一半：顯式宣告代理鏈的部署必須能正常經 ingress 解封，
// 否則「安全」的代價是產品在標準部署形態下不能用。
func TestUnsealCIDRUsesClientIPWhenTrustedProxyConfigured(t *testing.T) {
	h := NewSealHandler(seal.NewUnsealed(nil), nil)
	h.SetSourceControls(true, mustCIDRs(t, "10.0.0.0/24"), "")
	r := sourceTestRouter(t, h)

	w := sealRequest(r, http.MethodPost, "/api/v1/seal/unseal", "203.0.113.9", "10.0.0.5")
	if w.Code == http.StatusForbidden {
		t.Fatal("已約定可信代理時，代理轉送的來源仍被擋——經 ingress 的部署無法解封")
	}
}

// TestSealStatusRespectsSourceCIDR 網段限制涵蓋整個 seal 端點群。
//
// 只擋解封而放行狀態，等於把「是否待初始化、繫結位址、冷卻到期時間」這組
// 偵察面留在網段之外——網段繫結是對端點群的限制，不是對單一動作的限制。
func TestSealStatusRespectsSourceCIDR(t *testing.T) {
	h := NewSealHandler(seal.NewUnsealed(nil), nil)
	h.SetSourceControls(false, mustCIDRs(t, "10.0.0.0/24"), "")
	r := sourceTestRouter(t, h)

	w := sealRequest(r, http.MethodGet, "/api/v1/seal/status", "203.0.113.9", "10.0.0.5")
	if w.Code != http.StatusForbidden ||
		sourceBodyCode(t, w.Body.Bytes()) != string(apierror.CodeSealSourceNotAllowed) {
		t.Fatalf("網段外的 /seal/status 回 %d/%s，期望 403/SEAL_SOURCE_NOT_ALLOWED",
			w.Code, sourceBodyCode(t, w.Body.Bytes()))
	}
	if w := sealRequest(r, http.MethodGet, "/api/v1/seal/status", "10.0.0.7", ""); w.Code != http.StatusOK {
		t.Fatalf("網段內的 /seal/status 回 %d，期望 200", w.Code)
	}
}

// TestUnsealRelocatedRejectsOnMainListener 解封端點另行繫結時，主監聽硬拒解封。
//
// 缺此拒絕時，獨立監聽只是多開一個入口：部署方把管理埠收進管理網段，
// 而解封仍可從業務埠進來——網段隔離完全沒有發生。
func TestUnsealRelocatedRejectsOnMainListener(t *testing.T) {
	h := NewSealHandler(seal.NewUnsealed(nil), nil)
	h.SetSourceControls(false, nil, "127.0.0.1:9443")
	h.SetUnsealRelocated(true)
	r := sourceTestRouter(t, h)

	w := sealRequest(r, http.MethodPost, "/api/v1/seal/unseal", "10.0.0.5", "")
	if w.Code != http.StatusForbidden ||
		sourceBodyCode(t, w.Body.Bytes()) != string(apierror.CodeSealSourceNotAllowed) {
		t.Fatalf("主監聽上的解封回 %d/%s，期望 403/SEAL_SOURCE_NOT_ALLOWED",
			w.Code, sourceBodyCode(t, w.Body.Bytes()))
	}
	// 狀態查詢仍可用：監控需要能在業務網段讀到「服務尚未解封」。
	if w := sealRequest(r, http.MethodGet, "/api/v1/seal/status", "10.0.0.5", ""); w.Code != http.StatusOK {
		t.Fatalf("主監聽上的 /seal/status 回 %d，期望 200", w.Code)
	}

	// 未宣告 relocated 的 handler（掛在管理監聽）仍可受理解封。
	admin := NewSealHandler(seal.NewUnsealed(nil), nil)
	ar := sourceTestRouter(t, admin)
	if w := sealRequest(ar, http.MethodPost, "/api/v1/seal/unseal", "10.0.0.5", ""); w.Code == http.StatusForbidden {
		t.Fatal("管理監聽上的解封被拒——獨立監聽將無法解封")
	}
}
