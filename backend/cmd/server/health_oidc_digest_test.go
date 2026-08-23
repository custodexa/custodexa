package main

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 健康檢查輸出部署宣告指紋。
//
// 沒有這條，`OIDC_DEDICATED_ISSUERS` 在多副本部署下的分歧就只能靠人工登入
// 每個副本比對環境變數；有了它，監控可直接比對各副本 /health 的同一欄位。
//
// **不用 t.Parallel**：測試改寫套件層的 oidcIssuerDeclarationDigest（啟動期單寫者），
// 併行會互相覆寫。

// withDeclarationDigest 暫時替換本副本的宣告指紋
func withDeclarationDigest(t *testing.T, declared []string) string {
	t.Helper()
	prev := oidcIssuerDeclarationDigest
	t.Cleanup(func() { oidcIssuerDeclarationDigest = prev })
	oidcIssuerDeclarationDigest = identity.DedicatedIssuerDeclarationDigest(declared)
	return oidcIssuerDeclarationDigest
}

// healthDigestField 打 /health 並取出指紋欄位
func healthDigestField(t *testing.T) string {
	t.Helper()
	r := newTestRouter(t, false, true)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("/health 回 %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析 /health 回應: %v", err)
	}
	v, ok := body["oidc_dedicated_issuers_digest"]
	if !ok {
		t.Fatalf("/health 未輸出 oidc_dedicated_issuers_digest，副本間設定分歧無法由外部偵測；實得 %v", body)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("oidc_dedicated_issuers_digest 型別 = %T, want string", v)
	}
	return s
}

func TestHealthExposesDeclarationDigest(t *testing.T) {
	want := withDeclarationDigest(t, []string{"https://corp.okta.example.com"})
	if got := healthDigestField(t); got != want {
		t.Errorf("/health 指紋 = %q, want %q", got, want)
	}
}

// Scenario: 兩份不同宣告 → 指紋不同（分歧可被偵測）
func TestHealthDigestDiffersAcrossDeclarations(t *testing.T) {
	withDeclarationDigest(t, []string{"https://corp.okta.example.com"})
	first := healthDigestField(t)
	withDeclarationDigest(t, []string{"https://other.okta.example.com"})
	second := healthDigestField(t)
	if first == second {
		t.Error("兩份不同宣告的 /health 指紋相同——副本間的宣告分歧將靜默通過，" +
			"症狀只會表現為「自動供應時靈時不靈」")
	}
}

// Scenario: 未設宣告時仍輸出固定指紋——「欄位為空」與「欄位不存在」在監控端
// 難以區分，而「一個副本漏設環境變數」正是本機制要抓的第一種故障
func TestHealthDigestPresentWithoutDeclaration(t *testing.T) {
	want := withDeclarationDigest(t, nil)
	got := healthDigestField(t)
	if got == "" {
		t.Fatal("未設宣告時指紋為空字串——漏設環境變數的副本將無法與正常副本區分")
	}
	if got != want {
		t.Errorf("指紋 = %q, want %q", got, want)
	}
}

// Scenario: 指紋出現在 /health 的回應中，但宣告原文不得出現（該端點無須認證）
func TestHealthDoesNotLeakDeclaredIssuers(t *testing.T) {
	withDeclarationDigest(t, []string{"https://secret-idp.internal.corp"})
	r := newTestRouter(t, false, true)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if body := w.Body.String(); strings.Contains(body, "secret-idp") {
		t.Errorf("/health 回應含宣告原文：%s", body)
	}
}
