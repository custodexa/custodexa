package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestListK8sPods_PerKindCode pod 列表的 k8s 錯誤逐類配碼（V2 對抗驗收 H1）。
//
// 修正前六類共用 RULE_K8S_POD_UNAVAILABLE：同一個 401，走 WS 撥號時前端拿到
// RULE_K8S_UNAUTHORIZED（可提示換 Token），走 pod 列表時只拿到泛碼——同一件事
// 兩條路徑兩種碼，前端無法一致處置。現兩處共用 k8sproxy.ErrCodeOf。
//
// 本測試同時是「兩處不得各自為政」的守衛：期望值直接取自 k8sproxy.ErrCodeOf，
// 故若日後有人在 handler 內重寫一份映射並漏配新 Kind，這裡會紅。
func TestListK8sPods_PerKindCode(t *testing.T) {
	kinds := []string{
		k8sproxy.KindUnauthorized, k8sproxy.KindForbidden, k8sproxy.KindNotFound,
		k8sproxy.KindTLS, k8sproxy.KindUnreachable, k8sproxy.KindUnknown,
	}

	seen := map[string]string{}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			kerr := &k8sproxy.K8sError{Kind: kind, Message: "namespace prod 相關的原文案"}

			mockAssetService := new(MockAssetService)
			mockAuthService := new(MockAssetAuthorizationService)
			mockAssetService.On("ListK8sPods", mock.Anything, uint(42)).Return(nil, kerr)

			handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
			router := setupTestRouter()
			router.GET("/assets/:id/k8s/pods", func(c *gin.Context) {
				c.Set("userID", uint(7))
				handler.ListK8sPods(c)
			})

			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("GET", "/assets/42/k8s/pods", nil))

			assert.Equal(t, http.StatusBadGateway, w.Code, "狀態碼不變（502）")

			var resp map[string]any
			assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

			want := string(k8sproxy.ErrCodeOf(kerr))
			assert.Equal(t, want, resp["code"], "應回該 kind 的專屬碼")
			assert.NotEqual(t, string(apierror.CodeK8sPodUnavailable), resp["code"],
				"不得落回泛碼（六類將再度不可分辨）")
			assert.Equal(t, kind, resp["kind"], "機器欄 kind 仍須保留（既有前端契約）")
			// 原文案（含 namespace 等脈絡）不外洩至回應本體
			assert.NotContains(t, w.Body.String(), "namespace prod")

			if prev, dup := seen[want]; dup {
				t.Fatalf("kind %q 與 %q 共用碼 %q（六類必須可分辨）", kind, prev, want)
			}
			seen[want] = kind
			mockAssetService.AssertExpectations(t)
		})
	}
}

// TestListK8sPods_NonK8sErrorStaysInternal 非 K8sError 仍走 500 內部錯誤碼
// （分類碼化不得擴大 502 的適用面）
func TestListK8sPods_NonK8sErrorStaysInternal(t *testing.T) {
	mockAssetService := new(MockAssetService)
	mockAuthService := new(MockAssetAuthorizationService)
	mockAssetService.On("ListK8sPods", mock.Anything, uint(42)).Return(nil, errors.New("boom"))

	handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
	router := setupTestRouter()
	router.GET("/assets/:id/k8s/pods", func(c *gin.Context) {
		c.Set("userID", uint(7))
		handler.ListK8sPods(c)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/assets/42/k8s/pods", nil))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp map[string]any
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, string(apierror.CodeInternalK8sPodList), resp["code"])
}
