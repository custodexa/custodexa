package api

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 以固定錯誤回應的盤點服務替身。
type inventoryStubSvc struct{ err error }

func (s inventoryStubSvc) Initiate(uint, asset.InventoryActor) (*model.HostAccountScan, error) {
	return nil, s.err
}
func (s inventoryStubSvc) GetAssetInventory(uint, asset.InventoryFindingQuery) (*asset.AssetInventoryView, error) {
	return nil, s.err
}
func (s inventoryStubSvc) ListGlobalFindings(asset.InventoryGlobalQuery) (*asset.InventoryGlobalView, error) {
	return nil, s.err
}
func (s inventoryStubSvc) IgnoreFinding(uint, uint, string, asset.InventoryActor) (*model.HostAccountFinding, error) {
	return nil, s.err
}
func (s inventoryStubSvc) ReopenFinding(uint, uint, asset.InventoryActor) (*model.HostAccountFinding, error) {
	return nil, s.err
}

// TestHostAccountInventoryHandlerErrors 七個業務出口碼各一案：服務 sentinel 與路徑參數錯誤一對一映射，
// 逐碼斷言 HTTP 狀態與 code；另斷言未預期錯誤依讀寫回兩個內部碼的 500，且不外洩錯誤原文。
func TestHostAccountInventoryHandlerErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name   string
		err    error
		method string
		path   string
		body   string
		status int
		code   string
	}{
		{"platform", asset.ErrInventoryPlatformUnsupported, "POST", "/assets/5/account-inventory/scans", "", 422, "RULE_INVENTORY_PLATFORM_UNSUPPORTED"},
		{"no_account", asset.ErrInventoryNoAccount, "POST", "/assets/5/account-inventory/scans", "", 422, "RULE_INVENTORY_NO_ACCOUNT"},
		{"no_secret", asset.ErrInventoryNoSecret, "POST", "/assets/5/account-inventory/scans", "", 422, "RULE_INVENTORY_NO_SECRET"},
		{"executor_unavailable", asset.ErrInventoryExecutorUnavailable, "POST", "/assets/5/account-inventory/scans", "", 422, "RULE_INVENTORY_EXECUTOR_UNAVAILABLE"},
		{"executor_busy", asset.ErrInventoryExecutorBusy, "POST", "/assets/5/account-inventory/scans", "", 409, "CONFLICT_INVENTORY_EXECUTOR_BUSY"},
		{"executor_rate_limited", asset.ErrInventoryExecutorRateLimited, "POST", "/assets/5/account-inventory/scans", "", 429, "RULE_INVENTORY_EXECUTOR_RATE_LIMITED"},
		{"running", asset.ErrInventoryScanRunning, "POST", "/assets/5/account-inventory/scans", "", 409, "CONFLICT_INVENTORY_SCAN_RUNNING"},
		{"ignore_reason", asset.ErrInventoryIgnoreReason, "POST", "/assets/5/account-inventory/findings/9/ignore", `{"reason":""}`, 400, "VALIDATION_INVENTORY_IGNORE_REASON"},
		{"bad_finding_id", nil, "POST", "/assets/5/account-inventory/findings/abc/reopen", "", 400, "VALIDATION_INVALID_FINDING_ID"},
		{"finding_missing", asset.ErrInventoryFindingNotFound, "POST", "/assets/5/account-inventory/findings/9/reopen", "", 404, "NOTFOUND_INVENTORY_FINDING"},
		{"unexpected_read", errors.New("secret detail: dial tcp 10.0.0.1"), "GET", "/assets/5/account-inventory", "", 500, "INTERNAL_INVENTORY_QUERY"},
		{"unexpected_write", errors.New("secret detail: dial tcp 10.0.0.1"), "POST", "/assets/5/account-inventory/scans", "", 500, "INTERNAL_INVENTORY_UPDATE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHostInventoryHandler(inventoryStubSvc{err: tc.err}, nil, nil)
			r := gin.New()
			r.POST("/assets/:id/account-inventory/scans", h.Initiate)
			r.GET("/assets/:id/account-inventory", h.Get)
			r.POST("/assets/:id/account-inventory/findings/:findingId/ignore", h.Ignore)
			r.POST("/assets/:id/account-inventory/findings/:findingId/reopen", h.Reopen)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)
			assert.Equal(t, tc.status, w.Code)
			var resp map[string]any
			assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			if tc.code != "" {
				assert.Equal(t, tc.code, resp["code"])
			}
			assert.NotContains(t, w.Body.String(), "10.0.0.1", "未預期錯誤的原文不得外洩")
		})
	}
}

// 記下收到的查詢的盤點服務替身。
type inventoryQuerySpy struct {
	inventoryStubSvc
	got *asset.InventoryFindingQuery
}

func (s inventoryQuerySpy) GetAssetInventory(_ uint, q asset.InventoryFindingQuery) (*asset.AssetInventoryView, error) {
	*s.got = q
	return &asset.AssetInventoryView{}, nil
}

// TestHostAccountInventoryHandlerActionable 「需要處理」查詢參數 actionable：true 傳給服務、未帶為 false、非布林回 400。
func TestHostAccountInventoryHandlerActionable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		query  string
		status int
		want   bool
	}{
		{"?actionable=true&privileged=true", 200, true},
		{"?privileged=true", 200, false},
		{"?actionable=false", 200, false},
		{"?actionable=maybe", 400, false},
	} {
		t.Run(tc.query, func(t *testing.T) {
			var got asset.InventoryFindingQuery
			h := NewHostInventoryHandler(inventoryQuerySpy{got: &got}, nil, nil)
			r := gin.New()
			r.GET("/assets/:id/account-inventory", h.Get)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/5/account-inventory"+tc.query, nil))
			assert.Equal(t, tc.status, w.Code)
			assert.Equal(t, tc.want, got.Actionable)
		})
	}
}
