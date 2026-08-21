package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
)

// fakeAssetChecker 記錄呼叫參數的 AssetPermissionChecker 假件
type fakeAssetChecker struct {
	allow      bool
	err        error
	called     bool
	gotUserID  uint
	gotAssetID uint
	gotPerm    model.PermissionType
	gotRole    interface{}
}

func (f *fakeAssetChecker) CheckPermission(ctx context.Context, userID, assetID uint, perm model.PermissionType) (bool, error) {
	f.called = true
	f.gotUserID = userID
	f.gotAssetID = assetID
	f.gotPerm = perm
	f.gotRole = ctx.Value("role")
	return f.allow, f.err
}

// newVisibilityRouter 建最小路由：注入 role/userID 後掛 RequireAssetVisible，
// 終點 handler 回 200 ok——只驗中介層行為，不觸 handler 邏輯
func newVisibilityRouter(checker AssetPermissionChecker, role string, userID uint, setUserID bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/assets/:id/probe", func(c *gin.Context) {
		if role != "" {
			c.Set("role", role)
		}
		if setUserID {
			c.Set("userID", userID)
		}
		c.Next()
	}, RequireAssetVisible(checker), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})
	return r
}

func doVisibilityRequest(r *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	r.ServeHTTP(w, req)
	return w
}

// TestRequireAssetVisible_PrivilegedBypass admin/auditor 直通且不觸發授權查詢
func TestRequireAssetVisible_PrivilegedBypass(t *testing.T) {
	for _, role := range []string{model.RoleAdmin, model.RoleAuditor} {
		checker := &fakeAssetChecker{}
		r := newVisibilityRouter(checker, role, 1, true)
		w := doVisibilityRequest(r, "/assets/42/probe")

		if w.Code != http.StatusOK {
			t.Errorf("role=%s: 狀態碼 = %d, want 200", role, w.Code)
		}
		if checker.called {
			t.Errorf("role=%s: 直通不應呼叫 CheckPermission", role)
		}
	}
}

// TestRequireAssetVisible_AuthorizedPass 一般 user 有 view 授權放行，
// 且 checker 收到正確 userID/assetID/view 權限與 ctx 內 role
func TestRequireAssetVisible_AuthorizedPass(t *testing.T) {
	checker := &fakeAssetChecker{allow: true}
	r := newVisibilityRouter(checker, "user", 7, true)
	w := doVisibilityRequest(r, "/assets/42/probe")

	if w.Code != http.StatusOK {
		t.Errorf("狀態碼 = %d, want 200", w.Code)
	}
	if !checker.called {
		t.Fatal("應呼叫 CheckPermission")
	}
	if checker.gotUserID != 7 || checker.gotAssetID != 42 {
		t.Errorf("CheckPermission(userID=%d, assetID=%d), want (7, 42)", checker.gotUserID, checker.gotAssetID)
	}
	if checker.gotPerm != model.PermissionView {
		t.Errorf("perm = %v, want view", checker.gotPerm)
	}
	if checker.gotRole != "user" {
		t.Errorf("ctx role = %v, want user（CheckPermission 依 ctx role 判斷特權）", checker.gotRole)
	}
}

// TestRequireAssetVisible_Unauthorized404 未授權回 404「資產不存在」——不洩漏存在性
func TestRequireAssetVisible_Unauthorized404(t *testing.T) {
	checker := &fakeAssetChecker{allow: false}
	r := newVisibilityRouter(checker, "user", 7, true)
	w := doVisibilityRequest(r, "/assets/42/probe")

	if w.Code != http.StatusNotFound {
		t.Errorf("狀態碼 = %d, want 404", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "資產不存在") {
		t.Errorf("回應應為「資產不存在」（不洩漏授權狀態）, got %s", body)
	}
}

// TestRequireAssetVisible_MissingUserID401 認證上下文缺 userID 回 401
func TestRequireAssetVisible_MissingUserID401(t *testing.T) {
	checker := &fakeAssetChecker{allow: true}
	r := newVisibilityRouter(checker, "user", 0, false)
	w := doVisibilityRequest(r, "/assets/42/probe")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("狀態碼 = %d, want 401", w.Code)
	}
	if checker.called {
		t.Error("缺 userID 不應觸發授權查詢")
	}
}

// TestRequireAssetVisible_InvalidID400 非數字 ID 回 400 且不觸發授權查詢
func TestRequireAssetVisible_InvalidID400(t *testing.T) {
	checker := &fakeAssetChecker{allow: true}
	r := newVisibilityRouter(checker, "user", 7, true)
	w := doVisibilityRequest(r, "/assets/abc/probe")

	if w.Code != http.StatusBadRequest {
		t.Errorf("狀態碼 = %d, want 400", w.Code)
	}
	if checker.called {
		t.Error("無效 ID 不應觸發授權查詢")
	}
}

// TestRequireAssetVisible_CheckerError500 授權查詢失敗回 500，不得誤放行
func TestRequireAssetVisible_CheckerError500(t *testing.T) {
	checker := &fakeAssetChecker{allow: false, err: errors.New("db down")}
	r := newVisibilityRouter(checker, "user", 7, true)
	w := doVisibilityRequest(r, "/assets/42/probe")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("狀態碼 = %d, want 500", w.Code)
	}
}

// TestRequireAssetVisible_RoleMissingStillChecks 角色缺失（非特權）不直通，仍走授權查詢
func TestRequireAssetVisible_RoleMissingStillChecks(t *testing.T) {
	checker := &fakeAssetChecker{allow: false}
	r := newVisibilityRouter(checker, "", 7, true)
	w := doVisibilityRequest(r, "/assets/42/probe")

	if w.Code != http.StatusNotFound {
		t.Errorf("狀態碼 = %d, want 404（缺角色視同無特權）", w.Code)
	}
	if !checker.called {
		t.Error("缺角色仍應走授權查詢，不得直通")
	}
}
