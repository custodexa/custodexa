package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 標籤治理與主機金鑰重置是超管保留操作：持全部可指派能力的全域自訂角色也不能呼叫；
// 既有的稽核員與一般使用者主體維持原拒絕形狀；GET 檢視在沿用同位址記錄時標 inherited。

type reservedEnv struct {
	*fieldCapEnv
	hostKeys *asset.HostKeyService
}

func newReservedEnv(t *testing.T) *reservedEnv {
	t.Helper()
	env := newFieldCapEnv(t)
	if err := env.db.AutoMigrate(&model.AssetHostKey{}, &model.AssetHostKeyMismatch{}); err != nil {
		t.Fatal(err)
	}
	hostKeys := asset.NewHostKeyService(env.db)
	// 重置與採用都在同交易發系統告警、採用另寫審計：注入測試用落地面
	hostKeys.SetAuditTxSink(audit.NewTxSink())
	hostKeys.SetSystemAlertSink(noopAlertSink{})
	return &reservedEnv{fieldCapEnv: env, hostKeys: hostKeys}
}

func (e *reservedEnv) engine(p *authz.Principal) *gin.Engine {
	ah := api.NewAssetHandler(e.assets, nil, nil)
	hh := api.NewHostKeyHandler(e.hostKeys, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "reserved-route")
		middleware.SetPrincipal(c, p)
	})
	g := r.Group("/api/v1")
	assets := g.Group("/assets")
	assets.GET("/tags", middleware.EnforceRegistry(), ah.ListTags)
	assets.POST("/tags/rename", middleware.EnforceRegistry(), ah.RenameTag)
	assets.POST("/tags/delete", middleware.EnforceRegistry(), ah.DeleteTag)
	// 與 HostKeyHandler.RegisterRoutes 同一條守衛鏈；身分以測試注入取代 token 驗證
	g.GET("/assets/:id/host-key", middleware.EnforceRegistry(), hh.Get)
	g.DELETE("/assets/:id/host-key", middleware.EnforceRegistry(), api.RequireHostKeyResetSuperAdmin, hh.Reset)
	g.POST("/assets/:id/host-key/adopt", middleware.EnforceRegistry(), api.RequireHostKeyResetSuperAdmin, hh.Adopt)
	return r
}

func (e *reservedEnv) do(p *authz.Principal, method, path, body string) (int, map[string]any, string) {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.engine(p).ServeHTTP(w, req)
	var parsed map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &parsed)
	return w.Code, parsed, w.Body.String()
}

func TestAssetReservedRouteRegistration(t *testing.T) {
	var assignable []authz.Permission
	for _, d := range authz.Catalog() {
		if authz.IsAssignable(d.Key) {
			assignable = append(assignable, d.Key)
		}
	}
	fullCustom := customPrincipal(assignable...)
	superAdmin := principalWith(model.BuiltinSuperAdmin, model.RoleAdmin)
	auditor := principalWith(model.BuiltinAuditor, model.RoleAuditor)
	user := principalWith(model.BuiltinUser, model.RoleUser)

	t.Run("登錄項：三端點不再以可指派的權限點授權，主機金鑰重置鍵不可指派", func(t *testing.T) {
		for _, k := range []struct{ method, path string }{
			{"POST", "/api/v1/assets/tags/rename"}, {"POST", "/api/v1/assets/tags/delete"},
			{"DELETE", "/api/v1/assets/:id/host-key"}, {"POST", "/api/v1/assets/:id/host-key/adopt"},
		} {
			e, ok := authz.LookupRoute(k.method, k.path)
			if !ok || e.Base != authz.BaseAuthenticated {
				t.Errorf("%s %s 應登錄為登入即可（保留資格由守衛判定）: %+v ok=%v", k.method, k.path, e, ok)
			}
		}
		if authz.IsAssignable(authz.PermHostKeyReset) {
			t.Error("hostkey:reset 應為不可指派")
		}
		if _, err := authz.NormalizeRolePermissions([]string{"hostkey:reset"}); !authz.IsInvalidRolePermission(err) {
			t.Errorf("角色定義必須拒絕 hostkey:reset，實得 %v", err)
		}
		if customPrincipal(authz.PermHostKeyReset).Has(authz.PermHostKeyReset) {
			t.Error("自訂角色集合內的 hostkey:reset 不得生效")
		}
	})

	t.Run("持全部可指派能力的全域自訂角色呼叫三端點皆 403 且資料不變（反）", func(t *testing.T) {
		env := newReservedEnv(t)
		a, err := env.assets.Create(operatorCtx(), &asset.CreateAssetRequest{
			Name: "tagged", Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22, Tags: "tag-a", CreatedBy: 7})
		if err != nil {
			t.Fatal(err)
		}
		if err := seedHostKey(env.hostKeys, a.ID)("10.0.0.1:22", nil, mustHostKey(t)); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct{ method, path, body string }{
			{"POST", "/api/v1/assets/tags/rename", `{"from":"tag-a","to":"tag-b"}`},
			{"POST", "/api/v1/assets/tags/delete", `{"name":"tag-a"}`},
			{"DELETE", "/api/v1/assets/1/host-key", ""},
			{"POST", "/api/v1/assets/1/host-key/adopt", `{"fingerprint":"SHA256:not-observed"}`},
		} {
			if code, _, body := env.do(fullCustom, c.method, c.path, c.body); code != http.StatusForbidden {
				t.Errorf("%s %s：狀態 %d，應 403：%s", c.method, c.path, code, body)
			}
		}
		var row model.Asset
		env.db.First(&row, a.ID)
		if row.Tags != "tag-a" {
			t.Errorf("標籤被改動: %q", row.Tags)
		}
		if rec, err := env.hostKeys.Get(a.ID); err != nil || rec.Inherited {
			t.Errorf("指紋記錄被改動: %v %+v", err, rec)
		}
		// 重置待記錄標記也不得被設
		var pending int64
		env.db.Model(&model.AssetHostKey{}).Where("reset_pending = ?", true).Count(&pending)
		if pending != 0 {
			t.Errorf("被拒絕的重置竟留下 %d 筆待記錄標記", pending)
		}
	})

	t.Run("超管三端點成功（正）；GET /assets/tags 結果不變", func(t *testing.T) {
		env := newReservedEnv(t)
		a, err := env.assets.Create(operatorCtx(), &asset.CreateAssetRequest{
			Name: "tagged", Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22, Tags: "tag-a,tag-c", CreatedBy: 7})
		if err != nil {
			t.Fatal(err)
		}
		if err := seedHostKey(env.hostKeys, a.ID)("10.0.0.1:22", nil, mustHostKey(t)); err != nil {
			t.Fatal(err)
		}
		if code, _, body := env.do(superAdmin, "GET", "/api/v1/assets/tags", ""); code != http.StatusOK {
			t.Errorf("GET /assets/tags 超管應 200（登錄項未變）: %d %s", code, body)
		}
		for _, c := range []struct{ method, path, body string }{
			{"POST", "/api/v1/assets/tags/rename", `{"from":"tag-a","to":"tag-b"}`},
			{"POST", "/api/v1/assets/tags/delete", `{"name":"tag-c"}`},
			{"DELETE", "/api/v1/assets/1/host-key", ""},
		} {
			if code, _, body := env.do(superAdmin, c.method, c.path, c.body); code != http.StatusOK {
				t.Errorf("超管 %s %s：狀態 %d：%s", c.method, c.path, code, body)
			}
		}
		var row model.Asset
		env.db.First(&row, a.ID)
		if row.Tags != "tag-b" {
			t.Errorf("超管改名/刪除後標籤應為 tag-b，實為 %q", row.Tags)
		}
	})

	t.Run("既有稽核員與一般使用者皆 403 能力拒絕單一形狀", func(t *testing.T) {
		env := newReservedEnv(t)
		type shape struct {
			code string
		}
		// 標籤治理與主機金鑰重置、採用：一律能力拒絕單一形狀（本文只有 code、error）
		want := map[string]shape{
			"POST /api/v1/assets/tags/rename":      {code: "AUTH_PERMISSION_DENIED"},
			"POST /api/v1/assets/tags/delete":      {code: "AUTH_PERMISSION_DENIED"},
			"DELETE /api/v1/assets/1/host-key":     {code: "AUTH_PERMISSION_DENIED"},
			"POST /api/v1/assets/1/host-key/adopt": {code: "AUTH_PERMISSION_DENIED"},
		}
		bodies := map[string]string{
			"POST /api/v1/assets/tags/rename": `{"from":"a","to":"b"}`, "POST /api/v1/assets/tags/delete": `{"name":"a"}`,
			"POST /api/v1/assets/1/host-key/adopt": `{"fingerprint":"SHA256:not-observed"}`,
		}
		for name, p := range map[string]*authz.Principal{"稽核員": auditor, "一般使用者": user} {
			for key, w := range want {
				method, path := key[:bytesIndex(key, ' ')], key[bytesIndex(key, ' ')+1:]
				code, parsed, body := env.do(p, method, path, bodies[key])
				if code != http.StatusForbidden || parsed["code"] != w.code {
					t.Errorf("%s %s：狀態 %d code=%v，應 403 %s：%s", name, key, code, parsed["code"], w.code, body)
				}
				if len(parsed) != 2 || parsed["error"] == nil {
					t.Errorf("%s %s：本文鍵須恰為 code、error，實得 %s", name, key, body)
				}
			}
		}
	})

	t.Run("GET 檢視：沿用同位址記錄時標 inherited 且不帶來源識別；自身記錄時鍵集合不變", func(t *testing.T) {
		env := newReservedEnv(t)
		k := mustHostKey(t)
		old, err := env.assets.Create(operatorCtx(), &asset.CreateAssetRequest{
			Name: "old", Protocol: model.ProtocolSSH, Host: "10.0.9.9", Port: 22, CreatedBy: 7})
		if err != nil {
			t.Fatal(err)
		}
		if err := seedHostKey(env.hostKeys, old.ID)("10.0.9.9:22", nil, k); err != nil {
			t.Fatal(err)
		}
		// 自身記錄：鍵集合與改前相同
		code, parsed, body := env.do(superAdmin, "GET", "/api/v1/assets/1/host-key", "")
		if code != http.StatusOK {
			t.Fatalf("自身記錄 GET: %d %s", code, body)
		}
		if got := mapKeys(parsed); !equalStrings(got, []string{"algorithm", "asset_id", "created_at", "fingerprint", "id", "updated_at"}) {
			t.Errorf("自身記錄的回應鍵集合應與改前相同，實為 %v", got)
		}
		// 刪除後同位址重建：沿用
		assets := env.assets
		assets.SetAuthorizationRevoker(noopRevoker{})
		if err := assets.Delete(asset.WithSystemCaller(context.Background()), old.ID); err != nil {
			t.Fatal(err)
		}
		fresh, err := assets.Create(operatorCtx(), &asset.CreateAssetRequest{
			Name: "fresh", Protocol: model.ProtocolSSH, Host: "10.0.9.9", Port: 22, CreatedBy: 7})
		if err != nil {
			t.Fatal(err)
		}
		code, parsed, body = env.do(superAdmin, "GET", "/api/v1/assets/2/host-key", "")
		if code != http.StatusOK || parsed["inherited"] != true || parsed["asset_id"] != float64(fresh.ID) {
			t.Fatalf("沿用 GET: %d %s", code, body)
		}
		if _, hasID := parsed["id"]; hasID {
			t.Errorf("沿用回應不得帶來源列 id: %s", body)
		}
		for _, leak := range []string{"created_at", "updated_at", "id"} {
			if _, has := parsed[leak]; has {
				t.Errorf("沿用回應不得帶來源記錄的 %s: %s", leak, body)
			}
		}
		if got := mapKeys(parsed); !equalStrings(got, []string{"algorithm", "asset_id", "fingerprint", "inherited"}) {
			t.Errorf("沿用回應鍵集合應僅含 asset_id、algorithm、fingerprint、inherited，實為 %v", got)
		}
	})
}

type noopRevoker struct{}

func (noopRevoker) RevokeByAsset(_ *gorm.DB, _ uint) (int64, int64, error) { return 0, 0, nil }

// seedHostKey 以終端路徑的撥號脈絡取回呼（測試只用它種首次信任的記錄，不會走到不符留痕）
func seedHostKey(h *asset.HostKeyService, assetID uint) ssh.HostKeyCallback {
	cb, _ := h.CallbackFor(asset.HostKeyDialContext{AssetID: assetID, Path: asset.HostKeyPathTerminal, UserID: 7, Username: "reserved-route"})
	return cb
}

func mustHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func bytesIndex(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
