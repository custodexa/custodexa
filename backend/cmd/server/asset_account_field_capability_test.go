package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 帳號路由的帳號名稱欄位能力。
//
// 資產表單把帳號名稱列為需要憑證語義能力（或全域的相容憑證管理能力）的欄位；帳號路由同樣能改帳號名稱
// （預設帳號的名稱會鏡像回資產），因此套用同一判定：只持資產寫入能力者改名或以新名稱建帳號一律 403，且零寫入。
// 只建非預設帳號也要擋，否則「建非預設帳號再切成預設」就能繞過。

func (e *fieldCapEnv) accountWriteEngine(p *authz.Principal) *gin.Engine {
	svc := asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).
		WithManagementAuthorizer(fieldCapManagementAuthorizer{env: e}).WithSystemAlertSink(noopAlertSink{}).WithAccountWriteScope(allowAllAccountWriteScope{})
	h := api.NewAssetAccountHandler(svc, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "field-cap")
		middleware.SetPrincipal(c, p)
	})
	g := r.Group("/api/v1/assets/:id/accounts")
	g.POST("", middleware.EnforceRegistry(), h.Create)
	g.PUT("/:accountId", middleware.EnforceRegistry(), h.Update)
	return r
}

func (e *fieldCapEnv) callAccountWrite(p *authz.Principal, method, path, body string) (int, string) {
	e.current = p
	defer func() { e.current = nil }()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.accountWriteEngine(p).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func TestAssetAccountUsernameFieldCapability(t *testing.T) {
	updateOnly := customPrincipal(authz.PermAssetUpdate, authz.PermAssetView)
	var all []authz.Permission
	for _, d := range authz.Catalog() {
		all = append(all, d.Key)
	}
	fullCustom := customPrincipal(all...)
	superAdmin := principalWith(model.BuiltinSuperAdmin, model.RoleAdmin)

	t.Run("帳號兩條寫入路由宣告帳號名稱需憑證語義能力或相容能力", func(t *testing.T) {
		for _, r := range []struct {
			method, path string
			perm         authz.Permission
		}{
			{"POST", "/api/v1/assets/:id/accounts", authz.PermCredentialCreate},
			{"PUT", "/api/v1/assets/:id/accounts/:accountId", authz.PermCredentialUpdate},
		} {
			entry, ok := authz.LookupRoute(r.method, r.path)
			if !ok {
				t.Fatalf("%s %s 未登錄", r.method, r.path)
			}
			want := []authz.FieldCondition{{Field: "username", Perm: r.perm, AnyOf: []authz.Permission{authz.PermCredentialManage}}}
			if !reflect.DeepEqual(entry.Fields, want) {
				t.Errorf("%s %s 欄位條件 %v，應為 %v", r.method, r.path, entry.Fields, want)
			}
		}
	})

	seed := func(t *testing.T, env *fieldCapEnv) (model.Asset, model.AssetAccount) {
		t.Helper()
		a, err := env.assets.Create(asset.WithSystemCaller(context.Background()), &asset.CreateAssetRequest{
			Name: "srv", Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22,
			Username: "root", Password: "seed-pw", CreatedBy: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		var acc model.AssetAccount
		if err := env.db.Where("asset_id = ? AND is_default = ?", a.ID, true).First(&acc).Error; err != nil {
			t.Fatal(err)
		}
		return *a, acc
	}

	snapshot := func(t *testing.T, env *fieldCapEnv, assetID, accountID uint) string {
		t.Helper()
		var row model.Asset
		env.db.First(&row, assetID)
		var acc model.AssetAccount
		env.db.First(&acc, accountID)
		var cred model.Credential
		env.db.First(&cred, acc.CredentialID)
		return fmt.Sprintf("asset=%s account=%s cred=%s accounts=%d creds=%d audits=%d",
			row.Username, acc.Username, cred.Username,
			env.count(t, &model.AssetAccount{}), env.count(t, &model.Credential{}), env.count(t, &model.AuditLog{}))
	}

	t.Run("改名：只持資產寫入能力 403 且零寫入", func(t *testing.T) {
		env := newFieldCapEnv(t)
		a, acc := seed(t, env)
		before := snapshot(t, env, a.ID, acc.ID)
		path := fmt.Sprintf("/api/v1/assets/%d/accounts/%d", a.ID, acc.ID)
		code, resp := env.callAccountWrite(updateOnly, "PUT", path, `{"username":"other"}`)
		if code != http.StatusForbidden {
			t.Errorf("改名狀態 %d，應 403：%s", code, resp)
		}
		assertNoLeak(t, "改名", resp)
		if after := snapshot(t, env, a.ID, acc.ID); after != before {
			t.Errorf("被拒絕的改名改動了資料：前 %s，後 %s", before, after)
		}

		// 同值帳號名稱夾帶備註：沒有改名，成功
		code, resp = env.callAccountWrite(updateOnly, "PUT", path, `{"username":"root","note":"n1"}`)
		if code != http.StatusOK {
			t.Errorf("同值帳號名稱加備註應成功，狀態 %d：%s", code, resp)
		}

		for name, p := range map[string]*authz.Principal{"全能力自訂角色": fullCustom, "超管": superAdmin} {
			newName := "ops-" + map[string]string{"全能力自訂角色": "c", "超管": "s"}[name]
			code, resp := env.callAccountWrite(p, "PUT", path, fmt.Sprintf(`{"username":%q}`, newName))
			if code != http.StatusOK {
				t.Errorf("%s 改名狀態 %d：%s", name, code, resp)
			}
			var row model.Asset
			env.db.First(&row, a.ID)
			if row.Username != newName {
				t.Errorf("%s 改名後資產鏡像為 %q，應為 %q", name, row.Username, newName)
			}
		}
	})

	t.Run("建立：只持資產寫入能力以新名稱建帳號 403 且零寫入", func(t *testing.T) {
		env := newFieldCapEnv(t)
		a, acc := seed(t, env)
		before := snapshot(t, env, a.ID, acc.ID)
		path := fmt.Sprintf("/api/v1/assets/%d/accounts", a.ID)
		for _, body := range []string{
			`{"username":"takeover","is_default":true}`,
			`{"username":"later-default"}`,
			`{"credential":{"username":"inline"}}`,
		} {
			code, resp := env.callAccountWrite(updateOnly, "POST", path, body)
			if code != http.StatusForbidden {
				t.Errorf("%s：狀態 %d，應 403：%s", body, code, resp)
			}
			assertNoLeak(t, body, resp)
		}
		if after := snapshot(t, env, a.ID, acc.ID); after != before {
			t.Errorf("被拒絕的建立改動了資料：前 %s，後 %s", before, after)
		}

		for name, p := range map[string]*authz.Principal{"全能力自訂角色": fullCustom, "超管": superAdmin} {
			code, resp := env.callAccountWrite(p, "POST", path,
				fmt.Sprintf(`{"username":"new-%s"}`, map[string]string{"全能力自訂角色": "c", "超管": "s"}[name]))
			if code != http.StatusCreated {
				t.Errorf("%s 建帳號狀態 %d：%s", name, code, resp)
			}
		}
	})
}
