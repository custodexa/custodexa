package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 建立路徑的憑證能力：與更新路徑同一套判定。
//
// 內嵌秘密（password／private_key，含 credential 物件）＝新建一份專用憑證，需 credential:create
// （改既有憑證的秘密才是 credential:set-secret，那是更新路徑）；
// 帶 credential_id 掛既有共用憑證＝掛載，需 credential:bind；資產建立與匯入另有路由欄位條件
// 的 credential:manage。缺任一能力 403、零寫入。只持資產寫入能力者不得把共用憑證掛到自己
// 可連線的資產上（等於取得以該秘密登入的能力）。

func (e *fieldCapEnv) accountEngine(p *authz.Principal, svc *asset.AssetAccountService) *gin.Engine {
	h := api.NewAssetAccountHandler(svc, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "field-cap")
		middleware.SetPrincipal(c, p)
	})
	r.POST("/api/v1/assets/:id/accounts", middleware.EnforceRegistry(), h.Create)
	return r
}

func (e *fieldCapEnv) callAccount(p *authz.Principal, svc *asset.AssetAccountService, path, body string) (int, string) {
	e.current = p
	defer func() { e.current = nil }()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.accountEngine(p, svc).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func (e *fieldCapEnv) writeCounts(t *testing.T) [5]int64 {
	t.Helper()
	return [5]int64{
		e.count(t, &model.Asset{}), e.count(t, &model.AssetAccount{}), e.count(t, &model.Credential{}),
		e.count(t, &model.CredentialSecretVersion{}), e.count(t, &model.AuditLog{}),
	}
}

func assertNoLeak(t *testing.T, label, resp string) {
	t.Helper()
	for _, leak := range []string{"credential:", "asset:", "required_permission"} {
		if strings.Contains(resp, leak) {
			t.Errorf("%s：回應含 %q：%s", label, leak, resp)
		}
	}
}

func TestCreatePathCredentialCapabilities(t *testing.T) {
	base := []authz.Permission{authz.PermAssetView, authz.PermAssetCreate, authz.PermAssetUpdate, authz.PermCredentialManage}
	with := func(extra ...authz.Permission) *authz.Principal {
		return customPrincipal(append(append([]authz.Permission{}, base...), extra...)...)
	}
	manageOnly := with()
	withCreate := with(authz.PermCredentialCreate)
	// 只有改既有秘密的能力、沒有建立能力：建立時的內嵌秘密仍須拒絕
	withSetSecretOnly := with(authz.PermCredentialSetSecret, authz.PermCredentialBind)
	withBind := with(authz.PermCredentialBind)
	withBoth := with(authz.PermCredentialCreate, authz.PermCredentialBind)
	assetUpdateOnly := customPrincipal(authz.PermAssetView, authz.PermAssetUpdate)
	superAdmin := principalWith(model.BuiltinSuperAdmin, model.RoleAdmin)

	seedShared := func(t *testing.T, env *fieldCapEnv, name string) *asset.CredentialDTO {
		t.Helper()
		cred, err := env.creds.Create(operatorCtx(), &asset.CreateCredentialRequest{
			Name: name, Username: "shared-" + name, Password: "pw", ProtocolFamily: model.ProtocolFamilySSH})
		if err != nil {
			t.Fatal(err)
		}
		return cred
	}

	t.Run("資產建立：掛既有共用憑證缺 bind、內嵌秘密缺 create 皆 403 零寫入", func(t *testing.T) {
		env := newFieldCapEnv(t)
		cred := seedShared(t, env, "c1")
		denied := []struct {
			who  *authz.Principal
			name string
			body string
		}{
			{manageOnly, "manage 無 bind 掛共用", fmt.Sprintf(`"credential_id":%d`, cred.ID)},
			{withCreate, "create 無 bind 掛共用", fmt.Sprintf(`"credential_id":%d`, cred.ID)},
			{manageOnly, "manage 無 create 頂層密碼", `"username":"root","password":"Pw-1"`},
			{withBind, "bind 無 create 頂層密碼", `"username":"root","password":"Pw-1"`},
			{withSetSecretOnly, "set-secret 無 create 頂層密碼", `"username":"root","password":"Pw-1"`},
			{manageOnly, "manage 無 create 內嵌物件", `"credential":{"username":"root","password":"Pw-1"}`},
			{manageOnly, "manage 無 create 私鑰", `"username":"root","private_key":"-----BEGIN KEY-----"`},
		}
		before := env.writeCounts(t)
		for i, c := range denied {
			body := fmt.Sprintf(`{"name":"d%d","protocol":"ssh","host":"10.0.0.2","port":22,%s}`, i, c.body)
			code, resp := env.call(c.who, "POST", "/api/v1/assets", body)
			if code != http.StatusForbidden || !strings.Contains(resp, "AUTH_PERMISSION_DENIED") {
				t.Errorf("%s：狀態 %d，應 403 AUTH_PERMISSION_DENIED：%s", c.name, code, resp)
			}
			assertNoLeak(t, c.name, resp)
		}
		if after := env.writeCounts(t); after != before {
			t.Errorf("被拒絕的建立有寫入：前 %v 後 %v", before, after)
		}

		allowed := []struct {
			who  *authz.Principal
			name string
			body string
		}{
			{withBind, "bind 掛共用", fmt.Sprintf(`"credential_id":%d`, cred.ID)},
			{withCreate, "create 頂層密碼", `"username":"root","password":"Pw-1"`},
			{withBoth, "全部能力內嵌物件", `"credential":{"username":"root","password":"Pw-1"}`},
			{superAdmin, "超管掛共用", fmt.Sprintf(`"credential_id":%d`, cred.ID)},
			{manageOnly, "無憑證來源", `"description":"none"`},
		}
		for i, c := range allowed {
			body := fmt.Sprintf(`{"name":"ok%d","protocol":"ssh","host":"10.0.0.3","port":22,%s}`, i, c.body)
			if code, resp := env.call(c.who, "POST", "/api/v1/assets", body); code != http.StatusCreated {
				t.Errorf("%s：狀態 %d，應 201：%s", c.name, code, resp)
			}
		}
	})

	t.Run("帳號建立：只有資產更新能力者不得掛共用憑證或寫內嵌秘密", func(t *testing.T) {
		env := newFieldCapEnv(t)
		cred := seedShared(t, env, "c2")
		accounts := asset.NewAssetAccountService(env.assets, env.codec, audit.NewTxSink()).
			WithManagementAuthorizer(fieldCapManagementAuthorizer{env: env}).WithSystemAlertSink(noopAlertSink{}).WithAccountWriteScope(allowAllAccountWriteScope{})
		a, err := env.assets.Create(asset.WithSystemCaller(operatorCtx()), &asset.CreateAssetRequest{
			Name: "host", Protocol: model.ProtocolSSH, Host: "10.0.1.1", Port: 22, CreatedBy: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		path := fmt.Sprintf("/api/v1/assets/%d/accounts", a.ID)
		denied := []struct {
			who  *authz.Principal
			name string
			body string
		}{
			{assetUpdateOnly, "資產更新能力掛他人共用憑證", fmt.Sprintf(`{"credential_id":%d}`, cred.ID)},
			{withCreate, "create 無 bind 掛共用", fmt.Sprintf(`{"credential_id":%d}`, cred.ID)},
			{assetUpdateOnly, "資產更新能力寫頂層密碼", `{"username":"ops","password":"Pw-2"}`},
			{withBind, "bind 無 create 寫內嵌物件", `{"credential":{"username":"ops","password":"Pw-2"}}`},
			{withSetSecretOnly, "set-secret 無 create 寫頂層密碼", `{"username":"ops","password":"Pw-2"}`},
		}
		before := env.writeCounts(t)
		for _, c := range denied {
			code, resp := env.callAccount(c.who, accounts, path, c.body)
			if code != http.StatusForbidden || !strings.Contains(resp, "AUTH_PERMISSION_DENIED") {
				t.Errorf("%s：狀態 %d，應 403 AUTH_PERMISSION_DENIED：%s", c.name, code, resp)
			}
			assertNoLeak(t, c.name, resp)
		}
		if after := env.writeCounts(t); after != before {
			t.Errorf("被拒絕的帳號建立有寫入：前 %v 後 %v", before, after)
		}

		if code, resp := env.callAccount(withBind, accounts, path, fmt.Sprintf(`{"credential_id":%d}`, cred.ID)); code != http.StatusCreated {
			t.Errorf("bind 掛共用：狀態 %d：%s", code, resp)
		}
		if code, resp := env.callAccount(withCreate, accounts, path, `{"username":"ops","password":"Pw-2"}`); code != http.StatusCreated {
			t.Errorf("create 寫密碼：狀態 %d：%s", code, resp)
		}
		// 不帶秘密也不掛憑證：不需憑證建立或掛載能力，但帳號名稱欄位仍需憑證管理能力
		// （與資產表單的帳號名稱同一欄位條件），只持資產更新能力者 403
		if code, resp := env.callAccount(assetUpdateOnly, accounts, path, `{"username":"nopw"}`); code != http.StatusForbidden {
			t.Errorf("只持資產更新能力建無秘密帳號：狀態 %d，應 403：%s", code, resp)
		}
		if code, resp := env.callAccount(manageOnly, accounts, path, `{"username":"nopw"}`); code != http.StatusCreated {
			t.Errorf("持憑證管理能力建無秘密帳號：狀態 %d：%s", code, resp)
		}
	})

	t.Run("匯入：任一列掛共用憑證缺 bind，預檢與提交皆整批 403", func(t *testing.T) {
		env := newFieldCapEnv(t)
		cred := seedShared(t, env, "c3")
		batch := fmt.Sprintf(`{"source":"form","rows":[
			{"name":"m1","protocol":"ssh","host":"10.2.0.1"},
			{"name":"m2","protocol":"ssh","host":"10.2.0.2","credential_id":%d}]}`, cred.ID)
		before := env.writeCounts(t)
		for _, path := range []string{"/api/v1/assets/import/preview", "/api/v1/assets/import"} {
			code, resp := env.call(manageOnly, "POST", path, batch)
			if code != http.StatusForbidden || !strings.Contains(resp, "AUTH_PERMISSION_DENIED") {
				t.Errorf("%s：狀態 %d，應 403 AUTH_PERMISSION_DENIED：%s", path, code, resp)
			}
			assertNoLeak(t, path, resp)
		}
		if after := env.writeCounts(t); after != before {
			t.Errorf("被拒絕的匯入有寫入：前 %v 後 %v", before, after)
		}
		if code, resp := env.call(withBind, "POST", "/api/v1/assets/import/preview", batch); code != http.StatusOK {
			t.Errorf("bind 預檢：狀態 %d：%s", code, resp)
		}
		if code, resp := env.call(withBind, "POST", "/api/v1/assets/import", batch); code != http.StatusCreated {
			t.Errorf("bind 提交：狀態 %d：%s", code, resp)
		}
	})
}
