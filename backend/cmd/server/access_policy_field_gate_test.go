package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// fixedAccessDefault 降級判定用的全域預設替身。
type fixedAccessDefault struct{}

func (fixedAccessDefault) Get(string) string { return model.AccessPolicyOpen }

// gateDenied 欄位閘拒絕：403、能力拒絕單一形狀（本文只有 code、error），且審計依據為 all_of＝want。
func gateDenied(env *fieldCapEnv, code int, resp string, want authz.Permission) bool {
	var body map[string]any
	if code != http.StatusForbidden || json.Unmarshal([]byte(resp), &body) != nil ||
		len(body) != 2 || body["code"] != "AUTH_PERMISSION_DENIED" || body["error"] == nil {
		return false
	}
	d := env.lastDenial
	return d != nil && d.Basis == authz.DenialAllOf && len(d.Required) == 1 && d.Required[0] == string(want)
}

func apRow(t *testing.T, env *fieldCapEnv, id uint) model.Asset {
	t.Helper()
	var row model.Asset
	if err := env.db.First(&row, id).Error; err != nil {
		t.Fatal(err)
	}
	return row
}

// TestAccessPolicyFieldGate 存取政策覆寫的欄位閘：PUT 僅需登入加兩條欄位條件，POST 非空值另需權限點。
func TestAccessPolicyFieldGate(t *testing.T) {
	manageOnly := customPrincipal(authz.PermAccessPolicyManage, authz.PermAssetView)
	updateOnly := customPrincipal(authz.PermAssetUpdate, authz.PermAssetView)
	both := customPrincipal(authz.PermAssetUpdate, authz.PermAccessPolicyManage, authz.PermAssetView)
	neither := customPrincipal(authz.PermAssetView)
	createOnly := customPrincipal(authz.PermAssetCreate, authz.PermAssetView)
	createAndManage := customPrincipal(authz.PermAssetCreate, authz.PermAccessPolicyManage, authz.PermAssetView)

	seed := func(t *testing.T) (*fieldCapEnv, *asset.AssetService, uint) {
		env := newFieldCapEnv(t)
		env.assets.SetAccessPolicyDefaultReader(fixedAccessDefault{})
		a, err := env.assets.Create(asset.WithSystemCaller(context.Background()), &asset.CreateAssetRequest{
			Name: "gate", Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22, CreatedBy: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		return env, env.assets, a.ID
	}
	put := func(env *fieldCapEnv, p *authz.Principal, id uint, body string) (int, string) {
		return env.call(p, "PUT", fmt.Sprintf("/api/v1/assets/%d", id), body)
	}

	t.Run("只持權限點加資產檢視：只送 access_policy 可設定與清除", func(t *testing.T) {
		env, _, id := seed(t)
		if code, resp := put(env, manageOnly, id, `{"access_policy":"approval"}`); code != http.StatusOK {
			t.Fatalf("設定：狀態 %d：%s", code, resp)
		}
		if got := apRow(t, env, id).AccessPolicy; got == nil || *got != "approval" {
			t.Fatalf("覆寫值應為 approval，實得 %v", got)
		}
		if code, resp := put(env, manageOnly, id, `{"access_policy":""}`); code != http.StatusOK {
			t.Fatalf("清除：狀態 %d：%s", code, resp)
		}
		if got := apRow(t, env, id).AccessPolicy; got != nil {
			t.Fatalf("清除後應為 NULL，實得 %v", *got)
		}
	})

	t.Run("同一主體夾帶其他欄位整筆拒、資產不變", func(t *testing.T) {
		env, _, id := seed(t)
		code, resp := put(env, manageOnly, id, `{"access_policy":"approval","name":"renamed"}`)
		if !gateDenied(env, code, resp, authz.PermAssetUpdate) {
			t.Fatalf("應 403 並指向資產編輯能力，實得 %d：%s", code, resp)
		}
		row := apRow(t, env, id)
		if row.Name != "gate" || row.AccessPolicy != nil {
			t.Fatalf("資產被改動：%+v", row)
		}
		// 空本文與不可解析本文同樣需要資產編輯能力
		for _, body := range []string{``, `not json`, `[]`, `{}`} {
			if code, resp := put(env, manageOnly, id, body); !gateDenied(env, code, resp, authz.PermAssetUpdate) {
				t.Errorf("本文 %q：應 403 指向資產編輯能力，實得 %d：%s", body, code, resp)
			}
		}
	})

	t.Run("只持資產編輯能力：帶 access_policy（含空字串）整筆拒，不帶則成功", func(t *testing.T) {
		env, _, id := seed(t)
		for _, body := range []string{`{"access_policy":"approval"}`, `{"access_policy":""}`, `{"access_policy":"open","description":"d"}`, `{"Access_Policy":"open"}`} {
			code, resp := put(env, updateOnly, id, body)
			if !gateDenied(env, code, resp, authz.PermAccessPolicyManage) {
				t.Errorf("本文 %s：應 403 指向存取政策權限點，實得 %d：%s", body, code, resp)
			}
		}
		if row := apRow(t, env, id); row.AccessPolicy != nil || row.Description != "" {
			t.Fatalf("被拒絕的更新改動了資產：%+v", row)
		}
		if code, resp := put(env, updateOnly, id, `{"description":"ok"}`); code != http.StatusOK {
			t.Fatalf("不帶覆寫鍵的編輯應成功，實得 %d：%s", code, resp)
		}
	})

	t.Run("兩個權限點都持有：夾帶其他欄位成功", func(t *testing.T) {
		env, _, id := seed(t)
		if code, resp := put(env, both, id, `{"access_policy":"reason","description":"d"}`); code != http.StatusOK {
			t.Fatalf("狀態 %d：%s", code, resp)
		}
	})

	t.Run("兩者皆無：不存在的 ID 也是 403，錯誤碼與欄位同原守衛", func(t *testing.T) {
		env, _, _ := seed(t)
		for _, body := range []string{`{"access_policy":"approval"}`, `{"description":"x"}`, ``} {
			code, resp := put(env, neither, 99999, body)
			if !gateDenied(env, code, resp, authz.PermAssetUpdate) {
				t.Errorf("本文 %q：實得 %d：%s", body, code, resp)
			}
		}
		// 與以資產編輯能力守衛時（原基本要求）的拒絕依據一致：all_of＝資產編輯能力
		want := authz.DecideEntry(authz.RouteEntry{Base: authz.BasePerm, Perm: authz.PermAssetUpdate}, neither)
		if want.Allowed || want.Basis != authz.DenialAllOf || len(want.Required) != 1 || want.Required[0] != authz.PermAssetUpdate {
			t.Fatalf("對照組異常：%+v", want)
		}
	})

	t.Run("只持權限點者不能改全系統預設：安全政策端點登錄仍要求設定組能力", func(t *testing.T) {
		for _, m := range []string{"GET", "PUT"} {
			d := authz.DecideRoute(m, "/api/v1/security-policies", manageOnly)
			if d.Allowed {
				t.Errorf("%s /security-policies 不應對只持存取政策權限點者放行", m)
			}
		}
		if !authz.DecideRoute("PUT", "/api/v1/security-policies", customPrincipal(authz.PermSecurityPolicyManage)).Allowed {
			t.Error("對照組：持安全政策設定能力者應放行")
		}
	})

	t.Run("建立：非空 access_policy 另需權限點", func(t *testing.T) {
		env, _, _ := seed(t)
		before := env.count(t, &model.Asset{})
		code, resp := env.call(createOnly, "POST", "/api/v1/assets",
			`{"name":"c1","protocol":"ssh","host":"10.0.0.2","port":22,"access_policy":"open"}`)
		if code != http.StatusForbidden || env.count(t, &model.Asset{}) != before {
			t.Fatalf("只持 asset:create 帶 open 應 403 且不建立，實得 %d：%s", code, resp)
		}
		for i, body := range []string{
			`{"name":"c2","protocol":"ssh","host":"10.0.0.3","port":22,"access_policy":""}`,
			`{"name":"c3","protocol":"ssh","host":"10.0.0.4","port":22}`,
		} {
			if code, resp := env.call(createOnly, "POST", "/api/v1/assets", body); code != http.StatusCreated {
				t.Errorf("案例 %d：空字串或不帶應建立，實得 %d：%s", i, code, resp)
			}
		}
		code, resp = env.call(createAndManage, "POST", "/api/v1/assets",
			`{"name":"c4","protocol":"ssh","host":"10.0.0.5","port":22,"access_policy":"open"}`)
		if code != http.StatusCreated {
			t.Fatalf("持兩者應建立，實得 %d：%s", code, resp)
		}
		var row model.Asset
		env.db.Where("name = ?", "c4").First(&row)
		if row.AccessPolicy == nil || *row.AccessPolicy != "open" {
			t.Fatalf("應覆寫為 open，實得 %v", row.AccessPolicy)
		}
	})
}
