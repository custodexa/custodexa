package main

import (
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 逐端點對照（共同授權判定）：以只授權部分角色的 token 呼叫每一條開放端點，結果須與「只持有那些角色的人類帳號」
// 相同——回應狀態、回應本文與資料庫的變更皆同。輸入取自授權基準的路由目錄（每條路由一組合法輸入、實際存在的目標）。
// 角色配置兩組：
//   - super：所屬帳號持有超級管理者與稽核員，token 只授權超級管理者（幾乎所有開放端點都走到成功與寫入的分支）。
//   - scoped：所屬帳號持有一般管理角色與另一個角色；token 只授權前者。後者正是服務層另行判定的能力（指派角色、
//     掛載與建立憑證、寫入秘密、改密執行），本人經後者持有、token 沒有。
//   - protected：所屬帳號持有一般管理角色與超級管理者；token 只授權前者。受保護帳號的操作與超級管理者豁免
//     只能依 token 授權的角色判定。
// 另以 token 呼叫每一條不開放的端點，皆回 403 且沒有任何變更。

// apiTokenScopedGranted scoped 配置中 token 授權的角色：路由閘要求的管理能力。
var apiTokenScopedGranted = []authz.Permission{
	authz.PermUserManage, authz.PermUserGroupManage, authz.PermRoleView, authz.PermAssetView, authz.PermAssetCreate,
	authz.PermAssetUpdate, authz.PermAssetDelete, authz.PermAssetGroupManage, authz.PermChangeSecretManage,
	authz.PermCredentialView, authz.PermAlertRuleManage, authz.PermNotificationChannel,
	authz.PermIdentitySourceManage, authz.PermOIDCManage, authz.PermAuthorizationManage, authz.PermApproverScopeManage,
	authz.PermAuditView, authz.PermSessionView, authz.PermAlertView, authz.PermPolicyGroupView,
}

// apiTokenScopedExtra scoped 配置中只有本人持有的角色：服務層另行判定的能力。
var apiTokenScopedExtra = []authz.Permission{
	authz.PermRoleAssign, authz.PermCredentialCreate, authz.PermCredentialSetSecret, authz.PermCredentialBind,
	authz.PermCredentialUpdate, authz.PermAccountRotate, authz.PermCredentialRotate,
}

// apiTokenTokenSpecific 已知且預期的差異：token 專屬限制（另由專屬測試驗證），token 以該錯誤碼被拒、人類照常。
// 鍵為「配置名 方法 樣板路徑」，值為 token 回應的錯誤碼。
var apiTokenTokenSpecific = map[string]string{
	// 改密計畫的建立與保存：token 不持有改密執行能力時拒絕（人類照常保存，到期執行前才重驗）
	"scoped POST /api/v1/change-secret-plans":       string(apierror.CodePermissionDenied),
	"scoped PUT /api/v1/change-secret-plans/:id":    string(apierror.CodePermissionDenied),
	"protected POST /api/v1/change-secret-plans":    string(apierror.CodePermissionDenied),
	"protected PUT /api/v1/change-secret-plans/:id": string(apierror.CodePermissionDenied),
}

// apiTokenOnlyRoutes 只對 API token 有意義的端點：token 成功、人類工作階段以該錯誤碼被拒。
// 鍵為「方法 樣板路徑」，值為人類側回應的錯誤碼。
var apiTokenOnlyRoutes = map[string]string{
	"GET /api/v1/api-tokens/verify": string(apierror.CodePermissionDenied),
}

// apiTokenResponseOmits 回應刻意與人類不同的端點：token 呼叫時省略的頂層鍵。主迴圈所用輸入的對象帳號沒有 token，
// 兩邊同樣不出現該鍵而判為相同；差異本身由「APIToken 回應省略對象帳號的 token 資訊」子測試以有 token 的對象驗證。
var apiTokenResponseOmits = map[string]string{
	"POST /api/v1/role-assignment-previews": "api_tokens",
}

func seedAPITokenPairs(e *baselineEnv) []*apiTokenPair {
	granted := e.apiTokenCustomRole("cmp-scoped-granted", apiTokenScopedGranted...)
	extra := e.apiTokenCustomRole("cmp-scoped-extra", apiTokenScopedExtra...)
	pairs := []*apiTokenPair{
		e.apiTokenPairOf("super", []uint{e.roleID(model.RoleAdmin)}, []uint{e.roleID(model.RoleAuditor)}),
		e.apiTokenPairOf("scoped", []uint{granted}, []uint{extra}),
		e.apiTokenPairOf("protected", []uint{granted}, []uint{e.roleID(model.RoleAdmin)}),
	}
	e.apiTokenRetemplate()
	return pairs
}

// TestAPITokenRouteComparisonAndScope 逐端點對照與路由範圍的端到端驗證。
func TestAPITokenRouteComparisonAndScope(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	pairs := seedAPITokenPairs(e)
	catalog := loadRouteCatalog(t)
	openKeys := apiTokenOpenRouteKeys()
	open := map[string]bool{}
	for _, k := range openKeys {
		open[k] = true
	}

	t.Run("APIToken 開放端點與只持有授權角色的本人相同", func(t *testing.T) {
		covered := map[string]bool{}
		specificSeen := map[string]bool{}
		tokenOnlySeen := map[string]bool{}
		for _, p := range pairs {
			classes := map[int]int{}
			writes, specific := 0, 0
			for _, r := range catalog.Routes {
				key := routeKey(r)
				if !open[key] {
					continue
				}
				if usesDynamic(r) {
					e.issueDynamic(p.token)
				}
				tr := e.cmpRun(p.token, e.request(r), p.tokenSelf, p.humanSelf)
				if usesDynamic(r) {
					e.issueDynamic(p.human)
				}
				hr := e.cmpRun(p.human, e.request(r), p.humanSelf, p.tokenSelf)
				covered[key] = true
				classes[hr.Status/100]++
				if len(hr.DB) > 0 {
					writes++
				}
				d := cmpDiff(tr, hr)
				if d == "" {
					continue
				}
				if want, ok := apiTokenTokenSpecific[p.name+" "+key]; ok && cmpErrorCode(tr) == want {
					specific++
					specificSeen[p.name+" "+key] = true
					// 預期的拒絕也要確認沒有留下副作用（稽核列除外：拒絕本身要留痕）
					if len(tr.DB) > 0 || len(tr.FS) > 0 || len(tr.Remote) > 0 || len(tr.Alerts) > 0 {
						t.Errorf("[%s] %s：token 以 %s 被拒卻有變更 db=%v fs=%v remote=%v alerts=%v",
							p.name, key, want, tr.DB, tr.FS, tr.Remote, tr.Alerts)
					}
					continue
				}
				if want, ok := apiTokenOnlyRoutes[key]; ok && tr.Status == 200 && cmpErrorCode(hr) == want {
					tokenOnlySeen[p.name+" "+key] = true
					continue
				}
				t.Errorf("[%s] %s：token 與只持有授權角色的本人不同%s", p.name, key, d)
			}
			t.Logf("[%s] 回應類別（人類側）2xx=%d 3xx=%d 4xx=%d 5xx=%d；有資料寫入的端點 %d；token 專屬限制的預期差異 %d",
				p.name, classes[2], classes[3], classes[4], classes[5], writes, specific)
			if p.name == "super" && (classes[2] < 100 || writes < 40) {
				t.Errorf("[super] 成功或寫入的端點過少（2xx=%d、寫入=%d），對照可能沒有走到授權之後的分支", classes[2], writes)
			}
		}
		for k := range apiTokenOnlyRoutes {
			for _, p := range pairs {
				if !tokenOnlySeen[p.name+" "+k] {
					t.Errorf("[%s] %s 應為 token 成功、人類工作階段被拒", p.name, k)
				}
			}
		}
		// 預期差異沒有出現＝token 專屬限制失效（或清單過期）
		for k := range apiTokenTokenSpecific {
			if !specificSeen[k] {
				t.Errorf("預期的 token 專屬差異沒有出現：%s（token 應以 %s 被拒）", k, apiTokenTokenSpecific[k])
			}
		}
		var missing, extra []string
		for _, k := range openKeys {
			if !covered[k] {
				missing = append(missing, k)
			}
		}
		for k := range covered {
			if !open[k] {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		if len(missing) > 0 || len(extra) > 0 {
			t.Errorf("涵蓋集合與登錄的開放集合不符：登錄有而未涵蓋 %v；涵蓋而登錄不開放 %v", missing, extra)
		}
		keys := make([]string, 0, len(covered))
		for k := range covered {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Logf("涵蓋的開放端點 %d 條（登錄開放 %d 條，雙向相符）：\n%s", len(keys), len(openKeys), strings.Join(keys, "\n"))
	})

	t.Run("APIToken 回應省略對象帳號的 token 資訊", func(t *testing.T) {
		const key = "POST /api/v1/role-assignment-previews"
		if !open[key] {
			t.Fatalf("%s 應為開放端點", key)
		}
		omit := apiTokenResponseOmits[key]
		p := pairs[0]
		target := e.object("user.target").(uint)
		if err := model.AssignUserRoleWithSource(e.db, target, e.roleID(model.RoleAdmin), model.RoleSourceManual, model.RoleOriginSystem); err != nil {
			t.Fatalf("對象帳號指派角色：%v", err)
		}
		e.apiTokenIssue(cmpIdentity{userID: target, username: "baseline-target"}, "cmp-target-token", e.roleID(model.RoleAdmin))
		body := map[string]any{"kind": "direct_roles", "user_id": target, "role_ids": []uint{e.roleID(model.RoleAuditor)}}
		tc, tb := e.apiTokenRuleCall(p.token, "POST", "/api/v1/role-assignment-previews", body)
		hc, hb := e.apiTokenRuleCall(p.human, "POST", "/api/v1/role-assignment-previews", body)
		e.apiTokenRuleRestore()
		if tc != 200 || hc != 200 {
			t.Fatalf("兩邊應皆 200：token %d %v；人類 %d %v", tc, tb, hc, hb)
		}
		if _, ok := tb[omit]; ok {
			t.Errorf("token 回應不應含 %s：%v", omit, tb[omit])
		}
		if _, ok := hb[omit]; !ok {
			t.Fatalf("人類回應應含 %s（對象帳號有 token），情境沒有走到差異：%v", omit, hb)
		}
		delete(hb, omit)
		if d := cmpDiff(cmpRecord{Status: tc, Body: tb}, cmpRecord{Status: hc, Body: hb}); d != "" {
			t.Errorf("除 %s 外兩邊回應應相同：%s", omit, d)
		}
	})

	t.Run("APIToken 不開放端點皆回 403 且沒有變更", func(t *testing.T) {
		p := pairs[0]
		n := 0
		for _, r := range catalog.Routes {
			key := routeKey(r)
			if open[key] {
				continue
			}
			if usesDynamic(r) {
				e.issueDynamic(p.token)
			}
			rec := e.cmpRun(p.token, e.request(r), p.tokenSelf, p.humanSelf)
			n++
			if rec.Status != 403 || cmpErrorCode(rec) != string(apierror.CodeAuthAPITokenForbiddenRoute) {
				t.Errorf("%s：token 應回 403 %s，得到 %d %v", key, apierror.CodeAuthAPITokenForbiddenRoute, rec.Status, rec.Body)
			}
			if len(rec.DB) > 0 || len(rec.FS) > 0 || len(rec.Remote) > 0 || len(rec.Alerts) > 0 {
				t.Errorf("%s：被拒卻有變更 db=%v fs=%v remote=%v alerts=%v", key, rec.DB, rec.FS, rec.Remote, rec.Alerts)
			}
		}
		t.Logf("不開放端點 %d 條皆回 403", n)
	})
}
