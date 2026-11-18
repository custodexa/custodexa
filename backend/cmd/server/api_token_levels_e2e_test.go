package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 授權角色的層級（端到端，正式組裝）：
//   - 多能力的寫入：映射規則的寫入要身分來源管理與角色指派兩個能力；其中一個所需角色為唯讀時拒絕、不寫入。
//   - 內建身分：只授權唯讀超級管理者角色的 token 在寫入路由不具超級管理者身分；全唯讀時在閘門以專屬碼拒絕，
//     另有讀寫角色時由端點的超管限定拒絕。兩者皆不寫入。
// 每一組都以同一帳號、層級改為讀寫的 token 作對照，證明請求本身會成功（拒絕來自層級而非請求內容）。

// apiTokenIssueLeveled 以正式的建立流程替 owner 建立逐角色指定層級的 token。
func (e *baselineEnv) apiTokenIssueLeveled(owner cmpIdentity, name string, roles ...identity.APITokenRoleGrant) *baselineSubject {
	svc := identity.NewAPITokenService(e.db, apiTokenGateEvents{})
	svc.SetRestoreGenerationSource(authz.RestoreGeneration)
	op := identity.Operator{UserID: owner.userID, Username: owner.username,
		Principal: authz.NewPrincipal(owner.userID, authz.TokenFacts{SubjectKind: model.KindHuman}, nil)}
	created, err := svc.Create(op, identity.CreateAPITokenInput{Name: name, Roles: roles, NeverExpires: true})
	if err != nil {
		e.t.Fatalf("建立 API token %s：%v", name, err)
	}
	return &baselineSubject{ID: "T-" + name, Username: owner.username, UserID: owner.userID, Token: created.Token, Kind: "api_token"}
}

func levelRequest(method, path string, body any) baselineRequest {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	return baselineRequest{Method: method, Path: path, Body: raw, ContentType: "application/json"}
}

func cmpCode(r cmpRecord) string { return cmpErrorCode(r) }

// TestAPITokenLevelsEndToEnd 見檔頭。
func TestAPITokenLevelsEndToEnd(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	rw, ro := model.APITokenLevelReadWrite, model.APITokenLevelRead

	// 映射規則：身分來源管理與角色指派分在兩個自訂角色
	sourceRole := e.apiTokenCustomRole("lvl-source", authz.PermIdentitySourceManage)
	assignRole := e.apiTokenCustomRole("lvl-assign", authz.PermRoleAssign)
	mapper := e.apiTokenUser("lvl-mapper", sourceRole, assignRole)
	mapBoth := e.apiTokenIssueLeveled(mapper, "lvl-map-both", identity.APITokenRoleGrant{RoleID: sourceRole, Level: rw}, identity.APITokenRoleGrant{RoleID: assignRole, Level: rw})
	mapAssignRO := e.apiTokenIssueLeveled(mapper, "lvl-map-assign-ro", identity.APITokenRoleGrant{RoleID: sourceRole, Level: rw}, identity.APITokenRoleGrant{RoleID: assignRole, Level: ro})
	mapSourceRO := e.apiTokenIssueLeveled(mapper, "lvl-map-source-ro", identity.APITokenRoleGrant{RoleID: sourceRole, Level: ro}, identity.APITokenRoleGrant{RoleID: assignRole, Level: rw})

	// 超級管理者：所屬帳號持有超管與一個一般的管理角色
	userRole := e.apiTokenCustomRole("lvl-users", authz.PermUserManage)
	root := e.apiTokenUser("lvl-root", e.roleID(model.RoleAdmin), userRole)
	superRW := e.apiTokenIssueLeveled(root, "lvl-super-rw", identity.APITokenRoleGrant{RoleID: e.roleID(model.RoleAdmin), Level: rw})
	superRO := e.apiTokenIssueLeveled(root, "lvl-super-ro", identity.APITokenRoleGrant{RoleID: e.roleID(model.RoleAdmin), Level: ro})
	superROWithRW := e.apiTokenIssueLeveled(root, "lvl-super-ro-mixed", identity.APITokenRoleGrant{RoleID: e.roleID(model.RoleAdmin), Level: ro}, identity.APITokenRoleGrant{RoleID: userRole, Level: rw})
	e.apiTokenRetemplate()

	prov := e.object("oidcProvider.1").(uint)
	mappingReq := levelRequest(http.MethodPost, fmt.Sprintf("/api/v1/identity-sources/oidc/%d/role-mappings", prov),
		map[string]any{"match_value": "lvl-mapped", "role": model.RoleAuditor, "enabled": true, "risk_acknowledged": true})
	denied := string(apierror.CodePermissionDenied)
	readOnlyCode := string(apierror.CodeAuthAPITokenReadOnly)

	t.Run("APIToken 多能力寫入的對照：兩個角色皆為讀寫時成功", func(t *testing.T) {
		rec := e.cmpRun(mapBoth, mappingReq, mapper, mapper)
		if !is2xx(rec.Status) || rec.DB == nil {
			t.Fatalf("兩個所需角色皆為讀寫應成功並寫入，得到 %d %v（DB 差異 %v）", rec.Status, rec.Body, rec.DB)
		}
	})
	for _, c := range []struct {
		name string
		subj *baselineSubject
	}{{"角色指派的角色為唯讀", mapAssignRO}, {"身分來源管理的角色為唯讀", mapSourceRO}} {
		t.Run("APIToken 多能力寫入："+c.name+"時拒絕且不寫入", func(t *testing.T) {
			rec := e.cmpRun(c.subj, mappingReq, mapper, mapper)
			if rec.Status != http.StatusForbidden || cmpCode(rec) != string(apierror.CodePermissionDenied) {
				t.Fatalf("應以能力不足拒絕（混合層級不在閘門拒絕），得到 %d %v", rec.Status, rec.Body)
			}
			if rec.DB != nil || len(rec.Alerts) != 0 {
				t.Fatalf("拒絕後資料庫不應有變更：%v %v", rec.DB, rec.Alerts)
			}
			t.Logf("拒絕：%d %s", rec.Status, cmpCode(rec))
		})
	}
	t.Run("APIToken 多能力寫入：唯讀角色仍可讀取映射規則", func(t *testing.T) {
		rec := e.cmpRun(mapAssignRO, levelRequest(http.MethodGet, fmt.Sprintf("/api/v1/identity-sources/oidc/%d/role-mappings", prov), nil), mapper, mapper)
		if !is2xx(rec.Status) {
			t.Fatalf("讀取應成功，得到 %d %v", rec.Status, rec.Body)
		}
	})

	roleDefReq := levelRequest(http.MethodPost, "/api/v1/role-definitions",
		map[string]any{"name": "lvl-new-role", "description": "d", "permissions": []string{"asset:view"}})
	t.Run("APIToken 超管限定寫入的對照：讀寫的超管角色成功", func(t *testing.T) {
		rec := e.cmpRun(superRW, roleDefReq, root, root)
		if !is2xx(rec.Status) || rec.DB == nil {
			t.Fatalf("讀寫的超管角色應成功並寫入，得到 %d %v", rec.Status, rec.Body)
		}
	})
	t.Run("APIToken 只授權唯讀超管角色：閘門以專屬碼拒絕且不寫入", func(t *testing.T) {
		rec := e.cmpRun(superRO, roleDefReq, root, root)
		if rec.Status != http.StatusForbidden || cmpCode(rec) != readOnlyCode {
			t.Fatalf("應回 403 %s，得到 %d %v", readOnlyCode, rec.Status, rec.Body)
		}
		if rec.DB != nil {
			t.Fatalf("拒絕後資料庫不應有變更：%v", rec.DB)
		}
	})
	t.Run("APIToken 唯讀超管角色加讀寫的一般角色：寫入時不具超管身分、不寫入", func(t *testing.T) {
		rec := e.cmpRun(superROWithRW, roleDefReq, root, root)
		if rec.Status != http.StatusForbidden || cmpCode(rec) == readOnlyCode {
			t.Fatalf("應由端點的超管限定拒絕（不是閘門的唯讀拒絕），得到 %d %v", rec.Status, rec.Body)
		}
		if rec.DB != nil {
			t.Fatalf("拒絕後資料庫不應有變更：%v", rec.DB)
		}
		t.Logf("拒絕：%d %s（預期 %s 或同類的超管限定拒絕）", rec.Status, cmpCode(rec), denied)
	})
	t.Run("APIToken 唯讀超管角色仍可讀取", func(t *testing.T) {
		rec := e.cmpRun(superRO, levelRequest(http.MethodGet, "/api/v1/role-definitions", nil), root, root)
		if !is2xx(rec.Status) {
			t.Fatalf("讀取應成功，得到 %d %v", rec.Status, rec.Body)
		}
	})
}
