package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

type apsList struct {
	Data                []map[string]json.RawMessage `json:"data"`
	Total               int                          `json:"total"`
	Coverage            []authz.ApproverNodeCoverage `json:"coverage"`
	MinApprovals        *int                         `json:"min_approvals"`
	ApplicantManageable *bool                        `json:"applicant_manageable"`
	ManagementScope     *string                      `json:"management_scope"`
	raw                 string
}

func (e *apsEnv) list(uid uint) apsList {
	e.t.Helper()
	r := e.do(uid, http.MethodGet, "/api/v1/approver-scopes", nil)
	require.Equal(e.t, http.StatusOK, r.code, r.raw)
	var out apsList
	require.NoError(e.t, json.Unmarshal([]byte(r.raw), &out), r.raw)
	out.raw = r.raw
	return out
}

func (l apsList) count(node uint) int {
	for _, c := range l.Coverage {
		if c.NodeID == node {
			return c.ApproverCount
		}
	}
	return -1
}

func (l apsList) hasApplicantRow() bool {
	for _, r := range l.Data {
		if s := string(r["subject_user_id"]); s != "" && s != "null" {
			return true
		}
		if s := string(r["subject_group_id"]); s != "" && s != "null" {
			return true
		}
	}
	return false
}

func TestScopedApproverScopeList(t *testing.T) {
	t.Run("projection", func(t *testing.T) {
		e := apsEnvFor(t, "aps_list_projection")
		jia := e.approver("aps-jia")
		applicant := e.user("aps-applicant-zq")
		sitAsset := e.hostAsset("aps-sit-asset-zq", "10.66.3.33", "sit/web")
		e.seedScope(model.ApproverScope{ApproverID: &jia, AssetGroupID: ptrU(e.id("prod/db"))})
		e.seedScope(model.ApproverScope{ApproverID: &jia, AssetGroupID: ptrU(e.id("sit"))})
		e.seedScope(model.ApproverScope{ApproverID: &jia, AssetID: &sitAsset})
		e.seedScope(model.ApproverScope{ApproverID: &jia, SubjectUserID: &applicant})
		viewer := e.user("aps-viewer-prod")
		e.grantNodes(viewer, e.role(authz.PermApproverScopeManage), "prod")

		l := e.list(viewer)
		require.Equal(t, 1, l.Total, l.raw)
		require.Len(t, l.Data, 1)
		assert.Equal(t, fmt.Sprint(e.id("prod/db")), string(l.Data[0]["asset_group_id"]))
		assert.Equal(t, []string{"id", "username"}, keysOf(t, string(l.Data[0]["approver"])), "巢狀審核方鍵集")
		for _, s := range []string{`"name":"sit"`, "aps-sit-asset-zq", "10.66.3.33", "aps-applicant-zq",
			fmt.Sprintf(`"asset_group_id":%d`, e.id("sit")), fmt.Sprintf(`"node_id":%d,`, e.id("sit")),
			fmt.Sprintf(`"asset_id":%d`, sitAsset), fmt.Sprintf(`"subject_user_id":%d`, applicant), "@aps-fixture.test"} {
			assert.NotContains(t, l.raw, s, "範圍化列表原文不得含範圍外或申請人資料")
		}
		require.NotNil(t, l.ManagementScope)
		assert.Equal(t, "nodes", *l.ManagementScope)
		require.NotNil(t, l.MinApprovals)
		assert.Equal(t, 2, *l.MinApprovals)
		require.NotNil(t, l.ApplicantManageable)
		assert.False(t, *l.ApplicantManageable)
	})

	t.Run("coverage_and_flags", func(t *testing.T) {
		e := apsEnvFor(t, "aps_list_coverage")
		jia, yi, bing := e.approver("aps-jia"), e.approver("aps-yi"), e.approver("aps-bing")
		applicant := e.user("aps-applicant-zq")
		e.seedScope(model.ApproverScope{ApproverID: &jia, AssetGroupID: ptrU(e.id("prod"))})
		e.seedScope(model.ApproverScope{ApproverID: &yi, AssetGroupID: ptrU(e.id("prod/db"))})
		// 群組審核方掛在 prod/db/a：成員乙、丙，與上層的乙去重
		g := model.UserGroup{Name: "aps-approver-group"}
		require.NoError(t, e.db.Create(&g).Error)
		for _, m := range []uint{yi, bing} {
			require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: m, Manual: true}).Error)
		}
		e.seedScope(model.ApproverScope{ApproverGroupID: &g.ID, AssetGroupID: ptrU(e.id("prod/db/a"))})
		e.seedScope(model.ApproverScope{ApproverID: &jia, SubjectUserID: &applicant})

		k := e.role(authz.PermApproverScopeManage)
		ka := e.role(authz.PermApproverScopeApplicantManage)
		scopedDB := e.user("aps-viewer-db")
		e.grantNodes(scopedDB, k, "prod/db")
		globalBoth := e.user("aps-viewer-global-both")
		e.grantGlobal(globalBoth, e.role(authz.PermApproverScopeManage, authz.PermApproverScopeApplicantManage))
		nodeKGlobalKA := e.user("aps-viewer-node-k-global-ka")
		e.grantNodes(nodeKGlobalKA, k, "prod")
		e.grantGlobal(nodeKGlobalKA, ka)
		globalK := e.user("aps-viewer-global-k")
		e.grantGlobal(globalK, k)

		l := e.list(scopedDB)
		assert.Equal(t, 1, l.count(e.id("prod/db")), "範圍外祖先 prod 上的甲不計")
		assert.Equal(t, 2, l.count(e.id("prod/db/a")), "群組成員展開去重：乙、丙")
		assert.Equal(t, -1, l.count(e.id("prod")), "範圍外節點不出現在可審人數")
		g2 := e.list(globalBoth)
		assert.Equal(t, 2, g2.count(e.id("prod/db")), "全域持有者計入 prod 上的甲")
		assert.Equal(t, 3, g2.count(e.id("prod/db/a")))
		require.NotNil(t, g2.ApplicantManageable)
		assert.True(t, *g2.ApplicantManageable)
		assert.True(t, g2.hasApplicantRow())
		assert.Nil(t, g2.ManagementScope, "全域持有者不帶 management_scope")
		for _, uid := range []uint{nodeKGlobalKA, globalK} {
			v := e.list(uid)
			require.NotNil(t, v.ApplicantManageable, v.raw)
			assert.False(t, *v.ApplicantManageable)
			assert.False(t, v.hasApplicantRow(), "旗標為假者的列表不含申請人型列：%s", v.raw)
		}

		// 超級管理者：與現行實作逐欄相同，無新增的四個鍵
		sc := e.do(e.super, http.MethodGet, "/api/v1/approver-scopes", nil)
		pl := e.call(e.super, false, http.MethodGet, "/api/v1/approver-scopes", nil)
		require.Equal(t, http.StatusOK, sc.code, sc.raw)
		assert.Equal(t, pl, sc)
		assert.Equal(t, []string{"data", "total"}, keysOf(t, sc.raw))
	})
}

type apsTargets struct {
	Kind  string                       `json:"kind"`
	Data  []authz.ApproverTargetOption `json:"data"`
	Total int64                        `json:"total"`
}

func (e *apsEnv) targets(uid uint, query string) (apsTargets, string) {
	e.t.Helper()
	r := e.do(uid, http.MethodGet, "/api/v1/approver-scopes/target-options?"+query, nil)
	require.Equal(e.t, http.StatusOK, r.code, r.raw)
	var out apsTargets
	require.NoError(e.t, json.Unmarshal([]byte(r.raw), &out), r.raw)
	return out, r.raw
}

func TestApproverScopeOptions(t *testing.T) {
	e := apsEnvFor(t, "aps_options")
	approver := e.approver("aps-opt-approver")
	superApprover := e.approver("aps-opt-super-approver")
	grantLegacyRole(t, e.db, superApprover, model.RoleAdmin)
	inactive := e.user("aps-opt-inactive")
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", inactive).Update("active", false).Error)
	agent := e.user("aps-opt-agent")
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", agent).Update("kind", model.KindAgent).Error)
	k := e.role(authz.PermApproverScopeManage)
	op := e.user("aps-opt-op")
	e.grantNodes(op, k, "prod")
	mixed := e.user("aps-opt-mixed")
	e.grantNodes(mixed, k, "prod")
	e.grantNodes(mixed, e.role(authz.PermAssetGroupManage), "sit")
	noK := e.user("aps-opt-nok")
	e.grantGlobal(noK, e.role(authz.PermApproverScopeApplicantManage))
	inProd := e.hostAsset("aps-opt-prod-asset", "10.66.4.1", "prod/db/a")
	inSit := e.hostAsset("aps-opt-sit-asset", "10.66.4.2", "sit/web")

	t.Run("approver_options", func(t *testing.T) {
		r := e.do(op, http.MethodGet, "/api/v1/approver-scopes/approver-options", nil)
		require.Equal(t, http.StatusOK, r.code, r.raw)
		assert.NotContains(t, r.raw, "@aps-fixture.test", "審核方選項不含 email")
		var out struct {
			Users  []map[string]json.RawMessage `json:"users"`
			Groups []map[string]json.RawMessage `json:"groups"`
		}
		require.NoError(t, json.Unmarshal([]byte(r.raw), &out))
		byID := map[string]map[string]json.RawMessage{}
		for _, u := range out.Users {
			byID[string(u["id"])] = u
			b, _ := json.Marshal(u)
			assert.Equal(t, []string{"active", "display_name", "id", "is_approver", "selectable", "username"}, keysOf(t, string(b)))
		}
		_, hasAgent := byID[fmt.Sprint(agent)]
		assert.False(t, hasAgent, "不含 agent")
		sa := byID[fmt.Sprint(superApprover)]
		require.NotNil(t, sa)
		assert.Equal(t, "true", string(sa["is_approver"]))
		assert.Equal(t, "false", string(sa["selectable"]), "同時具超管與 approver 者不可選")
		in := byID[fmt.Sprint(inactive)]
		require.NotNil(t, in)
		assert.Equal(t, "false", string(in["active"]))
		assert.Equal(t, "true", string(in["selectable"]), "停用不改變 selectable")
		ap := byID[fmt.Sprint(approver)]
		require.NotNil(t, ap)
		assert.Equal(t, "true", string(ap["selectable"]))
	})

	t.Run("target_options", func(t *testing.T) {
		assets, _ := e.targets(op, "kind=asset")
		ids := map[uint]bool{}
		for _, a := range assets.Data {
			ids[a.ID] = true
		}
		assert.True(t, ids[inProd])
		assert.False(t, ids[inSit], "範圍外資產不在候選")
		_, sitRaw := e.targets(op, fmt.Sprintf("kind=asset&node_id=%d", e.id("sit")))
		_, missRaw := e.targets(op, fmt.Sprintf("kind=asset&node_id=%d", apsMissing))
		assert.Equal(t, missRaw, sitRaw, "範圍外與不存在的 node_id 同形")
		empty, _ := e.targets(op, fmt.Sprintf("kind=asset&node_id=%d", e.id("sit")))
		assert.Empty(t, empty.Data)
		assert.Zero(t, empty.Total)

		prodSub := map[uint]bool{}
		for _, p := range []string{"prod", "prod/db", "prod/db/a", "prod/db/b", "prod/web"} {
			prodSub[e.id(p)] = true
		}
		nodes, raw := e.targets(mixed, "kind=node")
		require.NotEmpty(t, nodes.Data, raw)
		for _, n := range nodes.Data {
			assert.True(t, prodSub[n.ID], "節點候選只含 prod 子樹：%s", raw)
			if n.Selectable != nil && *n.Selectable {
				assert.True(t, prodSub[n.ID])
			}
		}
		assert.EqualValues(t, len(prodSub), nodes.Total)
	})

	t.Run("requires_manage_key", func(t *testing.T) {
		for _, p := range []string{"/api/v1/approver-scopes/approver-options", "/api/v1/approver-scopes/target-options?kind=node"} {
			bodyOnlyCodeError(t, e.do(noK, http.MethodGet, p, nil))
		}
	})
}
