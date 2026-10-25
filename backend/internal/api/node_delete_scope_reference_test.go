package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// failingReferencePort 引用查詢回錯誤。
type failingReferencePort struct{}

func (failingReferencePort) NodeScopeReferences(*gorm.DB, uint) (asset.NodeReferences, error) {
	return asset.NodeReferences{}, errors.New("reference query failed")
}

// failingCascade 級聯參與者回錯誤。
type failingCascade struct{}

func (failingCascade) NodeDeleteCascade(*gorm.DB, uint, *uint) error {
	return errors.New("cascade participant failed")
}

// nodeGrants 在節點上建一筆節點授權與一筆審核範圍（級聯撤銷的對象）。
func (e *nodeScopeEnv) nodeGrants(path string) {
	e.t.Helper()
	nid := e.id(path)
	holder := e.user(fmt.Sprintf("holder-%d", nid))
	require.NoError(e.t, e.db.Create(&model.AssetAuthorization{UserID: &holder, AssetGroupID: &nid,
		Permission: model.PermissionConnect, Source: "manual", GrantedBy: 1}).Error)
	require.NoError(e.t, e.db.Create(&model.ApproverScope{ApproverID: &holder, AssetGroupID: &nid, GrantedBy: 1}).Error)
}

// liveGrants 節點上未軟刪的節點授權與審核範圍筆數。
func (e *nodeScopeEnv) liveGrants(path string) (int64, int64) {
	e.t.Helper()
	var a, s int64
	require.NoError(e.t, e.db.Model(&model.AssetAuthorization{}).Where("asset_group_id = ?", e.id(path)).Count(&a).Error)
	require.NoError(e.t, e.db.Model(&model.ApproverScope{}).Where("asset_group_id = ?", e.id(path)).Count(&s).Error)
	return a, s
}

// nodeLive 節點未被軟刪。
func (e *nodeScopeEnv) nodeLive(path string) bool {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(&model.AssetGroup{}).Where("id = ?", e.id(path)).Count(&n).Error)
	return n == 1
}

func (e *nodeScopeEnv) deleteNode(actor uint, path string) (int, map[string]any, string) {
	e.t.Helper()
	code, body := e.do(actor, http.MethodDelete, "/asset-groups/"+e.idStr(path), nil)
	m := map[string]any{}
	require.NoError(e.t, json.Unmarshal(body, &m), string(body))
	return code, m, string(body)
}

func TestNodeDeleteBlockedByScopeReference(t *testing.T) {
	referenced := string(apierror.CodeNodeScopeReferenced)

	t.Run("super_admin_blocked_on_referenced_empty_node", func(t *testing.T) {
		e := newNodeScopeEnv(t)
		holder := e.user("ref-holder")
		e.grantNodes(holder, e.role(authz.PermAssetView), "prod/web")
		e.nodeGrants("prod/web")
		super := e.superAdmin()

		code, body, raw := e.deleteNode(super, "prod/web")
		assert.Equal(t, http.StatusConflict, code, raw)
		assert.Equal(t, referenced, body["code"])
		assert.True(t, e.nodeLive("prod/web"), "節點不變")
		a, s := e.liveGrants("prod/web")
		assert.Equal(t, int64(1), a, "授權不變")
		assert.Equal(t, int64(1), s, "審核範圍不變")
	})

	t.Run("disabled_referencing_subject_still_blocks", func(t *testing.T) {
		e := newNodeScopeEnv(t)
		holder := e.user("ref-holder")
		e.grantNodes(holder, e.role(authz.PermAssetView), "prod/web")
		require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", holder).Update("active", false).Error)
		super := e.superAdmin()

		code, body, raw := e.deleteNode(super, "prod/web")
		assert.Equal(t, http.StatusConflict, code, raw)
		assert.Equal(t, referenced, body["code"])
		assert.True(t, e.nodeLive("prod/web"))
	})

	t.Run("last_scope_node_of_assignment_still_blocks", func(t *testing.T) {
		e := newNodeScopeEnv(t)
		holder := e.user("ref-holder")
		role := e.role(authz.PermAssetView)
		e.grantNodes(holder, role, "prod/db/a", "prod/db/b")
		super := e.superAdmin()

		for _, p := range []string{"prod/db/a", "prod/db/b"} {
			code, body, raw := e.deleteNode(super, p)
			assert.Equal(t, http.StatusConflict, code, raw)
			assert.Equal(t, referenced, body["code"])
		}
		// 指派範圍改為只剩 prod/db/b 後，prod/db/a 可刪；最後一個範圍節點仍被擋
		require.NoError(t, e.db.Where("subject_kind = ? AND subject_id = ? AND role_id = ? AND node_id = ?",
			model.BindingSubjectUser, holder, role, e.id("prod/db/a")).Delete(&model.RoleBindingNode{}).Error)
		code, _, raw := e.deleteNode(super, "prod/db/a")
		require.Equal(t, http.StatusOK, code, raw)
		code, body, raw := e.deleteNode(super, "prod/db/b")
		assert.Equal(t, http.StatusConflict, code, raw)
		assert.Equal(t, referenced, body["code"])
		assert.True(t, e.nodeLive("prod/db/b"))
	})

	t.Run("revoked_reference_allows_delete_with_cascade", func(t *testing.T) {
		e := newNodeScopeEnv(t)
		holder := e.user("ref-holder")
		role := e.role(authz.PermAssetView)
		e.grantNodes(holder, role, "prod/web")
		e.nodeGrants("prod/web")
		super := e.superAdmin()

		require.NoError(t, e.db.Where("user_id = ? AND role_id = ?", holder, role).Delete(&model.UserRole{}).Error)
		require.NoError(t, e.db.Where("subject_kind = ? AND subject_id = ? AND role_id = ?",
			model.BindingSubjectUser, holder, role).Delete(&model.RoleBindingNode{}).Error)

		before := len(e.serviceAudits())
		code, _, raw := e.deleteNode(super, "prod/web")
		require.Equal(t, http.StatusOK, code, raw)
		assert.False(t, e.nodeLive("prod/web"), "節點軟刪")
		a, s := e.liveGrants("prod/web")
		assert.Equal(t, int64(0), a, "授權級聯軟刪")
		assert.Equal(t, int64(0), s, "審核範圍級聯軟刪")
		var softA, softS int64
		require.NoError(t, e.db.Unscoped().Model(&model.AssetAuthorization{}).
			Where("asset_group_id = ? AND deleted_at IS NOT NULL", e.id("prod/web")).Count(&softA).Error)
		require.NoError(t, e.db.Unscoped().Model(&model.ApproverScope{}).
			Where("asset_group_id = ? AND deleted_at IS NOT NULL", e.id("prod/web")).Count(&softS).Error)
		assert.Equal(t, int64(1), softA)
		assert.Equal(t, int64(1), softS)
		rows := e.serviceAudits()
		require.Equal(t, before+1, len(rows), "刪除寫一筆審計")
		assert.Contains(t, rows[len(rows)-1].Details, `"revoked_authorizations":1`)
		assert.Contains(t, rows[len(rows)-1].Details, `"revoked_approver_scopes":1`)
	})

	t.Run("reference_block_precedes_non_empty", func(t *testing.T) {
		e := newNodeScopeEnv(t)
		holder := e.user("ref-holder")
		e.grantNodes(holder, e.role(authz.PermAssetView), "prod/db")
		e.asset("db-direct", "prod/db")
		super := e.superAdmin()

		code, body, raw := e.deleteNode(super, "prod/db")
		assert.Equal(t, http.StatusConflict, code, raw)
		assert.Equal(t, referenced, body["code"], "引用阻擋而非非空拒絕")
	})

	t.Run("reference_query_missing_or_failing_fails_closed", func(t *testing.T) {
		for name, port := range map[string]asset.NodeScopeReferencePort{"missing": nil, "failing": failingReferencePort{}} {
			t.Run(name, func(t *testing.T) {
				e := newNodeScopeEnv(t)
				e.nodeGrants("sit/web")
				super := e.superAdmin()
				e.svc.SetNodeScopeReferencePort(port)

				code, _, raw := e.deleteNode(super, "sit/web")
				assert.False(t, is2xx(code), "刪除回錯誤：%s", raw)
				assert.True(t, e.nodeLive("sit/web"), "節點不變")
				a, s := e.liveGrants("sit/web")
				assert.Equal(t, int64(1), a)
				assert.Equal(t, int64(1), s)
			})
		}
	})

	t.Run("cascade_participant_failure_rolls_back", func(t *testing.T) {
		e := newNodeScopeEnv(t)
		e.nodeGrants("sit/web")
		super := e.superAdmin()
		e.svc.AddNodeDeleteCascade(failingCascade{})

		code, _, raw := e.deleteNode(super, "sit/web")
		assert.False(t, is2xx(code), "刪除回錯誤：%s", raw)
		assert.True(t, e.nodeLive("sit/web"), "節點不變")
		a, s := e.liveGrants("sit/web")
		assert.Equal(t, int64(1), a, "授權撤銷回滾")
		assert.Equal(t, int64(1), s, "審核範圍撤銷回滾")
	})

	t.Run("non_super_response_carries_count_only", func(t *testing.T) {
		e := newNodeScopeEnv(t)
		mgr := e.user("mgr")
		e.grantNodes(mgr, e.role(authz.PermAssetGroupManage), "prod/db")
		global := e.user("global")
		e.grantGlobal(global, e.role(authz.PermAssetGroupManage))

		// 群組主體與成員以醒目的識別碼建立，便於確認回應不含其字串
		memberIDs := []uint{48301, 48302, 48303}
		memberNames := []string{"member-quokka", "member-narwhal", "member-axolotl"}
		for i, id := range memberIDs {
			require.NoError(t, e.db.Create(&model.User{ID: id, Username: memberNames[i], Password: "x", Active: true}).Error)
		}
		const groupID, groupName = uint(48213), "ops-team-zeta"
		require.NoError(t, e.db.Create(&model.UserGroup{ID: groupID, Name: groupName}).Error)
		for _, m := range memberIDs {
			require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: groupID, UserID: m, Manual: true}).Error)
		}
		role := e.role(authz.PermAssetView)
		require.NoError(t, e.db.Create(&model.UserGroupRole{UserGroupID: groupID, RoleID: role, ScopeKind: model.ScopeKindNodes}).Error)
		require.NoError(t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUserGroup,
			SubjectID: groupID, RoleID: role, NodeID: e.id("prod/db/a")}).Error)

		for actorName, actor := range map[string]uint{"node_scoped_manager": mgr, "global_holder": global} {
			code, body, raw := e.deleteNode(actor, "prod/db/a")
			require.Equal(t, http.StatusConflict, code, "%s：%s", actorName, raw)
			assert.Equal(t, referenced, body["code"], actorName)
			for _, s := range append([]string{groupName, fmt.Sprint(groupID)}, memberNames...) {
				assert.NotContains(t, raw, s, "%s：回應不含引用者名稱或識別碼", actorName)
			}
			for _, id := range memberIDs {
				assert.NotContains(t, raw, fmt.Sprint(id), actorName)
			}
			_, hasRefs := body["references"]
			assert.False(t, hasRefs, "%s：回應不含引用清單", actorName)
			params, _ := body["params"].(map[string]any)
			require.NotNil(t, params, "%s：回應帶參數：%s", actorName, raw)
			assert.Equal(t, "1", fmt.Sprint(params["count"]), "%s：引用筆數以指派計", actorName)
			_, hasPath := params["path"]
			assert.True(t, hasPath, actorName)
			assert.Len(t, params, 2, "%s：只含 path 與 count：%s", actorName, raw)
		}
	})

	t.Run("super_admin_response_lists_sorted_references", func(t *testing.T) {
		e := newNodeScopeEnv(t)
		holder := e.user("ref-holder")
		roleA := e.role(authz.PermAssetView)
		roleB := e.role(authz.PermAssetView)
		groupRole := e.role(authz.PermAssetView)
		m1, m2, m3 := e.user("gm-1"), e.user("gm-2"), e.user("gm-3")
		// 寫入順序與期望排序相反：群組先、同一使用者的第二個角色先於第一個
		groupID := e.groupNodes("ref-group", groupRole, []uint{m1, m2, m3}, "prod/web")
		e.grantNodes(holder, roleB, "prod/web")
		e.grantNodes(holder, roleA, "prod/web")
		super := e.superAdmin()

		roleName := func(id uint) string {
			var n string
			require.NoError(t, e.db.Raw("SELECT name FROM roles WHERE id = ?", id).Scan(&n).Error)
			return n
		}
		type ref struct {
			kind        string
			subjectID   uint
			subjectName string
			roleID      uint
			members     *int
		}
		three := 3
		want := []ref{
			{model.BindingSubjectUser, holder, "ref-holder", roleA, nil},
			{model.BindingSubjectUser, holder, "ref-holder", roleB, nil},
			{model.BindingSubjectUserGroup, groupID, "ref-group", groupRole, &three},
		}
		sort.SliceStable(want, func(i, j int) bool {
			a, b := want[i], want[j]
			if a.kind != b.kind {
				return a.kind < b.kind
			}
			if a.subjectID != b.subjectID {
				return a.subjectID < b.subjectID
			}
			return a.roleID < b.roleID
		})

		code, body, raw := e.deleteNode(super, "prod/web")
		require.Equal(t, http.StatusConflict, code, raw)
		refs, ok := body["references"].([]any)
		require.True(t, ok, "超管回應附引用清單：%s", raw)
		require.Len(t, refs, len(want), "同一主體以兩個角色引用時為兩筆")
		for i, w := range want {
			got, _ := refs[i].(map[string]any)
			require.NotNil(t, got)
			assert.Equal(t, w.kind, got["subject_kind"], "第 %d 筆", i)
			assert.Equal(t, fmt.Sprint(w.subjectID), fmt.Sprint(got["subject_id"]), "第 %d 筆", i)
			assert.Equal(t, w.subjectName, got["subject_name"], "第 %d 筆", i)
			assert.Equal(t, fmt.Sprint(w.roleID), fmt.Sprint(got["role_id"]), "第 %d 筆", i)
			assert.Equal(t, roleName(w.roleID), got["role_name"], "第 %d 筆", i)
			if w.members == nil {
				_, has := got["member_count"]
				assert.False(t, has, "使用者主體不附成員數（第 %d 筆）", i)
			} else {
				assert.Equal(t, fmt.Sprint(*w.members), fmt.Sprint(got["member_count"]), "群組成員數（第 %d 筆）", i)
			}
		}
	})
}
