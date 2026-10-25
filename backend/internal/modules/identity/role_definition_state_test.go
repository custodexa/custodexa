package identity

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoleDefinitionStateCompatibility（權限狀態證據的角色定義側）擋：自訂集合／版本／相容目錄改變卻不改摘要、
// 合法事件重放不等於現況、直改集合沒被指出、名稱說明進附證、恢復核對把無效內容當空集合放行。
// 權限狀態快照的編碼、舊格式解碼、封章與恢復世代不在本檔範圍，屬 audit 套件。
func TestRoleDefinitionStateCompatibility(t *testing.T) {
	ctx := context.Background()
	digest := func(t *testing.T, e *roleDefEnv) string {
		t.Helper()
		st, err := e.svc.State(ctx)
		require.NoError(t, err)
		require.NoError(t, authz.ValidateRoleDefinitionState(st))
		d, err := st.Digest()
		require.NoError(t, err)
		return d
	}
	t.Run("摘要隨集合、定義版本、範本識別、相容目錄改變，不隨名稱說明改變", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d0 := digest(t, e)
		r := e.create(t, "r", "asset:view")
		d1 := digest(t, e)
		assert.NotEqual(t, d0, d1, "新增自訂角色")
		_, err := e.svc.Update(ctx, e.admin, r.ID, 1, RoleInput{Name: "renamed", Description: "new text", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		d2 := digest(t, e)
		assert.NotEqual(t, d1, d2, "定義版本推進即改變")
		_, err = e.svc.Update(ctx, e.admin, r.ID, 2, RoleInput{Name: "renamed again", Description: "other", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		require.NoError(t, e.db.Model(&model.Role{}).Where("id = ?", r.ID).Update("definition_version", 2).Error) // 版本還原到同值，只剩名稱說明不同
		assert.Equal(t, d2, digest(t, e), "名稱與說明不進附證")
		_, err = e.svc.Copy(ctx, e.admin, e.roles["user"], "from-user", "")
		require.NoError(t, err)
		d3 := digest(t, e)
		require.NoError(t, e.db.Where("role_id = ?", r.ID).Delete(&model.RolePermission{}).Error)
		d4 := digest(t, e)
		assert.NotEqual(t, d3, d4, "集合改變")
		legacy := model.Role{Name: "legacy-x"}
		require.NoError(t, e.db.Create(&legacy).Error)
		assert.NotEqual(t, d4, digest(t, e), "相容目錄識別改變")
	})
	t.Run("合法的四種事件可重放為現況；直改集合被指出", func(t *testing.T) {
		e := newRoleDefEnv(t)
		a := e.create(t, "a", "asset:view")
		cp, err := e.svc.Copy(ctx, e.admin, a.ID, "b", "")
		require.NoError(t, err)
		_, err = e.svc.Update(ctx, e.admin, a.ID, 1, RoleInput{Name: "a", Permissions: []string{"asset:view", "session:view"}})
		require.NoError(t, err)
		gone := e.create(t, "gone", "audit:view")
		require.NoError(t, e.svc.Delete(ctx, e.admin, gone.ID, 1))
		var evs []authz.RoleDefinitionStateEvent
		for _, ev := range e.events.events {
			evs = append(evs, authz.RoleDefinitionStateEvent{Action: ev.Action, RoleID: ev.RoleID, DefinitionVersion: ev.DefinitionVersion, Before: ev.Before, After: ev.After})
		}
		replayed, err := authz.ReplayRoleDefinitionEvents(evs)
		require.NoError(t, err)
		live, err := e.svc.State(ctx)
		require.NoError(t, err)
		assert.Empty(t, authz.DiffRoleDefinitionState(replayed, live), "合法事件重放＝現況")
		assert.Contains(t, replayed, cp.ID)
		assert.NotContains(t, replayed, gone.ID, "刪除事件使角色自重放結果移除")
		// 直改集合（沒有事件）
		require.NoError(t, e.db.Create(&model.RolePermission{RoleID: cp.ID, PermissionKey: "audit:view"}).Error)
		live, err = e.svc.State(ctx)
		require.NoError(t, err)
		assert.Equal(t, []uint{cp.ID}, authz.DiffRoleDefinitionState(replayed, live))
		// 事件鏈被截斷或亂序：前集合／版本不符即回錯
		_, err = authz.ReplayRoleDefinitionEvents(evs[2:])
		assert.Error(t, err)
		bad := append([]authz.RoleDefinitionStateEvent{}, evs...)
		bad[2].Before = []string{"nope:key"}
		_, err = authz.ReplayRoleDefinitionEvents(bad)
		assert.Error(t, err)
	})
	t.Run("恢復核對拒絕未知格式、未知權限鍵、懸空範本來源，不當成空集合", func(t *testing.T) {
		e := newRoleDefEnv(t)
		e.create(t, "a", "asset:view")
		st, err := e.svc.State(ctx)
		require.NoError(t, err)
		require.NoError(t, authz.ValidateRoleDefinitionState(st))
		unknownFmt := st
		unknownFmt.Format = 99
		assert.Error(t, authz.ValidateRoleDefinitionState(unknownFmt))
		badKey := st.Canonical()
		badKey.Roles[0].Keys = append(badKey.Roles[0].Keys, "nope:key")
		assert.Error(t, authz.ValidateRoleDefinitionState(badKey))
		uiKey := st.Canonical()
		uiKey.Roles[0].Keys = []string{"ui:nav.users"}
		assert.Error(t, authz.ValidateRoleDefinitionState(uiKey))
		missing := uint(987654)
		dangling := st.Canonical()
		dangling.Roles[0].TemplateRoleID = &missing
		assert.Error(t, authz.ValidateRoleDefinitionState(dangling))
		zeroVer := st.Canonical()
		zeroVer.Roles[0].DefinitionVersion = 0
		assert.Error(t, authz.ValidateRoleDefinitionState(zeroVer))
	})
	t.Run("狀態不含角色名稱說明或自由文字", func(t *testing.T) {
		e := newRoleDefEnv(t)
		_, err := e.svc.Create(ctx, e.admin, RoleInput{Name: "secret-looking-name", Description: "free text here", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		st, err := e.svc.State(ctx)
		require.NoError(t, err)
		b := stateJSON(t, st)
		assert.NotContains(t, b, "secret-looking-name")
		assert.NotContains(t, b, "free text here")
	})
}

func stateJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}
