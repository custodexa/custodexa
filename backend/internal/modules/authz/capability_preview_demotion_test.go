package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// bindBoth 直接指派一個同時由管理者與外部群組映射持有、且限定節點範圍的角色。
func bindBoth(t *testing.T, f *decideFixture, uid, roleID uint, nodeIDs ...uint) {
	t.Helper()
	require.NoError(t, f.db.Create(&model.UserRole{UserID: uid, RoleID: roleID, Source: model.RoleSourceBoth, ScopeKind: model.ScopeKindNodes}).Error)
	for _, n := range nodeIDs {
		require.NoError(t, f.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: uid, RoleID: roleID, NodeID: n}).Error)
	}
}

// 移除並存來源角色的管理者那份時，正式寫入把該角色改為僅映射、全域、節點列清空；
// 試算必須得到相同的結果，台數與危險組合都不得沿用舊的節點範圍。
func TestPreviewRemovingManualFromBothSourceMatchesWrite(t *testing.T) {
	t.Run("管理台數與角色列：移除後角色為全域，不再計入節點範圍台數", func(t *testing.T) {
		e := newCountsEnv(t)
		f := e.f
		r := f.role(t, PermAssetView, PermAssetUpdate)
		u := f.user(t)
		bindBoth(t, f, u, r, f.n[3])
		require.Equal(t, 1, e.formal(t, u), "移除前：節點範圍內 1 台")

		c := e.direct(t, u, nil, nil)
		assert.Equal(t, 1, c.ManagedAssets.Before)
		assert.Equal(t, 0, c.ManagedAssets.After, "移除後角色僅以全域持有，不屬資產檢視的節點來源")
		for _, row := range c.RoleAssets {
			assert.NotEqual(t, r, row.RoleID, "僅全域持有的角色不列")
		}

		// 與正式寫入後的投影一致：來源改為映射、範圍改回全域、節點列清空
		require.NoError(t, f.db.Exec("UPDATE user_roles SET source = ?, scope_kind = ? WHERE user_id = ? AND role_id = ?",
			model.RoleSourceMapped, model.ScopeKindGlobal, u, r).Error)
		require.NoError(t, f.db.Exec("DELETE FROM role_binding_nodes WHERE subject_kind = ? AND subject_id = ? AND role_id = ?",
			model.BindingSubjectUser, u, r).Error)
		assert.Equal(t, e.formal(t, u), c.ManagedAssets.After)
	})

	t.Run("危險組合：原本節點不相交，移除後兩個角色都成為全域而列出", func(t *testing.T) {
		env := newScopedComboEnv(t)
		n := env.f.n
		u := env.f.user(t)
		bindBoth(t, env.f, u, env.rAuthz, n[3])
		bindBoth(t, env.f, u, env.rAsset, n[4])

		kept := env.preview(t, u, []uint{env.rAuthz, env.rAsset}, nil)
		assert.False(t, has(kept.Combos, ComboAuthzRulesWithAssetOrCredential), "兩者都保留管理者指派時範圍不變、節點不相交")

		got := env.preview(t, u, nil, nil)
		assert.True(t, has(got.Combos, ComboAuthzRulesWithAssetOrCredential), "兩者都移除管理者那份後成為全域")
	})
}
