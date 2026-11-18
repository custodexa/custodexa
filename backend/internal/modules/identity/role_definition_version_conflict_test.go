package identity

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 自訂角色的版本衝突有兩個出口：鎖定角色時的版本比對（lockCustomRole），以及條件式更新沒有更新到列
// （bumpDefinition）。兩個出口都必須回版本衝突的專屬哨兵，不與名稱重複共用；名稱重複維持既有哨兵。
func TestRoleDefinitionVersionConflictExits(t *testing.T) {
	ctx := context.Background()

	t.Run("鎖定時版本比對不符：版本衝突哨兵", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "vc-lock", "asset:view")
		err := e.db.Transaction(func(tx *gorm.DB) error {
			_, err := lockCustomRole(tx, d.ID, d.DefinitionVersion+1)
			return err
		})
		assert.ErrorIs(t, err, ErrRoleDefinitionVersionConflict)
		assert.NotErrorIs(t, err, ErrRoleDefinitionConflict)
	})

	t.Run("條件式更新沒有更新到列：版本衝突哨兵，資料不變", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "vc-bump", "asset:view")
		// 先以正常修改把版本推到 2，再拿版本 1 的舊快照做條件式更新：WHERE 帶舊版本，影響 0 列
		_, err := e.svc.Update(asSession(ctx, e.admin), e.admin, d.ID, 1, RoleInput{Name: "vc-bump", Permissions: []string{"asset:view", "session:view"}})
		require.NoError(t, err)
		stale := &model.Role{ID: d.ID, DefinitionVersion: 1}
		err = e.db.Transaction(func(tx *gorm.DB) error {
			return bumpDefinition(tx, stale, map[string]any{"description": "不應寫入"})
		})
		assert.ErrorIs(t, err, ErrRoleDefinitionVersionConflict)
		assert.NotErrorIs(t, err, ErrRoleDefinitionConflict)
		assert.Equal(t, int64(1), stale.DefinitionVersion, "失敗時不推進記憶體中的版本")
		got, gerr := e.svc.GetDefinition(ctx, d.ID)
		require.NoError(t, gerr)
		assert.Equal(t, int64(2), got.DefinitionVersion)
		assert.NotEqual(t, "不應寫入", got.Description)
	})

	t.Run("名稱重複：名稱衝突哨兵，不是版本衝突", func(t *testing.T) {
		e := newRoleDefEnv(t)
		e.create(t, "vc-taken")
		d := e.create(t, "vc-mine")
		_, err := e.svc.Update(asSession(ctx, e.admin), e.admin, d.ID, d.DefinitionVersion, RoleInput{Name: "vc-taken", Permissions: []string{}})
		assert.ErrorIs(t, err, ErrRoleDefinitionConflict)
		assert.NotErrorIs(t, err, ErrRoleDefinitionVersionConflict)
		_, err = e.svc.Create(asSession(ctx, e.admin), e.admin, RoleInput{Name: "  vc-taken  "})
		assert.ErrorIs(t, err, ErrRoleDefinitionConflict, "去除前後空白後相同即視為重複")
	})
}
