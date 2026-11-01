package main

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 升級相容串接：升級前以角色定義寫入步驟建立、含「結束連線」鍵的自訂角色，
// 經恢復 one-shot 實際提交、以讀取集合修改後，事件鏈重放仍與現況一致；
// 含從未可指派的保留鍵的角色則使 one-shot 拒絕且不提交。

type capturedRoleEvents struct {
	events []identity.RoleDefinitionEvent
}

func (c *capturedRoleEvents) WriteRoleDefinitionEvent(_ *gorm.DB, ev identity.RoleDefinitionEvent) error {
	c.events = append(c.events, ev)
	return nil
}

// createLegacyRole 以服務 write 同一組步驟（同交易寫列、推進版本、記事件）建立自訂角色，
// 只略過可指派檢查，模擬升級前的合法建立。
func createLegacyRole(t *testing.T, db *gorm.DB, ev *capturedRoleEvents, name string, keys ...string) uint {
	t.Helper()
	var id uint
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		if err := authz.BeginPermissionChange(tx); err != nil {
			return err
		}
		r := model.Role{Name: name, DefinitionVersion: 1}
		if err := tx.Create(&r).Error; err != nil {
			return err
		}
		for _, k := range keys {
			if err := tx.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: k}).Error; err != nil {
				return err
			}
		}
		if err := authz.AdvanceVersion(tx); err != nil {
			return err
		}
		id = r.ID
		return ev.WriteRoleDefinitionEvent(tx, identity.RoleDefinitionEvent{Action: string(model.ActionRoleDefinitionCreate),
			RoleID: r.ID, DefinitionVersion: 1, Before: []string{}, After: keys})
	}))
	return id
}

func rolePermissionKeys(t *testing.T, db *gorm.DB, roleID uint) []string {
	t.Helper()
	var keys []string
	require.NoError(t, db.Model(&model.RolePermission{}).Where("role_id = ?", roleID).Order("permission_key").Pluck("permission_key", &keys).Error)
	return keys
}

func TestUpgradeCompatRetiredKeyRestore(t *testing.T) {
	ctx := context.Background()
	prep := func(t *testing.T) (*gorm.DB, *capturedRoleEvents, *identity.RoleDefinitionService) {
		db := oneShotDB(t)
		require.NoError(t, db.AutoMigrate(&model.AuditLog{}, &model.PermissionStateEvent{}, &model.SystemAlertDetail{},
			&model.SystemAlertOutbox{}, &model.SystemAlertSeverityOverride{}, &model.NotificationChannel{}, &model.CommandAlert{}))
		ev := &capturedRoleEvents{}
		svc := identity.NewRoleDefinitionService(db, audit.NewTxSink(), ev,
			identity.NewGrantGrader(audit.NewTxSink(), audit.NewSystemAlertSink(nil)))
		return db, ev, svc
	}
	restore := func(db *gorm.DB) (int, string) {
		code, meta := oneShot(db, "permission-meta")
		require.Equal(t, oneShotOK, code, meta)
		return oneShot(db, "permission-restore", "--op-id", "op-1", "--input-digest", "d1", "--expect-digest", kvLines(meta)["authz.digest"])
	}

	t.Run("含已收回鍵：核對通過、實際提交、修改後只剩檢視、事件鏈重放與現況一致", func(t *testing.T) {
		db, ev, svc := prep(t)
		id := createLegacyRole(t, db, ev, "legacy-ops", "session:view", "session:terminate")

		code, meta := oneShot(db, "permission-meta")
		require.Equal(t, oneShotOK, code)
		assert.Equal(t, "ok", kvLines(meta)["authz.refs"])

		code, out := restore(db)
		require.Equal(t, oneShotOK, code, out)
		assert.NotContains(t, out, "finding=")
		assert.Equal(t, "true", kvLines(out)["restore.fresh"])
		assert.Equal(t, []string{"session:terminate", "session:view"}, rolePermissionKeys(t, db, id), "提交後該列原樣保留")

		var admin model.User
		require.NoError(t, db.Where("username = ?", "root").First(&admin).Error)
		def, err := svc.GetDefinition(ctx, id)
		require.NoError(t, err)
		require.Equal(t, []string{"session:view"}, def.Permissions)
		_, err = svc.Update(ctx, admin.ID, id, def.DefinitionVersion, identity.RoleInput{Name: "legacy-ops", Description: "說明", Permissions: def.Permissions})
		require.NoError(t, err)
		assert.Equal(t, []string{"session:view"}, rolePermissionKeys(t, db, id))
		last := ev.events[len(ev.events)-1]
		assert.Contains(t, last.Before, "session:terminate", "最後一筆事件的修改前集合含舊鍵")

		var evs []authz.RoleDefinitionStateEvent
		for _, e := range ev.events {
			evs = append(evs, authz.RoleDefinitionStateEvent{Action: e.Action, RoleID: e.RoleID, DefinitionVersion: e.DefinitionVersion, Before: e.Before, After: e.After})
		}
		replayed, err := authz.ReplayRoleDefinitionEvents(evs)
		require.NoError(t, err)
		live, err := svc.State(ctx)
		require.NoError(t, err)
		assert.Empty(t, authz.DiffRoleDefinitionState(replayed, live))
	})

	t.Run("含從未可指派的保留鍵：one-shot 拒絕、不提交、該列仍在", func(t *testing.T) {
		db, ev, _ := prep(t)
		id := createLegacyRole(t, db, ev, "legacy-hk", "hostkey:reset")
		before := authStateRow(t, db)
		code, out := restore(db)
		require.Equal(t, oneShotRefused, code, out)
		assert.Contains(t, out, "finding=non_assignable_role_permission_key:")
		after := authStateRow(t, db)
		assert.Empty(t, after.RestoreGeneration, "恢復世代未推進")
		assert.Equal(t, before.Version, after.Version)
		assert.Equal(t, []string{"hostkey:reset"}, rolePermissionKeys(t, db, id))
	})
}
