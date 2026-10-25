package identity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

type assignmentTuple struct {
	UserID    uint
	RoleID    uint
	Source    string
	ScopeKind string
}

func heldAssignments(t *testing.T, db *gorm.DB, uid uint) []assignmentTuple {
	t.Helper()
	var rows []model.UserRole
	require.NoError(t, db.Where("user_id = ?", uid).Order("role_id").Find(&rows).Error)
	out := make([]assignmentTuple, 0, len(rows))
	for i := range rows {
		out = append(out, assignmentTuple{rows[i].UserID, rows[i].RoleID, rows[i].Source, rows[i].ScopeKind})
	}
	return out
}

func restoreFindingCodes(t *testing.T, db *gorm.DB) map[string]bool {
	t.Helper()
	rep, err := authz.CheckRestoreIntegrity(db, CountLocalAdmins, RestoreMappingRefChecks())
	require.NoError(t, err)
	out := map[string]bool{}
	for _, f := range rep.Findings {
		out[f.Code] = true
	}
	return out
}

func eventKinds(t *testing.T, db *gorm.DB) map[string]int64 {
	t.Helper()
	var rows []struct {
		Kind string
		N    int64
	}
	require.NoError(t, db.Raw(`SELECT kind, COUNT(*) AS n FROM permission_state_events GROUP BY kind`).Scan(&rows).Error)
	out := map[string]int64{}
	for _, r := range rows {
		out[r.Kind] = r.N
	}
	return out
}

func userRoleAuditRows(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&model.AuditLog{}).Where("resource = ?", string(model.ResourceUserRole)).Count(&n).Error)
	return n
}

// TestDeletedAccountAssignmentsDoNotBlock 擋：已刪除帳號保留的指派列仍被算成角色引用而擋住刪除，
// 以及它們讓之後的還原完整性檢查多出 empty_user_nodes。停用中的帳號仍算引用，也仍會被檢查抓到。
func TestDeletedAccountAssignmentsDoNotBlock(t *testing.T) {
	ctx := context.Background()

	t.Run("帳號刪除後角色可刪除，指派列保留且事件鏈完整", func(t *testing.T) {
		e := newNodeRaceEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.LDAPDirectory{}, &model.OIDCProvider{}))
		// 夾具資料（角色、節點、帳號）先備齊再啟用事件鏈；啟用後的指派與刪除都走正式服務。
		assetmgr := e.rid(t, "assetmgr")
		globalRole := e.create(t, "deleted-holder-global", "asset:view").ID
		node := e.node(t, "deleted-holder-node")
		a := e.mkUser(t, "deleted-holder")
		audit.SetPermissionSources(authz.PermissionStateAuthzPart, PermissionStateIdentityPart)
		t.Cleanup(func() { audit.SetPermissionSources(nil, nil) })
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			st, err := audit.ReadPermissionState(ctx, tx)
			if err != nil {
				return err
			}
			_, err = audit.EnsurePermissionActivation(ctx, tx, st, 1)
			return err
		}))
		defs := e.roleDefEnv.svc
		defs.events = NewPermissionChainEventWriter()

		_, err := e.assign(a, []string{"assetmgr", "deleted-holder-global"}, map[string]RoleNodesValue{"assetmgr": nodesOf(node)})
		require.NoError(t, err)
		before := heldAssignments(t, e.db, a)
		require.Len(t, before, 2)
		base := restoreFindingCodes(t, e.db)

		_, err = e.users.DeleteWithSummaryBy(e.op(e.admin), a)
		require.NoError(t, err)

		set, err := NewRoleProjector(e.db, nil).ProjectRoles(e.admin)
		require.NoError(t, err)
		assert.Equal(t, RoleReferenceCounts{}, set.ByRole[assetmgr].References, "已刪除帳號的直接指派不計入引用")
		assert.Equal(t, RoleReferenceCounts{}, set.ByRole[globalRole].References)
		def, err := defs.GetDefinition(ctx, assetmgr)
		require.NoError(t, err)
		assert.EqualValues(t, 0, def.NodeScopedBindingCount)
		assert.Equal(t, base, restoreFindingCodes(t, e.db), "刪除帳號後還原檢查的發現碼與刪除前相同")
		assert.NotContains(t, restoreFindingCodes(t, e.db), "empty_user_nodes")

		k0 := eventKinds(t, e.db)
		auditBefore := userRoleAuditRows(t, e.db)
		require.NoError(t, defs.Delete(ctx, e.admin, assetmgr, def.DefinitionVersion))
		globalDef, err := defs.GetDefinition(ctx, globalRole)
		require.NoError(t, err)
		require.NoError(t, defs.Delete(ctx, e.admin, globalRole, globalDef.DefinitionVersion))

		assert.Equal(t, before, heldAssignments(t, e.db, a), "刪除角色不動已刪除帳號的指派列")
		assert.Equal(t, auditBefore, userRoleAuditRows(t, e.db), "刪除角色不寫 user_role 審計列")
		assert.Equal(t, base, restoreFindingCodes(t, e.db), "角色都刪除後還原檢查的發現碼不變")
		k1 := eventKinds(t, e.db)
		assert.EqualValues(t, 2, k1[model.PermEventChange]-k0[model.PermEventChange], "兩次角色刪除各一筆變動事件")
		assert.Zero(t, k1[model.PermEventUntraced], "啟用後沒有無來源變動")
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			st, err := audit.ReadPermissionState(ctx, tx)
			if err != nil {
				return err
			}
			for _, h := range before {
				assert.Contains(t, st.Sets[audit.PermSetUserRoles], audit.PermissionRow(h.UserID, h.RoleID, h.ScopeKind, h.Source))
			}
			assert.Contains(t, st.Sets[audit.PermSetRoles], audit.PermissionRow(assetmgr, "", 1))
			assert.Contains(t, st.Sets[audit.PermSetRoles], audit.PermissionRow(globalRole, "", 1))
			return nil
		}))
	})

	t.Run("對照：停用但未刪除的帳號仍算引用，範圍節點遺失仍被還原檢查抓到", func(t *testing.T) {
		e := newNodeRaceEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.LDAPDirectory{}, &model.OIDCProvider{}))
		assetmgr := e.rid(t, "assetmgr")
		node := e.node(t, "disabled-holder-node")
		b := e.mkUser(t, "disabled-holder")
		_, err := e.assign(b, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(node)})
		require.NoError(t, err)
		require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", b).Update("active", false).Error)

		set, err := NewRoleProjector(e.db, nil).ProjectRoles(e.admin)
		require.NoError(t, err)
		assert.EqualValues(t, 1, set.ByRole[assetmgr].References.Direct)
		def, err := e.roleDefEnv.svc.GetDefinition(ctx, assetmgr)
		require.NoError(t, err)
		assert.EqualValues(t, 1, def.NodeScopedBindingCount)
		assert.ErrorIs(t, e.roleDefEnv.svc.Delete(ctx, e.admin, assetmgr, def.DefinitionVersion), ErrRoleDefinitionInUse)

		require.NotContains(t, restoreFindingCodes(t, e.db), "empty_user_nodes")
		require.NoError(t, authz.ClearBindingNodes(e.db, model.BindingSubjectUser, b, assetmgr))
		assert.Contains(t, restoreFindingCodes(t, e.db), "empty_user_nodes")
	})
}
