package audit_test

import (
	"context"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 權限狀態測試夾具：與正式組裝相同的兩個所有者來源（authz、identity），
// sqlite in-memory 單連線。審計模組的外部測試包才能同時 import 兩個所有者模組。
func newPermDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(
		&model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{}, &model.UserGroupMember{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}, &model.AuthzState{}, &model.AssetGroup{},
		&model.GroupRoleMapping{}, &model.GroupUserGroupMapping{}, &model.ExternalGroup{},
		&model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.PermissionStateEvent{}, &model.RolePermission{}, &model.AuditCheckpoint{}))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
	audit.SetPermissionSources(authz.PermissionStateAuthzPart, identity.PermissionStateIdentityPart)
	t.Cleanup(func() { audit.SetPermissionSources(nil, nil) })
	// 事件列以完整性密鑰蓋章（正式組裝由段 2 的完整性服務提供）
	t.Cleanup(audit.UsePermissionEventTestKey([]byte("permission-event-test-key")))
	t.Cleanup(audit.DrainPendingPermissionStampsForTest)
	return db
}

// seedPerm 建一份涵蓋全部集合的權限狀態；reverse 反序寫入以證明讀序無關。
func seedPerm(t *testing.T, db *gorm.DB, reverse bool) {
	t.Helper()
	steps := []func(){
		func() {
			for _, bk := range []string{"super_admin", "auditor"} {
				k := bk
				require.NoError(t, db.Create(&model.Role{Name: "r-" + bk, BuiltinKey: &k}).Error)
			}
		},
		func() {
			for _, name := range []string{"u-admin", "u-plain"} {
				email := name + "@example.invalid"
				require.NoError(t, db.Create(&model.User{Username: name, Password: "s3cret-hash", Email: &email, Active: true, Kind: "human"}).Error)
			}
		},
		func() {
			require.NoError(t, db.Create(&model.UserGroup{Name: "g-ops"}).Error)
			require.NoError(t, db.Create(&model.AssetGroup{Name: "node-a"}).Error)
		},
		func() {
			require.NoError(t, db.Create(&model.UserRole{UserID: 1, RoleID: 1, Source: "manual", ScopeKind: "global"}).Error)
			require.NoError(t, db.Create(&model.UserRole{UserID: 2, RoleID: 2, Source: "mapped", ScopeKind: "nodes"}).Error)
			require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: "user", SubjectID: 2, RoleID: 2, NodeID: 1}).Error)
			require.NoError(t, db.Create(&model.UserGroupRole{UserGroupID: 1, RoleID: 2, ScopeKind: "global"}).Error)
		},
		func() {
			require.NoError(t, db.Create(&model.UserGroupMember{UserGroupID: 1, UserID: 2, Manual: true}).Error)
			require.NoError(t, db.Create(&model.UserGroupMappingRuleSupport{UserID: 2, UserGroupID: 1, Channel: "ldap", RuleID: 1}).Error)
		},
		func() {
			ldap := uint(1)
			eg := &model.ExternalGroup{LDAPDirectoryID: &ldap, MatchValue: "CN=Secret-Admins,DC=corp,DC=example"}
			require.NoError(t, db.Create(eg).Error)
			require.NoError(t, db.Create(&model.GroupRoleMapping{LDAPDirectoryID: &ldap, MatchValue: eg.MatchValue, ExternalGroupID: eg.ID, RoleID: 2, Enabled: true, CreatedBy: 1}).Error)
			require.NoError(t, db.Create(&model.GroupUserGroupMapping{LDAPDirectoryID: &ldap, ExternalGroupID: eg.ID, UserGroupID: 1, Enabled: true, CreatedBy: 1}).Error)
		},
	}
	if reverse {
		// 反序只對互不依賴的建立有意義：先建主表再建指派，維持 ID 對應；此處只反轉各步驟內部順序
		for _, i := range []int{0, 1, 2} {
			steps[i]()
		}
		steps[3]()
		steps[4]()
		steps[5]()
		return
	}
	for _, s := range steps {
		s()
	}
}

func permDigest(t *testing.T, db *gorm.DB) (string, []byte) {
	t.Helper()
	st, err := audit.ReadPermissionState(context.Background(), db)
	require.NoError(t, err)
	b, err := st.Encode()
	require.NoError(t, err)
	d, err := st.Digest()
	require.NoError(t, err)
	return d, b
}

func TestPermissionStateSnapshot(t *testing.T) {
	t.Run("同狀態不同讀序同 bytes 與摘要", func(t *testing.T) {
		a := newPermDB(t)
		seedPerm(t, a, false)
		d1, b1 := permDigest(t, a)
		// 以相反順序重新讀出（來源回傳順序不同）：直接打亂集合後編碼
		st, err := audit.ReadPermissionState(context.Background(), a)
		require.NoError(t, err)
		for name, rows := range st.Sets {
			for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
				rows[i], rows[j] = rows[j], rows[i]
			}
			st.Sets[name] = append(rows, rows...) // 重複列也應被去重
		}
		b2, err := st.Encode()
		require.NoError(t, err)
		require.Equal(t, string(b1), string(b2))
		d2, err := st.Digest()
		require.NoError(t, err)
		require.Equal(t, d1, d2)
		dec, err := audit.DecodePermissionState(b1)
		require.NoError(t, err)
		dd, _ := dec.Digest()
		require.Equal(t, d1, dd, "解碼後重新編碼必須逐位元組相同")
	})

	mutations := map[string]string{
		"角色目錄（內建身分改鍵）":       `UPDATE roles SET builtin_key = 'user' WHERE id = 2`,
		"直接指派來源 mapped→both": `UPDATE user_roles SET source = 'both' WHERE user_id = 2`,
		"直接指派範圍種類":           `UPDATE user_roles SET scope_kind = 'global' WHERE user_id = 2`,
		"群組指派範圍":             `UPDATE user_group_roles SET scope_kind = 'nodes'`,
		"節點集合新增":             `INSERT INTO role_binding_nodes (subject_kind, subject_id, role_id, node_id) VALUES ('user', 2, 2, 9)`,
		"節點被軟刪除":             `UPDATE asset_groups SET deleted_at = CURRENT_TIMESTAMP WHERE id = 1`,
		"外部群組→角色 目標角色":       `UPDATE group_role_mappings SET role_id = 1`,
		"外部群組→角色 啟用狀態":       `UPDATE group_role_mappings SET enabled = 0`,
		"外部群組→使用者群組 啟用":      `UPDATE group_user_group_mappings SET enabled = 0`,
		"外部群組→使用者群組 比對指紋":    `UPDATE external_groups SET match_value = 'CN=Other'`,
		"成員來源 both→manual":   `DELETE FROM user_group_mapping_rule_supports`,
		"主體種類／擁有者":           `UPDATE users SET kind = 'agent', owner_user_id = 1 WHERE id = 2`,
		"權限版本":               `UPDATE authz_state SET version = version + 1`,
	}
	for name, stmt := range mutations {
		t.Run("改一欄會改摘要/"+name, func(t *testing.T) {
			db := newPermDB(t)
			seedPerm(t, db, false)
			before, _ := permDigest(t, db)
			require.NoError(t, db.Exec(stmt).Error)
			after, _ := permDigest(t, db)
			require.NotEqual(t, before, after, stmt)
		})
	}

	t.Run("不含秘密與個資", func(t *testing.T) {
		db := newPermDB(t)
		seedPerm(t, db, false)
		_, body := permDigest(t, db)
		for _, leak := range []string{"s3cret-hash", "u-admin", "u-plain", "example.invalid", "Secret-Admins", "CN=", "g-ops", "node-a"} {
			require.NotContains(t, string(body), leak)
		}
	})

	t.Run("未知版本與非 canonical 拒絕解碼", func(t *testing.T) {
		db := newPermDB(t)
		seedPerm(t, db, false)
		_, body := permDigest(t, db)
		s := string(body)
		for name, bad := range map[string]string{
			"未知格式版本":  strings.Replace(s, `"v":2`, `"v":99`, 1),
			"未知格式識別":  strings.Replace(s, `"format":"permission_state"`, `"format":"other"`, 1),
			"多餘空白":    strings.Replace(s, `"v":2,`, `"v":2, `, 1),
			"缺集合":     strings.Replace(s, `"principals":`, `"extra_set":`, 1),
			"非 JSON":  "not json",
			"空集合不可默認": `{}`,
		} {
			_, err := audit.DecodePermissionState([]byte(bad))
			require.ErrorIs(t, err, audit.ErrPermissionSnapshotFormat, name)
		}
	})

	t.Run("來源未注入 fail-close", func(t *testing.T) {
		db := newPermDB(t)
		audit.SetPermissionSources(nil, nil)
		_, err := audit.ReadPermissionState(context.Background(), db)
		require.ErrorIs(t, err, audit.ErrPermissionSourceUnset)
	})

	t.Run("舊 pair bytes 不變", func(t *testing.T) {
		body, n := audit.EncodeRolePairs([]audit.RolePair{{UserID: 2, RoleID: 1}, {UserID: 1, RoleID: 3}})
		require.Equal(t, "[[1,3],[2,1]]", string(body))
		require.EqualValues(t, 2, n)
	})
}

// newPermDBWire 重新接上權限狀態來源（測試在中途模擬「附證啟用」用）。
func newPermDBWire(t *testing.T) {
	t.Helper()
	audit.SetPermissionSources(authz.PermissionStateAuthzPart, identity.PermissionStateIdentityPart)
}
