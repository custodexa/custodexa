package audit

import (
	"context"

	"gorm.io/gorm"
)

// 測試用的 `user_roles` 讀取來源。
//
// 產品組裝時來源是 identity.SnapshotUserRolePairs（cmd/server/stage2.go）；本套件的
// 測試不能 import identity（identity 已 import audit），故在此以同一條 SQL 自備一份。
// 兩者若分歧，identity 那側的 role_state_source_test.go 會抓到（同一張表、同一種讀法）
func rawUserRolePairsForTest(ctx context.Context, tx *gorm.DB) ([]RolePair, error) {
	tx = tx.WithContext(ctx)
	// 手建的兩欄 user_roles（沒有範圍欄位的舊結構）只含全域指派
	if !tx.Migrator().HasColumn("user_roles", "scope_kind") {
		return rawUserRolePairsGlobalOnly(tx)
	}
	hasNodes := tx.Migrator().HasTable("role_binding_nodes")
	rows, err := tx.Raw("SELECT user_id, role_id, scope_kind FROM user_roles").Rows()
	if err != nil {
		return nil, err
	}
	var pairs []RolePair
	kinds := []string{}
	for rows.Next() {
		var p RolePair
		var kind string
		if err := rows.Scan(&p.UserID, &p.RoleID, &kind); err != nil {
			rows.Close()
			return nil, err
		}
		pairs = append(pairs, p)
		kinds = append(kinds, kind)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for i := range pairs {
		if kinds[i] != "nodes" {
			continue
		}
		pairs[i].Range = NodeRangeEmpty
		if !hasNodes {
			continue
		}
		var ids []uint64
		if err := tx.Raw("SELECT node_id FROM role_binding_nodes WHERE subject_kind = 'user' AND subject_id = ? AND role_id = ?",
			pairs[i].UserID, pairs[i].RoleID).Scan(&ids).Error; err != nil {
			return nil, err
		}
		if len(ids) > 0 {
			pairs[i].Range = NodeRange(ids)
		}
	}
	return pairs, nil
}

func rawUserRolePairsGlobalOnly(tx *gorm.DB) ([]RolePair, error) {
	rows, err := tx.Raw("SELECT user_id, role_id FROM user_roles").Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pairs []RolePair
	for rows.Next() {
		var p RolePair
		if err := rows.Scan(&p.UserID, &p.RoleID); err != nil {
			return nil, err
		}
		pairs = append(pairs, p)
	}
	return pairs, rows.Err()
}

func init() {
	SetUserRolesSource(rawUserRolePairsForTest)
}
