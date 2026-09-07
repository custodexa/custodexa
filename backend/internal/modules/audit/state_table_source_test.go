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
	rows, err := tx.WithContext(ctx).Raw("SELECT user_id, role_id FROM user_roles").Rows()
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
