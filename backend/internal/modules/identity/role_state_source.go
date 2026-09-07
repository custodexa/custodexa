package identity

import (
	"context"
	"fmt"

	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// SnapshotUserRolePairs 讀 `user_roles` 全表，供 audit 模組的狀態表快照使用
// （role-assignment-integrity；經 `audit.SetUserRolesSource` 注入）。
//
// 表歸本模組所有，所以讀取放在這裡；排序、去重、編碼與雜湊是快照語義，
// 留在 audit（`EncodeRolePairs`）。**原生 SQL 而非 ORM 關聯**：user_roles 是
// 裸 join 表（無 model、無時間欄），經 many2many 讀出會被 GORM 的關聯載入改變形狀。
// 不含帳號名或任何個資——快照會進檢查點、會離機
func SnapshotUserRolePairs(ctx context.Context, tx *gorm.DB) ([]audit.RolePair, error) {
	rows, err := tx.WithContext(ctx).Raw("SELECT user_id, role_id FROM user_roles").Rows()
	if err != nil {
		return nil, fmt.Errorf("讀取 user_roles 失敗: %w", err)
	}
	defer rows.Close()
	var pairs []audit.RolePair
	for rows.Next() {
		var p audit.RolePair
		if err := rows.Scan(&p.UserID, &p.RoleID); err != nil {
			return nil, fmt.Errorf("掃描 user_roles 列失敗: %w", err)
		}
		pairs = append(pairs, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("迭代 user_roles 失敗: %w", err)
	}
	return pairs, nil
}
