package identity

import (
	"context"
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
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
	tx = tx.WithContext(ctx)
	rows, err := tx.Raw("SELECT user_id, role_id, scope_kind FROM user_roles").Rows()
	if err != nil {
		return nil, fmt.Errorf("讀取 user_roles 失敗: %w", err)
	}
	var pairs []audit.RolePair
	var kinds []string
	for rows.Next() {
		var p audit.RolePair
		var kind string
		if err := rows.Scan(&p.UserID, &p.RoleID, &kind); err != nil {
			rows.Close()
			return nil, fmt.Errorf("掃描 user_roles 列失敗: %w", err)
		}
		pairs = append(pairs, p)
		kinds = append(kinds, kind)
	}
	err = rows.Err()
	rows.Close() // 先關閉游標再發下一個查詢：單連線的連線池上兩者不能交疊
	if err != nil {
		return nil, fmt.Errorf("迭代 user_roles 失敗: %w", err)
	}
	// 節點範圍的節點集合由 authz 擁有的表提供。只有範圍種類為節點的指派才計入節點列
	//（種類才是生效的判準，種類為全域時殘留的節點列不具效力）
	nodes, err := authz.UserBindingNodeSets(tx)
	if err != nil {
		return nil, err
	}
	for i := range pairs {
		switch kinds[i] {
		case model.ScopeKindGlobal, "":
		case model.ScopeKindNodes:
			pairs[i].Range = audit.NodeRangeEmpty
			if ids := nodes[[2]uint{uint(pairs[i].UserID), uint(pairs[i].RoleID)}]; len(ids) > 0 {
				pairs[i].Range = audit.NodeRange(toUint64s(ids))
			}
		default:
			// 未知的範圍種類：不當成全域（那會把異常資料讀成最寬的範圍而相符），
			// 當成「節點範圍而無節點」使其與任何合法預期都不同
			pairs[i].Range = audit.NodeRangeEmpty
		}
	}
	return pairs, nil
}

func toUint64s(ids []uint) []uint64 {
	out := make([]uint64, len(ids))
	for i, id := range ids {
		out[i] = uint64(id)
	}
	return out
}
