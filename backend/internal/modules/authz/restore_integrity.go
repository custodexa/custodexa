package authz

import (
	"fmt"
	"sort"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 還原後的權限完整性關卡（參照、來源與範圍、最後本地超管）。
//
// 只檢查、不修復：懸空參照、無效來源／範圍、空節點集合、已刪除的範圍節點、內建身分歧義
// 一律列為 finding 阻止放行；不刪壞列、不把 nodes 改成 global、不把 mapped 改成 manual、
// 不補 user、不建帳號。最後本地超管的計數由呼叫端注入（identity 擁有該查詢與鎖，
// authz 不得 import identity），使用與日常不變式相同的那一個函式。
//
// 例外：已刪除帳號保留、沒有範圍節點的節點範圍指派不算 empty_user_nodes。該帳號無法登入，
// 指派不生效，其範圍節點在帳號刪除時已清除；列保留是為了讓權限變動的審計鏈完整。

// RestoreFinding 一筆阻止放行的發現。
type RestoreFinding struct {
	Code   string // 穩定識別字
	Detail string // 具型別 ID 的說明（不含個資）
}

// RestoreIntegrityReport 完整性關卡的結果。
type RestoreIntegrityReport struct {
	Findings         []RestoreFinding
	LocalSuperAdmins int64
}

// OK 無任何阻止放行的發現。
func (r *RestoreIntegrityReport) OK() bool { return len(r.Findings) == 0 }

// LocalAdminCounter 最後本地超管計數（identity.CountLocalAdmins 的注入點）。
type LocalAdminCounter func(tx *gorm.DB) (int64, error)

// RefCheck 一條參照檢查：query 以字面量 SQL 回傳違規列的第一欄 id（或複合識別），零列即通過。
// 查詢寫成字面量 Raw 呼叫（而非字串欄位）是為了讓資料邊界守衛能靜態解析到每一張被碰的表。
type RefCheck struct {
	Code  string
	Query func(tx *gorm.DB) *gorm.DB
}

func restoreRefChecks() []RefCheck {
	return []RefCheck{
		{"dangling_user_role_role", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT ur.user_id || ':' || ur.role_id FROM user_roles ur LEFT JOIN roles r ON r.id = ur.role_id WHERE r.id IS NULL`)
		}},
		{"dangling_user_role_user", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT ur.user_id || ':' || ur.role_id FROM user_roles ur LEFT JOIN users u ON u.id = ur.user_id WHERE u.id IS NULL`)
		}},
		{"invalid_user_role_source", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT user_id || ':' || role_id FROM user_roles WHERE source NOT IN ('manual','mapped','both')`)
		}},
		{"invalid_user_role_scope", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT user_id || ':' || role_id FROM user_roles WHERE scope_kind NOT IN ('global','nodes')`)
		}},
		{"dangling_group_role_role", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT g.user_group_id || ':' || g.role_id FROM user_group_roles g LEFT JOIN roles r ON r.id = g.role_id WHERE r.id IS NULL`)
		}},
		{"dangling_group_role_group", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT g.user_group_id || ':' || g.role_id FROM user_group_roles g LEFT JOIN user_groups ug ON ug.id = g.user_group_id WHERE ug.id IS NULL`)
		}},
		{"invalid_group_role_scope", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT user_group_id || ':' || role_id FROM user_group_roles WHERE scope_kind NOT IN ('global','nodes')`)
		}},
		{"dangling_member_group", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT m.user_group_id || ':' || m.user_id FROM user_group_members m LEFT JOIN user_groups ug ON ug.id = m.user_group_id WHERE ug.id IS NULL`)
		}},
		{"dangling_member_user", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT m.user_group_id || ':' || m.user_id FROM user_group_members m LEFT JOIN users u ON u.id = m.user_id WHERE u.id IS NULL`)
		}},
		{"dangling_binding_node", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT b.subject_kind || ':' || b.subject_id || ':' || b.role_id || ':' || b.node_id FROM role_binding_nodes b LEFT JOIN asset_groups n ON n.id = b.node_id WHERE n.id IS NULL`)
		}},
		{"deleted_binding_node", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT b.subject_kind || ':' || b.subject_id || ':' || b.role_id || ':' || b.node_id FROM role_binding_nodes b JOIN asset_groups n ON n.id = b.node_id WHERE n.deleted_at IS NOT NULL`)
		}},
		{"dangling_binding_subject_role", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT b.subject_kind || ':' || b.subject_id || ':' || b.role_id FROM role_binding_nodes b LEFT JOIN roles r ON r.id = b.role_id WHERE r.id IS NULL`)
		}},
		{"binding_without_assignment", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT b.subject_kind || ':' || b.subject_id || ':' || b.role_id FROM role_binding_nodes b
 WHERE (b.subject_kind = 'user' AND NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = b.subject_id AND ur.role_id = b.role_id AND ur.scope_kind = 'nodes'))
    OR (b.subject_kind = 'user_group' AND NOT EXISTS (SELECT 1 FROM user_group_roles g WHERE g.user_group_id = b.subject_id AND g.role_id = b.role_id AND g.scope_kind = 'nodes'))`)
		}},
		{"empty_user_nodes", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT ur.user_id || ':' || ur.role_id FROM user_roles ur JOIN users u ON u.id = ur.user_id AND u.deleted_at IS NULL
 WHERE ur.scope_kind = 'nodes'
 AND NOT EXISTS (SELECT 1 FROM role_binding_nodes b WHERE b.subject_kind = 'user' AND b.subject_id = ur.user_id AND b.role_id = ur.role_id)`)
		}},
		{"empty_group_nodes", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT g.user_group_id || ':' || g.role_id FROM user_group_roles g WHERE g.scope_kind = 'nodes'
 AND NOT EXISTS (SELECT 1 FROM role_binding_nodes b WHERE b.subject_kind = 'user_group' AND b.subject_id = g.user_group_id AND b.role_id = g.role_id)`)
		}},
		{"dangling_owner", func(tx *gorm.DB) *gorm.DB {
			return tx.Raw(`SELECT u.id FROM users u WHERE u.owner_user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users o WHERE o.id = u.owner_user_id)`)
		}},
	}
}

// CheckRestoreIntegrity 在 tx 內（extra 為他模組注入的檢查）執行參照、來源／範圍、內建身分歧義與最後本地超管檢查。
// 查詢本身失敗回 error（無法確認＝不放行）；發現問題回報告而非 error。
func CheckRestoreIntegrity(tx *gorm.DB, countLocalAdmins LocalAdminCounter, extra []RefCheck) (*RestoreIntegrityReport, error) {
	rep := &RestoreIntegrityReport{}
	// extra：他模組擁有的表的參照檢查（例如 identity 的外部群組映射），由組裝根注入，
	// 使 authz 不直接讀他模組的表。
	for _, c := range append(restoreRefChecks(), extra...) {
		var ids []string
		if err := c.Query(tx).Scan(&ids).Error; err != nil {
			return nil, fmt.Errorf("還原完整性檢查 %s 失敗: %w", c.Code, err)
		}
		sort.Strings(ids)
		for _, id := range ids {
			rep.Findings = append(rep.Findings, RestoreFinding{Code: c.Code, Detail: id})
		}
	}
	// 內建身分歧義：四個內建鍵各恰一列且未刪除；內建鍵不得落在非預期的鍵。
	for _, bk := range []string{model.BuiltinSuperAdmin, model.BuiltinAuditor, model.BuiltinUser, model.BuiltinApprover} {
		var live, all int64
		if err := tx.Raw(`SELECT COUNT(*) FROM roles WHERE builtin_key = ? AND deleted_at IS NULL`, bk).Scan(&live).Error; err != nil {
			return nil, fmt.Errorf("還原完整性檢查內建身分失敗: %w", err)
		}
		if err := tx.Raw(`SELECT COUNT(*) FROM roles WHERE builtin_key = ?`, bk).Scan(&all).Error; err != nil {
			return nil, fmt.Errorf("還原完整性檢查內建身分失敗: %w", err)
		}
		if live != 1 || all != 1 {
			rep.Findings = append(rep.Findings, RestoreFinding{Code: "builtin_identity_ambiguous", Detail: fmt.Sprintf("%s live=%d total=%d", bk, live, all)})
		}
	}
	if countLocalAdmins == nil {
		return nil, fmt.Errorf("還原完整性檢查缺少最後本地超管計數函式")
	}
	n, err := countLocalAdmins(tx)
	if err != nil {
		return nil, fmt.Errorf("最後本地超管計數失敗（無法確認＝不放行）: %w", err)
	}
	rep.LocalSuperAdmins = n
	if n < 1 {
		rep.Findings = append(rep.Findings, RestoreFinding{Code: "no_local_super_admin", Detail: "0"})
	}
	return rep, nil
}
