package authz

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 外部群組映射事件用的授權項讀取：規則目標（單一角色，或使用者群組）換算成可與
// 授權摘要比對的項目。只讀，不寫任何資料。

// RoleGrantEntry 一個角色以「直接指派、全域範圍」取得時的授權項（映射賦予角色的形態）。
// 角色不存在（含已軟刪除）回 found=false。
func RoleGrantEntry(tx *gorm.DB, roleID uint) (entry GrantEntry, found bool, err error) {
	var rows []assignmentRow
	if err := tx.Raw(`SELECT roles.id AS role_id, roles.name AS role_name, roles.builtin_key AS builtin_key,
 roles.definition_version AS def_version, ? AS scope_kind, 0 AS group_id
 FROM roles WHERE roles.id = ? AND roles.deleted_at IS NULL`, model.ScopeKindGlobal, roleID).Scan(&rows).Error; err != nil {
		return GrantEntry{}, false, fmt.Errorf("讀取映射目標角色失敗: %w", err)
	}
	if len(rows) == 0 {
		return GrantEntry{}, false, nil
	}
	custom, err := customPermissionsOf(tx, ProductCatalogue(), rows)
	if err != nil {
		return GrantEntry{}, false, err
	}
	g := rows[0]
	a := Assignment{RoleID: g.RoleID, RoleName: g.RoleName, Via: ViaDirect, Scope: model.ScopeKindGlobal}
	if g.BuiltinKey != nil {
		a.BuiltinKey = *g.BuiltinKey
	} else if g.DefVersion >= 1 {
		a.Custom, a.Permissions = true, custom[g.RoleID]
	}
	return entryOf(a), true, nil
}

// GroupAuthorizationRuleIDs 使用者群組帶的有效資產授權規則編號（未軟刪除者），升冪。
func GroupAuthorizationRuleIDs(tx *gorm.DB, groupID uint) ([]uint, error) {
	var ids []uint
	if err := tx.Model(&model.AssetAuthorization{}).Where("user_group_id = ?", groupID).
		Order("id").Pluck("id", &ids).Error; err != nil {
		return nil, fmt.Errorf("查詢群組授權規則失敗: %w", err)
	}
	return ids, nil
}

// WithGranted 回傳加上指定項目後的授權摘要副本（不改輸入）：模擬「這些項目被授予」。
// 比較鍵與真實摘要相同，已持有同鍵項目時不產生新增。
func (s GrantSummary) WithGranted(entries []GrantEntry, ruleIDs []uint) GrantSummary {
	out := GrantSummary{Entries: append([]GrantEntry(nil), s.Entries...), RuleIDs: append([]uint(nil), s.RuleIDs...)}
	have := map[string]bool{}
	for _, e := range out.Entries {
		have[e.key()] = true
	}
	for _, e := range entries {
		if !have[e.key()] {
			out.Entries = append(out.Entries, e)
			have[e.key()] = true
		}
	}
	seen := map[uint]bool{}
	for _, id := range out.RuleIDs {
		seen[id] = true
	}
	for _, id := range ruleIDs {
		if !seen[id] {
			out.RuleIDs = append(out.RuleIDs, id)
			seen[id] = true
		}
	}
	return out
}

// UserIDsInGroupsWithBuiltin 經所屬使用者群組的角色指派持有指定內建範本的帳號編號（升冪、不重複）。
// 供身分來源設定變更事件統計「此來源目前有多少位超級管理者」：群組角色指派的表由本模組所有。
func UserIDsInGroupsWithBuiltin(tx *gorm.DB, builtinKey string) ([]uint, error) {
	var ids []uint
	if err := tx.Raw(`SELECT DISTINCT m.user_id FROM user_group_members m
 JOIN user_groups g ON g.id = m.user_group_id AND g.deleted_at IS NULL
 JOIN user_group_roles gr ON gr.user_group_id = g.id
 JOIN roles r ON r.id = gr.role_id AND r.deleted_at IS NULL
 WHERE r.builtin_key = ? ORDER BY m.user_id`, builtinKey).Scan(&ids).Error; err != nil {
		return nil, fmt.Errorf("查詢群組持有範本的帳號失敗: %w", err)
	}
	return ids, nil
}
