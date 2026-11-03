package authz

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 「只有審核者角色」的帳號。
//
// 內建角色只在全域指派時產生能力；只剩審核者（或另加以節點範圍持有的內建一般使用者）的人類帳號
// 舊主角色為空、能力為空，無法使用資產與連線。判定只看有效指派（直接、外部映射、經使用者群組），
// 由本檔單一函式求得：指派入口的交易內斷言與使用者列表的標示共用同一條讀取與同一個判定。

// ApproverOnly 指派清單是否處於「只有審核者角色」：主體非 agent、清單非空、至少一筆為內建審核者
// （任何範圍），且其餘每一筆都是內建審核者（任何範圍）或以節點範圍持有的內建一般使用者。
func ApproverOnly(assignments []Assignment, kind string) bool {
	if kind == model.KindAgent || len(assignments) == 0 {
		return false
	}
	hasApprover := false
	for _, a := range assignments {
		switch {
		case a.BuiltinKey == model.BuiltinApprover:
			hasApprover = true
		case a.BuiltinKey == model.BuiltinUser && a.Scope == model.ScopeKindNodes:
		default:
			return false
		}
	}
	return hasApprover
}

type approverOnlyRow struct {
	UserID     uint
	BuiltinKey *string
	ScopeKind  string
}

// LoadApproverOnly 讀出帳號種類後以固定兩支查詢（直接指派、經使用者群組）一次求出一批帳號的判定，
// 查詢數與帳號數無關。
// 來源表與正式解析相同：已刪除的角色與已刪除的使用者群組不產生指派。不存在的帳號判為否。
func LoadApproverOnly(tx *gorm.DB, userIDs []uint) (map[uint]bool, error) {
	out := make(map[uint]bool, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	var users []struct {
		ID   uint
		Kind string
	}
	if err := tx.Table("users").Select("id, kind").Where("id IN ?", userIDs).Scan(&users).Error; err != nil {
		return nil, fmt.Errorf("讀取帳號種類失敗: %w", err)
	}
	kinds := make(map[uint]string, len(users))
	for _, u := range users {
		kinds[u.ID] = u.Kind
	}
	m, err := LoadApproverOnlyKnownKinds(tx, kinds)
	if err != nil {
		return nil, err
	}
	for _, id := range userIDs {
		out[id] = m[id]
	}
	return out, nil
}

// LoadApproverOnlyKnownKinds 呼叫端已持有帳號種類（如列表當頁）時的批次判定：固定兩支查詢。
// kinds 以帳號識別碼為鍵；回傳涵蓋 kinds 的每個鍵。
func LoadApproverOnlyKnownKinds(tx *gorm.DB, kinds map[uint]string) (map[uint]bool, error) {
	out := make(map[uint]bool, len(kinds))
	if len(kinds) == 0 {
		return out, nil
	}
	userIDs := make([]uint, 0, len(kinds))
	for id := range kinds {
		userIDs = append(userIDs, id)
	}
	var direct, viaGroup []approverOnlyRow
	if err := tx.Raw(`SELECT user_roles.user_id AS user_id, roles.builtin_key AS builtin_key, user_roles.scope_kind AS scope_kind
 FROM user_roles JOIN roles ON roles.id = user_roles.role_id AND roles.deleted_at IS NULL
 WHERE user_roles.user_id IN ?`, userIDs).Scan(&direct).Error; err != nil {
		return nil, fmt.Errorf("讀取直接角色指派失敗: %w", err)
	}
	// 審核者角色只能直接指派（不經使用者群組），沒有直接審核者指派的人類帳號必然不是此狀態：
	// 只對有直接審核者指派的人類帳號讀經群組的指派。
	var candidates []uint
	seen := map[uint]bool{}
	for _, r := range direct {
		if r.BuiltinKey != nil && *r.BuiltinKey == model.BuiltinApprover && kinds[r.UserID] != model.KindAgent && !seen[r.UserID] {
			seen[r.UserID] = true
			candidates = append(candidates, r.UserID)
		}
	}
	if len(candidates) > 0 {
		if err := tx.Raw(`SELECT user_group_members.user_id AS user_id, roles.builtin_key AS builtin_key, user_group_roles.scope_kind AS scope_kind
 FROM user_group_members
 JOIN user_groups ON user_groups.id = user_group_members.user_group_id AND user_groups.deleted_at IS NULL
 JOIN user_group_roles ON user_group_roles.user_group_id = user_group_members.user_group_id
 JOIN roles ON roles.id = user_group_roles.role_id AND roles.deleted_at IS NULL
 WHERE user_group_members.user_id IN ?`, candidates).Scan(&viaGroup).Error; err != nil {
			return nil, fmt.Errorf("讀取群組角色指派失敗: %w", err)
		}
	}
	byUser := map[uint][]Assignment{}
	for _, rows := range [][]approverOnlyRow{direct, viaGroup} {
		for _, r := range rows {
			a := Assignment{Scope: r.ScopeKind}
			if r.BuiltinKey != nil {
				a.BuiltinKey = *r.BuiltinKey
			}
			byUser[r.UserID] = append(byUser[r.UserID], a)
		}
	}
	for id, kind := range kinds {
		out[id] = ApproverOnly(byUser[id], kind)
	}
	return out, nil
}

// IsApproverOnlyTx 單一帳號的判定（LoadApproverOnly 以單一 ID 呼叫）。
func IsApproverOnlyTx(tx *gorm.DB, userID uint) (bool, error) {
	m, err := LoadApproverOnly(tx, []uint{userID})
	if err != nil {
		return false, err
	}
	return m[userID], nil
}
