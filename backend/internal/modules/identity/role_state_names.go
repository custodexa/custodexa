package identity

import "github.com/custodexa/backend/internal/model"

// 角色指派對帳差集的名稱換算面。
//
// # 為何住在 identity 而不在接入層
//
// `users` 與 `roles` 兩張表的主檔在 identity 域。原本這兩支查詢寫在
// `internal/api/checkpoint_role_state.go` 內、由 handler 自持 `*gorm.DB` 直查，
// 那正是 `TestAPILayerHasNoDirectModelQuery` 擋的形態：handler 一旦自己查表，
// 「帳號叫什麼名字」就會有第二份真相。查詢本體逐字搬入，行為不變
// （皆為 `Unscoped` 的批次取名，查無者不出現在回傳 map 內）。
//
// # 為何含軟刪
//
// 被刪的帳號留在差集裡正是要看的東西——用 `Unscoped` 才不會讓「刪帳號」
// 變成把差集變匿名的手段。

// RoleAssignmentUsernames 依識別批次取帳號名（含軟刪帳號）。
// 查無對應列者不出現在回傳 map 內，由呼叫端據此顯示「已不存在的帳號 #7」
func (s *UserService) RoleAssignmentUsernames(ids []uint64) (map[uint64]string, error) {
	out := make(map[uint64]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	var rows []model.User
	if err := s.db.Unscoped().Select("id", "username").
		Where("id IN ?", ids).Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		out[uint64(rows[i].ID)] = rows[i].Username
	}
	return out, nil
}

// RoleAssignmentRoleNames 依識別批次取角色名（同上，含軟刪）
func (s *UserService) RoleAssignmentRoleNames(ids []uint64) (map[uint64]string, error) {
	out := make(map[uint64]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	var rows []model.Role
	if err := s.db.Unscoped().Select("id", "name").
		Where("id IN ?", ids).Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		out[uint64(rows[i].ID)] = rows[i].Name
	}
	return out, nil
}
