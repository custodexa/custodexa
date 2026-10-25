package identity

import "github.com/custodexa/backend/internal/modules/authz"

// RoleBindings 使用者目前的直接角色指派（含來源與節點範圍）。使用者不存在回 ErrUserNotFound。
// 只讀，不含經群組取得的角色。
func (s *UserService) RoleBindings(userID uint) ([]authz.UserRoleBinding, error) {
	if _, err := s.loadUser(s.db, userID); err != nil {
		return nil, err
	}
	return authz.UserRoleBindings(s.db, userID)
}
