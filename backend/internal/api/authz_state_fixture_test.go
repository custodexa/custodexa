package api

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// seedAuthzState 補上權限版本表與初始列：經 authz.AdvanceVersion 的寫入路徑（停用帳號、
// 建帳號、刪帳號等）在測試庫缺此表時會回 ErrAuthzStateMissing。正式庫由遷移恆建此表，
// 故不讓 AdvanceVersion 吞「表不存在」，改在夾具補齊。
func seedAuthzState(tb testing.TB, db *gorm.DB) {
	tb.Helper()
	if err := db.AutoMigrate(&model.AuthzState{}, &model.Role{}, &model.UserGroup{}); err != nil {
		tb.Fatalf("migrate authz_state: %v", err)
	}
	if err := db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		tb.Fatalf("migrate authz_state: %v", err)
	}
	if err := db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error; err != nil {
		tb.Fatalf("seed authz_state: %v", err)
	}
}
