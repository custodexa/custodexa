package identity

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
)

// 寫入撞唯一索引時轉成對應的衝突哨兵。
//
// 先查再寫的預查擋得住單一請求的重複，擋不住兩個請求同時通過預查：後寫入者會撞資料庫的唯一索引。
// 這裡依撞到的是哪一個索引轉成與預查相同的衝突哨兵，呼叫端因此得到與單一請求相同的 409；
// 撞到其他唯一索引時原樣回傳，不改變那些錯誤的處理。

// uniqueIndex 一個唯一索引在兩種方言下的辨識字樣：PostgreSQL 的錯誤訊息帶索引名，SQLite 帶「表.欄」。
type uniqueIndex struct {
	pgName       string
	sqliteColumn string
}

var (
	roleNameIndex     = uniqueIndex{pgName: "idx_roles_name", sqliteColumn: "roles.name"}
	userUsernameIndex = uniqueIndex{pgName: "idx_users_username", sqliteColumn: "users.username"}
	userEmailIndex    = uniqueIndex{pgName: "idx_users_email", sqliteColumn: "users.email"}
)

// violates err 是否為撞到這個唯一索引的錯誤。
func (ix uniqueIndex) violates(err error) bool {
	if err == nil || !(errors.Is(err, gorm.ErrDuplicatedKey) || dberr.IsUniqueViolation(err)) {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, `"`+ix.pgName+`"`) || strings.Contains(msg, "UNIQUE constraint failed: "+ix.sqliteColumn)
}

// roleWriteError 角色列寫入（建立或改名）的錯誤：撞名稱唯一索引為名稱衝突，其他照舊包裝。
func roleWriteError(op string, err error) error {
	if roleNameIndex.violates(err) {
		return fmt.Errorf("%w: 名稱已被使用", ErrRoleDefinitionConflict)
	}
	return fmt.Errorf("%s角色失敗: %w", op, err)
}

// userCreateError 建立使用者列的錯誤：撞使用者名稱或電子郵件的唯一索引為各自的衝突，其他照舊包裝。
func userCreateError(err error) error {
	switch {
	case userUsernameIndex.violates(err):
		return ErrUsernameExists
	case userEmailIndex.violates(err):
		return ErrEmailConflict
	}
	return fmt.Errorf("建立使用者失敗: %w", err)
}

// ensureCreateIdentityFree 建立使用者前的預查：使用者名稱與其他未刪除帳號逐字比對，電子郵件以寫入時的
// 正規化（去除前後空白、轉小寫）後比對，與兩個唯一索引的判定相同。
func (s *UserService) ensureCreateIdentityFree(username, email string) error {
	var existing model.User
	err := s.db.Where("username = ?", username).First(&existing).Error
	if err == nil {
		return ErrUsernameExists
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("檢查使用者名稱失敗: %w", err)
	}
	normalized := normalizeEmail(email)
	if normalized == nil {
		return nil
	}
	conflict, err := s.emailInUseByOther(*normalized, 0)
	if err != nil {
		return fmt.Errorf("檢查電子郵件失敗: %w", err)
	}
	if conflict {
		return ErrEmailConflict
	}
	return nil
}
