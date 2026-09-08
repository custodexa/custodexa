package identity

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 群組映射規則的讀取面。兩條登入途徑共用。
//
// # 為什麼來源欄由種類推導而不是由呼叫端給欄名
//
// 規則表以兩條可空外鍵表達「來源恰一」，欄名與途徑種類是一對一的。讓呼叫端
// 自己填欄名，等於把這個對應關係複製到每一個呼叫點，而其中一處填錯的症狀是
// 「規則設了卻永遠不命中」——沒有錯誤、沒有訊號，只有一個拿不到角色的人。

// roleMappingSourceColumn 途徑種類對應的來源欄名。
func roleMappingSourceColumn(kind string) (string, error) {
	switch kind {
	case model.RoleMappingChannelKindDirectory:
		return "ldap_directory_id", nil
	case model.RoleMappingChannelKindProvider:
		return "oidc_provider_id", nil
	default:
		return "", fmt.Errorf("未知的途徑種類: %q", kind)
	}
}

// hasActiveGroupRoleMappings 本來源是否有啟用中的映射規則。
//
// 用於「來源未設群組屬性名／宣告名」時分辨完全短路與留痕跳過兩種處置。
func hasActiveGroupRoleMappings(db *gorm.DB, kind string, sourceID uint) (bool, error) {
	column, err := roleMappingSourceColumn(kind)
	if err != nil {
		return false, err
	}
	var n int64
	if err := db.Model(&model.GroupRoleMapping{}).
		Where(column+" = ? AND enabled = ?", sourceID, true).
		Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢啟用中的群組映射規則失敗: %w", err)
	}
	return n > 0, nil
}

// activeGroupRoleMappings 本來源全部啟用中的映射規則（含角色，供審計記角色名）。
//
// 停用的規則於重算時視同不存在——不刪規則即可暫停一條映射，而暫停必須真的
// 讓那條映射賦予的角色在下一次登入被收回，否則「停用」只是介面上的字。
func activeGroupRoleMappings(tx *gorm.DB, kind string, sourceID uint) ([]model.GroupRoleMapping, error) {
	column, err := roleMappingSourceColumn(kind)
	if err != nil {
		return nil, err
	}
	var rules []model.GroupRoleMapping
	if err := tx.Preload("Role").
		Where(column+" = ? AND enabled = ?", sourceID, true).
		Order("id").
		Find(&rules).Error; err != nil {
		return nil, fmt.Errorf("讀取群組映射規則失敗: %w", err)
	}
	return rules, nil
}
