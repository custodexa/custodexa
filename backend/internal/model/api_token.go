package model

import "time"

// APIToken 人類帳號為自己建立的管理 API 憑證。只存明文的 SHA-256 摘要，明文不入庫。
//
// ExpiresAt 為 NULL 表示永不到期。名稱占用（未撤銷、未到期、還原世代與目前相同）的唯一性
// 由建立流程在帳號層級鎖內判定，不以資料庫索引表達：是否到期隨時間改變，索引無法描述。
type APIToken struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	UserID    uint      `gorm:"not null;index:idx_api_tokens_user_revoked,priority:1" json:"user_id"`
	Name      string    `gorm:"size:100;not null" json:"name"`
	TokenHash string    `gorm:"size:64;not null;uniqueIndex:idx_api_tokens_token_hash" json:"-"`
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt 到期時刻；NULL＝永不到期
	ExpiresAt *time.Time `json:"expires_at"`
	// LastUsedAt、LastUsedIP 最近一次成功認證的時間與來源；屬遙測，不作為閘門
	LastUsedAt *time.Time `json:"last_used_at"`
	LastUsedIP string     `gorm:"size:50;not null;default:''" json:"last_used_ip"`
	RevokedAt  *time.Time `gorm:"index:idx_api_tokens_user_revoked,priority:2" json:"revoked_at"`
	RevokedBy  *uint      `json:"revoked_by"`
	RevokeNote string     `gorm:"type:text;not null;default:''" json:"revoke_note"`
	// RestoreGeneration 建立當下的還原世代；與目前世代不同即視為已因還原失效
	RestoreGeneration string `gorm:"size:64;not null;default:''" json:"-"`
	// LevelsRecorded 建立時已逐角色記下層級（層級功能生效後建立的每一把都為真）。資料庫預設為否：
	// 本欄出現前建立的列因此標為「升級前建立」。只供呈現，不參與任何判定。
	LevelsRecorded bool `gorm:"not null;default:false" json:"-"`
}

func (APIToken) TableName() string { return "api_tokens" }

// APITokenRole 一把 API token 建立時授權的角色（以角色識別為準，不以名稱）與其層級。
// 角色被刪除後列仍保留，有效權限由解析器以帳號當下的指派與此集合取交集。
//
// Level 建立後不修改。資料庫預設為讀寫：本欄出現前建立的列因此維持讀寫，行為不變。
// 讀取時一律經 NormalizeAPITokenLevel：不認得的值視為唯讀。
type APITokenRole struct {
	APITokenID uint   `gorm:"primaryKey;autoIncrement:false" json:"api_token_id"`
	RoleID     uint   `gorm:"primaryKey;autoIncrement:false" json:"role_id"`
	Level      string `gorm:"size:16;not null;default:read_write" json:"level"`
}

func (APITokenRole) TableName() string { return "api_token_roles" }

// API token 授權角色的層級（具名值；之後加值不必改結構）。
const (
	// APITokenLevelRead 唯讀：只為性質為讀的請求提供能力
	APITokenLevelRead = "read"
	// APITokenLevelReadWrite 讀寫：讀與寫的請求都提供能力
	APITokenLevelReadWrite = "read_write"
)

// IsAPITokenLevel 是否為系統認得的層級值。只用於接受輸入：不認得的輸入一律拒絕。
func IsAPITokenLevel(s string) bool {
	return s == APITokenLevelRead || s == APITokenLevelReadWrite
}

// NormalizeAPITokenLevel 讀取已保存的層級：恰為讀寫才是讀寫，其餘（含空值與不認得的值）一律視為唯讀。
func NormalizeAPITokenLevel(s string) string {
	if s == APITokenLevelReadWrite {
		return APITokenLevelReadWrite
	}
	return APITokenLevelRead
}

// API token 層級的彙總（每把 token 一個值）。
const (
	APITokenAccessRead      = "read"
	APITokenAccessReadWrite = "read_write"
	APITokenAccessMixed     = "mixed"
)

// APITokenAccessOf 由各授權角色的層級（已正規化）求彙總：全部讀寫為讀寫、全部唯讀為唯讀、兩者皆有為混合。
// 沒有任何授權角色時回唯讀：彙總用於辨識「含唯讀角色的 token」，空集合歸到需要注意的一側。
func APITokenAccessOf(levels []string) string {
	hasRead, hasWrite := false, false
	for _, l := range levels {
		if NormalizeAPITokenLevel(l) == APITokenLevelReadWrite {
			hasWrite = true
		} else {
			hasRead = true
		}
	}
	switch {
	case hasWrite && hasRead:
		return APITokenAccessMixed
	case hasWrite:
		return APITokenAccessReadWrite
	default:
		return APITokenAccessRead
	}
}
