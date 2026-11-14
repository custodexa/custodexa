package identity

import (
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
	"gorm.io/gorm"
)

// API token 認證失敗的稽核側原因碼。對外一律回同一個未認證錯誤碼，這些值只進稽核。
const (
	APITokenReasonStoreUnavailable   = "api_token_store_unavailable"
	APITokenReasonNotFound           = "api_token_not_found"
	APITokenReasonRevoked            = "api_token_revoked"
	APITokenReasonExpired            = "api_token_expired"
	APITokenReasonRestoreInvalidated = "api_token_restore_invalidated"
	APITokenReasonAccountDeleted     = "api_token_account_deleted"
	APITokenReasonAccountNotHuman    = "api_token_account_not_human"
	APITokenReasonAccountDisabled    = "api_token_account_disabled"
	APITokenReasonRolesUnreadable    = "api_token_roles_unreadable"
)

// apiTokenLastUsedInterval 最近使用時間的更新間隔：同一來源在間隔內的重複請求不再寫入。
const apiTokenLastUsedInterval = time.Minute

// APITokenIdentity 通過認證的 API token 與其所屬帳號（不含明文或雜湊）。
type APITokenIdentity struct {
	TokenID   uint
	TokenName string
	UserID    uint
	Username  string
	Email     string
	// CredentialEpoch 所屬帳號當下的憑證世代（與其他欄位同一次查詢讀出）；只用於下游的認證脈絡，
	// 驗證本身不比對世代：改密等推進世代的事件不影響 token。
	CredentialEpoch int
	// GrantedRoleIDs 建立時授權的角色；可能為空集合（角色列遺失時），呼叫端仍須以非 nil 的限定傳入解析器。
	GrantedRoleIDs []uint
}

// apiTokenAuthRow 一次查詢讀出 token 與所屬帳號的授權事實。帳號以未過濾軟刪除的方式聯結，
// 才能把「帳號已刪除」與「token 不存在」分成不同的稽核原因。
type apiTokenAuthRow struct {
	model.APIToken `gorm:"embedded"`
	OwnerKind      string     `gorm:"column:owner_kind"`
	OwnerActive    bool       `gorm:"column:owner_active"`
	OwnerDeletedAt *time.Time `gorm:"column:owner_deleted_at"`
	OwnerUsername  string     `gorm:"column:owner_username"`
	OwnerEmail     *string    `gorm:"column:owner_email"`
	OwnerCIDRs     string     `gorm:"column:owner_cidrs"`
	OwnerEpoch     int        `gorm:"column:owner_epoch"`
}

// ValidateAPIToken 每次請求現查 token、所屬帳號與來源位址，不快取。
//
// 檢查順序：token 存在、未撤銷、未到期、還原世代相同；帳號未刪除、為人類、啟用中；來源在帳號的
// 允許網段內。任一不符回 (nil, 原因碼)。帳號鎖定、被要求改密、被要求註冊兩步驟驗證、工作階段被撤銷、
// 改為僅外部登入都不在檢查之列：那些只約束互動式登入。
//
// 最近使用時間與來源是遙測：在全部檢查通過後以條件式更新寫入，不在任何鎖內，寫入失敗不影響結果。
func (s *AuthService) ValidateAPIToken(plaintext, ip string) (*APITokenIdentity, string) {
	db := s.epochDB()
	if db == nil {
		return nil, APITokenReasonStoreUnavailable
	}
	var row apiTokenAuthRow
	// 以雜湊查詢：這條語句的 SQL 紀錄（含查無資料）不帶參數值
	err := database.WithheldSQLParams(db).Table("api_tokens AS t").
		Select("t.*, u.kind AS owner_kind, u.active AS owner_active, u.deleted_at AS owner_deleted_at, u.username AS owner_username, u.email AS owner_email, u.allowed_cidrs AS owner_cidrs, u.credential_epoch AS owner_epoch").
		Joins("JOIN users u ON u.id = t.user_id").
		Where("t.token_hash = ?", apiTokenDigest(plaintext)).Take(&row).Error
	if err != nil {
		return nil, APITokenReasonNotFound
	}
	now := time.Now()
	if row.RevokedAt != nil {
		return nil, APITokenReasonRevoked
	}
	if row.ExpiresAt != nil && !row.ExpiresAt.After(now) {
		return nil, APITokenReasonExpired
	}
	if !restoreGenerationAccepts(s.restoreGen, db, row.RestoreGeneration) {
		return nil, APITokenReasonRestoreInvalidated
	}
	if row.OwnerDeletedAt != nil {
		return nil, APITokenReasonAccountDeleted
	}
	if row.OwnerKind != model.KindHuman {
		return nil, APITokenReasonAccountNotHuman
	}
	if !row.OwnerActive {
		return nil, APITokenReasonAccountDisabled
	}
	if verdict := sourceip.Evaluate(row.OwnerCIDRs, nil, ip); !verdict.Allowed {
		return nil, verdict.Reason
	}
	roleIDs := []uint{}
	if err := db.Model(&model.APITokenRole{}).Where("api_token_id = ?", row.ID).Order("role_id").Pluck("role_id", &roleIDs).Error; err != nil {
		return nil, APITokenReasonRolesUnreadable
	}
	touchAPITokenLastUsed(db, row.ID, row.LastUsedAt, row.LastUsedIP, ip, now)
	email := ""
	if row.OwnerEmail != nil {
		email = *row.OwnerEmail
	}
	return &APITokenIdentity{TokenID: row.ID, TokenName: row.Name, UserID: row.UserID, Username: row.OwnerUsername,
		Email: email, CredentialEpoch: row.OwnerEpoch, GrantedRoleIDs: roleIDs}, ""
}

// touchAPITokenLastUsed 更新最近使用時間與來源。間隔內且來源相同時不寫；條件式更新讓多副本不重複寫。
// 單一陳述、不開交易，錯誤刻意忽略：這是遙測，不得使已通過認證的請求失敗。
func touchAPITokenLastUsed(db *gorm.DB, tokenID uint, lastAt *time.Time, lastIP, ip string, now time.Time) {
	threshold := now.Add(-apiTokenLastUsedInterval)
	if lastAt != nil && !lastAt.Before(threshold) && lastIP == ip {
		return
	}
	_ = db.Session(&gorm.Session{SkipDefaultTransaction: true}).Model(&model.APIToken{}).
		Where("id = ? AND (last_used_at IS NULL OR last_used_at < ? OR last_used_ip <> ?)", tokenID, threshold, ip).
		UpdateColumns(map[string]any{"last_used_at": now, "last_used_ip": ip}).Error
}
