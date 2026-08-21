package model

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

// AccountScopeAll 全帳號別名（asset-multi-account D5）：
// 展開為客體範圍內資產的全部未刪帳號。授權綁 username 字串而非 AssetAccount FK，
// 因授權客體可為資產群組、帳號卻是 per-asset 物件——「授權群組內的 root」
// 只能以名字表達——這是「授權客體可為群組、帳號卻是 per-asset 物件」下的必然取捨
const AccountScopeAll = "@ALL"

// AccountScope 授權列的帳號範圍（asset-multi-account D5）。
//
// 儲存為 JSON 字串陣列（`type:text`，postgres/sqlite 皆可攜）。空值與空陣列
// **一律視為 `["@ALL"]`**：既有列 migration 回填 @ALL，而任何漏設此欄的新寫入
// 路徑若被解讀為「零帳號可用」會靜默切斷連線；反之解讀為 @ALL 只是維持
// 多帳號前的既有行為（回歸安全的預設方向）。收緊須顯式指定。
type AccountScope []string

// NormalizeAccountScope 正規化帳號範圍：去空白、去重、排序；含 @ALL 即塌縮為
// `["@ALL"]`（@ALL 與具名並存時 @ALL 恆為上界，保留具名項只會讓 UI 顯示
// 自相矛盾的「全部帳號＋app」）。空輸入回 nil，由讀取端的 IsAll 視為 @ALL
func NormalizeAccountScope(in []string) AccountScope {
	seen := make(map[string]bool, len(in))
	out := make(AccountScope, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if v == AccountScopeAll {
			return AccountScope{AccountScopeAll}
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// IsAll 是否為全帳號範圍。空／空陣列＝@ALL（見型別註解的回歸安全預設）
func (s AccountScope) IsAll() bool {
	if len(s) == 0 {
		return true
	}
	for _, v := range s {
		if v == AccountScopeAll {
			return true
		}
	}
	return false
}

// Contains 具名 username 是否在範圍內（@ALL 恆真）
func (s AccountScope) Contains(username string) bool {
	if s.IsAll() {
		return true
	}
	for _, v := range s {
		if v == username {
			return true
		}
	}
	return false
}

// Value 實作 driver.Valuer：一律以 JSON 陣列落庫（nil 亦寫 `["@ALL"]`，
// 使庫內不存在「語義待解讀的 NULL」——稽核直讀該欄即知範圍）
func (s AccountScope) Value() (driver.Value, error) {
	if len(s) == 0 {
		s = AccountScope{AccountScopeAll}
	}
	buf, err := json.Marshal([]string(s))
	if err != nil {
		return nil, fmt.Errorf("序列化帳號範圍失敗: %w", err)
	}
	return string(buf), nil
}

// Scan 實作 sql.Scanner：容忍 NULL／空字串（回 nil＝@ALL，見型別註解）。
// 非法 JSON 一律報錯而非默默視為 @ALL——庫內資料損毀時放行全帳號是權限擴張
func (s *AccountScope) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}
	var raw []byte
	switch v := value.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("帳號範圍欄位型別非預期: %T", value)
	}
	if len(raw) == 0 || string(raw) == "null" {
		*s = nil
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("解析帳號範圍失敗: %w", err)
	}
	*s = AccountScope(out)
	return nil
}

// PermissionType 權限類型
type PermissionType string

const (
	PermissionView    PermissionType = "view"    // 檢視資產資訊
	PermissionConnect PermissionType = "connect" // 連線到資產

	// Deprecated: manage 等級已於 access-policy-approval（J 決議）移除，等級階梯
	// 收斂為 view<connect 兩階。此常數僅供 v7.5 歷史 migration 碼與歷史軟刪列
	// 辨識引用，API 拒收、任何新寫入路徑不得使用
	PermissionManage PermissionType = "manage"
)

// 授權來源（access-policy-approval D3）
const (
	AuthorizationSourceManual = "manual" // 管理員手動授權（永久，無時效窗）
	AuthorizationSourceTicket = "ticket" // 申請核准流產生的臨時授權（帶時效窗）
)

// AssetAuthorization 資產授權模型
// 用於細粒度控制存取主體（使用者 XOR 使用者群組）對資產（直授 XOR 資產分組）的存取權限
type AssetAuthorization struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// 主體：user XOR user_group（user-group-authorization）。
	// PostgreSQL 唯一索引對 NULL 視為相異，主體×客體四種組合各需獨立唯一索引去重。
	// 唯一索引一律 partial（WHERE deleted_at IS NULL）：撤銷＝軟刪，非 partial 索引
	// 會讓「撤銷後重授同組合」永遠撞唯一衝突（實測證實的既有 bug）。
	// 另排除核准流來源（AND source <> 'ticket'，access-policy-approval D3 補充）：
	// 臨時授權必須能與同組合常設授權並存（強制審核蓋過常設、持有者可申請的
	// 核心場景），且同組合可有多筆不同時窗的臨時授權（預約維護窗）；
	// ticket 列去重由申請流狀態機保證（pending 去重＋一單一授權）
	UserID       *uint          `gorm:"uniqueIndex:idx_user_asset_permission,where:deleted_at IS NULL AND source <> 'ticket';uniqueIndex:idx_user_group_permission,where:deleted_at IS NULL AND source <> 'ticket'" json:"user_id,omitempty"`
	UserGroupID  *uint          `gorm:"uniqueIndex:idx_ugroup_asset_permission,where:deleted_at IS NULL AND source <> 'ticket';uniqueIndex:idx_ugroup_agroup_permission,where:deleted_at IS NULL AND source <> 'ticket'" json:"user_group_id,omitempty"`
	AssetID      *uint          `gorm:"uniqueIndex:idx_user_asset_permission;uniqueIndex:idx_ugroup_asset_permission;index:idx_asset" json:"asset_id,omitempty"`
	AssetGroupID *uint          `gorm:"uniqueIndex:idx_user_group_permission;uniqueIndex:idx_ugroup_agroup_permission" json:"asset_group_id,omitempty"`
	Permission   PermissionType `gorm:"type:varchar(20);not null;uniqueIndex:idx_user_asset_permission;uniqueIndex:idx_user_group_permission;uniqueIndex:idx_ugroup_asset_permission;uniqueIndex:idx_ugroup_agroup_permission" json:"permission"`

	// 時效窗（user-group-authorization D4）：空＝永久生效。到期語義＝解析不命中，
	// 記錄留存供審計。來源限核准流（access-policy-approval），管理 API 不接受手填
	DateStart   *time.Time `json:"date_start,omitempty"`
	DateExpired *time.Time `json:"date_expired,omitempty"`

	// 來源（access-policy-approval D3）：manual=管理員手動、ticket=核准流臨時授權。
	// 授權列表/複審矩陣直接可辨識，不需 join 申請單。欄位不帶 default tag
	//（GORM default 觸發 RETURNING 破壞 sqlmock），DB 端 default 與既有列回填
	// 由 20260718 migration 處理，寫入端顯式設值（BeforeCreate 兜底 manual）
	Source string `gorm:"type:varchar(20)" json:"source"`

	// Accounts 帳號範圍（asset-multi-account D5）：預設 `["@ALL"]`（客體範圍內
	// 資產的全部帳號，行為與多帳號前一致），可個別指定 username 清單
	//（語義＝範圍內資產上的同名帳號）。
	//
	// **不參與唯一索引**：帳號範圍是授權列的屬性、不是去重維度——若入索引，
	// 「同一 user×asset×connect 給兩組不同帳號範圍」會變成兩筆合法列，
	// 使「這個人對這台有幾筆授權」不再唯一，撤銷與複審矩陣全部要改語義。
	// 收緊帳號範圍＝改既有列，不是新增列
	Accounts AccountScope `gorm:"type:text" json:"accounts,omitempty"`

	// 授權元數據
	GrantedBy uint `gorm:"not null" json:"granted_by"` // 授權者 User ID

	// 關聯（用於 Preload）
	User          User        `gorm:"foreignKey:UserID" json:"user,omitempty"`
	UserGroup     *UserGroup  `gorm:"foreignKey:UserGroupID" json:"user_group,omitempty"`
	Asset         *Asset      `gorm:"foreignKey:AssetID" json:"asset,omitempty"`
	AssetGroup    *AssetGroup `gorm:"foreignKey:AssetGroupID" json:"asset_group,omitempty"`
	GrantedByUser User        `gorm:"foreignKey:GrantedBy" json:"granted_by_user,omitempty"`

	// RequestID 該票證所屬申請單 id（break-glass-revocation：撤銷入口回鏈用）。
	// 非 DB 欄位，由 ActiveTickets/MyActiveTickets 查詢後填入（撤銷走申請單，
	// 附註掛單上——見 D4）
	RequestID *uint `gorm:"-" json:"request_id,omitempty"`
}

// TableName 指定表名
func (AssetAuthorization) TableName() string {
	return "asset_authorizations"
}

// BeforeCreate GORM Hook - 創建前驗證：主體恰一（user XOR user_group）、
// 客體恰一（asset XOR asset_group）。主要約束由資料庫 CHECK constraint 保證
func (a *AssetAuthorization) BeforeCreate(tx *gorm.DB) error {
	if (a.UserID == nil) == (a.UserGroupID == nil) {
		return gorm.ErrInvalidValue
	}
	if (a.AssetID == nil) == (a.AssetGroupID == nil) {
		return gorm.ErrInvalidValue
	}
	// 來源兜底：未顯式設值一律視為手動授權（欄位不帶 default tag，見欄位註解）
	if a.Source == "" {
		a.Source = AuthorizationSourceManual
	}
	return nil
}

// ActiveWithin 判定授權於指定時刻是否在時效窗內（空值＝不設限）
func (a *AssetAuthorization) ActiveWithin(now time.Time) bool {
	if a.DateStart != nil && now.Before(*a.DateStart) {
		return false
	}
	if a.DateExpired != nil && !now.Before(*a.DateExpired) {
		return false
	}
	return true
}

// 授權有效性三態（authorization-page-redesign D2）：單一布林會把「未生效」
// 誤標「已過期」，序列化與篩選一律用三態
const (
	ValidityScheduled = "scheduled" // 未達 date_start
	ValidityActive    = "active"    // 時窗內（空值＝永久）
	ValidityExpired   = "expired"   // 已過 date_expired
)

// ValidityStateAt 授權於指定時刻的有效性三態，邊界語義與 ActiveWithin 一致
func (a *AssetAuthorization) ValidityStateAt(now time.Time) string {
	if a.DateStart != nil && now.Before(*a.DateStart) {
		return ValidityScheduled
	}
	if a.DateExpired != nil && !now.Before(*a.DateExpired) {
		return ValidityExpired
	}
	return ValidityActive
}
