package model

import (
	"fmt"
	"strconv"
	"time"
)

// UserRoleMapping 某一條登入途徑於最近一次重算後認定的一筆角色映射。
//
// # 為什麼通道要進主鍵
//
// 角色指派關聯表的主鍵是（角色，帳號）。同一個角色被目錄與身分提供者同時命中時，
// 單一個通道欄只表達得了其中一條，另一條的事實在下一次重算即被覆寫或誤刪。
// 主鍵擴為（帳號，角色，通道）之後兩條通道各自成列，某通道重算只動
// `channel` 等於該值的列，另一條通道的事實不受影響。
//
// 不分通道的後果是具體的：同一人交替經兩條途徑登入時，每次登入都會清掉對方
// 認定的列，每次都被判為「有效角色集縮減」，於是每次都推進憑證世代把對方的
// 會話踢下線。
//
// # 這張表是事實源
//
// 有效角色集＝角色指派關聯表的手動列聯集本表去重後的角色。關聯表上的來源欄
// 是由本表與手動列推導出的投影，兩者不一致時以本表為準。
type UserRoleMapping struct {
	UserID uint `gorm:"primaryKey;autoIncrement:false" json:"user_id"`
	RoleID uint `gorm:"primaryKey;autoIncrement:false" json:"role_id"`

	// Channel 途徑種類與該來源的識別，形如「種類:來源識別」。
	// 值由 RoleMappingChannel 產生，不要在別處自己拼字串
	Channel string `gorm:"primaryKey;size:64" json:"channel"`

	// MatchedAt 最近一次重算認定這筆映射的時間
	MatchedAt time.Time `gorm:"not null" json:"matched_at"`
}

// TableName 指定資料表名
func (UserRoleMapping) TableName() string {
	return "user_role_mappings"
}

// 登入途徑的種類。通道字串的前段。
const (
	// RoleMappingChannelKindDirectory 目錄途徑
	RoleMappingChannelKindDirectory = "directory"
	// RoleMappingChannelKindProvider 身分提供者途徑
	RoleMappingChannelKindProvider = "provider"
)

// RoleMappingChannel 由途徑種類與來源識別組出通道值。
//
// **單一產生點**：通道是主鍵的一部分，兩處各自拼字串而其中一處少了前綴時，
// 重算會把另一條途徑的列當成自己的而清掉——症狀是「登入之後角色莫名消失」，
// 且只在同時用了兩條途徑的帳號上出現。
func RoleMappingChannel(kind string, sourceID uint) string {
	return kind + ":" + strconv.FormatUint(uint64(sourceID), 10)
}

// ParseRoleMappingChannel 由通道值取回途徑種類與來源識別。
func ParseRoleMappingChannel(channel string) (kind string, sourceID uint, err error) {
	for i := 0; i < len(channel); i++ {
		if channel[i] != ':' {
			continue
		}
		kind = channel[:i]
		if kind != RoleMappingChannelKindDirectory && kind != RoleMappingChannelKindProvider {
			return "", 0, fmt.Errorf("未知的途徑種類: %q", kind)
		}
		id, convErr := strconv.ParseUint(channel[i+1:], 10, 64)
		if convErr != nil {
			return "", 0, fmt.Errorf("通道的來源識別無法解析: %w", convErr)
		}
		return kind, uint(id), nil
	}
	return "", 0, fmt.Errorf("通道值缺少分隔符: %q", channel)
}
