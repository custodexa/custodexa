package model

// 角色指派關聯表 `user_roles` 的 model 宣告。
//
// # 為什麼關聯表要有自己的 model
//
// 這張表原本只有 `(role_id, user_id)` 兩欄，由 `User.Roles`／`Role.Users` 的
// many2many 標籤隱式建出，沒有任何 Go 結構描述它。加上第三欄之後，
// 「這張表長什麼樣」就必須有一個明確的宣告來源，否則：
//
//   - 結構對照守衛（`internal/database/schema_parity_test.go`）看不到這張表，
//     加欄漂移整張脫離射程；
//   - 每一支需要它的測試各自手寫一份建表 DDL，加欄時要挨個改，
//     而漏改的那幾支會以「no such column」在無關的斷言上失敗。
//
// 故本結構是這張表的**單一定義來源**：正式庫由 baseline ＋ 增量 DDL 建，
// 兩者由結構對照守衛比對；測試庫直接以本結構 AutoMigrate。
//
// # 為什麼它不是 many2many 的自訂關聯結構
//
// GORM 允許以 `SetupJoinTable` 把關聯表換成自訂結構，藉此在關聯讀寫時帶上額外欄。
// 這裡刻意不那麼做——關聯讀取（`Preload("Roles")`）只需要角色本體，
// 而關聯寫入在本專案是被禁止的（寫入面收口在 `user_role_write.go`）。
// 掛上去只會讓「讀角色」這條最熱的路徑多背一層映射，卻換不到任何東西。
// 額外欄在預載入路徑下被忽略這件事，由 `TestUserRoleJoinModelPreloadIgnoresExtraColumns`
// 釘住，不靠推論。
type UserRole struct {
	RoleID uint `gorm:"primaryKey;autoIncrement:false" json:"role_id"`
	UserID uint `gorm:"primaryKey;autoIncrement:false" json:"user_id"`

	// Source 這一列的來源。三態，值域見下方常數。
	//
	// **這是投影而非事實源**：它由「這一列是不是管理者指派的」與
	// 「映射事實表有沒有對應的列」推導，於同一交易內更新。存在的理由是讓
	// 本地管理員計數與列表查詢不必每次去 join 映射事實表。
	// 兩者不一致時以事實源為準。
	Source string `gorm:"size:16;not null;default:manual" json:"source"`
}

// TableName 指定表名
func (UserRole) TableName() string {
	return "user_roles"
}

// 角色列的來源三態。
//
// # 為什麼是三態而不是兩態
//
// 兩態下「把某個由外部群組賦予的角色固定下來」只能靠刪列或加列表達，
// 而刪列等於有效角色集縮減，縮減等於推進憑證世代把人踢下線——下一次登入
// 重算又把列長回來。三態下固定與解除固定都是單條更新，不動有效集。
const (
	// RoleSourceManual 只由管理者指派
	RoleSourceManual = "manual"
	// RoleSourceMapped 只由外部群組映射賦予
	RoleSourceMapped = "mapped"
	// RoleSourceBoth 管理者指派與外部群組映射並存
	RoleSourceBoth = "both"
)

// IsManualSource 該來源值是否代表「管理者指派的成分存在」。
//
// 本地管理員計數的判準即此：只有管理者指派的成分能撐住解封能力，
// 僅由映射賦予的列會在下一次登入時隨群組異動消失。
func IsManualSource(source string) bool {
	return source == RoleSourceManual || source == RoleSourceBoth
}
