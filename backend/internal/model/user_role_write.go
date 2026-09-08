package model

import (
	"encoding/json"
	"fmt"

	"gorm.io/gorm"
)

// 角色指派的唯一寫入面（role-assignment-integrity）。
//
// # 為什麼寫入面要收成兩個函式
//
// 權限真相在 `user_roles`。檢查點鏈把它的指紋簽進鏈之後，對帳要能回答
// 「上一個檢查點之後的每一筆變動，是不是都經過應用程式」——而那個問題只有在
// **每一筆變動都留下審計列**時才答得出來。少一條留痕路徑，對帳就會把一個合法
// 變更報成繞過應用程式的竄改（假警報），而假警報會讓真警報失去意義。
//
// 故本檔提供 `AssignUserRole`／`RevokeUserRole` 兩個函式，是全樹寫 `user_roles`
// 的唯一合法位置（第三個函式 `AssignUserRoleAtSeed` 是解封前的播種專用變體，
// 不留痕、只准 `seed.go` 呼叫，理由見該函式）；AST 守衛 `TestRoleAuditWriteSitesGuard`
//（`internal/modules/identity`）雙向盯住這件事——別處出現 `user_roles` 的寫入
// SQL 或 `Association("Roles")` 的寫入呼叫即紅。
//
// # 為什麼落在 internal/model 而不是 identity
//
// 寫入點分布在 identity（管理面、LDAP、OIDC）與 database（初始管理員播種）兩個包，
// 而 `internal/database` 不能 import identity（會成環）。把唯一寫入面放在兩者都
// 依賴的最底層，守衛才可能是**零例外**的——放在 identity 就必須為播種開一條豁免，
// 而豁免正是這種守衛最先失守的地方。
//
// 直接以 `tx.Create` 落地審計列而非經 `audit/port.TxSink`，與
// `RecordAssetChange`／`RecordAssetAccountChange` 的落地本體、以及存量轉換
// （`internal/database/credential_secret_conversion.go`）同型：本層拿不到 sink，
// 而寫入吃的是呼叫方的 `tx`，回 error 即整筆回滾。manifest 分派仍為 TxSink。
//
// # 安全紀律
//
// details 只記 `user_id`、`role_id`、`origin` 三個機器可讀的識別，
// **不含帳號名、角色名或任何個資**——與快照同一條紀律（快照會進檢查點、會離機、
// 會被稽核方拿去）；呈現時再以現行資料換算。

// 角色指派的來源（審計 details 的 origin 欄）。
//
// **不是操作者，是路徑**：操作者記在審計列的 user_id／username（取自交易的
// context，無脈絡時為 system）。origin 回答的是「這筆指派從哪條程式路徑進來」，
// 對帳與事後追查靠它分辨「管理者按了按鈕」與「某人首次以目錄帳號登入」。
const (
	// RoleOriginAPI 管理面端點：指派、移除、一站式代配
	RoleOriginAPI = "api"
	// RoleOriginRegister 本地帳號建立時配的角色
	RoleOriginRegister = "register"
	// RoleOriginOIDC OIDC 首次登入自動建帳號時配的預設角色
	RoleOriginOIDC = "oidc"
	// RoleOriginLDAP LDAP 影子帳號供應時配的預設角色
	RoleOriginLDAP = "ldap"
	// RoleOriginMapping 外部群組映射：登入時重算認定的授予與撤除。
	//
	// **它不是操作者**：真正的行為者是外部目錄或身分提供者那一端的群組管理員，
	// 本系統看不見他。留下這個值的意義是讓事後追查分得出「管理者按了按鈕」與
	// 「某人所屬的群組變了」——後者要去外部來源的變更記錄裡查。
	RoleOriginMapping = "mapping"
	// RoleOriginSystem 系統路徑。**現況無任何呼叫點**：唯一曾用它的初始管理員播種
	// 已改走不留痕的 `AssignUserRoleAtSeed`（解封前無蓋章鑰）。值保留是因為它是
	// details 的既定值域之一，日後若有解封後執行的系統路徑（例如存量轉換）要配角色，
	// 該路徑走 `AssignUserRole` 並帶本值——不要因為現在沒人用就改寫成別的語義
	RoleOriginSystem = "system"
)

// UserRoleAuditDetails 角色指派審計列的 details 形狀。
//
// 欄位順序即序列化順序（struct tag 決定），對帳與事後比對讀的是這三個鍵；
// 新增欄位前先問「它會不會是個資」
type UserRoleAuditDetails struct {
	Resource string `json:"resource"`
	UserID   uint   `json:"user_id"`
	RoleID   uint   `json:"role_id"`
	Origin   string `json:"origin"`
}

// AssignUserRole 於 tx 內授予一筆角色指派並同交易留痕。
//
// **冪等**：該指派已存在時不寫列、不留痕（沒有狀態變更就沒有事件；
// 留一筆「什麼都沒改」的 assign 會讓對帳重放時多算一次，而重放是集合語義，
// 多算雖不致錯但會讓事件流與現實不對應）。
//
// 回 error 時呼叫方 SHALL 讓它逸出交易閉包：審計寫不進去，角色就不許掛上。
func AssignUserRole(tx *gorm.DB, userID, roleID uint, origin string) error {
	res := tx.Exec(
		"INSERT INTO user_roles (user_id, role_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
		userID, roleID)
	if res.Error != nil {
		return fmt.Errorf("寫入角色指派失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil
	}
	return recordUserRoleChange(tx, ActionAssign, userID, roleID, origin)
}

// AssignUserRoleAtSeed 初始管理員播種專用：授予角色但**不留痕**。
//
// # 為什麼這一條路徑不留痕
//
// 播種發生在段 1（`cmd/server/stage1.go`），那時尚未解封，審計蓋章鑰還不存在
// （蓋章 hook 於段 2 的 `InitAuditIntegrityVersioned` 才裝上）。在那裡寫一筆審計列，
// 結果是一列**永遠不帶章**的審計列——驗章端只能把它讀成「上線前的歷史列」，
// 於是這條路徑產出的不是留痕，是一個假的未蓋章訊號。
//
// **對帳不需要它**：對帳的基準是第一個含快照的檢查點，而播種的指派早在那之前，
// 本來就在快照裡；它不是「檢查點之後的變動」，重放時也不該出現。
//
// **射程僅此一處**：AST 守衛 `TestRoleAuditWriteSitesGuard` 把
// `internal/database/seed.go` 的 `seedAdmin` 登記為本函式的唯一呼叫點，
// 其餘任何呼叫即紅——其他五條路徑都在解封之後，一律走 `AssignUserRole` 留痕。
func AssignUserRoleAtSeed(tx *gorm.DB, userID, roleID uint) error {
	if err := tx.Exec(
		"INSERT INTO user_roles (user_id, role_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
		userID, roleID).Error; err != nil {
		return fmt.Errorf("寫入初始管理員角色指派失敗: %w", err)
	}
	return nil
}

// RevokeUserRole 於 tx 內移除一筆角色指派並同交易留痕。
// 該指派不存在時為 no-op（理由同 AssignUserRole 的冪等）
func RevokeUserRole(tx *gorm.DB, userID, roleID uint, origin string) error {
	res := tx.Exec("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", userID, roleID)
	if res.Error != nil {
		return fmt.Errorf("移除角色指派失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil
	}
	return recordUserRoleChange(tx, ActionRevoke, userID, roleID, origin)
}

// recordUserRoleChange 角色指派變更的**唯一**審計產生點（manifest AP-87）。
//
// 主體取自交易的 context（同 Asset hook 的 getUserFromContext）：管理面路徑帶得到
// 操作者，系統與登入供應路徑落在 (0, "system")。**origin 才是路徑的權威**——
// 主體會因呼叫層是否帶 context 而有無，路徑不會
func recordUserRoleChange(tx *gorm.DB, action AuditAction, userID, roleID uint, origin string) error {
	operatorID, operator := getUserFromContext(tx.Statement.Context)
	details, err := json.Marshal(UserRoleAuditDetails{
		Resource: string(ResourceUserRole), UserID: userID, RoleID: roleID, Origin: origin,
	})
	if err != nil {
		return fmt.Errorf("序列化角色指派審計詳情失敗: %w", err)
	}
	subject := userID
	row := AuditLog{
		Action:     action,
		Resource:   ResourceUserRole,
		ResourceID: &subject,
		Status:     StatusSuccess,
		UserID:     operatorID,
		Username:   operator,
		Details:    string(details),
	}
	if err := tx.Create(&row).Error; err != nil {
		return fmt.Errorf("角色指派留痕失敗: %w", err)
	}
	return nil
}

// UserRoleSourceOf 讀一列角色指派的來源；該列不存在時 exists 為 false。
//
// 讀取面與寫入面放在一起的理由：來源三態的每一次轉移都是「先知道現在是哪一態、
// 再決定寫什麼」，兩者分家會讓呼叫端自己拼 SQL，而那正是本檔要收掉的東西。
func UserRoleSourceOf(tx *gorm.DB, userID, roleID uint) (source string, exists bool, err error) {
	var rows []string
	if err := tx.Table("user_roles").
		Where("user_id = ? AND role_id = ?", userID, roleID).
		Pluck("source", &rows).Error; err != nil {
		return "", false, fmt.Errorf("讀取角色指派來源失敗: %w", err)
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	return rows[0], true, nil
}

// SetUserRoleSource 更新一列角色指派的來源。
//
// # 為什麼它不留痕
//
// 來源欄是**投影**，不是權限本身：`manual` 升 `both`、`both` 降 `mapped` 都不改變
// 「這個帳號有沒有這個角色」。對帳問的是「有效角色集有沒有在應用程式之外被改過」，
// 而投影的變動不改變有效集，留一列審計只會讓事件流多出對帳重放不回來的雜訊。
// 真正改變有效集的兩件事——列被建立、列被刪除——走的是
// AssignUserRole／RevokeUserRole，兩者都留痕。
//
// 呼叫端 SHALL 與事實面的變動同交易：投影落後於事實的中間態一旦外洩到查詢，
// 本地管理員計數就會讀到錯的答案。
func SetUserRoleSource(tx *gorm.DB, userID, roleID uint, source string) error {
	switch source {
	case RoleSourceManual, RoleSourceMapped, RoleSourceBoth:
	default:
		return fmt.Errorf("未知的角色指派來源: %q", source)
	}
	res := tx.Exec("UPDATE user_roles SET source = ? WHERE user_id = ? AND role_id = ?",
		source, userID, roleID)
	if res.Error != nil {
		return fmt.Errorf("更新角色指派來源失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("更新角色指派來源失敗：(%d, %d) 無對應列", userID, roleID)
	}
	return nil
}

// AssignUserRoleWithSource 於 tx 內授予一筆角色指派、落指定來源並同交易留痕。
//
// 與 AssignUserRole 的差別只有來源值：後者走欄位預設（管理者指派），
// 本函式供映射路徑以 `mapped` 建立新列。冪等語義相同——該指派已存在時
// 不寫列、不留痕、**也不動來源**（既存列的來源由轉移函式決定，不由建立面覆寫）。
func AssignUserRoleWithSource(tx *gorm.DB, userID, roleID uint, source, origin string) error {
	switch source {
	case RoleSourceManual, RoleSourceMapped, RoleSourceBoth:
	default:
		return fmt.Errorf("未知的角色指派來源: %q", source)
	}
	res := tx.Exec(
		"INSERT INTO user_roles (user_id, role_id, source) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
		userID, roleID, source)
	if res.Error != nil {
		return fmt.Errorf("寫入角色指派失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil
	}
	return recordUserRoleChange(tx, ActionAssign, userID, roleID, origin)
}
