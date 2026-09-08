package identity

import (
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 角色列來源三態的四種狀態轉移。
//
// # 事實源與投影
//
// 有效角色集＝角色指派關聯表的手動列（來源為 manual 或 both）聯集映射事實表
// 去重後的角色。關聯表上的來源欄是這兩件事的**投影**：
//
//	手動成分在不在  ← 只存在於來源欄本身（manual／both 代表在）
//	映射成分在不在  ← 映射事實表有沒有對應的列（本通道或其他通道皆算）
//
// 故轉移不是「重算一次投影」而是明確的狀態機：每一種事件各自知道自己動的是
// 哪一半，另一半原封不動。全部函式 SHALL 由呼叫端在同一交易內呼叫——投影落後
// 於事實的中間態一旦被查詢讀到，本地管理員計數就會給出錯的答案。
//
// # 通道分域
//
// 映射事實以（帳號，角色，通道）為鍵。重算只比對本次登入通道的列，其他通道的
// 列不動；不分域的話，同一人交替經兩條途徑登入會互相清除對方的認定，每次都被
// 判為有效集縮減而把對方的會話踢下線。
//
// # 留痕
//
// 真正改變有效集的兩件事（列被建立、列被刪除）走 model 的寫入面並留痕，
// 來源值 origin 為映射；只改投影的兩種轉移不留痕（見 model.SetUserRoleSource）。

// GrantMappedRole 轉移一：某條通道的重算命中了這個角色。
//
// 動兩張表：映射事實表插入（或更新命中時間）本通道這一列；角色指派關聯表
// 依現況推進來源——不存在則以 mapped 建立並留痕，manual 升 both，
// mapped 與 both 不動。
//
// 回傳 granted 表示「這次真的多給了一個角色」（用於判斷有效集是否擴張）。
func GrantMappedRole(tx *gorm.DB, userID, roleID uint, channel string,
	matchedAt time.Time) (granted bool, err error) {
	if _, _, err := model.ParseRoleMappingChannel(channel); err != nil {
		return false, err
	}
	if err := upsertRoleMappingFact(tx, userID, roleID, channel, matchedAt); err != nil {
		return false, err
	}
	source, exists, err := model.UserRoleSourceOf(tx, userID, roleID)
	if err != nil {
		return false, err
	}
	if !exists {
		if err := model.AssignUserRoleWithSource(tx, userID, roleID,
			model.RoleSourceMapped, model.RoleOriginMapping); err != nil {
			return false, err
		}
		return true, nil
	}
	if source == model.RoleSourceManual {
		if err := model.SetUserRoleSource(tx, userID, roleID, model.RoleSourceBoth); err != nil {
			return false, err
		}
	}
	return false, nil
}

// RevokeMappedRolesForChannel 轉移二：本通道的重算之後，不再命中的角色要收回。
//
// matched 是本次重算命中的角色集。本通道映射事實表內不在 matched 裡的列全數刪除；
// 對每一個因此失去映射成分的角色，再看它有沒有**其他通道**還命中——
// 有就只刪這一列、關聯表不動；沒有的話關聯表上 mapped 的列刪除（留痕）、
// both 的列降回 manual。
//
// # 空集合分支
//
// matched 為空（本次一個群組都沒命中）時**不加 `NOT IN` 條件**，直接刪本通道全部
// 映射列。兩種方言都不接受空的 `NOT IN ()`，而 ORM 對空清單產生的
// `NOT IN (NULL)` 更糟——它不報錯，只是一列都不匹配，於是「全部撤除」靜默變成
// 「什麼都沒做」，被移出全部群組的人保留原有權限。
//
// 回傳 revoked＝關聯表上真的被刪掉的角色（有效集縮減的判準）。
func RevokeMappedRolesForChannel(tx *gorm.DB, userID uint, channel string,
	matched []uint) (revoked []uint, err error) {
	if _, _, err := model.ParseRoleMappingChannel(channel); err != nil {
		return nil, err
	}
	// 先讀本通道現況：要知道哪些角色失去了映射成分，刪完就問不到了
	var current []uint
	if err := tx.Table("user_role_mappings").
		Where("user_id = ? AND channel = ?", userID, channel).
		Pluck("role_id", &current).Error; err != nil {
		return nil, fmt.Errorf("讀取本通道映射事實失敗: %w", err)
	}
	keep := make(map[uint]struct{}, len(matched))
	for _, id := range matched {
		keep[id] = struct{}{}
	}
	var stale []uint
	for _, id := range current {
		if _, ok := keep[id]; !ok {
			stale = append(stale, id)
		}
	}

	del := tx.Where("user_id = ? AND channel = ?", userID, channel)
	if len(matched) > 0 {
		del = del.Where("role_id NOT IN ?", matched)
	}
	if err := del.Delete(&model.UserRoleMapping{}).Error; err != nil {
		return nil, fmt.Errorf("刪除本通道映射事實失敗: %w", err)
	}
	if len(stale) == 0 {
		return nil, nil
	}

	for _, roleID := range stale {
		stillMapped, err := roleStillMappedByAnyChannel(tx, userID, roleID)
		if err != nil {
			return nil, err
		}
		if stillMapped {
			continue
		}
		source, exists, err := model.UserRoleSourceOf(tx, userID, roleID)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		switch source {
		case model.RoleSourceMapped:
			if err := model.RevokeUserRole(tx, userID, roleID, model.RoleOriginMapping); err != nil {
				return nil, err
			}
			revoked = append(revoked, roleID)
		case model.RoleSourceBoth:
			if err := model.SetUserRoleSource(tx, userID, roleID, model.RoleSourceManual); err != nil {
				return nil, err
			}
		}
	}
	return revoked, nil
}

// RemoveManualRole 轉移三：管理者把這個角色移出手動集。
//
// manual 的列刪除（留痕）；both 降回 mapped——外部群組給的那一半不因管理者
// 收回自己那一半而消失，否則下一次登入重算又會把列長回來，而中間那一段
// 已經推進過憑證世代把人踢下線了。mapped 的列不動（它本來就不在手動集裡）。
//
// 回傳 removed 表示有效集是否真的少了一個角色。
//
// **origin 不做成參數**：AST 守衛以「第四個引數是不是具名常數」辨識寫入呼叫點，
// 把來源改成變數會讓這條路徑靜默脫離登記表的射程。這個函式的來源本來就恆為
// 管理面，寫死即可。
func RemoveManualRole(tx *gorm.DB, userID, roleID uint) (removed bool, err error) {
	source, exists, err := model.UserRoleSourceOf(tx, userID, roleID)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	switch source {
	case model.RoleSourceManual:
		if err := model.RevokeUserRole(tx, userID, roleID, model.RoleOriginAPI); err != nil {
			return false, err
		}
		return true, nil
	case model.RoleSourceBoth:
		if err := model.SetUserRoleSource(tx, userID, roleID, model.RoleSourceMapped); err != nil {
			return false, err
		}
	}
	return false, nil
}

// AddManualRole 轉移四：管理者把這個角色加入手動集（含把映射來的角色固定下來）。
//
// 不存在的列以 manual 建立並留痕；mapped 升 both（固定下來，此後不隨群組異動消失）；
// manual 與 both 不動。
//
// 回傳 granted 表示有效集是否真的多了一個角色——mapped 升 both **不算**：
// 那個角色本來就在有效集裡，固定它不擴張任何權限。
//
// origin 不做成參數，理由同 RemoveManualRole。
func AddManualRole(tx *gorm.DB, userID, roleID uint) (granted bool, err error) {
	source, exists, err := model.UserRoleSourceOf(tx, userID, roleID)
	if err != nil {
		return false, err
	}
	if !exists {
		if err := model.AssignUserRole(tx, userID, roleID, model.RoleOriginAPI); err != nil {
			return false, err
		}
		return true, nil
	}
	if source == model.RoleSourceMapped {
		if err := model.SetUserRoleSource(tx, userID, roleID, model.RoleSourceBoth); err != nil {
			return false, err
		}
	}
	return false, nil
}

// upsertRoleMappingFact 寫一筆映射事實（已存在則只更新命中時間）。
//
// 以 ON CONFLICT 一句完成而不是先查後寫：同一帳號同時經兩條途徑登入時，
// 先查後寫有 TOCTOU 窗，敗方會撞主鍵回錯而讓一次合法登入失敗。
func upsertRoleMappingFact(tx *gorm.DB, userID, roleID uint, channel string,
	matchedAt time.Time) error {
	res := tx.Exec(`INSERT INTO user_role_mappings (user_id, role_id, channel, matched_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (user_id, role_id, channel) DO UPDATE SET matched_at = ?`,
		userID, roleID, channel, matchedAt, matchedAt)
	if res.Error != nil {
		return fmt.Errorf("寫入映射事實失敗: %w", res.Error)
	}
	return nil
}

// roleStillMappedByAnyChannel 這個角色是否仍被任一條通道映射著。
//
// 判定要跨全部通道：只看本通道的話，兩條途徑都給了同一個角色時，
// 其中一條不再命中就會把關聯表的列刪掉，而另一條下次登入才會把它補回來
// ——中間這段時間權限是錯的，且刪列會推進憑證世代把人踢下線。
func roleStillMappedByAnyChannel(tx *gorm.DB, userID, roleID uint) (bool, error) {
	var n int64
	if err := tx.Model(&model.UserRoleMapping{}).
		Where("user_id = ? AND role_id = ?", userID, roleID).
		Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢角色的映射成分失敗: %w", err)
	}
	return n > 0, nil
}
