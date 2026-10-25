package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// 權限版本與使用者群組指派。
//
// authz_state.version 是單一計數：授權相關狀態的寫入與版本推進**在呼叫端的同一交易內**
// 完成，交易回滾則不推進；唯讀路徑不推進。其他模組經 AdvanceVersion 寫入，不直接寫表
// （資料表所有權）。目前沒有讀者。

// ErrAuthzStateMissing 權限狀態初始列不存在（遷移未套用）。
var ErrAuthzStateMissing = errors.New("authz_state 初始列不存在（權限模型遷移未套用）")

// AdvanceVersion 於呼叫端交易 tx 內把權限版本加一。tx 必須是交易（或測試用的單一連線）。
func AdvanceVersion(tx *gorm.DB) error {
	res := tx.Exec("UPDATE authz_state SET version = version + 1 WHERE id = 1")
	if res.Error != nil {
		return fmt.Errorf("推進權限版本失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrAuthzStateMissing
	}
	// 與版本推進同交易寫入可重放的權限狀態事件。
	// 事件寫入失敗使本交易（資料變更與版本）一併回滾。附證尚未啟用時為 no-op。
	return audit.RecordPermissionStateEvent(context.Background(), tx, model.PermEventChange, "")
}

// BeginPermissionChange 必須在同一交易內、第一個權限相關寫入「之前」呼叫：
// 比對目前權限狀態與上一筆事件的事後狀態，不一致（兩次合法事件之間有人直接改庫）就先寫一筆
// 獨立的無來源變動事件，之後的合法事件差集因此不含那些直寫。不阻擋合法寫入；
// 附證尚未啟用時為 no-op。AdvanceVersion 發生在寫入之後，看不到變更前狀態，所以這一步不能省略；
// 所有權限寫入點都必須在各自交易開頭呼叫。
func BeginPermissionChange(tx *gorm.DB) error {
	_, err := audit.RecordUntracedPermissionDrift(context.Background(), tx)
	return err
}

// SettlePermissionChange 於同一交易內、版本推進「之後」仍有權限寫入時，在交易結尾呼叫，
// 把推進後的寫入補記進事件鏈（不再推進版本），否則下一個交易的
// BeginPermissionChange 會把這些合法寫入誤記成無來源變動。無差異時不寫。
func SettlePermissionChange(tx *gorm.DB) error {
	return audit.SettlePermissionStateEvent(context.Background(), tx)
}

// LockStateForPermissionActivation 於呼叫端交易 tx 內對 authz_state 單列取 FOR UPDATE 列鎖，
// 持有到該交易結束。權限附證首次啟用（封章與接受的事件表為空路徑）用它與合法權限寫入
// （AdvanceVersion 的同列 UPDATE）序列化；經 audit.SetPermissionActivationLock 注入，
// audit 不直接讀這張表。錯誤原樣回傳：REPEATABLE READ 下快照後該列已被更新時 PG 回 40001，
// 呼叫端據此讓位重試。只在 PG 上被呼叫。
func LockStateForPermissionActivation(ctx context.Context, tx *gorm.DB) error {
	var version int64
	return tx.WithContext(ctx).Raw("SELECT version FROM authz_state WHERE id = 1 FOR UPDATE").Scan(&version).Error
}

// CurrentVersion 讀目前權限版本（測試與日後的讀者用；不推進）。
func CurrentVersion(db *gorm.DB) (int64, error) {
	var v int64
	if err := db.Raw("SELECT version FROM authz_state WHERE id = 1").Scan(&v).Error; err != nil {
		return 0, fmt.Errorf("讀取權限版本失敗: %w", err)
	}
	return v, nil
}

// SetUserGroupRoles 把使用者群組的角色指派整組替換為 roleIDs（全域範圍），並在同一交易內推進版本。
// 目前沒有呼叫它的 API，保留函式供角色定義功能使用。
func SetUserGroupRoles(tx *gorm.DB, groupID uint, roleIDs []uint, createdBy uint) error {
	if err := BeginPermissionChange(tx); err != nil {
		return err
	}
	if err := tx.Where("user_group_id = ?", groupID).Delete(&model.UserGroupRole{}).Error; err != nil {
		return fmt.Errorf("清除群組角色指派失敗: %w", err)
	}
	for _, rid := range roleIDs {
		row := model.UserGroupRole{UserGroupID: groupID, RoleID: rid, ScopeKind: model.ScopeKindGlobal, CreatedBy: &createdBy}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("寫入群組角色指派失敗: %w", err)
		}
	}
	return AdvanceVersion(tx)
}

// RemoveUserGroupRole 移除一筆使用者群組 × 角色指派，並在同一交易內推進版本。
// 指派不存在時不改變任何狀態、也不推進版本。
func RemoveUserGroupRole(tx *gorm.DB, groupID, roleID uint) error {
	if err := BeginPermissionChange(tx); err != nil {
		return err
	}
	res := tx.Where("user_group_id = ? AND role_id = ?", groupID, roleID).Delete(&model.UserGroupRole{})
	if res.Error != nil {
		return fmt.Errorf("移除群組角色指派失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil
	}
	return AdvanceVersion(tx)
}

// CountNodeScopedGroupRoleBindings 某角色以節點範圍給使用者群組的指派數（資料表由 authz 所有）。
func CountNodeScopedGroupRoleBindings(tx *gorm.DB, roleID uint) (int64, error) {
	var n int64
	if err := tx.Model(&model.UserGroupRole{}).Where("role_id = ? AND scope_kind = ?", roleID, model.ScopeKindNodes).Count(&n).Error; err != nil {
		return 0, fmt.Errorf("讀取群組節點範圍指派數失敗: %w", err)
	}
	return n, nil
}

// CountUserGroupRoleBindings 某角色的使用者群組指派數（資料表由 authz 所有；刪除角色前的引用檢查用）。
func CountUserGroupRoleBindings(tx *gorm.DB, roleID uint) (int64, error) {
	var n int64
	if err := tx.Model(&model.UserGroupRole{}).Where("role_id = ?", roleID).Count(&n).Error; err != nil {
		return 0, fmt.Errorf("讀取群組角色指派數失敗: %w", err)
	}
	return n, nil
}
