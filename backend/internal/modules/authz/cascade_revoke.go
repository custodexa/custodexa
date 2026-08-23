package authz

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 交易級聯撤銷的 tx-taking 窄 port（拍板形態）。
//
// **問題**：刪除資產組／使用者群組／使用者時，必須在**同一交易**內連動撤銷 authz 的
// 授權列與審核範圍（不留幽靈引用）。呼叫方（asset／identity）
// 原本直接對 `model.AssetAuthorization`／`model.ApproverScope` 下 `Delete`——
// 那是跨模組寫入他模組的表，撞資料邊界閘門的「寫入非自有表一律紅」。
//
// **處置**：authz 提供 tx-taking 方法，呼叫方交出自己的 `tx`。呼叫方以**消費者側
// 窄介面**宣告意圖，由組裝根注入本型別，故 asset **不 import authz**（矩陣 asset→authz ✗）。
//
// **🔴 誠實邊界（不得誤讀為編譯器保護）**：交易句柄一旦交出去，
// **編譯器管不到它寫哪張表**——`*gorm.DB` 的寫入目標是執行期決定的。
// DoD 第 1 條「跨模組存取只經對外介面（編譯器可證）」在這類路徑上**名存實亡**，
// 剩下的保護只有：(a) 本檔方法體是唯一的寫入處（窄化），
// (b) `cmd/server/tx_taking_whitelist_test.go` 的具名白名單（每條附理由，
// 無理由即紅、未登記的呼叫點即紅、新增的 tx-taking 匯出方法未登記即紅），
// (c) code review。**白名單有 commit 權者可刪**，這是設計上接受的殘餘風險。
//
// **零行為變更**：三個方法的查詢條件、刪除順序、`RowsAffected` 語義與錯誤包裝詞
// 皆自原呼叫點**逐字搬入**。錯誤包裝詞屬呼叫方的用語，為求逐位相同而一併搬來；
// 這是刻意的取捨，不在此處重寫。

// RevokeByAssetGroup 資產組（節點）刪除時的級聯撤銷（原 `asset_group_service.go:523,530`）。
// 回傳（連動軟刪的授權筆數、連動軟刪的審核範圍筆數）——兩者皆為呼叫端審計
// Details 的欄位（`revoked_authorizations`／`revoked_approver_scopes`），故必須分別回傳。
func (s *AssetAuthorizationService) RevokeByAssetGroup(tx *gorm.DB, groupID uint) (int64, int64, error) {
	// 連動軟刪節點授權：節點消失後這些記錄永不再命中，留著只會誤導授權列表
	res := tx.Where("asset_group_id = ?", groupID).Delete(&model.AssetAuthorization{})
	if res.Error != nil {
		return 0, 0, res.Error
	}
	revoked := res.RowsAffected

	// 連動軟刪 approver 審核範圍（範圍與授權客體同構，懸掛範圍同樣誤導）
	scopeRes := tx.Where("asset_group_id = ?", groupID).Delete(&model.ApproverScope{})
	if scopeRes.Error != nil {
		return 0, 0, scopeRes.Error
	}
	return revoked, scopeRes.RowsAffected, nil
}

// RevokeByAsset 資產刪除時的級聯撤銷（塊 2）。
// 回傳（連動軟刪的授權筆數、連動軟刪的審核範圍筆數），與 RevokeByAssetGroup 同形。
//
// **為何需要**：`CheckPermission` 與其同語義姊妹查詢只查 `asset_authorizations` 單表、
// 不 join `assets`，故資產被軟刪後其授權在權限判定中**仍然命中**。修法作用於授權
// 記錄本身而非在各查詢加「資產未刪」條件——同語義查詢有三個（權限檢查、連線來源
// 解析、帳號範圍解析），逐處加條件會使日後新增的同構查詢預設不受保護。
//
// **審核範圍一併撤銷**：`ApproverScope.AssetID` 直指資產，資產消失後留下的是懸掛
// 範圍——與 RevokeByAssetGroup 處理 `asset_group_id` 的理由相同。
//
// 軟刪而非硬刪：授權記錄是稽核軌跡，「誰曾被授權存取哪台資產」在資產刪除後仍須可查。
func (s *AssetAuthorizationService) RevokeByAsset(tx *gorm.DB, assetID uint) (int64, int64, error) {
	res := tx.Where("asset_id = ?", assetID).Delete(&model.AssetAuthorization{})
	if res.Error != nil {
		return 0, 0, fmt.Errorf("連動撤銷資產授權失敗: %w", res.Error)
	}
	revoked := res.RowsAffected

	scopeRes := tx.Where("asset_id = ?", assetID).Delete(&model.ApproverScope{})
	if scopeRes.Error != nil {
		return 0, 0, fmt.Errorf("連動移除資產審核範圍失敗: %w", scopeRes.Error)
	}
	return revoked, scopeRes.RowsAffected, nil
}

// RevokeByUserGroup 使用者群組刪除時的級聯撤銷（原 `user_group_service.go:110,122`）。
// 回傳連動軟刪的授權筆數。
func (s *AssetAuthorizationService) RevokeByUserGroup(tx *gorm.DB, groupID uint) (int64, error) {
	// 連動軟刪授權（不留惰性記錄誤導審計）
	res := tx.Where("user_group_id = ?", groupID).Delete(&model.AssetAuthorization{})
	if res.Error != nil {
		return 0, fmt.Errorf("連動撤銷群組授權失敗: %w", res.Error)
	}
	revoked := res.RowsAffected

	// 連動軟刪審核範圍：群組作審核方
	//（approver_group_id）或作申請人群組（subject_group_id）的範圍一併失效——
	// 否則留下 approver_group=null 的幽靈範圍，且殘留成員列可回復審核資格。
	if err := tx.Where("approver_group_id = ? OR subject_group_id = ?", groupID, groupID).
		Delete(&model.ApproverScope{}).Error; err != nil {
		return 0, fmt.Errorf("連動移除群組審核範圍失敗: %w", err)
	}
	return revoked, nil
}

// RevokeByUser 使用者刪除時的級聯撤銷（原 `user_service.go:529`）：
// 審核範圍（作審核方 approver_id 或作申請人 subject_user_id）連動軟刪。
func (s *AssetAuthorizationService) RevokeByUser(tx *gorm.DB, userID uint) error {
	if err := tx.Where("approver_id = ? OR subject_user_id = ?", userID, userID).
		Delete(&model.ApproverScope{}).Error; err != nil {
		return fmt.Errorf("連動移除使用者審核範圍失敗: %w", err)
	}
	return nil
}
