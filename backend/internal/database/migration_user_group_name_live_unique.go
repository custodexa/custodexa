package database

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// 使用者群組名稱的唯一性只計未刪除列：idx_user_groups_name 由涵蓋全部列的唯一索引換成
// `WHERE deleted_at IS NULL` 的部分唯一索引，與 idx_users_username 同型。刪除群組後即可用
// 同一個名稱重建；已刪除的舊列保留原名，不改寫（稽核與歷史呈現仍以刪除當時的名稱顯示）。
//
// 新索引比舊索引寬鬆：舊索引成立的資料，新索引必然成立，升級方向不會因既有資料失敗。
// 無資料步驟，既有列不變。
//
// # Down 契約
//
// Down 重建涵蓋全部列的唯一索引。升級後若已出現同名的列（已刪除與現存同名，或兩筆已刪除
// 同名），舊索引無法成立：Down 在任何 DDL 之前回錯並指出重複的名稱數，新索引與版本紀錄維持
// 不變（回滾在同一交易內進行），此時只能還原升級前備份。檢查之前先鎖住群組表，檢查到重建索引之間
// 沒有並發寫入能讓結論失效。
func userGroupNameLiveUniqueDDL() []string {
	return []string{
		`DROP INDEX idx_user_groups_name`,
		`CREATE UNIQUE INDEX idx_user_groups_name ON user_groups USING btree (name) WHERE (deleted_at IS NULL)`,
	}
}

func applyUserGroupNameLiveUnique(db *gorm.DB) error {
	for _, stmt := range userGroupNameLiveUniqueDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 user_group_name_live_unique DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// userGroupNameDownSampleLimit Down 失敗訊息列出的重複名稱上限。
const userGroupNameDownSampleLimit = 5

// rollbackUserGroupNameLiveUnique 見檔頭 Down 契約。
//
// 同名檢查之前先以 ACCESS EXCLUSIVE 鎖住 user_groups 並持有到交易結束：檢查到重建索引之間不會有
// 其他交易寫入同名列，檢查的結論在重建時仍然成立；正在進行的寫入交易先完成，檢查看得到它的結果。
// 鎖的強度與其後 DROP INDEX 所需相同，不發生鎖升級。
func rollbackUserGroupNameLiveUnique(db *gorm.DB) error {
	if db.Dialector.Name() == "postgres" {
		if err := db.Exec(`LOCK TABLE user_groups IN ACCESS EXCLUSIVE MODE`).Error; err != nil {
			return fmt.Errorf("回滾 user_group_name_live_unique 前鎖定 user_groups 失敗: %w", err)
		}
	}
	var dups []struct {
		Name  string
		Count int64
	}
	if err := db.Raw(`SELECT name, count(*) AS count FROM user_groups GROUP BY name HAVING count(*) > 1 ORDER BY name`).
		Scan(&dups).Error; err != nil {
		return fmt.Errorf("回滾 user_group_name_live_unique 前檢查同名列失敗: %w", err)
	}
	if len(dups) > 0 {
		shown := make([]string, 0, userGroupNameDownSampleLimit)
		for i, d := range dups {
			if i == userGroupNameDownSampleLimit {
				break
			}
			shown = append(shown, fmt.Sprintf("%q×%d", d.Name, d.Count))
		}
		return fmt.Errorf("無法回滾 user_group_name_live_unique：user_groups 有 %d 個名稱同時出現在多列"+
			"（含已刪除的列，例如 %s），涵蓋全部列的唯一索引無法重建；新索引與版本紀錄維持不變，"+
			"回退請還原升級前的備份", len(dups), strings.Join(shown, "、"))
	}
	for _, stmt := range []string{
		`DROP INDEX idx_user_groups_name`,
		`CREATE UNIQUE INDEX idx_user_groups_name ON user_groups USING btree (name)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 user_group_name_live_unique 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
