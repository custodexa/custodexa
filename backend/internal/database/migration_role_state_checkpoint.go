package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 角色指派納入檢查點鏈的資料層增量 migration（role-assignment-integrity）。
// 沿既有增量的紀律：DDL 無條件、不用 IF NOT EXISTS——在已套用的庫上重跑
// 必須大聲失敗，而非靜默 no-op。
//
// # Up 做什麼
//
// audit_checkpoints 加四欄，**全部可空、全部純加法、無回填**：
//
//  1. role_state_hash：封章當下 user_roles 快照本體的長度前綴 SHA-256（hex）。
//  2. role_state_snapshot：快照本體（canonical JSON，以表名為鍵）。**入庫的理由
//     是對帳要能重放上一狀態**——只留雜湊推不回集合，差集就算不出來。
//  3. role_state_count：快照筆數，供呈現與規模告警。
//  4. role_state_reconciled：封章當下的對帳結果；可空的第三態是「該次封章未對帳」。
//
// **既有列一律留空，且這是語義而非缺漏**：本能力之前封的檢查點不涵蓋角色指派，
// 空值即「尚未涵蓋」，驗證端據此顯示未涵蓋而不是不符。升級後首個封章起才有值。
//
// # 為什麼不加索引
//
// 四欄的讀者只有「取最近一個含快照的檢查點」與「以 seq 取單點」，前者已由
// seq 的既有唯一索引承擔（自鏈尾往回找），後者是主鍵查詢。為可空欄位加索引
// 只會增加封章寫入成本而無查詢受益。
//
// # Down 契約（讀完再用）
//
// **本 Down 純刪欄**：刪掉的四欄都是本能力自己產生的證據投影，不含任何
// 其他功能的資料，故回退後系統回到「檢查點不涵蓋角色指派」的既有形態，
// 舊檢查點續以 cp-agg-v1 驗證通過。**但已封的 v2 檢查點會因此失去
// 簽章輸入的一部分而永久驗不過**——回退前必須連同產品版本一起退回，
// 不可只退 schema。生產沒有回滾入口（RollbackMigration 無產品碼呼叫者，
// 回退手段是部署回舊版映像並還原升級前備份，docs/ops/upgrade-sop.md §4）。
func roleStateCheckpointDDL() []string {
	return []string{
		`ALTER TABLE audit_checkpoints ADD COLUMN role_state_hash character varying(64)`,
		`ALTER TABLE audit_checkpoints ADD COLUMN role_state_snapshot text`,
		`ALTER TABLE audit_checkpoints ADD COLUMN role_state_count bigint`,
		`ALTER TABLE audit_checkpoints ADD COLUMN role_state_reconciled boolean`,
	}
}

func applyRoleStateCheckpoint(db *gorm.DB) error {
	for _, stmt := range roleStateCheckpointDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 role_state_checkpoint DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackRoleStateCheckpoint 反序刪欄。見本檔檔頭的 Down 契約。
func rollbackRoleStateCheckpoint(db *gorm.DB) error {
	stmts := []string{
		`ALTER TABLE audit_checkpoints DROP COLUMN role_state_reconciled`,
		`ALTER TABLE audit_checkpoints DROP COLUMN role_state_count`,
		`ALTER TABLE audit_checkpoints DROP COLUMN role_state_snapshot`,
		`ALTER TABLE audit_checkpoints DROP COLUMN role_state_hash`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 role_state_checkpoint 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
