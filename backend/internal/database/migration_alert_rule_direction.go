package database

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 輸出敏感資料規則的增量：新增方向及 CHECK，原有列取 input 預設值，
// 隨後插入兩條 output 終態種子。新裝與已套 baseline 的部署走同一條 Up。
// DDL 無條件，不用 IF NOT EXISTS；migration 版本集合負責避免重跑。
//
// # Down 契約（讀完再用）
//
// 本 Down 有損：刪掉 direction 後，輸出面規則的方向值沒有第二處存放。
// 規則列仍在，但再次 Up 無法還原它們原有的方向，不能視為可逆升級。
// 生產沒有回滾入口；回退須部署舊版映像並還原升級前備份，
// 不以本 Down 取代備份還原（同 migration_kek_topology.go）。
func alertRuleDirectionDDL() []string {
	return []string{
		`ALTER TABLE alert_rules ADD COLUMN direction character varying(10) NOT NULL DEFAULT 'input'`,
		`ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_direction_check CHECK (direction IN ('input','output'))`,
	}
}

func applyAlertRuleDirection(db *gorm.DB) error {
	for _, stmt := range alertRuleDirectionDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 alert_rule_direction DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return seedBuiltinAlertRulesForDirection(db, model.DirectionOutput)
}

// rollbackAlertRuleDirection 有損刪除方向；見檔頭 Down 契約。
func rollbackAlertRuleDirection(db *gorm.DB) error {
	for _, stmt := range []string{
		`ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_direction_check`,
		`ALTER TABLE alert_rules DROP COLUMN direction`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 alert_rule_direction 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
