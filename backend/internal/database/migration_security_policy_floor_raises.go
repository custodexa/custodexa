package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 保留下限抬升紀錄增量。
//
// 內容：新表 security_policy_floor_raises，每列是啟動對帳把一個保留鍵抬升到下限（或
// 讓檢查點保留跟隨抬升）的紀錄。保留值的抬升本身不在 migration 內做，而在每次啟動的
// 冪等對帳（可重入、涵蓋還原後的資料）；本增量只建表、不回填、不改既有表。
//
// # Down 契約
//
// 不提供回滾：抬升紀錄是升級告知的依據，回退只走升級前備份。
func securityPolicyFloorRaisesDDL() []string {
	return []string{
		`CREATE TABLE security_policy_floor_raises (id bigserial, policy_key character varying(64) NOT NULL, old_value text NOT NULL, new_value text NOT NULL, reason character varying(32) NOT NULL, raised_at timestamp with time zone NOT NULL, product_version character varying(64) NOT NULL, CONSTRAINT security_policy_floor_raises_pkey PRIMARY KEY (id))`,
	}
}

func applySecurityPolicyFloorRaises(db *gorm.DB) error {
	for _, stmt := range securityPolicyFloorRaisesDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 security_policy_floor_raises DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackSecurityPolicyFloorRaises 不提供回滾；見檔頭 Down 契約。
func rollbackSecurityPolicyFloorRaises(_ *gorm.DB) error {
	return fmt.Errorf("retention floor raise records back the upgrade notice; restore the pre-upgrade backup instead")
}
