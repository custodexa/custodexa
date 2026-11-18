package database

import (
	"fmt"

	"gorm.io/gorm"
)

// API token 授權角色的層級：api_token_roles 加 level 欄（read｜read_write），NOT NULL、預設 read_write；
// api_tokens 加 levels_recorded 欄（boolean，NOT NULL、預設 false），本版起建立的 token 一律寫為 true，
// 供呈現「升級前建立」，不參與判定。
//
// 純加法，無資料步驟：既有列由預設值取得 read_write 與 false，行為與加欄前相同（每個授權角色皆可讀寫）。
// 讀取端把不認得的值視為唯讀。DDL 無條件、不用 IF NOT EXISTS，在已套用的庫上重跑必須大聲失敗。
//
// # Down 契約
//
// Down 有損（刪欄即失去層級，所有授權角色回到可讀寫），只供 parity 守衛與開發環境使用；生產回退只走
// 部署回舊版映像並還原升級前備份。升級前的備份不含升級後建立的 token，還原後不存在唯讀的 token。
// 較早的版本不認得層級，不可直接跑在已套用本條的資料庫上（見營運程序）。
func apiTokenRoleLevelDDL() []string {
	return []string{
		`ALTER TABLE api_token_roles ADD COLUMN level character varying(16) DEFAULT 'read_write'::character varying NOT NULL`,
		`ALTER TABLE api_tokens ADD COLUMN levels_recorded boolean DEFAULT false NOT NULL`,
	}
}

func applyAPITokenRoleLevel(db *gorm.DB) error {
	for _, stmt := range apiTokenRoleLevelDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 api_token_role_level DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackAPITokenRoleLevel 見檔頭 Down 契約。
func rollbackAPITokenRoleLevel(db *gorm.DB) error {
	for _, stmt := range []string{
		`ALTER TABLE api_tokens DROP COLUMN levels_recorded`,
		`ALTER TABLE api_token_roles DROP COLUMN level`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 api_token_role_level 失敗（%s）: %w", stmt, err)
		}
	}
	return nil
}
