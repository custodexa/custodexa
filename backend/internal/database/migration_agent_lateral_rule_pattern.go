package database

import "gorm.io/gorm"

// 資料 migration（無 schema 變更）：把已安裝站點上的「Agent 橫向移動阻斷」
// 出廠規則升級為現行 pattern。
//
// 為什麼需要它：出廠規則只在建表的那一刻以 `ON CONFLICT (name) DO NOTHING`
// 插種子（見 migration_agent_subject_rules.go），既有站點升級時那條 INSERT 不
// 會生效，於是舊 pattern 會一直留著——舊版在**任何位置**比對指令字，讀取
// ~/.ssh 這類路徑即誤觸阻斷。
//
// 邊界：WHERE 只認 agentLateralLegacyPatterns 列舉的歷史出廠值。管理員調校過的
// 規則（pattern 不等於任何歷史值）一律不動，升級不得覆寫站點自己的判斷。
func applyAgentLateralRulePattern(db *gorm.DB) error {
	return db.Exec(
		`UPDATE alert_rules SET pattern = ?, updated_at = CURRENT_TIMESTAMP
   WHERE name = ? AND pattern IN (?)`,
		AgentLateralRulePattern, AgentLateralRuleName, agentLateralLegacyPatterns,
	).Error
}

// Down 為 no-op：舊 pattern 是已知的誤判來源，回退等於把誤觸阻斷裝回去；
// 且此處無法分辨「本次升級改的」與「管理員升級後又自行改回舊值的」，
// 一律回寫會覆蓋後者。要退版請還原升級前的備份。
func rollbackAgentLateralRulePattern(db *gorm.DB) error { return nil }
