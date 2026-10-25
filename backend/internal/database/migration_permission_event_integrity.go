package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 權限狀態事件的逐列完整性驗證碼（權限模型調和與還原）。
//
// permission_state_events 加兩欄，與 audit_logs／agent_tool_calls 同一組完整性密鑰：
//   - integrity_hmac：HMAC-SHA256 的 hex，空字串＝未蓋章；
//   - key_version：蓋章鑰版本。
//
// 只加結構、不回填：本 migration 執行時拿不到完整性密鑰，既有列一律保持空字串。
// 空字串的列在對帳重放時視為不可信，其帶來的狀態計為無來源變動並告警，
// 由超級管理員確認（寫審計）後成為新基準——升級前就存在的事件列由此留下一次
// 受審計的接受紀錄，之後的事件一律帶驗證碼。
//
// DDL 無條件，不用 IF NOT EXISTS；版本集合負責避免重跑。
//
// # Down 契約
//
// 不提供回滾：與 20261016_authz_permission_model 同一個模型邊界，回退只走升級前備份。
func permissionEventIntegrityDDL() []string {
	return []string{
		`ALTER TABLE permission_state_events ADD COLUMN integrity_hmac character varying(64) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE permission_state_events ADD COLUMN key_version bigint DEFAULT 0 NOT NULL`,
	}
}

func applyPermissionEventIntegrity(db *gorm.DB) error {
	for _, stmt := range permissionEventIntegrityDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 permission_event_integrity DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackPermissionEventIntegrity 不提供回滾；見檔頭 Down 契約。
func rollbackPermissionEventIntegrity(db *gorm.DB) error {
	return fmt.Errorf("permission event integrity has no rollback; restore the pre-upgrade backup")
}
