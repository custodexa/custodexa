package database

import (
	"fmt"
	"gorm.io/gorm"
)

// Down retains forensic records. Revert readers/writers to disable this feature.
func agentBreakerAlertDDL() []string {
	return []string{
		`ALTER TABLE command_alerts ALTER COLUMN kind TYPE varchar(32)`,
		`ALTER TABLE command_alerts ALTER COLUMN session_id DROP NOT NULL`,
		`ALTER TABLE command_alerts DROP CONSTRAINT command_alerts_kind_check`,
		`ALTER TABLE command_alerts ADD CONSTRAINT command_alerts_kind_check CHECK (kind IN ('rule','audit_degraded','new_source_ip','agent_breaker_tripped'))`,
		`ALTER TABLE command_alerts ADD CONSTRAINT command_alerts_session_ref CHECK (session_id IS NOT NULL OR kind='agent_breaker_tripped')`,
	}
}
func applyAgentBreakerAlert(db *gorm.DB) error {
	for _, sql := range agentBreakerAlertDDL() {
		if err := db.Exec(sql).Error; err != nil {
			return err
		}
	}
	return nil
}
func rollbackAgentBreakerAlert(db *gorm.DB) error {
	return fmt.Errorf("agent breaker retains evidence; disable readers/writers without deleting data")
}
