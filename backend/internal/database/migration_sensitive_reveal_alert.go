package database

import (
	"fmt"

	"gorm.io/gorm"
)

func sensitiveRevealAlertDDL() []string {
	return []string{
		`ALTER TABLE command_alerts DROP CONSTRAINT command_alerts_kind_check`,
		`ALTER TABLE command_alerts ADD CONSTRAINT command_alerts_kind_check CHECK (kind IN ('rule','audit_degraded','new_source_ip','agent_breaker_tripped','sensitive_reveal'))`,
	}
}
func applySensitiveRevealAlert(db *gorm.DB) error {
	for _, sql := range sensitiveRevealAlertDDL() {
		if err := db.Exec(sql).Error; err != nil {
			return err
		}
	}
	return nil
}
func rollbackSensitiveRevealAlert(_ *gorm.DB) error {
	return fmt.Errorf("sensitive reveal alerts retain evidence; disable the policy without deleting records")
}
