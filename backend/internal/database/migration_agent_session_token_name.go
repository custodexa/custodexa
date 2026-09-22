package database

import "gorm.io/gorm"

func agentSessionTokenNameDDL() []string {
	return []string{`ALTER TABLE sessions ADD COLUMN agent_token_name varchar(100) NULL`}
}
func applyAgentSessionTokenName(db *gorm.DB) error {
	for _, sql := range agentSessionTokenNameDDL() {
		if err := db.Exec(sql).Error; err != nil {
			return err
		}
	}
	return nil
}

// Rollback disables the feature by using the older application. Retain snapshots.
func rollbackAgentSessionTokenName(db *gorm.DB) error { return nil }
