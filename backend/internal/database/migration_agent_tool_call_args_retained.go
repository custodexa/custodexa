package database

import "gorm.io/gorm"

func agentToolCallArgsRetainedDDL() []string {
	return []string{
		`ALTER TABLE agent_tool_calls ADD COLUMN args_sealed bytea NULL`,
		`ALTER TABLE agent_tool_calls ADD COLUMN args_retained boolean NOT NULL DEFAULT false`,
	}
}

func applyAgentToolCallArgsRetained(db *gorm.DB) error {
	for _, sql := range agentToolCallArgsRetainedDDL() {
		if err := db.Exec(sql).Error; err != nil {
			return err
		}
	}
	return nil
}

// Evidence survives application rollback, as do existing signed ledger rows.
func rollbackAgentToolCallArgsRetained(*gorm.DB) error { return nil }
