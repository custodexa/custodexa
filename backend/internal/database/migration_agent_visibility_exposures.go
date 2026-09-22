package database

import (
	"fmt"
	"gorm.io/gorm"
)

// Down retains disclosure evidence; disabling readers/writers is the rollback.
func agentVisibilityExposuresDDL() []string {
	return []string{`CREATE TABLE agent_visibility_exposures (
 user_id bigint NOT NULL, asset_id bigint NOT NULL,
 first_seen_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL,
 CONSTRAINT agent_visibility_exposures_pkey PRIMARY KEY (user_id, asset_id))`}
}
func applyAgentVisibilityExposures(db *gorm.DB) error {
	for _, sql := range agentVisibilityExposuresDDL() {
		if err := db.Exec(sql).Error; err != nil {
			return err
		}
	}
	return nil
}
func rollbackAgentVisibilityExposures(db *gorm.DB) error {
	return fmt.Errorf("agent visibility exposures retain evidence; disable readers/writers without deleting data")
}
