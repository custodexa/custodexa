package database

import "gorm.io/gorm"

// No data columns change: preserve single-open semantics for legacy mechanisms,
// while each principal projection has its own open failure interval.
func principalIntegrityDDL() []string {
	return []string{
		`DROP INDEX idx_failure_events_single_open`,
		`CREATE UNIQUE INDEX idx_failure_events_single_open ON audit_failure_events (mechanism) WHERE ended_at IS NULL AND mechanism <> 'principal_state_integrity'`,
		`CREATE UNIQUE INDEX idx_failure_events_principal_open ON audit_failure_events ((cause_params::jsonb->>'table')) WHERE ended_at IS NULL AND mechanism = 'principal_state_integrity'`,
	}
}
func applyPrincipalIntegrity(db *gorm.DB) error {
	for _, stmt := range principalIntegrityDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
	}
	return nil
}
