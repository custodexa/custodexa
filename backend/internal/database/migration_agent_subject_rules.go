package database

import (
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// subject_kind already exists from agent_audit_ledger. Seed only after that
// migration; keep edited rules on conflict and retain evidence on rollback.
func applyAgentSubjectRules(db *gorm.DB) error {
	for _, r := range builtinAlertRules {
		if r.SubjectKind != model.KindAgent {
			continue
		}
		if err := db.Exec(`INSERT INTO alert_rules (name,pattern,severity,action,enabled,protocols,direction,subject_kind,created_at,updated_at)
   VALUES (?,?,?,?,TRUE,?,?,?,NOW(),NOW()) ON CONFLICT (name) DO NOTHING`, r.Name, r.Pattern, r.Severity, r.Action, r.Protocols, r.Direction, r.SubjectKind).Error; err != nil {
			return err
		}
	}
	return nil
}
func rollbackAgentSubjectRules(db *gorm.DB) error {
	return fmt.Errorf("agent rule subjects and evidence must be retained; restore the pre-upgrade backup for an older reader")
}
