package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func principalFailureQuery(db *gorm.DB, table string) *gorm.DB {
	// Canonical serialization is produced solely by encodeCauseParams.
	return db.Where("mechanism = ? AND cause_params LIKE ?", model.MechanismPrincipalStateIntegrity, `%"table":"`+table+`"%`)
}
func validPrincipalTable(table string) bool {
	return table == StateTablePrincipals || table == StateTableAgentTokens
}
func principalFailureLock(tx *gorm.DB, table string) error {
	if tx.Dialector.Name() != "postgres" {
		return nil
	}
	key := int64(7314101)
	if table == StateTableAgentTokens {
		key++
	}
	return tx.Exec("SELECT pg_advisory_xact_lock(?)", key).Error
}
func (s *AuditFailureService) ReportStateMismatch(table string, params map[string]string) error {
	if !validPrincipalTable(table) {
		return fmt.Errorf("unknown principal projection %q", table)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	created := false
	started := time.Now()
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := principalFailureLock(tx, table); err != nil {
			return err
		}
		var existing model.AuditFailureEvent
		err := principalFailureQuery(tx, table).Where("ended_at IS NULL").Clauses(clause.Locking{Strength: "UPDATE"}).First(&existing).Error
		if err == nil {
			var old map[string]string
			_ = json.Unmarshal([]byte(existing.CauseParams), &old)
			if old["since_seq"] == params["since_seq"] && old["actual_hash"] == params["actual_hash"] {
				return nil
			}
			if err := tx.Model(&existing).Update("ended_at", started).Error; err != nil {
				return err
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		// Only bounded metadata and identifiers belong in the stored detail.
		evidence := map[string]string{"table": table, "since_seq": params["since_seq"], "actual_hash": params["actual_hash"], "missing": params["missing"], "extra": params["extra"]}
		event := model.AuditFailureEvent{Mechanism: model.MechanismPrincipalStateIntegrity, StartedAt: started, Cause: CauseText(model.CausePrincipalStateMismatch, evidence), CauseCode: model.CausePrincipalStateMismatch, CauseParams: encodeCauseParams(model.CausePrincipalStateMismatch, evidence)}
		if err := tx.Create(&event).Error; err != nil {
			return err
		}
		created = true
		return nil
	})
	if err == nil && created {
		s.sendNotify(notifycat.EventAuditFailure, map[string]string{"mechanism": model.MechanismPrincipalStateIntegrity, "cause_code": model.CausePrincipalStateMismatch, "started_at": started.Format(time.RFC3339)})
	}
	return err
}
func (s *AuditFailureService) ResolveStateMismatch(table string) error {
	if !validPrincipalTable(table) {
		return fmt.Errorf("unknown principal projection %q", table)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var count int64
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := principalFailureLock(tx, table); err != nil {
			return err
		}
		result := principalFailureQuery(tx.Model(&model.AuditFailureEvent{}), table).Where("ended_at IS NULL").Update("ended_at", now)
		count = result.RowsAffected
		return result.Error
	})
	if err == nil && count > 0 {
		s.sendNotify(notifycat.EventAuditFailureResolved, map[string]string{"mechanism": model.MechanismPrincipalStateIntegrity, "interval": notifycat.IntervalUnknown})
	}
	return err
}
func (s *AuditFailureService) LatestByStateTable(table string) (*model.AuditFailureEvent, error) {
	if !validPrincipalTable(table) {
		return nil, fmt.Errorf("unknown principal projection")
	}
	var row model.AuditFailureEvent
	err := principalFailureQuery(s.db, table).Order("id DESC").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &row, err
}
