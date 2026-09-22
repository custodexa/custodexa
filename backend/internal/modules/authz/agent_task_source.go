package authz

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"time"
)

// ReadAgentTaskForReport serializes submissions with task closure on the same row lock.
func ReadAgentTaskForReport(tx *gorm.DB, id uint) (audit.AgentTaskFacts, error) {
	var task model.AccessRequest
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&task, id).Error; err != nil {
		return audit.AgentTaskFacts{}, err
	}
	return audit.AgentTaskFacts{ID: task.ID, RequesterID: task.RequesterID, ExecutorID: executorIDValue(task.ExecutorUserID, task.RequesterID), ClosedAt: task.ClosedAt}, nil
}

// CloseAgentTask is called under ReadAgentTaskForReport's lock and executor check.
// The initial close instant is immutable, including on later report revisions.
func CloseAgentTask(tx *gorm.DB, id uint, at time.Time) error {
	return tx.Model(&model.AccessRequest{}).Where("id=? AND closed_at IS NULL", id).Update("closed_at", at).Error
}

// AgentTask reads either autonomous or delegated execution without broadening ListMine.
func (s *AccessRequestService) AgentTask(userID, id uint) (*model.AccessRequest, error) {
	var r model.AccessRequest
	if err := s.db.Preload("Items").First(&r, id).Error; err != nil {
		return nil, err
	}
	if executorIDValue(r.ExecutorUserID, r.RequesterID) != userID {
		return nil, ErrAccessRequestNotFound
	}
	s.attachApprovalProgress([]*model.AccessRequest{&r})
	return &r, nil
}
