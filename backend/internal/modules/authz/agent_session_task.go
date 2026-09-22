package authz

import (
	"errors"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// BindAgentSessionTask reads the persisted task, not caller-supplied delegation.
func BindAgentSessionTask(tx *gorm.DB, sess *model.Session) error {
	if sess.AccessRequestID == nil {
		return errors.New("agent session task required")
	}
	var task model.AccessRequest
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&task, *sess.AccessRequestID).Error; err != nil {
		return err
	}
	if executorIDValue(task.ExecutorUserID, task.RequesterID) != sess.UserID || task.ClosedAt != nil {
		return errors.New("agent task unavailable")
	}
	sess.OnBehalfOfUserID = nil
	if task.RequesterID != sess.UserID {
		id := task.RequesterID
		sess.OnBehalfOfUserID = &id
	}
	return nil
}
