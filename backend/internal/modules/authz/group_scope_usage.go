package authz

import (
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// GroupScopeUsage returns current approver and requester scope counts for a user group.
func GroupScopeUsage(tx *gorm.DB, groupID uint) (approver, requester int64, err error) {
	if err = tx.Model(&model.ApproverScope{}).Where("approver_group_id=?", groupID).Count(&approver).Error; err != nil {
		return
	}
	err = tx.Model(&model.ApproverScope{}).Where("subject_group_id=?", groupID).Count(&requester).Error
	return
}
