package authz

import (
	"context"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"time"
)

// ReadAgentTask returns one agent request, never a page searched on the client.
func ReadAgentTask(ctx context.Context, db *gorm.DB, id uint, approvalOffset, limit int) (*model.AccessRequest, int64, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	if approvalOffset < 0 {
		approvalOffset = 0
	}
	db = db.WithContext(ctx)
	var request model.AccessRequest
	err := db.Model(&model.AccessRequest{}).
		Joins("JOIN users agent ON agent.id = COALESCE(access_requests.executor_user_id, access_requests.requester_id) AND agent.kind = ?", model.KindAgent).
		Preload("Items", func(q *gorm.DB) *gorm.DB { return q.Order("id").Limit(20) }).
		Preload("Requester", func(q *gorm.DB) *gorm.DB { return q.Select("id", "username", "kind", "owner_user_id") }).
		Preload("Approvals", func(q *gorm.DB) *gorm.DB { return q.Order("id").Offset(approvalOffset).Limit(limit) }).First(&request, id).Error
	if err != nil {
		return nil, 0, err
	}
	s := &AccessRequestService{db: db}
	if err := s.attachReadFields([]*model.AccessRequest{&request}, time.Now()); err != nil {
		return nil, 0, err
	}
	var approvalTotal int64
	if err := db.Model(&model.AccessRequestApproval{}).Where("request_id = ?", id).Count(&approvalTotal).Error; err != nil {
		return nil, 0, err
	}
	return &request, approvalTotal, nil
}
