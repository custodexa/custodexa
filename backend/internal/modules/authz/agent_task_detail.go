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
	if err := fillApproverNames(db, request.Approvals); err != nil {
		return nil, 0, err
	}
	// The stored column is null when the agent opened the task for itself; the join above
	// already proved the effective executor is that agent. Project the effective id on this
	// read path so a reader never has to know that null means "the requester". The request
	// is never written back from here, so the stored semantics stay untouched.
	if request.ExecutorUserID == nil {
		effective := executorIDValue(request.ExecutorUserID, request.RequesterID)
		request.ExecutorUserID = &effective
	}
	var approvalTotal int64
	if err := db.Model(&model.AccessRequestApproval{}).Where("request_id = ?", id).Count(&approvalTotal).Error; err != nil {
		return nil, 0, err
	}
	return &request, approvalTotal, nil
}

// fillApproverNames resolves every approver on the returned approval page in one query.
func fillApproverNames(db *gorm.DB, approvals []model.AccessRequestApproval) error {
	ids := make([]uint, 0, len(approvals))
	seen := make(map[uint]bool, len(approvals))
	for i := range approvals {
		approvals[i].ApproverUsername = ""
		if id := approvals[i].ApproverID; id != 0 && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	var users []model.User
	if err := db.Model(&model.User{}).Select("id", "username").Where("id IN ?", ids).Find(&users).Error; err != nil {
		return err
	}
	names := make(map[uint]string, len(users))
	for _, u := range users {
		names[u.ID] = u.Username
	}
	for i := range approvals {
		approvals[i].ApproverUsername = names[approvals[i].ApproverID]
	}
	return nil
}
