package authz

import (
	"context"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

type AgentTaskFilter struct {
	Subject, Owner *uint
	From, To       *time.Time
	ReportStatus   string
	Offset, Limit  int
}
type AgentTaskRow struct {
	ID            uint   `json:"id"`
	Subject       uint   `json:"subject"`
	Username      string `json:"username"`
	OwnerUserID   *uint  `json:"owner_user_id"`
	OwnerUsername string `json:"owner_username"`
	// OnBehalfOfUsername names the human the task was filed for; empty when the agent
	// filed for itself (requester and executor are the same principal).
	OnBehalfOfUsername string     `json:"on_behalf_of_username"`
	Reason             string     `json:"reason"`
	Status             string     `json:"status"`
	ReportStatus       string     `json:"report_status"`
	CreatedAt          time.Time  `json:"created_at"`
	ClosedAt           *time.Time `json:"closed_at"`
}

// QueryAgentTasks is a read projection. Owner is current, not a historical snapshot.
func QueryAgentTasks(ctx context.Context, db *gorm.DB, f AgentTaskFilter) ([]AgentTaskRow, int64, error) {
	const reportStatus = "CASE WHEN access_requests.id IN (?) THEN 'submitted' WHEN access_requests.closed_at IS NOT NULL THEN 'missing' ELSE 'not_submitted' END"
	q := db.WithContext(ctx).Model(&model.AccessRequest{}).Joins("JOIN users agent ON agent.id = COALESCE(access_requests.executor_user_id, access_requests.requester_id) AND agent.kind = ?", model.KindAgent)
	if f.Subject != nil {
		q = q.Where("agent.id = ?", *f.Subject)
	}
	if f.Owner != nil {
		q = q.Where("agent.owner_user_id = ?", *f.Owner)
	}
	if f.From != nil {
		q = q.Where("access_requests.created_at >= ?", *f.From)
	}
	if f.To != nil {
		q = q.Where("access_requests.created_at < ?", *f.To)
	}
	if f.ReportStatus != "" {
		q = q.Where("("+reportStatus+") = ?", audit.AgentTaskReportRequestIDs(db), f.ReportStatus)
	}
	if f.Limit <= 0 || f.Limit > 100 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	rows := []AgentTaskRow{}
	const onBehalfOf = "CASE WHEN access_requests.requester_id <> agent.id THEN COALESCE(requester.username, '') ELSE '' END"
	err := q.Joins("LEFT JOIN users owner ON owner.id = agent.owner_user_id").Joins("LEFT JOIN users requester ON requester.id = access_requests.requester_id").Select("access_requests.id, agent.id AS subject, agent.username, agent.owner_user_id, owner.username AS owner_username, "+onBehalfOf+" AS on_behalf_of_username, access_requests.reason, access_requests.status, access_requests.created_at, access_requests.closed_at, "+reportStatus+" AS report_status", audit.AgentTaskReportRequestIDs(db)).Order("access_requests.created_at DESC, access_requests.id DESC").Offset(f.Offset).Limit(f.Limit).Scan(&rows).Error
	return rows, total, err
}
