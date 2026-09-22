package audit

import (
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"time"
)

type AgentTaskReportPage struct {
	Versions       []model.AgentTaskReport `json:"versions"`
	Total          int64                   `json:"total"`
	MissingAtClose *bool                   `json:"missing_report_at_close"`
	ClosedAt       *time.Time              `json:"closed_at"`
}

func ReadAgentTaskReportPage(db *gorm.DB, requestID uint, closedAt *time.Time, offset, limit int) (*AgentTaskReportPage, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	q := db.Model(&model.AgentTaskReport{}).Where("access_request_id = ?", requestID)
	out := &AgentTaskReportPage{Versions: []model.AgentTaskReport{}, ClosedAt: closedAt}
	if err := q.Count(&out.Total).Error; err != nil {
		return nil, err
	}
	if closedAt != nil {
		var count int64
		if err := q.Session(&gorm.Session{}).Where("submitted_at <= ?", *closedAt).Count(&count).Error; err != nil {
			return nil, err
		}
		missing := count == 0
		out.MissingAtClose = &missing
	}
	if err := q.Order("version DESC").Offset(offset).Limit(limit).Find(&out.Versions).Error; err != nil {
		return nil, err
	}
	return out, nil
}
