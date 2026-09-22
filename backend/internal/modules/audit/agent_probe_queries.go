package audit

import (
	"context"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// QueryAgentProbeEvents returns observations, not reconstructed trip/release cycles.
func QueryAgentProbeEvents(ctx context.Context, db *gorm.DB, userID uint, from, to *time.Time, offset, limit int) ([]model.AgentProbeEvent, int64, error) {
	q := db.WithContext(ctx).Model(&model.AgentProbeEvent{}).Where("user_id = ?", userID)
	if from != nil {
		q = q.Where("created_at >= ?", *from)
	}
	if to != nil {
		q = q.Where("created_at < ?", *to)
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	rows := []model.AgentProbeEvent{}
	err := q.Order("created_at DESC, id DESC").Offset(offset).Limit(limit).Find(&rows).Error
	return rows, total, err
}
