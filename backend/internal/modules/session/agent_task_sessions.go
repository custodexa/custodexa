package session

import (
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

func AgentTaskSessionIDs(db *gorm.DB, requestID uint, offset, limit int) ([]uint, int64, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	q := db.Model(&model.Session{}).Where("access_request_id = ?", requestID)
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	ids := []uint{}
	err := q.Order("id").Offset(offset).Limit(limit).Pluck("id", &ids).Error
	return ids, total, err
}
