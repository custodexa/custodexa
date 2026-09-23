package audit

import (
	"context"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// AgentProbeEventRow is the read projection handed to the UI. asset_name exists
// only so a screen does not have to name a target by its number; it is the
// asset's current name, not a snapshot of the name at observation time. Removed
// assets keep their row here: the join deliberately ignores soft deletion, and
// asset_deleted lets the screen say the target no longer exists instead of
// silently falling back to a bare identifier.
type AgentProbeEventRow struct {
	model.AgentProbeEvent `gorm:"embedded"`
	AssetName             string `gorm:"column:asset_name" json:"asset_name"`
	AssetDeleted          bool   `gorm:"column:asset_deleted" json:"asset_deleted"`
}

// QueryAgentProbeEvents returns observations, not reconstructed trip/release cycles.
func QueryAgentProbeEvents(ctx context.Context, db *gorm.DB, userID uint, from, to *time.Time, offset, limit int) ([]AgentProbeEventRow, int64, error) {
	q := db.WithContext(ctx).Model(&model.AgentProbeEvent{}).Where("agent_probe_events.user_id = ?", userID)
	if from != nil {
		q = q.Where("agent_probe_events.created_at >= ?", *from)
	}
	if to != nil {
		q = q.Where("agent_probe_events.created_at < ?", *to)
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
	rows := []AgentProbeEventRow{}
	err := q.
		Select("agent_probe_events.*, assets.name AS asset_name, (assets.deleted_at IS NOT NULL) AS asset_deleted").
		Joins("LEFT JOIN assets ON assets.id = agent_probe_events.asset_ref").
		Order("agent_probe_events.created_at DESC, agent_probe_events.id DESC").
		Offset(offset).Limit(limit).Find(&rows).Error
	return rows, total, err
}
