package authz

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RecordAgentVisibilityExposures persists the identifiers actually returned in a page.
// Failure prevents the page from being disclosed without evidence.
func (s *AssetAuthorizationService) RecordAgentVisibilityExposures(ctx context.Context, userID uint, assetIDs []uint) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error { return recordAgentVisibilityExposures(tx, userID, assetIDs) })
}

// Called in the same transaction as item approval, and by the list disclosure path.
func recordAgentVisibilityExposures(tx *gorm.DB, userID uint, assetIDs []uint) error {
	if len(assetIDs) == 0 {
		return nil
	}
	var principal model.User
	if err := tx.Select("id", "kind").First(&principal, userID).Error; err != nil {
		return err
	}
	if principal.Kind != model.KindAgent {
		return nil
	}
	ids := append([]uint(nil), assetIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	now := time.Now().UTC()
	for i, id := range ids {
		if i > 0 && id == ids[i-1] {
			continue
		}
		row := model.AgentVisibilityExposure{UserID: userID, AssetID: id, FirstSeenAt: now, LastSeenAt: now}
		// A delayed concurrent transaction must not move last_seen_at backwards.
		err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "user_id"}, {Name: "asset_id"}}, DoUpdates: clause.Assignments(map[string]interface{}{
			"first_seen_at": gorm.Expr("CASE WHEN excluded.first_seen_at < agent_visibility_exposures.first_seen_at THEN excluded.first_seen_at ELSE agent_visibility_exposures.first_seen_at END"),
			"last_seen_at":  gorm.Expr("CASE WHEN excluded.last_seen_at > agent_visibility_exposures.last_seen_at THEN excluded.last_seen_at ELSE agent_visibility_exposures.last_seen_at END"),
		})}).Create(&row).Error
		if err != nil {
			return err
		}
	}
	return nil
}

// ClassifyAgentProbe deliberately does not infer historical group membership.
// Assets outside the default (non-deleted) scope are retired, even if disclosed.
func ClassifyAgentProbe(tx *gorm.DB, userID, assetID uint) (string, error) {
	var target model.Asset
	err := tx.Select("id").First(&target, assetID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.ProbeRetired, nil
	}
	if err != nil {
		return "", err
	}
	var count int64
	if err := tx.Model(&model.AgentVisibilityExposure{}).Where("user_id=? AND asset_id=?", userID, assetID).Count(&count).Error; err != nil {
		return "", err
	}
	if count > 0 {
		return model.ProbeRevoked, nil
	}
	return model.ProbeNeverVisible, nil
}
