package asset

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 改密候選的讀取投影：候選 → 帳號 → 資產，以帳號改密的讀取範圍（ChangeSecretScopePort.ViewScope）判定。
// 不限範圍者（含未注入範圍判定）與現行逐欄相同；範圍化檢視者的列表只列範圍內候選，
// 對範圍外候選的單筆存取與不存在同形（範圍拒絕值交 handler 的範圍拒絕出口）。

// WithScope 注入候選的範圍判定（組裝時）。
func (s *ChangeSecretCandidateService) WithScope(p ChangeSecretScopePort) *ChangeSecretCandidateService {
	s.scope = p
	return s
}

// ListFor 檢視者可見的候選（新到舊）。
func (s *ChangeSecretCandidateService) ListFor(ctx context.Context, actorID uint) ([]model.ChangeSecretCandidate, error) {
	if s.scope == nil {
		return s.List()
	}
	sc, err := s.scope.ViewScope(ctx, s.db, actorID, CredCapAccountRotate)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	if !sc.Limited {
		return s.List()
	}
	var out []model.ChangeSecretCandidate
	if err := s.db.Where("account_id IN (?)", s.db.Model(&model.AssetAccount{}).Select("asset_accounts.id").
		Where("asset_accounts.asset_id IN (?)", sc.AssetIDs)).
		Order("id desc").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// GetFor 檢視者可見的單筆候選；範圍外回範圍判定的拒絕值，不存在回 ErrCandidateNotFound。
func (s *ChangeSecretCandidateService) GetFor(ctx context.Context, actorID, id uint) (*model.ChangeSecretCandidate, error) {
	if s.scope != nil {
		if err := s.scope.CandidateDenial(ctx, s.db, actorID, id); err != nil {
			return nil, err
		}
	}
	return s.Get(id)
}

// DiscardFor 顯式清除檢視者可見的候選，回傳被清除候選所屬的資產。範圍判定與刪除在同一交易：
// 第一個動作取拓撲序列化鎖，鎖後以交易內視圖判定候選 → 帳號 → 資產是否在範圍內，範圍外回範圍
// 判定的拒絕值（與不存在同形，由 handler 交範圍拒絕出口）。未注入範圍判定時與 DiscardByAdmin 相同。
func (s *ChangeSecretCandidateService) DiscardFor(ctx context.Context, actorID, id uint, operator string) (uint, error) {
	if s.scope == nil {
		return s.discard(id, actorID, operator, nil)
	}
	return s.discard(id, actorID, operator, func(tx *gorm.DB) error {
		if err := s.scope.LockTopology(tx); err != nil {
			return err
		}
		return s.scope.CandidateDenial(ctx, tx, actorID, id)
	})
}
