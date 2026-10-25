package asset

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 改密計畫的範圍收斂（讀取、修改、刪除、執行與記錄）。
//
// 範圍化檢視者只看到計畫目標在其範圍內的計畫（見 visiblePlanIDs）；其餘計畫的讀、改、刪、執行與記錄
// 與不存在同形。建立與修改時：以帳號為目標者，明列資產有不存在或範圍外即整份拒絕、只帶筆數；以憑證為
// 目標者，範圍外與不存在同形；範圍化發起者另須確認範圍外掛載的影響，並在同一儲存交易內把該憑證當下
// 的全部掛載寫入該版的掛載上界。不限範圍者（含未注入範圍判定）照全系統口徑，不寫掛載上界。

// WithScope 注入計畫的範圍判定與影響確認切分來源（組裝時）。未注入＝全系統口徑。
func (s *ChangeSecretPlanService) WithScope(p ChangeSecretScopePort, impact CredentialScopeSource) *ChangeSecretPlanService {
	s.scope, s.impactScope = p, impact
	return s
}

func planActor(ctx context.Context) uint {
	uid, _ := model.UserFromContext(ctx)
	return uid
}

// lockTopology 已注入範圍判定時取拓撲序列化鎖（交易的第一個動作）。
func (s *ChangeSecretPlanService) lockTopology(tx *gorm.DB) error {
	if s.scope == nil {
		return nil
	}
	return s.scope.LockTopology(tx)
}

// visibleOnly 只留檢視者可見的計畫（未注入範圍判定＝全部）。
func (s *ChangeSecretPlanService) visibleOnly(ctx context.Context, plans []model.ChangeSecretPlan) ([]model.ChangeSecretPlan, error) {
	if s.scope == nil {
		return plans, nil
	}
	vis, err := visiblePlanIDs(ctx, s.db, s.scope, planActor(ctx), plans)
	if err != nil {
		return nil, err
	}
	return filterPlans(plans, vis), nil
}

// requireVisibleTx 計畫對檢視者不可見即回 ErrPlanNotFound（與不存在同形）。
func (s *ChangeSecretPlanService) requireVisibleTx(ctx context.Context, db *gorm.DB, plan *model.ChangeSecretPlan) error {
	if s.scope == nil {
		return nil
	}
	vis, err := visiblePlanIDs(ctx, db, s.scope, planActor(ctx), []model.ChangeSecretPlan{*plan})
	if err != nil {
		return err
	}
	if vis != nil && !vis[plan.ID] {
		return ErrPlanNotFound
	}
	return nil
}

// ListFor 檢視者可見的計畫。
func (s *ChangeSecretPlanService) ListFor(ctx context.Context) ([]model.ChangeSecretPlan, error) {
	plans, err := s.List()
	if err != nil {
		return nil, err
	}
	return s.visibleOnly(ctx, plans)
}

// GetFor 檢視者可見的單一計畫；不可見與不存在同為 ErrPlanNotFound。
func (s *ChangeSecretPlanService) GetFor(ctx context.Context, id uint) (*model.ChangeSecretPlan, error) {
	plan, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	if err := s.requireVisibleTx(ctx, s.db, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

// latestPlanTx 拓撲鎖之後以交易內視圖重讀計畫最新列（修改與承接一律以它判定與遞增修訂）；
// 不存在回 ErrPlanNotFound。
func latestPlanTx(tx *gorm.DB, id uint) (*model.ChangeSecretPlan, error) {
	var plan model.ChangeSecretPlan
	if err := tx.First(&plan, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPlanNotFound
		}
		return nil, err
	}
	return &plan, nil
}

// DeleteFor 刪除檢視者可見的計畫；判定與刪除同一交易（拓撲鎖之後）。
func (s *ChangeSecretPlanService) DeleteFor(ctx context.Context, id uint) error {
	if s.scope == nil {
		return s.Delete(id)
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := s.lockTopology(tx); err != nil {
			return err
		}
		var plan model.ChangeSecretPlan
		if err := tx.First(&plan, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrPlanNotFound
			}
			return err
		}
		if err := s.requireVisibleTx(ctx, tx, &plan); err != nil {
			return err
		}
		res := tx.Delete(&model.ChangeSecretPlan{}, id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrPlanNotFound
		}
		return nil
	})
}

// RecordsFor 可見計畫的執行記錄，只列目標資產在檢視者範圍內者（範圍判定在查詢內，先過濾再取筆數上限）。
// 不可見的計畫與不存在同形：回空清單。完全不限範圍的檢視者沿用 Records（含已刪計畫保留的記錄）；
// 範圍化或混合能力的檢視者才經計畫可見性，計畫已不存在時回空清單、不退回無範圍查詢。
func (s *ChangeSecretPlanService) RecordsFor(ctx context.Context, planID uint, limit int) ([]model.ChangeSecretRecord, error) {
	if s.scope == nil {
		return s.Records(planID, limit)
	}
	vis, err := visiblePlanIDs(ctx, s.db, s.scope, planActor(ctx), nil)
	if err != nil {
		return nil, err
	}
	if vis == nil {
		return s.Records(planID, limit)
	}
	plan, err := s.GetFor(ctx, planID)
	if errors.Is(err, ErrPlanNotFound) {
		return []model.ChangeSecretRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	sc, err := s.scope.ViewScope(ctx, s.db, planActor(ctx), planRunCapabilities(plan.TargetKind)[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	if !sc.Limited {
		return s.Records(planID, limit)
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var records []model.ChangeSecretRecord
	if err := s.db.Where("plan_id = ? AND asset_id IN (?)", planID, sc.AssetIDs).
		Order("id desc").Limit(limit).Find(&records).Error; err != nil {
		return nil, err
	}
	return records, nil
}

// scopePlanTargetsTx 儲存交易內的目標判定（拓撲鎖為交易的第一個動作）；回該版的掛載上界（空字串＝不寫）。
// 未注入範圍判定時不做任何事（呼叫端已在交易外做既有的目標驗證）。
func (s *ChangeSecretPlanService) scopePlanTargetsTx(ctx context.Context, tx *gorm.DB,
	req *ChangeSecretPlanRequest) (string, error) {

	if s.scope == nil {
		return "", nil
	}
	if err := s.scope.LockTopology(tx); err != nil {
		return "", err
	}
	return s.scopePlanTargetsLockedTx(ctx, tx, req)
}

// scopePlanTargetsLockedTx 同 scopePlanTargetsTx，呼叫端已在同一交易取得拓撲鎖。
func (s *ChangeSecretPlanService) scopePlanTargetsLockedTx(ctx context.Context, tx *gorm.DB,
	req *ChangeSecretPlanRequest) (string, error) {

	if s.scope == nil {
		return "", nil
	}
	uid := planActor(ctx)
	if req.TargetKind == model.PlanTargetCredential {
		return s.scopeCredentialTargetTx(ctx, tx, uid, req)
	}
	sc, err := s.scope.ViewScope(ctx, tx, uid, CredCapAccountRotate)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	if sc.Limited {
		ids := uniqueIDs(req.AssetIDs)
		var n int64
		if err := tx.Model(&model.Asset{}).Where("assets.id IN ? AND assets.id IN (?)", ids, sc.AssetIDs).
			Count(&n).Error; err != nil {
			return "", err
		}
		if missing := len(ids) - int(n); missing > 0 {
			return "", &BatchItemsUnavailableError{Count: missing}
		}
	}
	return "", s.assertNoSharedCredentialTarget(tx, req)
}

// scopeCredentialTargetTx 憑證目標：範圍化發起者先鎖憑證列（不存在）、再判歸屬（範圍外），兩者同為
// 目標憑證不存在；之後重算並消耗影響確認，再取當下全部掛載（資產帳號列，識別升冪）作為掛載上界。
func (s *ChangeSecretPlanService) scopeCredentialTargetTx(ctx context.Context, tx *gorm.DB, uid uint,
	req *ChangeSecretPlanRequest) (string, error) {

	sc, err := s.scope.ViewScope(ctx, tx, uid, CredCapRotate)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	if !sc.Limited {
		return "", s.assertTargetResolvable(tx, req)
	}
	id := req.TargetCredentialID
	if _, err := lockCredentialRow(tx, id); err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			return "", ErrPlanTargetCredentialNotFound
		}
		return "", err
	}
	visible, unlimited, err := s.scope.CredentialsVisible(ctx, tx, uid, CredCapRotate, []uint{id})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	if !unlimited && !visible[id] {
		return "", ErrPlanTargetCredentialNotFound
	}
	if _, err := (impactGuard{scope: s.impactScope}).enforce(ctx, tx, id,
		model.CredentialImpactOpRotate, req.ImpactConfirmationID); err != nil {
		return "", err
	}
	var mounts []uint
	if err := tx.Model(&model.AssetAccount{}).Where("credential_id = ?", id).
		Order("id ASC").Pluck("id", &mounts).Error; err != nil {
		return "", fmt.Errorf("查詢目標憑證掛載失敗: %w", err)
	}
	return mustJSON(mounts), nil
}
