package asset

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 改密計畫的可見性投影（範圍化檢視者只看到計畫目標在其範圍內的計畫）：
//   - account 目標：資產集合全部在帳號改密的讀取範圍內（空集合不可見）；
//   - credential 目標：目標憑證的歸屬在憑證改密的讀取範圍內；掛載上界不參與。
//
// 不限範圍者回 nil（全部可見）。供計畫讀取面與以計畫彙總的衍生值（涵蓋計畫、適用天數）共用，
// 使範圍化檢視者看不到、也推不出不可見計畫的名稱與存在。

// visiblePlanIDs 檢視者可見的計畫識別；回 nil 表示不限範圍（全部可見）。
func visiblePlanIDs(ctx context.Context, db *gorm.DB, scope ChangeSecretScopePort, actorID uint,
	plans []model.ChangeSecretPlan) (map[uint]bool, error) {

	if scope == nil {
		return nil, nil
	}
	accScope, err := scope.ViewScope(ctx, db, actorID, CredCapAccountRotate)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	var credIDs []uint
	for i := range plans {
		if plans[i].TargetKind == model.PlanTargetCredential && plans[i].TargetCredentialID != nil {
			credIDs = append(credIDs, *plans[i].TargetCredentialID)
		}
	}
	credVisible, credUnlimited, err := scope.CredentialsVisible(ctx, db, actorID, CredCapRotate, credIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialAuthzUnavailable, err)
	}
	if !accScope.Limited && credUnlimited {
		return nil, nil
	}
	out := map[uint]bool{}
	for i := range plans {
		p := &plans[i]
		if p.TargetKind == model.PlanTargetCredential {
			if p.TargetCredentialID != nil && (credUnlimited || credVisible[*p.TargetCredentialID]) {
				out[p.ID] = true
			}
			continue
		}
		if !accScope.Limited {
			out[p.ID] = true
			continue
		}
		ok, err := planAssetsAllInScope(db, AssetIDList(p), accScope)
		if err != nil {
			return nil, err
		}
		if ok {
			out[p.ID] = true
		}
	}
	return out, nil
}

// planAssetsAllInScope 資產集合是否全部在範圍內（判定在查詢內；空集合為否）。
func planAssetsAllInScope(db *gorm.DB, ids []uint, sc ChangeSecretAssetScope) (bool, error) {
	ids = uniqueIDs(ids)
	if len(ids) == 0 {
		return false, nil
	}
	var n int64
	if err := db.Model(&model.Asset{}).Where("assets.id IN ? AND assets.id IN (?)", ids, sc.AssetIDs).
		Count(&n).Error; err != nil {
		return false, err
	}
	return int(n) == len(ids), nil
}

// filterPlans 只留可見計畫；visible 為 nil＝全部。
func filterPlans(plans []model.ChangeSecretPlan, visible map[uint]bool) []model.ChangeSecretPlan {
	if visible == nil {
		return plans
	}
	out := make([]model.ChangeSecretPlan, 0, len(plans))
	for i := range plans {
		if visible[plans[i].ID] {
			out = append(out, plans[i])
		}
	}
	return out
}
