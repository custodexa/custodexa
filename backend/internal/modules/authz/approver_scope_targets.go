package authz

import (
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 審核範圍面的範圍目標。
//
// 目標種類「審核範圍」：RefID 非零為既有列，RefID 為零為「建立申請人型」（尚無列，無涵蓋節點）。
//   - 資產型、節點型列：目標是列的客體（資產或節點），涵蓋節點取自該客體；列不存在、已軟刪、
//     客體已刪除皆為單層目標不成立，與範圍外同為範圍拒絕。
//   - 申請人型列與建立申請人型：沒有涵蓋節點，只有全域指派涵蓋（節點範圍指派一律範圍外）。
//
// 建立資產型與節點型時，客體直接用資產、節點兩種內建目標判定，不經本種類。

// ScopeTargetApproverScope 審核範圍（既有列或建立申請人型）。
const ScopeTargetApproverScope ScopeTargetKind = "approver_scope"

// ApproverScopeRowTarget 既有審核範圍列。
func ApproverScopeRowTarget(id uint) ScopeTarget {
	return ScopeTarget{Kind: ScopeTargetApproverScope, RefID: id}
}

// ApproverScopeApplicantCreateTarget 建立申請人型審核範圍（尚無列）。
func ApproverScopeApplicantCreateTarget() ScopeTarget {
	return ScopeTarget{Kind: ScopeTargetApproverScope}
}

// ApproverScopeScopeResolvers 審核範圍面的解析器登記（建構判定器時傳入）。
func ApproverScopeScopeResolvers() []ScopeTargetResolverRegistration {
	return []ScopeTargetResolverRegistration{
		{Kind: ScopeTargetApproverScope, Resolve: resolveApproverScopeTarget},
	}
}

func resolveApproverScopeTarget(tx *gorm.DB, topo ScopeTopology, t ScopeTarget) (ResolvedScopeTarget, error) {
	if topo == nil {
		return ResolvedScopeTarget{}, errScopeResolverNoTopology
	}
	if t.Kind != ScopeTargetApproverScope {
		return ResolvedScopeTarget{}, errScopeResolverKind
	}
	if t.RefID == 0 {
		return ResolvedScopeTarget{Exists: true, Layer: ScopeLayerTarget}, nil
	}
	var row model.ApproverScope
	err := tx.Select("id", "asset_id", "asset_group_id", "subject_user_id", "subject_group_id").First(&row, t.RefID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ResolvedScopeTarget{Layer: ScopeLayerTarget}, nil
	}
	if err != nil {
		return ResolvedScopeTarget{}, err
	}
	var assetID, nodeID uint
	if row.AssetID != nil {
		assetID = *row.AssetID
	}
	if row.AssetGroupID != nil {
		nodeID = *row.AssetGroupID
	}
	if assetID == 0 && nodeID == 0 {
		// 申請人型：只有全域指派涵蓋
		return ResolvedScopeTarget{Exists: true, Layer: ScopeLayerTarget}, nil
	}
	rt, err := resolveObject(tx, topo, assetID, nodeID)
	if err != nil {
		return ResolvedScopeTarget{}, err
	}
	if !rt.Exists {
		return ResolvedScopeTarget{Layer: ScopeLayerTarget}, nil
	}
	rt.Layer = ScopeLayerTarget
	return rt, nil
}
