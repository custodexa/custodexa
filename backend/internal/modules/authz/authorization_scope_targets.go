package authz

import (
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 授權規則面的兩種範圍目標。
//
//   - 授權客體：建立規則時所指的資產或節點（資產分組即節點）；範圍外與不存在同為範圍拒絕。
//     以 AssetID 或 NodeID 其一指定（NodeID 非零時為節點）。
//   - 授權規則：既有規則；範圍目標是它的客體。規則不存在、已軟刪、客體已刪除，皆為範圍拒絕。
//
// 主體（使用者、群組、agent）不是範圍目標。

const (
	// ScopeTargetAuthorizationObject 建立授權時的客體（資產或節點）。
	ScopeTargetAuthorizationObject ScopeTargetKind = "authorization_object"
	// ScopeTargetAuthorizationRule 既有授權規則（以 RefID 指定）。
	ScopeTargetAuthorizationRule ScopeTargetKind = "authorization_rule"
)

// AuthorizationAssetObjectTarget 以資產為客體。
func AuthorizationAssetObjectTarget(assetID uint) ScopeTarget {
	return ScopeTarget{Kind: ScopeTargetAuthorizationObject, AssetID: assetID}
}

// AuthorizationNodeObjectTarget 以節點為客體。
func AuthorizationNodeObjectTarget(nodeID uint) ScopeTarget {
	return ScopeTarget{Kind: ScopeTargetAuthorizationObject, NodeID: nodeID}
}

// AuthorizationRuleTarget 既有授權規則。
func AuthorizationRuleTarget(ruleID uint) ScopeTarget {
	return ScopeTarget{Kind: ScopeTargetAuthorizationRule, RefID: ruleID}
}

// AuthorizationScopeResolvers 回傳兩種目標的解析器登記（建構判定器時傳入）。
func AuthorizationScopeResolvers() []ScopeTargetResolverRegistration {
	return []ScopeTargetResolverRegistration{
		{Kind: ScopeTargetAuthorizationObject, Resolve: resolveAuthorizationObjectTarget},
		{Kind: ScopeTargetAuthorizationRule, Resolve: resolveAuthorizationRuleTarget},
	}
}

// resolveObject 解析資產或節點客體；不存在（含識別碼為 0）回 Exists=false 並標對應層。
func resolveObject(tx *gorm.DB, topo ScopeTopology, assetID, nodeID uint) (ResolvedScopeTarget, error) {
	switch {
	case nodeID != 0:
		nodes, exists, err := topo.NodeCoverNodes(tx, nodeID)
		if err != nil {
			return ResolvedScopeTarget{}, err
		}
		if !exists {
			return ResolvedScopeTarget{Layer: ScopeLayerNode}, nil
		}
		return ResolvedScopeTarget{Exists: true, Layer: ScopeLayerNode, CoverNodes: nodes}, nil
	case assetID != 0:
		nodes, exists, err := topo.AssetCoverNodes(tx, assetID)
		if err != nil {
			return ResolvedScopeTarget{}, err
		}
		if !exists {
			return ResolvedScopeTarget{Layer: ScopeLayerAsset}, nil
		}
		return ResolvedScopeTarget{Exists: true, Layer: ScopeLayerAsset, CoverNodes: nodes}, nil
	}
	// 識別碼 0 恆不存在，與不存在同形：列表與選擇器的節點篩選落空、批次計入不可用。
	// 單筆建立在 handler 已擋 0，此處的層只供範圍拒絕出口對應錯誤碼，取資產層。
	return ResolvedScopeTarget{Layer: ScopeLayerAsset}, nil
}

func resolveAuthorizationObjectTarget(tx *gorm.DB, topo ScopeTopology, t ScopeTarget) (ResolvedScopeTarget, error) {
	if topo == nil {
		return ResolvedScopeTarget{}, errScopeResolverNoTopology
	}
	if t.Kind != ScopeTargetAuthorizationObject {
		return ResolvedScopeTarget{}, errScopeResolverKind
	}
	return resolveObject(tx, topo, t.AssetID, t.NodeID)
}

// resolveAuthorizationRuleTarget 規則的範圍目標是它的客體；規則缺席與客體已刪除一律標單層目標不成立。
func resolveAuthorizationRuleTarget(tx *gorm.DB, topo ScopeTopology, t ScopeTarget) (ResolvedScopeTarget, error) {
	if topo == nil {
		return ResolvedScopeTarget{}, errScopeResolverNoTopology
	}
	if t.Kind != ScopeTargetAuthorizationRule {
		return ResolvedScopeTarget{}, errScopeResolverKind
	}
	var rule model.AssetAuthorization
	err := tx.Select("id", "asset_id", "asset_group_id").First(&rule, t.RefID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ResolvedScopeTarget{Layer: ScopeLayerTarget}, nil
	}
	if err != nil {
		return ResolvedScopeTarget{}, err
	}
	var assetID, nodeID uint
	if rule.AssetID != nil {
		assetID = *rule.AssetID
	}
	if rule.AssetGroupID != nil {
		nodeID = *rule.AssetGroupID
	}
	if assetID == 0 && nodeID == 0 {
		return ResolvedScopeTarget{Layer: ScopeLayerTarget}, nil
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
