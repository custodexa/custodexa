package authz

import (
	"errors"

	"gorm.io/gorm"
)

// 前三種目標（資產、資產帳號、節點）的內建解析器。
//
// 解析只回答「目標在不在、掛在哪些節點之下」，不看主體；是否落在範圍內由判定器
// 以 CoverNodes 與各指派的有效節點比對。已刪除、不存在、帳號不屬於所指資產
// 三種情形都只回 Exists=false，由判定器歸成同一個範圍拒絕。

var (
	errScopeResolverNoTopology = errors.New("authz: scope target resolution without topology")
	errScopeResolverKind       = errors.New("authz: scope target resolver given a different kind")
)

// builtinScopeResolvers 內建三種目標的解析器；每次呼叫建新 map，不留包級狀態。
func builtinScopeResolvers() map[ScopeTargetKind]ScopeTargetResolver {
	return map[ScopeTargetKind]ScopeTargetResolver{
		ScopeTargetAsset:        resolveAssetScopeTarget,
		ScopeTargetAssetAccount: resolveAssetAccountScopeTarget,
		ScopeTargetNode:         resolveNodeScopeTarget,
	}
}

func resolveAssetScopeTarget(tx *gorm.DB, topo ScopeTopology, t ScopeTarget) (ResolvedScopeTarget, error) {
	if topo == nil {
		return ResolvedScopeTarget{}, errScopeResolverNoTopology
	}
	if t.Kind != ScopeTargetAsset {
		return ResolvedScopeTarget{}, errScopeResolverKind
	}
	nodes, exists, err := topo.AssetCoverNodes(tx, t.AssetID)
	if err != nil {
		return ResolvedScopeTarget{}, err
	}
	if !exists {
		return ResolvedScopeTarget{Layer: ScopeLayerAsset}, nil
	}
	return ResolvedScopeTarget{Exists: true, Layer: ScopeLayerAsset, CoverNodes: nodes}, nil
}

// resolveAssetAccountScopeTarget 帳號隨所屬資產判定：先確認資產，再確認帳號存在
// 且屬於所指資產；資產不成立標資產層，帳號不成立或不屬於該資產標帳號層（判定器再依資產是否在
// 主體範圍內，把範圍外資產一律改標資產層，見 decideOn）。
// 目標存在時 Layer 標資產層：涵蓋節點是資產的，範圍外即資產範圍外。
func resolveAssetAccountScopeTarget(tx *gorm.DB, topo ScopeTopology, t ScopeTarget) (ResolvedScopeTarget, error) {
	if topo == nil {
		return ResolvedScopeTarget{}, errScopeResolverNoTopology
	}
	if t.Kind != ScopeTargetAssetAccount {
		return ResolvedScopeTarget{}, errScopeResolverKind
	}
	nodes, exists, err := topo.AssetCoverNodes(tx, t.AssetID)
	if err != nil {
		return ResolvedScopeTarget{}, err
	}
	if !exists {
		return ResolvedScopeTarget{Layer: ScopeLayerAsset}, nil
	}
	owner, ok, err := topo.AccountAsset(tx, t.AccountID)
	if err != nil {
		return ResolvedScopeTarget{}, err
	}
	if !ok || owner != t.AssetID {
		// 帶回資產的涵蓋節點：判定器據此先判資產是否在範圍內，範圍外一律標資產層
		return ResolvedScopeTarget{Layer: ScopeLayerAccount, CoverNodes: nodes}, nil
	}
	return ResolvedScopeTarget{Exists: true, Layer: ScopeLayerAsset, CoverNodes: nodes}, nil
}

func resolveNodeScopeTarget(tx *gorm.DB, topo ScopeTopology, t ScopeTarget) (ResolvedScopeTarget, error) {
	if topo == nil {
		return ResolvedScopeTarget{}, errScopeResolverNoTopology
	}
	if t.Kind != ScopeTargetNode {
		return ResolvedScopeTarget{}, errScopeResolverKind
	}
	nodes, exists, err := topo.NodeCoverNodes(tx, t.NodeID)
	if err != nil {
		return ResolvedScopeTarget{}, err
	}
	if !exists {
		return ResolvedScopeTarget{Layer: ScopeLayerNode}, nil
	}
	return ResolvedScopeTarget{Exists: true, Layer: ScopeLayerNode, CoverNodes: nodes}, nil
}
