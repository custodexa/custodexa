package authz

import (
	"gorm.io/gorm"
)

// ScopeTargetChangeSecretCandidate 改密候選目標（RefID 為候選識別）。
// 範圍以候選所屬帳號的資產判定：候選 → 帳號 → 資產涵蓋節點；範圍外與不存在同為「候選不存在」。
const ScopeTargetChangeSecretCandidate ScopeTargetKind = "change_secret_candidate"

// ChangeSecretCandidateTarget 改密候選目標。
func ChangeSecretCandidateTarget(candidateID uint) ScopeTarget {
	return ScopeTarget{Kind: ScopeTargetChangeSecretCandidate, RefID: candidateID}
}

// ChangeSecretCandidateScopeResolver 改密候選目標解析器的登記項（組裝判定器時傳入 NewScopeEvaluator）。
func ChangeSecretCandidateScopeResolver() ScopeTargetResolverRegistration {
	return ScopeTargetResolverRegistration{Kind: ScopeTargetChangeSecretCandidate, Resolve: resolveChangeSecretCandidateTarget}
}

// resolveChangeSecretCandidateTarget 候選 → 帳號 → 資產；候選、帳號或資產任一不在一律標單層目標不成立，
// 不分辨缺的是哪一層。
func resolveChangeSecretCandidateTarget(tx *gorm.DB, topo ScopeTopology, t ScopeTarget) (ResolvedScopeTarget, error) {
	if topo == nil {
		return ResolvedScopeTarget{}, errScopeResolverNoTopology
	}
	if t.Kind != ScopeTargetChangeSecretCandidate {
		return ResolvedScopeTarget{}, errScopeResolverKind
	}
	notFound := ResolvedScopeTarget{Layer: ScopeLayerTarget}
	if t.RefID == 0 {
		return notFound, nil
	}
	accountID, exists, err := topo.CandidateAccount(tx, t.RefID)
	if err != nil {
		return ResolvedScopeTarget{}, err
	}
	if !exists {
		return notFound, nil
	}
	assetID, exists, err := topo.AccountAsset(tx, accountID)
	if err != nil {
		return ResolvedScopeTarget{}, err
	}
	if !exists {
		return notFound, nil
	}
	nodes, exists, err := topo.AssetCoverNodes(tx, assetID)
	if err != nil {
		return ResolvedScopeTarget{}, err
	}
	if !exists {
		return notFound, nil
	}
	return ResolvedScopeTarget{Exists: true, Layer: ScopeLayerTarget, CoverNodes: nodes}, nil
}
