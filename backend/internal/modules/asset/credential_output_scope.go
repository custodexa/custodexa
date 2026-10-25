package asset

import (
	"context"
	"sort"

	"github.com/custodexa/backend/internal/model"
)

// CredentialOutputScope 憑證相關輸出的可見判定（產生回應當下以請求主體重解的結果）。
// 全量只由正面判定產生；判定失敗以錯誤回報，呼叫端不得退回全量。
type CredentialOutputScope interface {
	// Full 是否可見全部內容。
	Full() bool
	// AssetsInView ids 中落在憑證檢視集合內的資產。
	AssetsInView(ids []uint) (map[uint]bool, error)
	// CredentialsInView ids 中落在憑證檢視集合內的憑證。
	CredentialsInView(ids []uint) (map[uint]bool, error)
}

// CredentialOutputScopeSource 輸出判定的來源；輪替與改密輸出共用，沒有用途參數。
type CredentialOutputScopeSource interface {
	CredentialOutputScope(ctx context.Context) (CredentialOutputScope, error)
}

// WithOutputScope 注入輸出判定來源（組裝根）。
func (s *CredentialRotationService) WithOutputScope(src CredentialOutputScopeSource) *CredentialRotationService {
	s.output = src
	return s
}

// OutputScopeWired 輸出判定來源已注入（組裝自檢用）。
func (s *CredentialRotationService) OutputScopeWired() bool {
	return s != nil && s.output != nil
}

// MembersInView 輪替成員中請求主體可見者，與被省略成員所屬資產的去重台數（全量為 nil）。
// 輸出判定未注入、判定或讀取失敗都回錯誤與 nil 成員，不退回全部成員。
func (s *CredentialRotationService) MembersInView(ctx context.Context, rotationID uint) ([]model.CredentialRotationMember, *int, error) {
	if s == nil || s.output == nil {
		return nil, nil, ErrCredentialAuthzUnavailable
	}
	scope, err := s.output.CredentialOutputScope(ctx)
	if err != nil {
		return nil, nil, err
	}
	if scope == nil {
		return nil, nil, ErrCredentialAuthzUnavailable
	}
	members, err := rotationMembers(s.db, rotationID)
	if err != nil {
		return nil, nil, err
	}
	if scope.Full() {
		return members, nil, nil
	}
	seen := map[uint]bool{}
	ids := make([]uint, 0, len(members))
	for i := range members {
		if !seen[members[i].AssetID] {
			seen[members[i].AssetID] = true
			ids = append(ids, members[i].AssetID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	inView, err := scope.AssetsInView(ids)
	if err != nil {
		return nil, nil, err
	}
	kept := make([]model.CredentialRotationMember, 0, len(members))
	hidden := map[uint]bool{}
	for i := range members {
		if inView[members[i].AssetID] {
			kept = append(kept, members[i])
		} else {
			hidden[members[i].AssetID] = true
		}
	}
	n := len(hidden)
	return kept, &n, nil
}

// VisiblePlanRefs 候選的來源計畫中請求主體可見者（與計畫列表同一個可見性判定）；
// 回 nil 表示不限範圍（全部可見）。計畫範圍判定未注入時回錯誤，不退回全部可見。
func (s *ChangeSecretCandidateService) VisiblePlanRefs(ctx context.Context, actorID uint, planIDs []uint) (map[uint]bool, error) {
	if s == nil || s.scope == nil {
		return nil, ErrCredentialAuthzUnavailable
	}
	var plans []model.ChangeSecretPlan
	if len(planIDs) > 0 {
		if err := s.db.Where("id IN ?", planIDs).Find(&plans).Error; err != nil {
			return nil, err
		}
	}
	return visiblePlanIDs(ctx, s.db, s.scope, actorID, plans)
}

// ScopeWired 計畫範圍判定已注入（組裝自檢用）。
func (s *ChangeSecretCandidateService) ScopeWired() bool {
	return s != nil && s.scope != nil
}
