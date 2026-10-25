package main

import (
	"context"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"gorm.io/gorm"
)

// globalOwnershipScopeForTest 測試用的共用憑證歸屬判定：等同不限範圍的主體（未帶或全域→全域，節點→該節點）。
// 範圍化主體的歸屬規則由專屬測試以正式判定器驗，本替身只讓既有流程照全域主體運作。
type globalOwnershipScopeForTest struct{}

func (globalOwnershipScopeForTest) AuthorizeSharedOwnership(_ context.Context, _ *gorm.DB, _ uint, _ string,
	requested *asset.CredentialOwnershipInput) (asset.CredentialOwnership, error) {
	if requested == nil || requested.Kind != model.CredentialOwnerNode || requested.NodeID == nil {
		return asset.CredentialOwnership{Kind: model.CredentialOwnerGlobal}, nil
	}
	id := *requested.NodeID
	return asset.CredentialOwnership{Kind: model.CredentialOwnerNode, NodeID: &id}, nil
}

func (globalOwnershipScopeForTest) AuthorizeOwnershipChange(_ context.Context, _ *gorm.DB, _ uint, _ string,
	_ asset.CredentialOwnershipInput, current []asset.CredentialOwnership) ([]bool, error) {
	allowed := make([]bool, len(current))
	for i := range allowed {
		allowed[i] = true
	}
	return allowed, nil
}
