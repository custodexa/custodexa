package main

import (
	"testing"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// asset 端的拓撲讀取器須結構相容於 authz 的 ScopeTopology（asset 不 import authz）。
var _ authz.ScopeTopology = (*asset.ScopeTopologyReader)(nil)

func TestNewScopeEvaluatorAssembled(t *testing.T) {
	if newScopeEvaluator() == nil {
		t.Fatal("newScopeEvaluator returned nil")
	}
}
