package main

import (
	"testing"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// asset 端的拓撲讀取器須結構相容於 authz 的 ScopeTopology（asset 不 import authz）。
var _ authz.ScopeTopology = (*asset.ScopeTopologyReader)(nil)

func TestNewScopeEvaluatorAssembled(t *testing.T) {
	e := newScopeEvaluator()
	if e == nil {
		t.Fatal("newScopeEvaluator returned nil")
	}
	for _, k := range authz.ProductScopeTargetKinds() {
		if !e.HasResolver(k) {
			t.Errorf("newScopeEvaluator lacks a resolver for target kind %q", k)
		}
	}
}
