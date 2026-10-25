package authz

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
)

// TestApplicantManageKeyGlobalOnly 擋：申請人型管理鍵只在全域指派生效。同一自訂角色（審核範圍管理鍵加
// 申請人型管理鍵）掛在節點範圍時，後者不生效；補鍵不改變任何節點範圍主體的有效能力。
func TestApplicantManageKeyGlobalOnly(t *testing.T) {
	perms := []Permission{PermApproverScopeManage, PermApproverScopeApplicantManage}
	node := NewPrincipal(7, TokenFacts{SubjectKind: model.KindHuman}, []Assignment{
		{Scope: model.ScopeKindNodes, LiveNodeIDs: []uint{3}, Permissions: perms, Custom: true}})
	assert.False(t, node.Has(PermApproverScopeApplicantManage), "節點範圍指派不得讓申請人型管理鍵生效")
	// 補鍵前（只有 K）與補鍵後的節點範圍主體，申請人型管理鍵的有效狀態相同（皆無）。
	before := NewPrincipal(7, TokenFacts{SubjectKind: model.KindHuman}, []Assignment{
		{Scope: model.ScopeKindNodes, LiveNodeIDs: []uint{3}, Permissions: perms[:1], Custom: true}})
	assert.Equal(t, before.Has(PermApproverScopeApplicantManage), node.Has(PermApproverScopeApplicantManage))
	global := NewPrincipal(8, TokenFacts{SubjectKind: model.KindHuman}, []Assignment{
		{Scope: model.ScopeKindGlobal, Permissions: perms, Custom: true}})
	assert.True(t, global.Has(PermApproverScopeApplicantManage), "全域指派生效")
	// 全域與節點範圍各掛一個角色：不跨指派組合，節點範圍那份不貢獻申請人型管理鍵。
	mixed := NewPrincipal(9, TokenFacts{SubjectKind: model.KindHuman}, []Assignment{
		{Scope: model.ScopeKindGlobal, Permissions: perms[:1], Custom: true},
		{Scope: model.ScopeKindNodes, LiveNodeIDs: []uint{3}, Permissions: perms, Custom: true}})
	assert.False(t, mixed.Has(PermApproverScopeApplicantManage))
}
