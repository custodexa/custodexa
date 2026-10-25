package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

func outGlobal(perms ...Permission) Assignment {
	return Assignment{RoleID: 1, RoleName: "g", Scope: model.ScopeKindGlobal, Via: ViaDirect, Custom: true, Permissions: perms}
}

func outNodes(live []uint, perms ...Permission) Assignment {
	return Assignment{RoleID: 2, RoleName: "n", Scope: model.ScopeKindNodes, Via: ViaDirect, Custom: true,
		Permissions: perms, LiveNodeIDs: live}
}

// TestCredentialOutputFullJudgment 以真實主體逐列窮舉輸出判定的真值表，並列出兩個舊判定的結論，
// 證明表中含新舊結論相反的列。
func TestCredentialOutputFullJudgment(t *testing.T) {
	// 撤除前的改密相容式：不持憑證檢視、且改密管理有全域來源就回全量
	withdrawnCompat := func(p *Principal) bool {
		return !p.Has(PermCredentialView) && !p.assignsPermission(PermCredentialView) &&
			scopeSetOn(p, PermChangeSecretManage, sourcesAll).State() == ScopeSetUnlimited
	}
	legacyNotScoped := func(p *Principal) bool { return !isCredentialScopedViewer(p) }

	super := Assignment{RoleID: 9, RoleName: "super", BuiltinKey: model.BuiltinSuperAdmin, Scope: model.ScopeKindGlobal, Via: ViaDirect}
	rows := []struct {
		name        string
		assignments []Assignment
		full        bool
		legacy      *bool // 非空時斷言 legacyNotScoped
		withdrawn   *bool // 非空時斷言 withdrawnCompat
	}{
		{name: "1 超級管理者", assignments: []Assignment{super}, full: true},
		{name: "2 全域憑證檢視", assignments: []Assignment{outGlobal(PermCredentialView)}, full: true},
		{name: "3 節點憑證檢視", assignments: []Assignment{outNodes([]uint{1}, PermCredentialView)}, full: false},
		{name: "4 節點憑證檢視加全域憑證管理",
			assignments: []Assignment{outNodes([]uint{1}, PermCredentialView), outGlobal(PermCredentialManage)}, full: false},
		{name: "5 只持全域憑證管理", assignments: []Assignment{outGlobal(PermCredentialManage)}, full: true},
		{name: "6 只持全域改密管理", assignments: []Assignment{outGlobal(PermChangeSecretManage)}, full: false, withdrawn: tp()},
		{name: "7 全域改密管理加輪替加資產檢視",
			assignments: []Assignment{outGlobal(PermChangeSecretManage, PermAccountRotate, PermAssetView)}, full: false, withdrawn: tp()},
		{name: "8 只持全域憑證輪替", assignments: []Assignment{outGlobal(PermCredentialRotate)}, full: false},
		{name: "9 混合指派",
			assignments: []Assignment{outGlobal(PermChangeSecretManage), outNodes([]uint{1}, PermAssetView, PermAccountRotate)},
			full:        false, withdrawn: tp()},
		{name: "10 混合指派加有效節點已空的節點憑證檢視",
			assignments: []Assignment{outGlobal(PermChangeSecretManage), outNodes([]uint{1}, PermAssetView, PermAccountRotate),
				outNodes(nil, PermCredentialView)}, full: false},
		{name: "11 沒有任何指派", assignments: nil, full: false, legacy: tp()},
		{name: "12 節點指派的有效節點已空", assignments: []Assignment{outNodes(nil, PermCredentialView, PermAssetView)}, full: false},
	}
	for _, r := range rows {
		p := NewPrincipalOn(ProductCatalogue(), 7, TokenFacts{}, r.assignments)
		got := credentialOutputFull(p)
		lg, wd := legacyNotScoped(p), withdrawnCompat(p)
		t.Logf("ROW %s: 新判定=%v legacyNotScoped=%v withdrawnCompat=%v", r.name, got, lg, wd)
		assert.Equal(t, r.full, got, r.name)
		if r.withdrawn != nil {
			assert.True(t, wd, "%s: 撤除前的相容式應為真", r.name)
		}
		if r.legacy != nil {
			assert.True(t, lg, "%s: 舊的非範圍化檢視者判定應為真", r.name)
		}
	}

	// 13 脈絡無主體：回錯誤
	f := newDecideFixture(t)
	reader := NewCredentialScopeReader(NewScopeEvaluator(ProductCatalogue(), f.topo), f.db)
	out, err := reader.CredentialOutputScope(context.Background())
	t.Logf("ROW 13 脈絡無主體: err=%v", err)
	require.Error(t, err)
	assert.Nil(t, out)
	t.Logf("ROWS %d", len(rows)+1)
}

func tp() *bool { v := true; return &v }
