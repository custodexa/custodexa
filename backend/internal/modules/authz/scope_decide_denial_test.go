package authz

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// scopeDenyReasons 範圍拒絕的受控原因（no_effective_binding 只配能力拒絕，不在其中）。
var scopeDenyReasons = map[ScopeReason]bool{
	ScopeReasonOutOfScope:          true,
	ScopeReasonResolverMissing:     true,
	ScopeReasonTopologyUnavailable: true,
}

// runDecideDenialSubtests DecideWithDenial 的子測試（掛在 TestScopeTargetResolvers 之下）。
func runDecideDenialSubtests(t *testing.T) {
	t.Run("denial_carries_kind_layer_reason", func(t *testing.T) {
		f := newDecideFixture(t)
		ev := f.evaluator(f.catView)
		uid := f.user(t)
		f.bindDirect(t, uid, f.role(t, PermAssetView), f.n[1]) // 範圍＝n1 子樹（n1、n2、n3）；a1 在內、a2 在外
		deny := func(e *ScopeEvaluator, target ScopeTarget) *ErrScopeDenied {
			t.Helper()
			res, denied, err := e.DecideWithDenial(f.db, &Principal{UserID: uid}, PermAssetView, target)
			require.NoError(t, err)
			require.Equal(t, ScopeDenyScope, res.Outcome, "%v 應為範圍拒絕", target)
			require.NotNil(t, denied)
			return denied
		}
		want := func(k ScopeTargetKind, l ScopeDeniedLayer, r ScopeReason) *ErrScopeDenied {
			return &ErrScopeDenied{Kind: k, Layer: l, Reason: r}
		}

		// 資產目標
		assert.Equal(t, want(ScopeTargetAsset, ScopeLayerAsset, ScopeReasonOutOfScope), deny(ev, AssetTarget(f.a[2])))
		assert.Equal(t, want(ScopeTargetAsset, ScopeLayerAsset, ScopeReasonOutOfScope), deny(ev, AssetTarget(99999)))
		// 帳號目標：資產在範圍外（帳號屬於它、不屬於它、不存在）一律資產層
		for _, target := range []ScopeTarget{AssetAccountTarget(f.a[2], f.acc[2]), AssetAccountTarget(f.a[2], f.acc[1]),
			AssetAccountTarget(f.a[2], 99999), AssetAccountTarget(99999, f.acc[1])} {
			assert.Equal(t, want(ScopeTargetAssetAccount, ScopeLayerAsset, ScopeReasonOutOfScope), deny(ev, target), "%v", target)
		}
		// 帳號目標：資產在範圍內，帳號不屬於它或不存在＝帳號層
		assert.Equal(t, want(ScopeTargetAssetAccount, ScopeLayerAccount, ScopeReasonOutOfScope), deny(ev, AssetAccountTarget(f.a[1], f.acc[2])))
		assert.Equal(t, want(ScopeTargetAssetAccount, ScopeLayerAccount, ScopeReasonOutOfScope), deny(ev, AssetAccountTarget(f.a[1], 99999)))
		// 節點目標
		assert.Equal(t, want(ScopeTargetNode, ScopeLayerNode, ScopeReasonOutOfScope), deny(ev, NodeTarget(f.n[4])))
		// 拓撲缺席、解析器未登記
		noTopo := NewScopeEvaluator(f.catView, nil)
		assert.Equal(t, want(ScopeTargetAssetAccount, ScopeLayerAsset, ScopeReasonTopologyUnavailable), deny(noTopo, AssetAccountTarget(f.a[1], f.acc[1])))
		assert.Equal(t, want(ScopeTargetNode, ScopeLayerNode, ScopeReasonTopologyUnavailable), deny(noTopo, NodeTarget(f.n[1])))
		assert.Equal(t, want("credential", ScopeLayerTarget, ScopeReasonResolverMissing), deny(ev, ScopeTarget{Kind: "credential", RefID: 1}))

		// 拒絕可經 errors.As 取回，字串固定
		var got *ErrScopeDenied
		require.True(t, errors.As(error(deny(ev, AssetAccountTarget(f.a[1], f.acc[2]))), &got))
		assert.Equal(t, ScopeLayerAccount, got.Layer)
		assert.Equal(t, "authz: scope denied", got.Error())
	})

	t.Run("allow_and_capability_denial_have_nil_denial", func(t *testing.T) {
		f := newDecideFixture(t)
		ev := f.evaluator(f.catView)
		scoped, noCap, global, su := f.user(t), f.user(t), f.user(t), f.user(t)
		f.bindDirect(t, scoped, f.role(t, PermAssetView), f.n[1])
		f.bindDirect(t, noCap, f.role(t, PermAuditView), f.n[1])
		f.global(t, global, f.role(t, PermAssetView))
		f.global(t, su, f.builtinRole(t, model.BuiltinSuperAdmin))
		check := func(uid uint, target ScopeTarget, wantRes ScopeResult) {
			t.Helper()
			res, denied, err := ev.DecideWithDenial(f.db, &Principal{UserID: uid}, PermAssetView, target)
			require.NoError(t, err)
			assert.Equal(t, wantRes, res, "%v", target)
			assert.Nil(t, denied, "%v：放行與能力拒絕不帶範圍拒絕", target)
		}
		check(scoped, AssetTarget(f.a[1]), wantAllow)
		check(scoped, AssetAccountTarget(f.a[1], f.acc[1]), wantAllow)
		check(scoped, NodeTarget(f.n[3]), wantAllow)
		for _, target := range []ScopeTarget{AssetTarget(f.a[2]), AssetAccountTarget(f.a[1], f.acc[2]), NodeTarget(f.n[4])} {
			check(noCap, target, wantNoCap)
			check(global, target, wantAllow)
			check(su, target, wantAllow)
		}
	})

	t.Run("read_failure_and_bad_input_return_error_only", func(t *testing.T) {
		f := newDecideFixture(t)
		uid := f.user(t)
		f.bindDirect(t, uid, f.role(t, PermAssetView), f.n[1])
		ev := f.evaluator(f.catView)
		bad := NewScopeEvaluator(f.catView, failingTopology{f.topo})
		for _, target := range []ScopeTarget{AssetTarget(f.a[1]), NodeTarget(f.n[1]), AssetAccountTarget(f.a[1], f.acc[1])} {
			res, denied, err := bad.DecideWithDenial(f.db, &Principal{UserID: uid}, PermAssetView, target)
			assert.ErrorIs(t, err, errTopologyDown)
			assert.Equal(t, ScopeResult{}, res)
			assert.Nil(t, denied, "讀取失敗不偽裝成範圍拒絕")
		}
		res, denied, err := ev.DecideWithDenial(f.db, nil, PermAssetView, AssetTarget(1))
		assert.ErrorIs(t, err, ErrScopeNilPrincipal)
		assert.Equal(t, ScopeResult{}, res)
		assert.Nil(t, denied)
		res, denied, err = ev.DecideWithDenial(nil, &Principal{UserID: uid}, PermAssetView, AssetTarget(1))
		assert.ErrorIs(t, err, errScopeNilTx)
		assert.Equal(t, ScopeResult{}, res)
		assert.Nil(t, denied)
	})

	t.Run("same_result_as_decide_over_population", func(t *testing.T) {
		f := newDecideFixture(t)
		require.NoError(t, f.db.Delete(&model.Asset{}, f.a[5]).Error)
		f.deleteNode(t, f.n[5])
		users := map[string]uint{}
		add := func(name string, bind func(uint)) {
			u := f.user(t)
			bind(u)
			users[name] = u
		}
		add("scoped_direct", func(u uint) { f.bindDirect(t, u, f.role(t, PermAssetView, PermAssetUpdate), f.n[1]) })
		add("scoped_group", func(u uint) { f.bindGroup(t, u, f.role(t, PermAssetView), f.n[4]) })
		add("split_bindings", func(u uint) {
			f.bindDirect(t, u, f.role(t, PermAssetView), f.n[3])
			f.bindDirect(t, u, f.role(t, PermAssetUpdate), f.n[4])
		})
		add("no_capability", func(u uint) { f.bindDirect(t, u, f.role(t, PermAuditView), f.n[1]) })
		add("global", func(u uint) { f.global(t, u, f.role(t, PermAssetView)) })
		add("super_admin", func(u uint) { f.global(t, u, f.builtinRole(t, model.BuiltinSuperAdmin)) })

		var targets []ScopeTarget
		assets := []uint{f.a[1], f.a[2], f.a[3], f.a[4], f.a[5], 99999}
		for _, a := range assets {
			targets = append(targets, AssetTarget(a))
			for _, acc := range []uint{f.acc[1], f.acc[2], 99999} {
				targets = append(targets, AssetAccountTarget(a, acc))
			}
		}
		for _, n := range []uint{f.n[1], f.n[2], f.n[3], f.n[4], f.n[5], 99999} {
			targets = append(targets, NodeTarget(n))
		}
		targets = append(targets, ScopeTarget{Kind: "credential", RefID: 1}, ScopeTarget{Kind: "approval_scope", RefID: 2})

		evaluators := map[string]*ScopeEvaluator{
			"topology": f.evaluator(f.catView),
			"no_topo":  NewScopeEvaluator(f.catView, nil),
			"credential_registered": NewScopeEvaluator(f.catView, f.topo, ScopeTargetResolverRegistration{Kind: "credential",
				Resolve: func(*gorm.DB, ScopeTopology, ScopeTarget) (ResolvedScopeTarget, error) {
					return ResolvedScopeTarget{Exists: false, Layer: ScopeLayerTarget}, nil
				}}),
		}
		layers := map[ScopeDeniedLayer]int{}
		cases := 0
		for en, e := range evaluators {
			for un, u := range users {
				p := mustResolve(t, f, e, u)
				for _, perm := range []Permission{PermAssetView, PermAssetUpdate} {
					for _, target := range targets {
						cases++
						base, err := e.Decide(f.db, &Principal{UserID: u}, perm, target)
						require.NoError(t, err)
						res, denied, err := e.DecideWithDenial(f.db, &Principal{UserID: u}, perm, target)
						require.NoError(t, err)
						assert.Equal(t, base, res, "%s/%s/%s/%v：結果逐欄相同", en, un, perm, target)
						if res.Outcome != ScopeDenyScope {
							assert.Nil(t, denied, "%s/%s/%s/%v", en, un, perm, target)
							continue
						}
						require.NotNil(t, denied, "%s/%s/%s/%v：範圍拒絕必帶拒絕值", en, un, perm, target)
						_, layer, err := e.decideOn(f.db, p, perm, target)
						require.NoError(t, err)
						assert.Equal(t, NewErrScopeDenied(target.Kind, layer, res.Reason), denied, "%s/%s/%s/%v：種類、層、原因", en, un, perm, target)
						assert.True(t, scopeDenyReasons[denied.Reason], "原因 %q 不在範圍拒絕三值", denied.Reason)
						layers[denied.Layer]++
					}
				}
			}
		}
		// 母體確實走到四種層次（含帳號層），不是只比到放行
		for _, l := range []ScopeDeniedLayer{ScopeLayerAsset, ScopeLayerAccount, ScopeLayerNode, ScopeLayerTarget} {
			assert.Positive(t, layers[l], "母體缺少 %s 層拒絕", l)
		}
		t.Logf("population cases=%d deny_layers=%v", cases, layers)
	})
}
