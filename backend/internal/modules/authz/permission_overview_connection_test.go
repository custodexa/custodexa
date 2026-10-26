package authz

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// connFx 連線面夾具：檢視者只對 nIn 範圍持授權管理；被檢視者可連線 nIn 下三台與 nOut 下兩台。
type connFx struct {
	e                 *ovEnv
	nIn, nInSub, nOut uint
	in                [3]uint
	out               [2]uint
	viewer, subject   *model.User
	inNames, outNames []string
}

const (
	cxOutName = "zz-out-secret-"
	cxOutNode = "zz-out-node-secret"
)

func newConnFx(t *testing.T) *connFx {
	t.Helper()
	e := newOvEnv(t)
	fx := &connFx{e: e}
	fx.nIn = e.node("cx-in", nil)
	fx.nInSub = e.node("cx-in-sub", &fx.nIn)
	fx.nOut = e.node(cxOutNode, nil)
	fx.in[0] = e.assetOn("cx-in-1", fx.nIn)
	fx.in[1] = e.assetOn("cx-in-2", fx.nInSub)
	fx.in[2] = e.assetOn("cx-in-3", fx.nInSub)
	fx.out[0] = e.assetOn(cxOutName+"1", fx.nOut)
	fx.out[1] = e.assetOn(cxOutName+"2", fx.nOut)
	fx.viewer = e.scopedViewer(fx.nIn)
	fx.subject = e.user("cx-subject")
	e.grantUserNode(fx.subject.ID, fx.nIn, model.PermissionConnect)
	e.grantUserNode(fx.subject.ID, fx.nOut, model.PermissionConnect)
	return fx
}

func (fx *connFx) allAssets() []uint {
	return append(append([]uint{}, fx.in[:]...), fx.out[:]...)
}

func (fx *connFx) get(t *testing.T) *PermissionOverview {
	t.Helper()
	return fx.e.overview(fx.viewer, fx.subject)
}

func outOfScopeCount(t *testing.T, o *PermissionOverview) (int, bool) {
	t.Helper()
	m := jsonMap(t, o.Connection)
	v, ok := m["out_of_scope_asset_count"]
	if !ok {
		return 0, false
	}
	return int(v.(float64)), true
}

func requireNoLeak(t *testing.T, o *PermissionOverview) {
	t.Helper()
	full := jsonOf(t, o.Connection)
	assert.NotContains(t, full, cxOutName)
	assert.NotContains(t, full, cxOutNode)
}

// TestPermissionOverviewConnectionProjection 連線面投影、匿名計數、無權不回、也能管理與能管不能連。
func TestPermissionOverviewConnectionProjection(t *testing.T) {
	t.Run("可連五台、三台在檢視者範圍內：項目只含三台，匿名台數為二且不洩漏範圍外名稱", func(t *testing.T) {
		fx := newConnFx(t)
		o := fx.get(t)
		require.True(t, o.Connection.Available)
		require.NotNil(t, o.Connection.Items)
		items := *o.Connection.Items
		require.Len(t, items, 1)
		assert.Equal(t, 3, items[0].VisibleAssetCount)
		assert.Equal(t, OverviewItemAuthorization, items[0].Kind)
		assert.Equal(t, "cx-in", items[0].Target.Name)
		assert.Equal(t, "self", items[0].Via.Type)
		assert.Equal(t, model.AccessPolicyOpen, items[0].AccessPolicy)
		n, ok := outOfScopeCount(t, o)
		require.True(t, ok)
		assert.Equal(t, 2, n)
		requireNoLeak(t, o)

		// 每台資產：計入可連集合與 CheckPermissionForPrincipal 的 connect 結果逐台相同
		p := fx.e.principalOf(fx.subject)
		connectable, err := fx.e.svc.connectableSet(fx.subject.ID, time.Now())
		require.NoError(t, err)
		for _, a := range fx.allAssets() {
			ok, err := fx.e.acl.CheckPermissionForPrincipal(p, fx.subject.ID, a, model.PermissionConnect)
			require.NoError(t, err)
			assert.Equal(t, ok, connectable[a], "資產 %d", a)
		}
	})

	t.Run("四種分辨案例加入後台數仍為二", func(t *testing.T) {
		fx := newConnFx(t)
		e := fx.e
		// (i) 範圍外兩台只有 view 授權（掛在沒有 connect 授權的另一節點）
		nOther := e.node("zz-out-other-node", nil)
		v1 := e.assetOn("zz-out-secret-view-1", nOther)
		v2 := e.assetOn("zz-out-secret-view-2", nOther)
		e.grantUserAsset(fx.subject.ID, v1, model.PermissionView)
		e.grantUserAsset(fx.subject.ID, v2, model.PermissionView)
		// (ii) 被檢視者的審核範圍涵蓋範圍外一台
		ap := e.assetOn("zz-out-secret-approver", nOther)
		require.NoError(t, e.db.Create(&model.ApproverScope{ApproverID: &fx.subject.ID, AssetID: &ap}).Error)
		// (iii) 節點範圍資產管理指派能管範圍外三台、無授權
		nM := e.node("zz-out-manage-node", nil)
		for i := 0; i < 3; i++ {
			e.assetOn("zz-out-secret-managed-"+string(rune('a'+i)), nM)
		}
		e.assign(fx.subject.ID, model.BuiltinAssetAdmin, "", nM)
		// (iv) 範圍外 o1 同時經個人與群組兩筆 connect 授權命中；範圍內 i1 也加一筆群組授權
		g := e.group("cx-group")
		e.join(g.ID, fx.subject.ID, true)
		e.grantGroupAsset(g.ID, fx.out[0], model.PermissionConnect)
		e.grantUserAsset(fx.subject.ID, fx.out[0], model.PermissionConnect)
		e.grantGroupAsset(g.ID, fx.in[0], model.PermissionConnect)
		o := fx.get(t)
		n, ok := outOfScopeCount(t, o)
		require.True(t, ok)
		assert.Equal(t, 2, n)
		for _, mo := range *o.Connection.ManageOnly {
			assert.NotContains(t, mo.NodePath, "zz-out")
		}
		requireNoLeak(t, o)
		assert.NotContains(t, jsonOf(t, o.Connection), "zz-out-secret")
	})

	t.Run("每個分辨案例單獨加入台數都不變", func(t *testing.T) {
		for _, name := range []string{"view", "approver", "manage", "dedupe"} {
			name := name
			t.Run(name, func(t *testing.T) {
				fx := newConnFx(t)
				e := fx.e
				switch name {
				case "view":
					e.grantUserAsset(fx.subject.ID, e.assetOn("zz-out-secret-v", e.node("zz-out-other-node", nil)), model.PermissionView)
				case "approver":
					ap := e.assetOn("zz-out-secret-a", e.node("zz-out-other-node", nil))
					require.NoError(t, e.db.Create(&model.ApproverScope{ApproverID: &fx.subject.ID, AssetID: &ap}).Error)
				case "manage":
					nM := e.node("zz-out-manage-node", nil)
					e.assetOn("zz-out-secret-m", nM)
					e.assign(fx.subject.ID, model.BuiltinAssetAdmin, "", nM)
				case "dedupe":
					g := e.group("cx-group")
					e.join(g.ID, fx.subject.ID, true)
					e.grantGroupAsset(g.ID, fx.out[0], model.PermissionConnect)
					e.grantUserAsset(fx.subject.ID, fx.out[0], model.PermissionConnect)
				}
				n, ok := outOfScopeCount(t, fx.get(t))
				require.True(t, ok)
				assert.Equal(t, 2, n)
			})
		}
	})

	t.Run("檢視者資產頁聯集內但不在授權管理範圍的資產計入匿名台數而不出項", func(t *testing.T) {
		fx := newConnFx(t)
		e := fx.e
		nExtra := e.node("cx-union-only", nil)
		x := e.assetOn("zz-out-secret-union", nExtra)
		e.grantUserAsset(fx.subject.ID, x, model.PermissionConnect)
		e.custom("ov-asset-only", PermAssetView)
		e.assign(fx.viewer.ID, "ov-asset-only", "", nExtra)
		// 該資產在檢視者的資產可視聯集內
		visible, err := e.svc.assetVisibleTo(e.principalOf(fx.viewer), x)
		require.NoError(t, err)
		require.True(t, visible)
		o := fx.get(t)
		n, _ := outOfScopeCount(t, o)
		assert.Equal(t, 3, n)
		requireNoLeak(t, o)
	})

	t.Run("檢視者為全域時不帶匿名台數", func(t *testing.T) {
		fx := newConnFx(t)
		o := fx.e.overview(fx.e.globalViewer(), fx.subject)
		_, ok := outOfScopeCount(t, o)
		assert.False(t, ok)
		require.True(t, o.Connection.Available)
		assert.Len(t, *o.Connection.Items, 2, "全域檢視者看到兩項授權")
	})

	t.Run("檢視者不具授權管理能力時連線區段不可用且不回項目或台數", func(t *testing.T) {
		fx := newConnFx(t)
		e := fx.e
		e.custom("ov-no-authz", PermAssetView)
		v := e.user("cx-no-authz")
		e.assign(v.ID, "ov-no-authz", "")
		o := e.overview(v, fx.subject)
		assert.False(t, o.Connection.Available)
		m := jsonMap(t, o.Connection)
		assert.Equal(t, map[string]any{"available": false}, m)
		assert.NotEmpty(t, o.Management.Permissions, "管理區段照常回傳")
	})

	t.Run("超管被檢視者：無顯式授權時以摘要呈現且不帶台數，群組取得者亦同", func(t *testing.T) {
		for _, via := range []string{"direct", "group"} {
			via := via
			t.Run(via, func(t *testing.T) {
				fx := newConnFx(t)
				e := fx.e
				su := e.user("cx-super-" + via)
				if via == "direct" {
					e.assign(su.ID, model.BuiltinSuperAdmin, "")
				} else {
					g := e.group("cx-super-group")
					e.groupRole(g.ID, model.BuiltinSuperAdmin)
					e.join(g.ID, su.ID, true)
				}
				o := e.overview(fx.viewer, su)
				assert.Equal(t, model.RoleAdmin, o.Connection.RoleOverride)
				assert.True(t, o.Management.Identity.SuperAdmin)
				_, ok := outOfScopeCount(t, o)
				assert.False(t, ok, "超管被檢視者不帶範圍外台數")
				if via == "group" {
					res, err := e.eff.ResolveEffectiveAssetsFor(e.ctxOf(fx.viewer), su.ID, time.Now())
					require.NoError(t, err)
					assert.Empty(t, res.RoleOverride, "既有主體視角對群組取得的超管 role_override 為空，本段不沿用")
				}
			})
		}
	})

	t.Run("稽核員只在範圍外有一台 connect 授權時台數為一", func(t *testing.T) {
		fx := newConnFx(t)
		e := fx.e
		au := e.user("cx-auditor")
		e.assign(au.ID, model.BuiltinAuditor, "")
		e.grantUserAsset(au.ID, fx.out[0], model.PermissionConnect)
		o := e.overview(fx.viewer, au)
		n, ok := outOfScopeCount(t, o)
		require.True(t, ok)
		assert.Equal(t, 1, n, "稽核員的角色隱含只到 view")
		assert.Equal(t, model.RoleAuditor, o.Connection.RoleOverride)
	})

	t.Run("授權記錄不在檢視者授權列表投影內時只併入不具名項", func(t *testing.T) {
		fx := newConnFx(t)
		e := fx.e
		parent := e.node("cx-parent", nil)
		require.NoError(t, e.db.Model(&model.AssetGroup{}).Where("id = ?", fx.nIn).Update("parent_id", parent).Error)
		hidden := e.grantUserNode(fx.subject.ID, parent, model.PermissionView)
		require.NoError(t, e.db.Model(hidden).Update("accounts", `["secret-account"]`).Error)
		o := fx.get(t)
		var undisclosed *OverviewConnectionItem
		for i, it := range *o.Connection.Items {
			if it.Kind == OverviewItemUndisclosed {
				undisclosed = &(*o.Connection.Items)[i]
			}
		}
		require.NotNil(t, undisclosed, "應有不具名項")
		assert.Equal(t, string(model.PermissionView), undisclosed.Permission)
		assert.Equal(t, 3, undisclosed.VisibleAssetCount)
		keys := []string{}
		for k := range jsonMap(t, undisclosed) {
			keys = append(keys, k)
		}
		assert.ElementsMatch(t, []string{"kind", "permission", "visible_asset_count", "managed_asset_count"}, keys)
		full := jsonOf(t, o.Connection)
		assert.NotContains(t, full, "secret-account")
		for _, it := range *o.Connection.Items {
			if it.OverviewItemDetail != nil {
				assert.NotEqual(t, hidden.ID, it.AuthorizationID, "不回傳該記錄識別碼")
			}
		}
	})

	t.Run("整項都看不到時不出項", func(t *testing.T) {
		e := newOvEnv(t)
		nIn := e.node("cx-in", nil)
		nOut := e.node(cxOutNode, nil)
		e.assetOn("cx-in-1", nIn)
		e.assetOn(cxOutName+"1", nOut)
		viewer := e.scopedViewer(nIn)
		s := e.user("cx-only-out")
		e.grantUserNode(s.ID, nOut, model.PermissionConnect)
		o := e.overview(viewer, s)
		assert.Empty(t, *o.Connection.Items)
		n, ok := outOfScopeCount(t, o)
		require.True(t, ok)
		assert.Equal(t, 1, n)
		requireNoLeak(t, o)
	})

	t.Run("帳號範圍、時效與連線政策", func(t *testing.T) {
		fx := newConnFx(t)
		e := fx.e
		var g model.AssetAuthorization
		require.NoError(t, e.db.Where("asset_group_id = ?", fx.nIn).First(&g).Error)
		require.NoError(t, e.db.Model(&g).Update("accounts", `["app","root"]`).Error)
		exp := time.Now().Add(48 * time.Hour)
		require.NoError(t, e.db.Model(&g).Update("date_expired", exp).Error)
		pol := model.AccessPolicyApproval
		require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", fx.in[0]).Update("access_policy", pol).Error)
		it := (*fx.get(t).Connection.Items)[0]
		assert.Equal(t, []string{"app", "root"}, it.AccountScope)
		require.NotNil(t, it.Validity.DateExpired)
		assert.Nil(t, it.Validity.DateStart)
		assert.Equal(t, OverviewPolicyMixed, it.AccessPolicy)
	})

	t.Run("也能管理的台數與能管不能連的範圍", func(t *testing.T) {
		e := newOvEnv(t)
		nM := e.node("cx-m", nil)
		nM1 := e.node("cx-m1", &nM)
		nM2 := e.node("cx-m2", &nM)
		for i := 0; i < 2; i++ {
			e.assetOn("cx-m1-"+string(rune('a'+i)), nM1)
			e.assetOn("cx-m2-"+string(rune('a'+i)), nM2)
		}
		nE := e.node("cx-eight", nil)
		for i := 0; i < 8; i++ {
			e.assetOn("cx-eight-"+string(rune('a'+i)), nE)
		}
		viewer := e.scopedViewer(nM, nE)
		full, half := e.user("cx-full"), e.user("cx-half")
		e.grantUserNode(full.ID, nM, model.PermissionConnect)
		e.grantUserNode(half.ID, nM, model.PermissionConnect)
		e.assign(full.ID, model.BuiltinAssetAdmin, "", nM, nE)
		e.assign(half.ID, model.BuiltinAssetAdmin, "", nM1)
		of := e.overview(viewer, full)
		it := (*of.Connection.Items)[0]
		assert.Equal(t, 4, it.VisibleAssetCount)
		assert.Equal(t, 4, it.ManagedAssetCount)
		oh := e.overview(viewer, half)
		assert.Equal(t, 2, (*oh.Connection.Items)[0].ManagedAssetCount)
		require.Len(t, *of.Connection.ManageOnly, 1)
		assert.Equal(t, OverviewManageOnly{NodePath: "cx-eight", AssetCount: 8}, (*of.Connection.ManageOnly)[0])
		assert.Empty(t, *oh.Connection.ManageOnly, "半數指派的範圍內資產都有連線授權")
	})

	t.Run("既有主體視角與客體視角的回應不因本段改變", func(t *testing.T) {
		fx := newConnFx(t)
		e := fx.e
		before := func() (string, string) {
			a, err := e.eff.ResolveEffectiveAssetsFor(e.ctxOf(fx.viewer), fx.subject.ID, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			require.NoError(t, err)
			u, err := e.eff.ResolveEffectiveUsersFor(e.ctxOf(fx.viewer), fx.in[0], time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			require.NoError(t, err)
			return jsonOf(t, a), jsonOf(t, u)
		}
		a1, u1 := before()
		fx.get(t)
		a2, u2 := before()
		assert.Equal(t, a1, a2)
		assert.Equal(t, u1, u2)
		assert.False(t, strings.Contains(a1, "out_of_scope_asset_count"), "既有回應對交集外資產照舊不給計數")
	})
}
