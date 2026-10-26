package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

func (e *ovEnv) probe(viewer, subject *model.User, assetID uint) (*OverviewAssetProbe, error) {
	return e.svc.ProbeAsset(e.ctxOf(viewer), subject.ID, assetID)
}

// TestPermissionOverviewAssetProbe 查一台資產與同形 404。
func TestPermissionOverviewAssetProbe(t *testing.T) {
	t.Run("能管理不能連線：附角色與範圍節點", func(t *testing.T) {
		e := newOvEnv(t)
		nM := e.node("pr-manage", nil)
		a := e.assetOn("pr-asset-m", nM)
		s := e.user("pr-s")
		e.assign(s.ID, model.BuiltinAssetAdmin, "", nM)
		got, err := e.probe(e.globalViewer(), s, a)
		require.NoError(t, err)
		assert.True(t, got.Manage.Allowed)
		require.Len(t, got.Manage.Grants, 1)
		assert.Equal(t, model.BuiltinAssetAdmin, *got.Manage.Grants[0].Role.BuiltinKey)
		assert.Equal(t, OverviewScopeNodes, got.Manage.Grants[0].Scope.Kind)
		assert.Equal(t, []uint{nM}, ovScopeNodeIDs(got.Manage.Grants[0].Scope))
		require.True(t, got.Connect.Available)
		require.NotNil(t, got.Connect.Allowed)
		assert.False(t, *got.Connect.Allowed)
		assert.Empty(t, *got.Connect.Items)
	})

	t.Run("能連線：附命中的授權項", func(t *testing.T) {
		e := newOvEnv(t)
		n := e.node("pr-conn", nil)
		a := e.assetOn("pr-asset-c", n)
		s := e.user("pr-s2")
		g := e.grantUserNode(s.ID, n, model.PermissionConnect)
		got, err := e.probe(e.globalViewer(), s, a)
		require.NoError(t, err)
		assert.False(t, got.Manage.Allowed)
		assert.Empty(t, got.Manage.Grants)
		require.NotNil(t, got.Connect.Allowed)
		assert.True(t, *got.Connect.Allowed)
		items := *got.Connect.Items
		require.Len(t, items, 1)
		assert.Equal(t, g.ID, items[0].AuthorizationID)
		assert.Equal(t, "pr-conn", items[0].Target.Name)
		// 超管被檢視者：可連線，摘要為 admin
		su := e.user("pr-super")
		e.assign(su.ID, model.BuiltinSuperAdmin, "")
		got, err = e.probe(e.globalViewer(), su, a)
		require.NoError(t, err)
		assert.True(t, *got.Connect.Allowed)
		assert.Equal(t, model.RoleAdmin, got.Connect.RoleOverride)
		assert.True(t, got.Manage.Allowed)
	})

	t.Run("看不到的資產與不存在的 ID 回同一個錯誤", func(t *testing.T) {
		e := newOvEnv(t)
		nIn := e.node("pr-in", nil)
		nOut := e.node("pr-out-secret", nil)
		e.assetOn("pr-in-a", nIn)
		hidden := e.assetOn("pr-hidden-secret", nOut)
		viewer := e.scopedViewer(nIn)
		s := e.user("pr-s3")
		_, errHidden := e.probe(viewer, s, hidden)
		_, errMissing := e.probe(viewer, s, 987654)
		require.Error(t, errHidden)
		require.Error(t, errMissing)
		assert.ErrorIs(t, errHidden, ErrEffectiveAssetNotFound)
		assert.Equal(t, errMissing, errHidden)
		assert.Equal(t, errMissing.Error(), errHidden.Error())
	})

	t.Run("檢視者無授權管理能力時連線不可用且回應只有 available", func(t *testing.T) {
		e := newOvEnv(t)
		nIn := e.node("pr-in2", nil)
		a := e.assetOn("pr-in2-a", nIn)
		e.custom("pr-asset-only", PermAssetView)
		viewer := e.user("pr-v")
		e.assign(viewer.ID, "pr-asset-only", "", nIn)
		s := e.user("pr-s4")
		e.grantUserNode(s.ID, nIn, model.PermissionConnect)
		got, err := e.probe(viewer, s, a)
		require.NoError(t, err)
		assert.False(t, got.Connect.Available)
		assert.Equal(t, map[string]any{"available": false}, jsonMap(t, got.Connect))
	})

	t.Run("資產在檢視者資產可視集合內但不在授權管理範圍：管理照常、連線不可用且不含授權項", func(t *testing.T) {
		e := newOvEnv(t)
		nAuthz := e.node("pr-authz", nil)
		nAsset := e.node("pr-asset-view", nil)
		e.assetOn("pr-authz-a", nAuthz)
		a := e.assetOn("pr-extra", nAsset)
		viewer := e.scopedViewer(nAuthz)
		e.custom("pr-asset-only2", PermAssetView)
		e.assign(viewer.ID, "pr-asset-only2", "", nAsset)
		s := e.user("pr-s5")
		e.assign(s.ID, model.BuiltinAssetAdmin, "", nAsset)
		e.grantUserNode(s.ID, nAsset, model.PermissionConnect)
		got, err := e.probe(viewer, s, a)
		require.NoError(t, err)
		assert.True(t, got.Manage.Allowed, "管理照常回答")
		assert.False(t, got.Connect.Available)
		m := jsonMap(t, got.Connect)
		assert.Equal(t, map[string]any{"available": false}, m)
		assert.NotContains(t, jsonOf(t, got), "authorization_id")
	})
}
