package authz

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
)

func TestApproverOnlyClassification(t *testing.T) {
	g := model.ScopeKindGlobal
	n := model.ScopeKindNodes
	approver := func(scope string) Assignment {
		return Assignment{BuiltinKey: model.BuiltinApprover, Via: ViaDirect, Scope: scope, RoleSource: model.RoleSourceManual}
	}
	user := func(scope, via, source string) Assignment {
		return Assignment{BuiltinKey: model.BuiltinUser, Via: via, Scope: scope, RoleSource: source}
	}
	cases := []struct {
		name string
		as   []Assignment
		kind string
		want bool
	}{
		{"零指派", nil, model.KindHuman, false},
		{"只有全域審核者", []Assignment{approver(g)}, model.KindHuman, true},
		{"只有節點範圍審核者", []Assignment{approver(n)}, model.KindHuman, true},
		{"審核者加一般使用者", []Assignment{approver(g), user(g, ViaDirect, model.RoleSourceManual)}, model.KindHuman, false},
		{"審核者加經群組一般使用者", []Assignment{approver(g), user(g, ViaGroup, "")}, model.KindHuman, false},
		{"審核者加經映射一般使用者", []Assignment{approver(g), user(g, ViaDirect, model.RoleSourceMapped)}, model.KindHuman, false},
		{"審核者加授權管理員", []Assignment{approver(g), {BuiltinKey: model.BuiltinAuthzAdmin, Via: ViaDirect, Scope: g}}, model.KindHuman, false},
		{"全域審核者加節點範圍一般使用者", []Assignment{approver(g), user(n, ViaDirect, model.RoleSourceManual)}, model.KindHuman, true},
		{"節點範圍審核者加節點範圍一般使用者", []Assignment{approver(n), user(n, ViaGroup, "")}, model.KindHuman, true},
		{"只有節點範圍一般使用者", []Assignment{user(n, ViaDirect, model.RoleSourceManual)}, model.KindHuman, false},
		{"審核者加節點範圍資產管理員", []Assignment{approver(g), {BuiltinKey: model.BuiltinAssetAdmin, Via: ViaDirect, Scope: n}}, model.KindHuman, false},
		{"agent 持審核者", []Assignment{approver(g)}, model.KindAgent, false},
	}
	for _, c := range cases {
		require.Equal(t, c.want, ApproverOnly(c.as, c.kind), c.name)
	}
}

func TestApproverOnlyBatchMatchesSingle(t *testing.T) {
	db := newPrincipalDB(t)
	mkRole := func(name, key string) model.Role {
		k := key
		r := model.Role{Name: name, BuiltinKey: &k}
		require.NoError(t, db.Create(&r).Error)
		return r
	}
	approver := mkRole("approver", model.BuiltinApprover)
	user := mkRole("user", model.BuiltinUser)
	mkUser := func(name string) model.User {
		u := model.User{Username: name, Password: "x", Active: true}
		require.NoError(t, db.Create(&u).Error)
		return u
	}
	only := mkUser("only-approver")
	both := mkUser("approver-and-user")
	viaGroup := mkUser("approver-group-user")
	grant := func(u model.User, r model.Role, scope string) {
		require.NoError(t, db.Create(&model.UserRole{UserID: u.ID, RoleID: r.ID, Source: model.RoleSourceManual, ScopeKind: scope}).Error)
	}
	grant(only, approver, model.ScopeKindGlobal)
	grant(both, approver, model.ScopeKindGlobal)
	grant(both, user, model.ScopeKindGlobal)
	grant(viaGroup, approver, model.ScopeKindGlobal)
	grp := model.UserGroup{Name: "g"}
	require.NoError(t, db.Create(&grp).Error)
	require.NoError(t, db.Create(&model.UserGroupMember{UserGroupID: grp.ID, UserID: viaGroup.ID, Manual: true}).Error)
	require.NoError(t, db.Create(&model.UserGroupRole{UserGroupID: grp.ID, RoleID: user.ID, ScopeKind: model.ScopeKindGlobal}).Error)

	ids := []uint{only.ID, both.ID, viaGroup.ID}
	batch, err := LoadApproverOnly(db, ids)
	require.NoError(t, err)
	require.Equal(t, map[uint]bool{only.ID: true, both.ID: false, viaGroup.ID: false}, batch)
	for _, id := range ids {
		single, err := IsApproverOnlyTx(db, id)
		require.NoError(t, err)
		require.Equal(t, batch[id], single, id)
	}
}
