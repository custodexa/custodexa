package authz

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupResolverDB 真 SQL 整合測試（in-memory SQLite）：resolver 與既有解析引擎
// 的雙向等價必須實際執行驗證（防漂移硬要求）
func setupResolverDB(t *testing.T) (*EffectiveAccessResolver, *AssetAuthorizationService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetAuthorization{},
		&model.ApproverScope{}, &model.AuditLog{},
	))
	// NodePathMap 等既有共用函式走 database.DB
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return NewEffectiveAccessResolver(db), NewAssetAuthorizationService(db), db
}

func mkUser(t *testing.T, db *gorm.DB, name string) *model.User {
	t.Helper()
	u := &model.User{Username: name, Password: "x", Email: strPtr(name + "@test.local"), Active: true}
	require.NoError(t, db.Create(u).Error)
	return u
}

func mkAsset(t *testing.T, db *gorm.DB, name string) *model.Asset {
	t.Helper()
	a := &model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: "h", Port: 22}
	require.NoError(t, db.Create(a).Error)
	return a
}

func mkNode(t *testing.T, db *gorm.DB, name string, parent *uint) *model.AssetGroup {
	t.Helper()
	g := &model.AssetGroup{Name: name, ParentID: parent}
	require.NoError(t, db.Create(g).Error)
	return g
}

func grant(t *testing.T, db *gorm.DB, userID, groupID, assetID, nodeID *uint, perm model.PermissionType, source string, ds, de *time.Time) *model.AssetAuthorization {
	t.Helper()
	a := &model.AssetAuthorization{
		UserID: userID, UserGroupID: groupID, AssetID: assetID, AssetGroupID: nodeID,
		Permission: perm, GrantedBy: 1, Source: source, DateStart: ds, DateExpired: de,
	}
	require.NoError(t, db.Create(a).Error)
	return a
}

func idp(v uint) *uint { return &v }

// TestResolverEquivalence_GeneralUser 一般使用者主體：四路徑溯因齊全，
// 且與 GetAuthorizedAssets/CheckPermission 雙向等價（含過期排除）
func TestResolverEquivalence_GeneralUser(t *testing.T) {
	resolver, svc, db := setupResolverDB(t)
	now := time.Now()

	u := mkUser(t, db, "u1")
	a1 := mkAsset(t, db, "a1-direct")
	a2 := mkAsset(t, db, "a2-node")
	a3 := mkAsset(t, db, "a3-group")
	a4 := mkAsset(t, db, "a4-expired")
	aX := mkAsset(t, db, "ax-unrelated")

	n1 := mkNode(t, db, "N1", nil)
	n2 := mkNode(t, db, "N2", idp(n1.ID))
	require.NoError(t, db.Create(&model.AssetNode{AssetID: a2.ID, NodeID: n2.ID}).Error)

	g := &model.UserGroup{Name: "sre"}
	require.NoError(t, db.Create(g).Error)
	require.NoError(t, db.Model(g).Association("Users").Append(u))

	grant(t, db, idp(u.ID), nil, idp(a1.ID), nil, model.PermissionConnect, model.AuthorizationSourceManual, nil, nil)
	grant(t, db, idp(u.ID), nil, nil, idp(n1.ID), model.PermissionConnect, model.AuthorizationSourceManual, nil, nil)
	grant(t, db, nil, idp(g.ID), idp(a3.ID), nil, model.PermissionView, model.AuthorizationSourceManual, nil, nil)
	past := now.Add(-2 * time.Hour)
	expired := now.Add(-1 * time.Hour)
	grant(t, db, idp(u.ID), nil, idp(a4.ID), nil, model.PermissionConnect, model.AuthorizationSourceTicket, &past, &expired)

	result, err := resolver.ResolveEffectiveAssets(u.ID, now)
	require.NoError(t, err)
	assert.Equal(t, "", result.RoleOverride)

	byID := map[uint]EffectiveAssetEntry{}
	for _, e := range result.Assets {
		byID[e.AssetID] = e
	}
	// a1 直授 connect
	require.Contains(t, byID, a1.ID)
	assert.Equal(t, model.PermissionConnect, byID[a1.ID].Permission)
	require.Len(t, byID[a1.ID].Paths, 1)
	assert.Equal(t, PathDirectUser, byID[a1.ID].Paths[0].Kind)
	assert.NotNil(t, byID[a1.ID].Paths[0].AuthorizationID)
	// a2 經節點 N1 含子樹（掛 N2）
	require.Contains(t, byID, a2.ID)
	require.Len(t, byID[a2.ID].Paths, 1)
	assert.Equal(t, PathAssetNode, byID[a2.ID].Paths[0].Kind)
	assert.Equal(t, "N1", byID[a2.ID].Paths[0].ViaNodePath)
	// a3 經群組 view
	require.Contains(t, byID, a3.ID)
	assert.Equal(t, model.PermissionView, byID[a3.ID].Permission)
	assert.Equal(t, PathUserGroup, byID[a3.ID].Paths[0].Kind)
	assert.Equal(t, "sre", byID[a3.ID].Paths[0].ViaGroupName)
	// 過期票證與無關資產不出現
	assert.NotContains(t, byID, a4.ID)
	assert.NotContains(t, byID, aX.ID)

	// 雙向等價：GetAuthorizedAssets（一般 user ctx）集合一致
	ctx := context.Background() // 無 role 值＝一般使用者路徑
	dtos, err := svc.GetAuthorizedAssets(ctx, u.ID, model.PermissionView)
	require.NoError(t, err)
	engineIDs := map[uint]bool{}
	for _, d := range dtos {
		engineIDs[d.Asset.ID] = true
	}
	resolverIDs := map[uint]bool{}
	for _, e := range result.Assets {
		resolverIDs[e.AssetID] = true
	}
	assert.Equal(t, engineIDs, resolverIDs)

	// 逐資產 CheckPermission 等價（以 resolver 的等級查詢）
	for _, e := range result.Assets {
		ok, err := svc.CheckPermission(ctx, u.ID, e.AssetID, e.Permission)
		require.NoError(t, err)
		assert.True(t, ok, "CheckPermission 應命中 asset %d %s", e.AssetID, e.Permission)
	}
	// 過期票證資產 connect 不命中
	ok, err := svc.CheckPermission(ctx, u.ID, a4.ID, model.PermissionConnect)
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestResolverEquivalence_ApproverScope approver 主體：範圍隱含 view 為第五來源，
// 與資產列表（含第三來源）等價
func TestResolverEquivalence_ApproverScope(t *testing.T) {
	resolver, svc, db := setupResolverDB(t)
	now := time.Now()

	p := mkUser(t, db, "approver1")
	a5 := mkAsset(t, db, "a5-scoped")
	require.NoError(t, db.Create(&model.ApproverScope{ApproverID: &p.ID, AssetID: idp(a5.ID)}).Error)

	result, err := resolver.ResolveEffectiveAssets(p.ID, now)
	require.NoError(t, err)
	assert.Equal(t, "", result.RoleOverride)
	require.Len(t, result.Assets, 1)
	entry := result.Assets[0]
	assert.Equal(t, a5.ID, entry.AssetID)
	assert.Equal(t, model.PermissionView, entry.Permission)
	require.Len(t, entry.Paths, 1)
	assert.Equal(t, PathApproverScope, entry.Paths[0].Kind)
	assert.Nil(t, entry.Paths[0].AuthorizationID)

	// 等價：view 判定經第三來源命中、connect 不命中
	ctx := context.Background()
	ok, err := svc.CheckPermission(ctx, p.ID, a5.ID, model.PermissionView)
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = svc.CheckPermission(ctx, p.ID, a5.ID, model.PermissionConnect)
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestResolver_AdminRoleOverride admin 主體：role_override 標示、顯式授權照列、
// 不因角色展開全資產
func TestResolver_AdminRoleOverride(t *testing.T) {
	resolver, _, db := setupResolverDB(t)
	now := time.Now()

	adm := mkUser(t, db, "admin1")
	role := &model.Role{Name: model.RoleAdmin}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Model(adm).Association("Roles").Append(role))

	a1 := mkAsset(t, db, "a1")
	mkAsset(t, db, "a2-unrelated")
	grant(t, db, idp(adm.ID), nil, idp(a1.ID), nil, model.PermissionConnect, model.AuthorizationSourceManual, nil, nil)

	result, err := resolver.ResolveEffectiveAssets(adm.ID, now)
	require.NoError(t, err)
	assert.Equal(t, model.RoleAdmin, result.RoleOverride)
	// 僅顯式授權列出（角色隱含以摘要標示，不逐列展開）
	require.Len(t, result.Assets, 1)
	assert.Equal(t, a1.ID, result.Assets[0].AssetID)
}

// TestResolver_SubjectNotFound 主體不存在
func TestResolver_SubjectNotFound(t *testing.T) {
	resolver, _, _ := setupResolverDB(t)
	_, err := resolver.ResolveEffectiveAssets(9999, time.Now())
	assert.ErrorIs(t, err, ErrEffectiveSubjectNotFound)
}

// TestResolverEffectiveUsers 客體視角：直授＋群組節點展開成員＋approver 命中，
// 逐使用者與 CheckPermission 等價
func TestResolverEffectiveUsers(t *testing.T) {
	resolver, svc, db := setupResolverDB(t)
	now := time.Now()

	u2 := mkUser(t, db, "u2-direct")
	u3 := mkUser(t, db, "u3-member")
	u4 := mkUser(t, db, "u4-member")
	p := mkUser(t, db, "approver2")
	uX := mkUser(t, db, "ux-unrelated")

	a := mkAsset(t, db, "target")
	n1 := mkNode(t, db, "Root", nil)
	n2 := mkNode(t, db, "Child", idp(n1.ID))
	require.NoError(t, db.Create(&model.AssetNode{AssetID: a.ID, NodeID: n2.ID}).Error)

	g := &model.UserGroup{Name: "ops"}
	require.NoError(t, db.Create(g).Error)
	require.NoError(t, db.Model(g).Association("Users").Append(u3, u4))

	grant(t, db, idp(u2.ID), nil, idp(a.ID), nil, model.PermissionConnect, model.AuthorizationSourceManual, nil, nil)
	grant(t, db, nil, idp(g.ID), nil, idp(n1.ID), model.PermissionView, model.AuthorizationSourceManual, nil, nil)
	// 過期票證不入列
	past := now.Add(-2 * time.Hour)
	expired := now.Add(-1 * time.Hour)
	grant(t, db, idp(uX.ID), nil, idp(a.ID), nil, model.PermissionConnect, model.AuthorizationSourceTicket, &past, &expired)
	require.NoError(t, db.Create(&model.ApproverScope{ApproverID: &p.ID, AssetGroupID: idp(n1.ID)}).Error)

	result, err := resolver.ResolveEffectiveUsers(a.ID, now)
	require.NoError(t, err)
	assert.NotEmpty(t, result.RoleOverrideNote)

	byID := map[uint]EffectiveUserEntry{}
	for _, e := range result.Users {
		byID[e.UserID] = e
	}
	require.Contains(t, byID, u2.ID)
	assert.Equal(t, model.PermissionConnect, byID[u2.ID].Permission)
	assert.Equal(t, PathDirectUser, byID[u2.ID].Paths[0].Kind)

	require.Contains(t, byID, u3.ID)
	require.Contains(t, byID, u4.ID)
	assert.Equal(t, model.PermissionView, byID[u3.ID].Permission)
	assert.Equal(t, PathUserGroupAssetNode, byID[u3.ID].Paths[0].Kind)
	assert.Equal(t, "ops", byID[u3.ID].Paths[0].ViaGroupName)
	assert.Equal(t, "Root", byID[u3.ID].Paths[0].ViaNodePath)

	// approver 經範圍節點含子樹命中 view
	require.Contains(t, byID, p.ID)
	assert.Equal(t, model.PermissionView, byID[p.ID].Permission)
	assert.Equal(t, PathApproverScope, byID[p.ID].Paths[0].Kind)

	// 過期票證主體不入列
	assert.NotContains(t, byID, uX.ID)

	// 等價：逐使用者 CheckPermission
	ctx := context.Background()
	for _, e := range result.Users {
		ok, err := svc.CheckPermission(ctx, e.UserID, a.ID, e.Permission)
		require.NoError(t, err)
		assert.True(t, ok, "CheckPermission 應命中 user %d %s", e.UserID, e.Permission)
	}
}

// TestResolverEffectiveUsers_AssetNotFound 資產不存在
func TestResolverEffectiveUsers_AssetNotFound(t *testing.T) {
	resolver, _, _ := setupResolverDB(t)
	_, err := resolver.ResolveEffectiveUsers(9999, time.Now())
	assert.ErrorIs(t, err, ErrEffectiveAssetNotFound)
}
