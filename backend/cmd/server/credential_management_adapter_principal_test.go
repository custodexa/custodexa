package main

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 憑證管理關卡的轉接頭依路徑分流：請求路徑取請求主體的事實（含角色限定）、缺主體即拒絕；
// 背景作業只在帶背景發起者標示時以帳號完整身分重驗。

type credAdapterEnv struct {
	db                  *gorm.DB
	ad                  *credentialManagementAdapter
	user                uint
	assetRole, credRole uint
}

func newCredAdapterEnv(t *testing.T) *credAdapterEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.RolePermission{}, &model.UserGroup{},
		&model.AuthzState{}, &model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{},
		&model.RoleBindingNode{}, &model.AssetGroup{}))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
	e := &credAdapterEnv{db: db, ad: newCredentialManagementAdapter(authz.NewResolver(db))}
	u := model.User{Username: "holder", Password: "x", Active: true}
	require.NoError(t, db.Create(&u).Error)
	e.user = u.ID
	e.assetRole = e.customRole(t, "asset-editor", authz.PermAssetView, authz.PermAssetCreate, authz.PermAssetUpdate)
	e.credRole = e.customRole(t, "credential-keeper", authz.PermCredentialCreate, authz.PermCredentialSetSecret, authz.PermCredentialBind)
	for _, rid := range []uint{e.assetRole, e.credRole} {
		require.NoError(t, db.Create(&model.UserRole{UserID: u.ID, RoleID: rid, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	}
	return e
}

func (e *credAdapterEnv) customRole(t *testing.T, name string, perms ...authz.Permission) uint {
	t.Helper()
	r := model.Role{Name: name, DefinitionVersion: 1}
	require.NoError(t, e.db.Create(&r).Error)
	for _, p := range perms {
		require.NoError(t, e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(p)}).Error)
	}
	return r.ID
}

func (e *credAdapterEnv) principal(t *testing.T, filter *authz.RoleFilter) *authz.Principal {
	t.Helper()
	p, err := authz.ResolveUserOn(e.db, e.user, authz.TokenFacts{SubjectKind: model.KindHuman, RoleFilter: filter})
	require.NoError(t, err)
	return p
}

func requestCtx(kind model.RequestCredential, p *authz.Principal, userID uint) context.Context {
	ctx := model.WithRequestCredential(context.Background(), kind)
	ctx = context.WithValue(ctx, "userID", userID) //nolint:staticcheck // 審計 context 的既有鍵
	return authz.ContextWithPrincipal(ctx, p)
}

func (e *credAdapterEnv) allowed(t *testing.T, ctx context.Context, caps ...string) bool {
	t.Helper()
	d, err := e.ad.AuthorizeCredentialManagement(ctx, nil, asset.CredentialManagementActor{UserID: e.user},
		asset.CredentialManagementRequest{Operation: asset.CredOpSetSecret, Capabilities: caps})
	require.NoError(t, err)
	return d.Allowed
}

// TestAPITokenAssetRoleCannotSetSecretOrCreateEmbeddedCredential 只授權資產角色的 token 寫入秘密與建立
// 內嵌憑證被拒（本人經另一個角色持有憑證能力）；人類工作階段與修改前相同。
func TestAPITokenAssetRoleCannotSetSecretOrCreateEmbeddedCredential(t *testing.T) {
	e := newCredAdapterEnv(t)
	token := requestCtx(model.RequestCredentialAPIToken, e.principal(t, authz.NewRoleFilter([]uint{e.assetRole})), e.user)
	assert.False(t, e.allowed(t, token, asset.CredCapSetSecret), "寫入秘密")
	assert.False(t, e.allowed(t, token, asset.CredCapCreate), "建立內嵌憑證")
	assert.False(t, e.allowed(t, token, asset.CredCapBind), "掛載共用憑證")

	human := requestCtx(model.RequestCredentialHumanSession, e.principal(t, nil), e.user)
	assert.True(t, e.allowed(t, human, asset.CredCapSetSecret), "人類工作階段照常")
	assert.True(t, e.allowed(t, human, asset.CredCapCreate))

	granted := requestCtx(model.RequestCredentialAPIToken, e.principal(t, authz.NewRoleFilter([]uint{e.assetRole, e.credRole})), e.user)
	assert.True(t, e.allowed(t, granted, asset.CredCapSetSecret), "授權了憑證角色的 token 可寫入秘密")
}

// TestCredentialGateRequestWithoutPrincipalDenied 請求路徑刻意不放主體時關卡拒絕，不退回帳號完整身分。
func TestCredentialGateRequestWithoutPrincipalDenied(t *testing.T) {
	e := newCredAdapterEnv(t)
	bare := requestCtx(model.RequestCredentialHumanSession, nil, e.user)
	assert.False(t, e.allowed(t, bare, asset.CredCapSetSecret))
	noMarker := context.WithValue(context.Background(), "userID", e.user) //nolint:staticcheck
	assert.False(t, e.allowed(t, noMarker, asset.CredCapSetSecret), "既無標示也缺主體時拒絕")
	other := requestCtx(model.RequestCredentialHumanSession, authz.NewPrincipal(e.user+100, authz.TokenFacts{}, nil), e.user)
	assert.False(t, e.allowed(t, other, asset.CredCapSetSecret), "主體與操作者不符時拒絕")
}

// TestCredentialGateBackgroundInitiatorRevalidatesFullIdentity 帶背景發起者標示者以帳號完整身分重驗：
// 能力照常通過（既有改密計劃與輪替不被打斷）；帳號停用或能力收回時照常拒絕。
func TestCredentialGateBackgroundInitiatorRevalidatesFullIdentity(t *testing.T) {
	e := newCredAdapterEnv(t)
	bg := model.WithBackgroundInitiator(context.Background(), e.user, "holder")
	assert.True(t, e.allowed(t, bg, asset.CredCapSetSecret, asset.CredCapCreate))

	require.NoError(t, e.db.Where("user_id = ? AND role_id = ?", e.user, e.credRole).Delete(&model.UserRole{}).Error)
	assert.False(t, e.allowed(t, bg, asset.CredCapSetSecret), "背景重驗現查能力")
	require.NoError(t, e.db.Create(&model.UserRole{UserID: e.user, RoleID: e.credRole, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", e.user).Update("active", false).Error)
	assert.False(t, e.allowed(t, bg, asset.CredCapSetSecret), "背景重驗現查帳號是否啟用")
}

// TestBackgroundMarkerCannotOverrideRequestCredential context 已有請求憑證種類時，背景標示不能覆蓋它：
// 請求內呼叫背景入口不取得帳號完整身分。
func TestBackgroundMarkerCannotOverrideRequestCredential(t *testing.T) {
	e := newCredAdapterEnv(t)
	tokenNoPrincipal := model.WithRequestCredential(context.Background(), model.RequestCredentialAPIToken)
	forged := model.WithBackgroundInitiator(tokenNoPrincipal, e.user, "holder")
	_, isBG := model.BackgroundInitiatorFrom(forged)
	assert.False(t, isBG)
	assert.False(t, e.allowed(t, forged, asset.CredCapSetSecret))

	// 帶限定的請求主體在請求內被包上背景入口，仍以請求主體的限定判定
	token := requestCtx(model.RequestCredentialAPIToken, e.principal(t, authz.NewRoleFilter([]uint{e.assetRole})), e.user)
	assert.False(t, e.allowed(t, model.WithBackgroundInitiator(token, e.user, "holder"), asset.CredCapSetSecret))
}
