package authz

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 權限一覽測試共用夾具：真 SQL（in-memory SQLite）上建主體、角色、節點、資產與授權，
// 組出與正式組裝相同形狀的解釋服務（映射規則與政策段位以測試替身提供）。

type stubOverviewMappings struct {
	roles  map[uint][]OverviewRuleRef
	groups map[uint][]OverviewRuleRef
}

func (m stubOverviewMappings) RoleMappingRules(_ *gorm.DB, _ uint) (map[uint][]OverviewRuleRef, error) {
	return m.roles, nil
}

func (m stubOverviewMappings) GroupMappingRules(_ *gorm.DB, _ uint) (map[uint][]OverviewRuleRef, error) {
	return m.groups, nil
}

type stubOverviewPolicies struct{}

func (stubOverviewPolicies) ResolveSegments(in []*string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = model.AccessPolicyOpen
		if v != nil {
			out[i] = *v
		}
	}
	return out
}

type ovEnv struct {
	t        *testing.T
	db       *gorm.DB
	e        *ScopeEvaluator
	eff      *EffectiveAccessResolver
	acl      *AssetAuthorizationService
	svc      *PermissionOverviewService
	mappings stubOverviewMappings
	roles    map[string]uint
	seq      int
}

func newOvEnv(t *testing.T) *ovEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, migrateWithAuthz(db, &model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{},
		&model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}, &model.RolePermission{},
		&model.AuthzState{}, &model.AssetGroup{}, &model.Asset{}, &model.AssetNode{}, &model.AssetAuthorization{},
		&model.ApproverScope{}, &model.AuditLog{}))
	require.NoError(t, db.Create(&model.AuthzState{ID: 1}).Error)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	env := &ovEnv{t: t, db: db, roles: map[string]uint{}}
	env.e = NewScopeEvaluator(ProductCatalogue(), asset.NewScopeTopologyReader(), ProductScopeResolvers()...)
	env.eff = NewEffectiveAccessResolver(db).WithScope(env.e)
	env.acl = NewAssetAuthorizationService(db)
	env.mappings = stubOverviewMappings{roles: map[uint][]OverviewRuleRef{}, groups: map[uint][]OverviewRuleRef{}}
	env.svc = NewPermissionOverviewService(db, env.e, env.eff, env.acl, env.mappings, stubOverviewPolicies{})
	for _, k := range []string{model.BuiltinSuperAdmin, model.BuiltinAuditor, model.BuiltinUser, model.BuiltinApprover,
		model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin, model.BuiltinIdentityAdmin} {
		env.builtin(k)
	}
	return env
}

func (e *ovEnv) rebuild() {
	e.svc = NewPermissionOverviewService(e.db, e.e, e.eff, e.acl, e.mappings, stubOverviewPolicies{})
}

func (e *ovEnv) builtin(key string) uint {
	k := key
	r := model.Role{Name: key, BuiltinKey: &k}
	require.NoError(e.t, e.db.Create(&r).Error)
	e.roles[key] = r.ID
	return r.ID
}

func (e *ovEnv) custom(name string, perms ...Permission) uint {
	r := model.Role{Name: name, DefinitionVersion: 1}
	require.NoError(e.t, e.db.Create(&r).Error)
	for _, p := range perms {
		require.NoError(e.t, e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(p)}).Error)
	}
	e.roles[name] = r.ID
	return r.ID
}

func (e *ovEnv) uniq(prefix string) string {
	e.seq++
	return prefix + "-" + string(rune('a'+e.seq/26)) + string(rune('a'+e.seq%26))
}

func (e *ovEnv) user(name string) *model.User {
	u := &model.User{Username: name, Password: "x", Email: strPtr(name + "@test.local"), Active: true, Kind: model.KindHuman}
	require.NoError(e.t, e.db.Create(u).Error)
	return u
}

func (e *ovEnv) agent(name string) *model.User {
	u := &model.User{Username: name, Password: "x", Active: true, Kind: model.KindAgent}
	require.NoError(e.t, e.db.Create(u).Error)
	return u
}

// assign 直接指派；nodes 非空即節點範圍。source 空值視為 manual。
func (e *ovEnv) assign(userID uint, role string, source string, nodes ...uint) {
	if source == "" {
		source = model.RoleSourceManual
	}
	scope := model.ScopeKindGlobal
	if len(nodes) > 0 {
		scope = model.ScopeKindNodes
	}
	require.NoError(e.t, e.db.Create(&model.UserRole{UserID: userID, RoleID: e.roles[role], Source: source, ScopeKind: scope}).Error)
	for _, n := range nodes {
		require.NoError(e.t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: userID, RoleID: e.roles[role], NodeID: n}).Error)
	}
}

func (e *ovEnv) group(name string) *model.UserGroup {
	g := &model.UserGroup{Name: name}
	require.NoError(e.t, e.db.Create(g).Error)
	return g
}

func (e *ovEnv) groupRole(groupID uint, role string, nodes ...uint) {
	scope := model.ScopeKindGlobal
	if len(nodes) > 0 {
		scope = model.ScopeKindNodes
	}
	require.NoError(e.t, e.db.Create(&model.UserGroupRole{UserGroupID: groupID, RoleID: e.roles[role], ScopeKind: scope}).Error)
	for _, n := range nodes {
		require.NoError(e.t, e.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUserGroup, SubjectID: groupID, RoleID: e.roles[role], NodeID: n}).Error)
	}
}

func (e *ovEnv) join(groupID, userID uint, manual bool) {
	require.NoError(e.t, e.db.Create(&model.UserGroupMember{UserGroupID: groupID, UserID: userID, Manual: manual}).Error)
	if !manual { // GORM 對 false 取預設值 true，需補寫
		require.NoError(e.t, e.db.Model(&model.UserGroupMember{}).Where("user_group_id = ? AND user_id = ?", groupID, userID).Update("manual", false).Error)
	}
}

func (e *ovEnv) node(name string, parent *uint) uint {
	return mkNode(e.t, e.db, name, parent).ID
}

func (e *ovEnv) assetOn(name string, nodes ...uint) uint {
	a := mkAsset(e.t, e.db, name)
	for _, n := range nodes {
		require.NoError(e.t, e.db.Create(&model.AssetNode{AssetID: a.ID, NodeID: n}).Error)
	}
	return a.ID
}

func (e *ovEnv) grantUserAsset(userID, assetID uint, perm model.PermissionType) *model.AssetAuthorization {
	return grant(e.t, e.db, &userID, nil, &assetID, nil, perm, model.AuthorizationSourceManual, nil, nil)
}

func (e *ovEnv) grantUserNode(userID, nodeID uint, perm model.PermissionType) *model.AssetAuthorization {
	return grant(e.t, e.db, &userID, nil, nil, &nodeID, perm, model.AuthorizationSourceManual, nil, nil)
}

func (e *ovEnv) grantGroupNode(groupID, nodeID uint, perm model.PermissionType) *model.AssetAuthorization {
	return grant(e.t, e.db, nil, &groupID, nil, &nodeID, perm, model.AuthorizationSourceManual, nil, nil)
}

func (e *ovEnv) grantGroupAsset(groupID, assetID uint, perm model.PermissionType) *model.AssetAuthorization {
	return grant(e.t, e.db, nil, &groupID, &assetID, nil, perm, model.AuthorizationSourceManual, nil, nil)
}

// ctxOf 帶檢視者主體的 context（服務會在讀取連線上重解）。
func (e *ovEnv) ctxOf(viewer *model.User) context.Context {
	return ContextWithPrincipal(context.Background(), &Principal{UserID: viewer.ID, Facts: TokenFacts{SubjectKind: viewer.Kind}})
}

func (e *ovEnv) overview(viewer, subject *model.User) *PermissionOverview {
	e.t.Helper()
	res, err := e.svc.Overview(e.ctxOf(viewer), subject.ID)
	require.NoError(e.t, err)
	return res
}

func (e *ovEnv) principalOf(u *model.User) *Principal {
	e.t.Helper()
	p, err := ResolveUserOn(e.db, u.ID, TokenFacts{SubjectKind: u.Kind})
	require.NoError(e.t, err)
	return p
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

func jsonMap(t *testing.T, v any) map[string]any {
	t.Helper()
	out := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(jsonOf(t, v)), &out))
	return out
}

// scopedViewer 只對一個節點範圍持 authorization:manage 與 asset:view 的檢視者。
func (e *ovEnv) scopedViewer(nodes ...uint) *model.User {
	if _, ok := e.roles["ov-authz-viewer"]; !ok {
		e.custom("ov-authz-viewer", PermAuthorizationManage, PermAssetView)
	}
	v := e.user(e.uniq("viewer"))
	e.assign(v.ID, "ov-authz-viewer", "", nodes...)
	return v
}

func (e *ovEnv) globalViewer() *model.User {
	v := e.user(e.uniq("gviewer"))
	e.assign(v.ID, model.BuiltinSuperAdmin, "")
	return v
}
