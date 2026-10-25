package main

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// TestMappingExposureBoundary 擋：新範本經映射或釘住提前取得、映射路徑出現範圍或新入口、
// 目標集合被做成可切換的開關。依據是生產組裝的關卡與路由集合，不是前端隱藏。
func TestMappingExposureBoundary(t *testing.T) {
	newEnv := func(t *testing.T) (*gorm.DB, map[string]uint, uint) {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		sqlDB, _ := db.DB()
		sqlDB.SetMaxOpenConns(1)
		t.Cleanup(func() { _ = sqlDB.Close() })
		require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.RolePermission{}, &model.AuthzState{},
			&model.AuditLog{}, &model.RefreshToken{}, &model.UserRoleMappingRuleSupport{}, &model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.OIDCProvider{}, &model.LDAPDirectory{}, &model.ExternalGroup{},
			&model.GroupRoleMapping{}, &model.GroupUserGroupMapping{}, &model.UserRoleMappingRuleSupport{},
			&model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.UserRoleMapping{}, &model.PermissionStateEvent{}, &model.UserGroup{},
			&model.AssetAuthorization{}, &model.ApproverScope{}))
		require.NoError(t, db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}))
		require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
		ids := map[string]uint{}
		for _, n := range []string{"admin", "auditor", "user", "approver"} {
			r := model.Role{Name: n} // BeforeCreate 帶入內建識別
			require.NoError(t, db.Create(&r).Error)
			ids[n] = r.ID
		}
		for _, seed := range []struct{ name, key string }{{"identity_admin", model.BuiltinIdentityAdmin}, {"security_admin", model.BuiltinSecurityAdmin}} {
			k := seed.key
			r := model.Role{Name: seed.name, BuiltinKey: &k, DefinitionVersion: 1}
			require.NoError(t, db.Create(&r).Error)
			ids[seed.name] = r.ID
		}
		root := model.User{Username: "root", Active: true}
		require.NoError(t, db.Create(&root).Error)
		require.NoError(t, db.Create(&model.UserRole{UserID: root.ID, RoleID: ids["admin"], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		return db, ids, root.ID
	}

	compatGuard, compatVia := catalogGuard(false)
	t.Run("相容目錄（"+compatVia+"）：映射與釘住拒絕兩個新範本，舊四範本行為不變", func(t *testing.T) {
		db, ids, rootID := newEnv(t)
		guard := compatGuard
		src := identity.NewIdentitySourceService(db, audit.NewTxSink())
		src.SetAssignmentGuard(guard)
		us := identity.NewUserService(db, nil)
		us.SetAssignmentGuard(guard)
		us.SetPinAuditSink(audit.NewTxSink())
		p := model.OIDCProvider{Name: "idp", Issuer: "https://idp.example.com", ClientID: "c", GroupsClaim: "groups",
			Enabled: true, AdmissionMode: model.AdmissionPreboundOnly, ClientSecretEnc: "enc"}
		require.NoError(t, db.Create(&p).Error)
		actor := identity.GroupRoleMappingActor{ID: rootID, Name: "root", IP: "10.0.0.1"}
		kind := model.RoleMappingChannelKindProvider

		// 超級管理者本人也不能經映射寫入尚未放行的新範本
		for _, name := range []string{"identity_admin", "security_admin"} {
			_, err := src.CreateMapping(kind, p.ID, identity.GroupRoleMappingInput{MatchValue: "g-" + name, Role: name, RiskAcknowledged: true, Actor: actor})
			assert.ErrorIs(t, err, identity.ErrMappingRoleUnknown, name)
		}
		// 舊四範本照常
		for _, name := range []string{"admin", "auditor", "user", "approver"} {
			_, err := src.CreateMapping(kind, p.ID, identity.GroupRoleMappingInput{MatchValue: "g-" + name, Role: name, RiskAcknowledged: true, Actor: actor})
			assert.NoError(t, err, name)
		}
		var n int64
		require.NoError(t, db.Model(&model.GroupRoleMapping{}).Count(&n).Error)
		assert.EqualValues(t, 4, n, "新範本的規則一條都沒有寫入")

		// 釘住：新範本的映射成分即使存在也不能被釘住
		victim := model.User{Username: "victim", Active: true}
		require.NoError(t, db.Create(&victim).Error)
		for _, name := range []string{"identity_admin", "security_admin"} {
			require.NoError(t, db.Create(&model.UserRole{UserID: victim.ID, RoleID: ids[name], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
			_, err := us.PinMappedRoleBy(identity.Operator{UserID: rootID, Username: "root"}, victim.ID, name)
			assert.ErrorIs(t, err, identity.ErrRoleNotFound, name)
			s, _, err := model.UserRoleSourceOf(db, victim.ID, ids[name])
			require.NoError(t, err)
			assert.Equal(t, model.RoleSourceMapped, s, "仍為 mapped")
		}
	})

	fullGuard, fullVia := catalogGuard(true)
	t.Run("完整目錄（"+fullVia+"）：新範本經映射、釘住、直接、群組取得，保護角色、agent、範圍欄位照舊拒絕", func(t *testing.T) {
		db, ids, rootID := newEnv(t)
		src := identity.NewIdentitySourceService(db, audit.NewTxSink())
		src.SetAssignmentGuard(fullGuard)
		us := identity.NewUserService(db, nil)
		us.SetAssignmentGuard(fullGuard)
		us.SetPinAuditSink(audit.NewTxSink())
		p := model.OIDCProvider{Name: "idp", Issuer: "https://idp.example.com", ClientID: "c", GroupsClaim: "groups",
			Enabled: true, AdmissionMode: model.AdmissionPreboundOnly, ClientSecretEnc: "enc"}
		require.NoError(t, db.Create(&p).Error)
		actor := identity.GroupRoleMappingActor{ID: rootID, Name: "root", IP: "10.0.0.1"}
		kind := model.RoleMappingChannelKindProvider
		root := identity.Operator{UserID: rootID, Username: "root"}

		// 映射：兩個新範本的規則都寫入
		for _, name := range []string{"identity_admin", "security_admin"} {
			_, err := src.CreateMapping(kind, p.ID, identity.GroupRoleMappingInput{MatchValue: "g-" + name, Role: name, RiskAcknowledged: true, Actor: actor})
			assert.NoError(t, err, name)
		}
		var n int64
		require.NoError(t, db.Model(&model.GroupRoleMapping{}).Count(&n).Error)
		assert.EqualValues(t, 2, n)

		// 釘住：新範本的映射成分可被釘住
		victim := model.User{Username: "victim", Active: true}
		require.NoError(t, db.Create(&victim).Error)
		for _, name := range []string{"identity_admin", "security_admin"} {
			require.NoError(t, db.Create(&model.UserRole{UserID: victim.ID, RoleID: ids[name], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
			_, err := us.PinMappedRoleBy(root, victim.ID, name)
			assert.NoError(t, err, name)
			s, _, err := model.UserRoleSourceOf(db, victim.ID, ids[name])
			require.NoError(t, err)
			assert.Equal(t, model.RoleSourceBoth, s, name)
		}

		// 直接指派：超管可發放兩個新範本
		direct := model.User{Username: "direct", Active: true}
		require.NoError(t, db.Create(&direct).Error)
		require.NoError(t, us.AddRoleBy(root, direct.ID, "identity_admin"))
		_, err := us.AssignRolesBy(root, direct.ID, []string{"identity_admin", "security_admin"})
		require.NoError(t, err)

		// 群組角色指派：新範本放行
		g := model.UserGroup{Name: "g1"}
		require.NoError(t, db.Create(&g).Error)
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
			return fullGuard.Check(tx, root, identity.AssignmentChange{Path: identity.PathGroupRoles, GroupID: g.ID, NewRoleIDs: []uint{ids["identity_admin"]}})
		}))

		// 既有關卡照舊：非超管發放保護角色、agent 取得管理類角色、帶範圍欄位都拒絕
		ida := model.User{Username: "ida", Active: true}
		require.NoError(t, db.Create(&ida).Error)
		require.NoError(t, db.Create(&model.UserRole{UserID: ida.ID, RoleID: ids["identity_admin"], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		plain := model.User{Username: "plain", Active: true}
		require.NoError(t, db.Create(&plain).Error)
		assert.ErrorIs(t, us.AddRoleBy(identity.Operator{UserID: ida.ID, Username: "ida"}, plain.ID, "security_admin"), identity.ErrProtectedRoleAssignment)
		owner := rootID
		bot := model.User{Username: "bot", Kind: model.KindAgent, OwnerUserID: &owner, Active: true}
		require.NoError(t, db.Create(&bot).Error)
		assert.ErrorIs(t, us.AddRoleBy(root, bot.ID, "identity_admin"), identity.ErrAgentRoleForbidden)
		assert.ErrorIs(t, us.AddRoleBy(root, plain.ID, "identity_admin", identity.DirectAssignOptions{ScopeRequested: true}), identity.ErrRoleBindingScopeUnsupported)
		_, exists, err := model.UserRoleSourceOf(db, plain.ID, ids["identity_admin"])
		require.NoError(t, err)
		assert.False(t, exists, "被拒時沒有寫入")
	})

	t.Run("組裝的目標集合沒有可切換的開關", func(t *testing.T) {
		assert.Equal(t, 0, reflect.TypeOf(newMappingAssignmentGuard).NumIn(), "建構函式不接受任何設定或請求輸入")
	})

	t.Run("實際路由集合與 golden 相同，映射與釘住路徑沒有範圍或新入口", func(t *testing.T) {
		routes, _ := buildRouter(t, "release", true)
		pick := func(method, path string) bool {
			p := strings.ToLower(path)
			return strings.Contains(p, "mapping") || strings.HasSuffix(p, "/pin-role") || strings.Contains(p, "/pin")
		}
		var actual []string
		for k := range routes {
			if pick(k[0], k[1]) {
				actual = append(actual, k[0]+" "+k[1])
			}
		}
		raw, err := os.ReadFile(releaseRoutesPath)
		require.NoError(t, err)
		var golden struct {
			Routes []struct {
				Method string `json:"method"`
				Path   string `json:"path"`
			} `json:"routes"`
		}
		require.NoError(t, json.Unmarshal(raw, &golden))
		var expected []string
		for _, r := range golden.Routes {
			if pick(r.Method, r.Path) {
				expected = append(expected, r.Method+" "+r.Path)
			}
		}
		sort.Strings(actual)
		sort.Strings(expected)
		assert.NotEmpty(t, expected)
		assert.Equal(t, expected, actual)
		for _, a := range actual {
			assert.NotContains(t, strings.ToLower(a), "scope")
			assert.NotContains(t, strings.ToLower(a), "node")
		}
	})
}

// assembledCatalogIsFull 正式組裝實際注入的目標集合是否為完整集合。
func assembledCatalogIsFull() bool {
	return newMappingAssignmentGuard().Catalog() == identity.FullCatalog()
}

// catalogGuard 依正式組裝實際注入的目錄分派：與正式組裝相同的那一種取正式組裝的關卡，
// 另一種明示注入。兩種目錄因此在切換前後都各跑一組，且其中一組恆經正式組裝。
func catalogGuard(full bool) (*identity.AssignmentGuard, string) {
	if full == assembledCatalogIsFull() {
		return newMappingAssignmentGuard(), viaAssembly
	}
	if full {
		return identity.NewAssignmentGuard(identity.FullCatalog()), viaExplicit
	}
	return identity.NewAssignmentGuard(identity.CompatCatalog()), viaExplicit
}

// catalogVia 回報某種目錄在本次建置是經正式組裝還是明示注入。
func catalogVia(full bool) string {
	if full == assembledCatalogIsFull() {
		return viaAssembly
	}
	return viaExplicit
}

const (
	viaAssembly = "正式組裝"
	viaExplicit = "明示注入"
)
