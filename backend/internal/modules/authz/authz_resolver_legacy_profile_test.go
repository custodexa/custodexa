package authz

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newPrincipalDB 解析器與短路測試共用的 in-memory SQLite（含權限模型的三張新表）。
func newPrincipalDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	migratePrincipalDB(t, db)
	return db
}

// migratePrincipalDB 主體資料庫的表（SQLite 與 PG 夾具共用同一份清單）。
func migratePrincipalDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, migrateWithAuthz(db,
		&model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{}, &model.UserGroupMember{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}, &model.AuthzState{}, &model.AssetGroup{},
		&model.Asset{}, &model.AssetNode{}, &model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{}))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
}

// newPrincipalDBPG 與 newPrincipalDB 同表的 PostgreSQL 主體資料庫：每次呼叫一個獨立 schema，
// 測試結束時刪除。dsn 由呼叫方經 testgate 取得（沒有 DSN 時跳過或失敗由 testgate 決定）。
func newPrincipalDBPG(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	var b [4]byte
	_, err = rand.Read(b[:])
	require.NoError(t, err)
	schema := "authz_principal_" + hex.EncodeToString(b[:])
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = sqlDB.Close() }) // 後註冊先執行：先關本 schema 的連線再刪 schema
	migratePrincipalDB(t, db)
	return db
}

// mkRole 建角色；builtinKey 為空即非內建。
func mkRole(t *testing.T, db *gorm.DB, name, builtinKey string) *model.Role {
	t.Helper()
	r := &model.Role{Name: name}
	if builtinKey != "" {
		k := builtinKey
		r.BuiltinKey = &k
	}
	require.NoError(t, db.Create(r).Error)
	if builtinKey == "" {
		// model.Role 的 BeforeCreate 會替保留名稱補上內建識別；這裡要的是「名稱保留但未標記」的列
		// （例如手工寫表），故明確清掉，驗證解析器不依角色名稱判定
		require.NoError(t, db.Exec("UPDATE roles SET builtin_key = NULL WHERE id = ?", r.ID).Error)
		r.BuiltinKey = nil
	}
	return r
}

func assignDirect(t *testing.T, db *gorm.DB, userID, roleID uint, scope string) {
	t.Helper()
	require.NoError(t, db.Create(&model.UserRole{UserID: userID, RoleID: roleID, Source: model.RoleSourceManual, ScopeKind: scope}).Error)
}

func permStrings(ps []Permission) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	sort.Strings(out)
	return out
}

func asg(key, scope string, nodes ...uint) Assignment {
	return Assignment{RoleName: key, BuiltinKey: key, Via: ViaDirect, Scope: scope, LiveNodeIDs: nodes}
}

// TestAuthzResolverLegacyProfile 擋：範圍回退全域、跨指派拼權限、零角色或純審核者能力漂移、agent 升權。
func TestAuthzResolverLegacyProfile(t *testing.T) {
	g, n := model.ScopeKindGlobal, model.ScopeKindNodes

	t.Run("範本巢狀性與內容：超管含稽核員含一般使用者", func(t *testing.T) {
		su, au, us, ap := TemplatePermissions(model.BuiltinSuperAdmin), TemplatePermissions(model.BuiltinAuditor),
			TemplatePermissions(model.BuiltinUser), TemplatePermissions(model.BuiltinApprover)
		assert.ElementsMatch(t, permStrings(CatalogKeys()), permStrings(su), "超管＝目錄全部")
		assert.Subset(t, permStrings(su), permStrings(au))
		assert.Subset(t, permStrings(au), permStrings(us))
		assert.Equal(t, []string{"alert:manage", "alert:view", "asset:view", "audit:integrity_view", "audit:view",
			"compliance:view", "policygroup:view", "session:view"}, permStrings(au))
		assert.Equal(t, []string{"asset:view"}, permStrings(us))
		assert.Empty(t, ap, "審核者範本無權限點，審核資格是獨立的內建身分")
		assert.Nil(t, TemplatePermissions("custom"), "未知範本鍵無集合")
	})

	t.Run("折疊與零角色純審核者未知角色", func(t *testing.T) {
		cases := []struct {
			name  string
			facts TokenFacts
			asgs  []Assignment
			want  string // 舊主角色
			caps  []string
		}{
			{"基準主體09 零角色視同 user", TokenFacts{}, nil, "user", []string{"asset:view"}},
			{"基準主體04 純審核者無能力", TokenFacts{}, []Assignment{asg(model.BuiltinApprover, g)}, "", nil},
			{"只有未知角色無能力", TokenFacts{}, []Assignment{{RoleName: "ops", Via: ViaDirect, Scope: g}}, "", nil},
			{"admin 勝過 auditor", TokenFacts{}, []Assignment{asg(model.BuiltinAuditor, g), asg(model.BuiltinSuperAdmin, g)}, "admin", permStrings(CatalogKeys())},
			{"auditor 勝過 user", TokenFacts{}, []Assignment{asg(model.BuiltinUser, g), asg(model.BuiltinAuditor, g)}, "auditor", permStrings(TemplatePermissions(model.BuiltinAuditor))},
			{"user 加審核者仍為 user", TokenFacts{}, []Assignment{asg(model.BuiltinUser, g), asg(model.BuiltinApprover, g)}, "user", []string{"asset:view"}},
			{"agent 固定一般使用者範本，不受角色列影響", TokenFacts{SubjectKind: model.KindAgent}, []Assignment{asg(model.BuiltinSuperAdmin, g)}, "user", []string{"asset:view"}},
			{"agent 無角色亦同", TokenFacts{SubjectKind: model.KindAgent}, nil, "user", []string{"asset:view"}},
		}
		for _, c := range cases {
			c := c
			t.Run(c.name, func(t *testing.T) {
				p := NewPrincipal(1, c.facts, c.asgs)
				assert.Equal(t, c.want, p.LegacyRole())
				assert.ElementsMatch(t, c.caps, permStrings(p.Capabilities()))
			})
		}
		t.Run("基準主體04 純審核者仍具審核資格", func(t *testing.T) {
			assert.True(t, NewPrincipal(1, TokenFacts{}, []Assignment{asg(model.BuiltinApprover, g)}).IsApprover())
		})
		t.Run("agent 不因角色列取得超管身分", func(t *testing.T) {
			assert.False(t, NewPrincipal(1, TokenFacts{SubjectKind: model.KindAgent}, []Assignment{asg(model.BuiltinSuperAdmin, g)}).IsSuperAdmin())
		})
	})

	t.Run("非全域指派不生效且不回退成全域", func(t *testing.T) {
		t.Run("不生效一：節點範圍，目錄內沒有 scoped-enforced 權限點", func(t *testing.T) {
			p := NewPrincipal(1, TokenFacts{}, []Assignment{asg(model.BuiltinSuperAdmin, n, 7)})
			assert.Empty(t, p.Capabilities(), "節點範圍的超管指派目前不生效")
			assert.False(t, p.IsSuperAdmin(), "節點範圍不構成超管身分")
		})
		t.Run("不生效二：空範圍", func(t *testing.T) {
			assert.Empty(t, NewPrincipal(1, TokenFacts{}, []Assignment{asg(model.BuiltinAuditor, n)}).Capabilities())
			enforced := PermissionDef{Key: "x:y", Scope: ScopeEnforced}
			assert.False(t, scopeGrants(asg(model.BuiltinUser, n), enforced), "scoped-enforced 遇空節點集合也不生效")
		})
		t.Run("不生效三：global-only 權限點遇非全域指派", func(t *testing.T) {
			def, _ := LookupPermission(PermUserManage)
			require.Equal(t, ScopeGlobalOnly, def.Scope)
			assert.False(t, scopeGrants(asg(model.BuiltinSuperAdmin, n, 7), def))
			assert.True(t, scopeGrants(asg(model.BuiltinSuperAdmin, g), def))
		})
		t.Run("不生效四：scoped-reserved 權限點遇非全域指派", func(t *testing.T) {
			def, _ := LookupPermission(PermCredentialManage) // 仍為 scoped-reserved 的鍵
			require.Equal(t, ScopeReserved, def.Scope)
			assert.False(t, scopeGrants(asg(model.BuiltinUser, n, 7), def))
		})
		t.Run("對照：scoped-enforced 且節點集合非空才生效", func(t *testing.T) {
			enforced := PermissionDef{Key: "x:y", Scope: ScopeEnforced}
			assert.True(t, scopeGrants(asg(model.BuiltinUser, n, 7), enforced))
			assert.True(t, scopeGrants(asg(model.BuiltinUser, g), enforced))
		})
	})

	t.Run("同一筆指派原則：不跨指派拼權限", func(t *testing.T) {
		// 節點範圍的超管 + 全域的一般使用者：只得一般使用者範本，超管的權限點拼不進來
		p := NewPrincipal(1, TokenFacts{}, []Assignment{asg(model.BuiltinSuperAdmin, n, 7), asg(model.BuiltinUser, g)})
		assert.Equal(t, "user", p.LegacyRole())
		assert.Equal(t, []string{"asset:view"}, permStrings(p.Capabilities()))
		assert.False(t, p.Has(PermUserManage))
	})

	t.Run("解析器：直接指派、群組指派、已刪除角色與群組、節點", func(t *testing.T) {
		db := newPrincipalDB(t)
		r := NewResolver(db)
		_ = mkRole(t, db, "admin", model.BuiltinSuperAdmin)
		aud := mkRole(t, db, "auditor", model.BuiltinAuditor)
		_ = mkRole(t, db, "user", model.BuiltinUser)
		custom := mkRole(t, db, "ops", "")

		zero := mkUser(t, db, "zero")
		p, err := r.ResolveUser(zero.ID, TokenFacts{})
		require.NoError(t, err)
		assert.Equal(t, "user", p.LegacyRole(), "基準主體09：零角色")

		d := mkUser(t, db, "direct")
		assignDirect(t, db, d.ID, aud.ID, g)
		p, _ = r.ResolveUser(d.ID, TokenFacts{})
		assert.Equal(t, "auditor", p.LegacyRole())
		require.Len(t, p.Assignments, 1)
		assert.Equal(t, ViaDirect, p.Assignments[0].Via)

		// 群組指派
		grp := &model.UserGroup{Name: "g1"}
		require.NoError(t, db.Create(grp).Error)
		member := mkUser(t, db, "member")
		require.NoError(t, db.Create(&model.UserGroupMember{UserGroupID: grp.ID, UserID: member.ID, Manual: true}).Error)
		require.NoError(t, db.Create(&model.UserGroupRole{UserGroupID: grp.ID, RoleID: aud.ID, ScopeKind: g}).Error)
		p, _ = r.ResolveUser(member.ID, TokenFacts{})
		assert.Equal(t, "auditor", p.LegacyRole(), "群組指派生效")
		assert.Equal(t, ViaGroup, p.Assignments[0].Via)
		// 已刪除的群組不產生指派
		require.NoError(t, db.Delete(grp).Error)
		p, _ = r.ResolveUser(member.ID, TokenFacts{})
		assert.Equal(t, "user", p.LegacyRole(), "群組刪除後回到零角色語義")
		assert.Empty(t, p.Assignments)

		// 已刪除的角色不產生指派
		del := mkUser(t, db, "deleted-role")
		oldRole := mkRole(t, db, "old", "")
		assignDirect(t, db, del.ID, oldRole.ID, g)
		require.NoError(t, db.Delete(oldRole).Error)
		p, _ = r.ResolveUser(del.ID, TokenFacts{})
		assert.Empty(t, p.Assignments)
		assert.Equal(t, "user", p.LegacyRole(), "只有已刪除角色＝零角色語義（與 Preload 的行為相同）")

		// 非內建角色（名稱不論）無能力
		c := mkUser(t, db, "custom")
		assignDirect(t, db, c.ID, custom.ID, g)
		p, _ = r.ResolveUser(c.ID, TokenFacts{})
		assert.Empty(t, p.Capabilities())
		assert.Equal(t, "", p.LegacyRole())

		// 節點範圍：存活節點、已刪節點、空範圍都不生效（目前沒有 scoped-enforced）
		live := mkNode(t, db, "live", nil)
		dead := mkNode(t, db, "dead", nil)
		require.NoError(t, db.Delete(dead).Error)
		nu := mkUser(t, db, "nodes")
		assignDirect(t, db, nu.ID, aud.ID, n)
		p, _ = r.ResolveUser(nu.ID, TokenFacts{})
		require.Len(t, p.Assignments, 1)
		assert.Empty(t, p.Assignments[0].LiveNodeIDs, "空範圍")
		assert.Empty(t, p.Capabilities())
		require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: nu.ID, RoleID: aud.ID, NodeID: live.ID}).Error)
		require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: nu.ID, RoleID: aud.ID, NodeID: dead.ID}).Error)
		p, _ = r.ResolveUser(nu.ID, TokenFacts{})
		assert.Equal(t, []uint{live.ID}, p.Assignments[0].LiveNodeIDs, "已刪節點不計")
		assert.Empty(t, p.Capabilities(), "有存活節點仍不生效：目錄內沒有 scoped-enforced 權限點")
		assert.False(t, p.Has(PermAuditView))
	})

	t.Run("解析失敗即拒，不兜底", func(t *testing.T) {
		db := newPrincipalDB(t)
		require.NoError(t, db.Exec("DROP TABLE user_roles").Error)
		p, err := NewResolver(db).ResolveUser(1, TokenFacts{})
		require.Error(t, err)
		assert.Nil(t, p)
		assert.True(t, strings.Contains(err.Error(), "解析直接角色指派失敗"), fmt.Sprint(err))
	})
}
