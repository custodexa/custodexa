package identity

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 角色定義服務測試夾具：in-memory SQLite、真的 TxSink（寫 audit_logs 同交易）、可注入失敗的事件寫入面。

type fakeRoleEvents struct {
	events []RoleDefinitionEvent
	fail   error
}

func (f *fakeRoleEvents) WriteRoleDefinitionEvent(_ *gorm.DB, ev RoleDefinitionEvent) error {
	if f.fail != nil {
		return f.fail
	}
	f.events = append(f.events, ev)
	return nil
}

type failingSink struct{ err error }

func (f failingSink) WriteInTx(*gorm.DB, port.AuditEvent) error { return f.err }

type roleDefEnv struct {
	db     *gorm.DB
	svc    *RoleDefinitionService
	events *fakeRoleEvents
	admin  uint // 內建超管
	roles  map[string]uint
}

func newRoleDefEnv(t *testing.T) *roleDefEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return newRoleDefEnvOn(t, db)
}

// newRoleDefEnvOn 在給定連線上建夾具（SQLite 或 PostgreSQL 皆可）。
func newRoleDefEnvOn(t *testing.T, db *gorm.DB) *roleDefEnv {
	t.Helper()
	require.NoError(t, migrateWithAuthz(db, &model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{}, &model.UserGroupMember{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}, &model.RolePermission{}, &model.ExternalGroup{}, &model.GroupRoleMapping{}, &model.AuditLog{},
		&model.AssetGroup{}, &model.GroupUserGroupMapping{}, &model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.PermissionStateEvent{},
		&model.SystemAlertDetail{}, &model.SystemAlertOutbox{}, &model.SystemAlertSeverityOverride{}, &model.NotificationChannel{},
		&model.CommandAlert{}, &model.AssetAuthorization{}))
	seedAuthzState(t, db)
	ev := &fakeRoleEvents{}
	env := &roleDefEnv{db: db, events: ev, roles: map[string]uint{}, svc: NewRoleDefinitionService(db, audit.NewTxSink(), ev,
		NewGrantGrader(audit.NewTxSink(), audit.NewSystemAlertSink(nil)))}
	for _, name := range []string{"admin", "auditor", "user", "approver"} {
		r := model.Role{Name: name}
		require.NoError(t, db.Create(&r).Error) // BeforeCreate 帶入內建識別
		env.roles[name] = r.ID
	}
	for _, seed := range []struct{ name, key string }{{"identity_admin", model.BuiltinIdentityAdmin}, {"security_admin", model.BuiltinSecurityAdmin}} {
		k := seed.key
		r := model.Role{Name: seed.name, BuiltinKey: &k, DefinitionVersion: 1}
		require.NoError(t, db.Create(&r).Error)
		env.roles[seed.name] = r.ID
	}
	env.admin = env.mkUser(t, "root", "admin")
	return env
}

func (e *roleDefEnv) mkUser(t *testing.T, name string, roleNames ...string) uint {
	t.Helper()
	u := model.User{Username: name, Active: true}
	require.NoError(t, e.db.Create(&u).Error)
	for _, rn := range roleNames {
		require.NoError(t, e.db.Create(&model.UserRole{UserID: u.ID, RoleID: e.roles[rn], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	}
	return u.ID
}

func (e *roleDefEnv) snapshot(t *testing.T) (roles, perms int64, authzVer int64, audits int64) {
	t.Helper()
	require.NoError(t, e.db.Unscoped().Model(&model.Role{}).Count(&roles).Error)
	require.NoError(t, e.db.Model(&model.RolePermission{}).Count(&perms).Error)
	v, err := authz.CurrentVersion(e.db)
	require.NoError(t, err)
	require.NoError(t, e.db.Model(&model.AuditLog{}).Count(&audits).Error)
	return roles, perms, v, audits
}

func (e *roleDefEnv) create(t *testing.T, name string, perms ...string) *RoleDefinition {
	t.Helper()
	d, err := e.svc.Create(context.Background(), e.admin, RoleInput{Name: name, Permissions: perms})
	require.NoError(t, err)
	return d
}

// TestRoleDefinitionMutations 擋：非超管（含全權自訂角色）寫入、不合法集合部分保留、內建被改刪、
// 引用中的角色被刪、舊版本覆蓋、複製帶走身分、空集合補權。
func TestRoleDefinitionMutations(t *testing.T) {
	ctx := context.Background()
	t.Run("超管新建、複製一般範本、修改、刪未引用角色成功", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "viewer", "asset:view", "session:view")
		assert.Equal(t, int64(1), d.DefinitionVersion)
		assert.Equal(t, []string{"asset:view", "session:view"}, d.Permissions)
		assert.Empty(t, d.BuiltinKey)
		assert.False(t, d.Locked)

		cp, err := e.svc.Copy(ctx, e.admin, e.roles["identity_admin"], "id-copy", "")
		require.NoError(t, err)
		assert.Empty(t, cp.BuiltinKey, "複製不帶內建身分")
		assert.Equal(t, sortedStrings(authz.TemplatePermissions(model.BuiltinIdentityAdmin)), cp.Permissions)
		require.NotNil(t, cp.TemplateRoleID)
		assert.Equal(t, e.roles["identity_admin"], *cp.TemplateRoleID)

		up, err := e.svc.Update(ctx, e.admin, d.ID, 1, RoleInput{Name: "viewer2", Description: "x", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		assert.Equal(t, int64(2), up.DefinitionVersion)
		assert.Equal(t, []string{"asset:view"}, up.Permissions)
		assert.Equal(t, "viewer2", up.Name)

		require.NoError(t, e.svc.Delete(ctx, e.admin, d.ID, 2))
		_, err = e.svc.GetDefinition(ctx, d.ID)
		assert.ErrorIs(t, err, ErrRoleDefinitionNotFound)
		// 名稱釋出：可重新使用
		e.create(t, "viewer2", "asset:view")
	})
	t.Run("只剩已刪帳號的直接指派時可刪除，停用帳號仍擋", func(t *testing.T) {
		e := newRoleDefEnv(t)
		gone := e.create(t, "only-deleted", "asset:view")
		kept := e.create(t, "only-disabled", "asset:view")
		uDeleted := e.mkUser(t, "will-be-deleted")
		uDisabled := e.mkUser(t, "disabled-holder")
		for _, p := range []struct{ user, role uint }{{uDeleted, gone.ID}, {uDisabled, kept.ID}} {
			require.NoError(t, e.db.Create(&model.UserRole{UserID: p.user, RoleID: p.role, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		}
		require.NoError(t, e.db.Delete(&model.User{}, uDeleted).Error)
		require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", uDisabled).Update("active", false).Error)
		var rowsBefore int64
		require.NoError(t, e.db.Model(&model.UserRole{}).Where("user_id = ?", uDeleted).Count(&rowsBefore).Error)
		require.EqualValues(t, 1, rowsBefore)

		require.NoError(t, e.svc.Delete(ctx, e.admin, gone.ID, 1))
		var rowsAfter int64
		require.NoError(t, e.db.Model(&model.UserRole{}).Where("user_id = ?", uDeleted).Count(&rowsAfter).Error)
		assert.Equal(t, rowsBefore, rowsAfter, "角色刪除不動已刪帳號的指派列")
		assert.ErrorIs(t, e.svc.Delete(ctx, e.admin, kept.ID, 1), ErrRoleDefinitionInUse, "停用中的帳號仍算引用")
	})
	t.Run("非超管含全可指派能力者四種寫入都拒絕且內容不變", func(t *testing.T) {
		e := newRoleDefEnv(t)
		target := e.create(t, "t", "asset:view")
		all := e.create(t, "all", authzKeys()...)
		holder := e.mkUser(t, "holder")
		require.NoError(t, e.db.Create(&model.UserRole{UserID: holder, RoleID: all.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		idAdmin := e.mkUser(t, "ida", "identity_admin")
		named := e.mkUser(t, "admin-lookalike") // 顯示名稱像 admin 但沒有內建身分
		r0, p0, v0, a0 := e.snapshot(t)
		for _, who := range []uint{holder, idAdmin, named, 99999} {
			_, err := e.svc.Create(ctx, who, RoleInput{Name: "n", Permissions: []string{"asset:view"}})
			assert.ErrorIs(t, err, ErrRoleDefinitionForbidden)
			_, err = e.svc.Copy(ctx, who, e.roles["user"], "c", "")
			assert.ErrorIs(t, err, ErrRoleDefinitionForbidden)
			_, err = e.svc.Update(ctx, who, target.ID, 1, RoleInput{Name: "t", Permissions: []string{}})
			assert.ErrorIs(t, err, ErrRoleDefinitionForbidden)
			assert.ErrorIs(t, e.svc.Delete(ctx, who, target.ID, 1), ErrRoleDefinitionForbidden)
		}
		r1, p1, v1, a1 := e.snapshot(t)
		assert.Equal(t, []int64{r0, p0, v0, a0}, []int64{r1, p1, v1, a1}, "被拒絕的寫入不改任何狀態、不推進版本、不留成功審計")
		got, err := e.svc.GetDefinition(ctx, target.ID)
		require.NoError(t, err)
		assert.Equal(t, int64(1), got.DefinitionVersion)
	})
	t.Run("停用的超管不得寫入", func(t *testing.T) {
		e := newRoleDefEnv(t)
		require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", e.admin).Update("active", false).Error)
		_, err := e.svc.Create(ctx, e.admin, RoleInput{Name: "n"})
		assert.ErrorIs(t, err, ErrRoleDefinitionForbidden)
	})
	t.Run("不合法集合整筆拒絕：未知、ui:、保留身分、明文鍵", func(t *testing.T) {
		e := newRoleDefEnv(t)
		r0, p0, v0, a0 := e.snapshot(t)
		for _, bad := range [][]string{{"asset:view", "nope:key"}, {"asset:view", "ui:nav.users"}, {"asset:view", "superadmin:all"},
			{"asset:view", "credential:reveal"}, {"connect:bypass"}, {"role:define"}} {
			_, err := e.svc.Create(ctx, e.admin, RoleInput{Name: "n", Permissions: bad})
			assert.True(t, authz.IsInvalidRolePermission(err), "%v", bad)
		}
		r1, p1, v1, a1 := e.snapshot(t)
		assert.Equal(t, []int64{r0, p0, v0, a0}, []int64{r1, p1, v1, a1})
		// 修改時同樣整筆拒絕，原內容保留
		d := e.create(t, "keep", "asset:view")
		_, err := e.svc.Update(ctx, e.admin, d.ID, 1, RoleInput{Name: "keep", Permissions: []string{"asset:view", "nope:key"}})
		assert.True(t, authz.IsInvalidRolePermission(err))
		got, _ := e.svc.GetDefinition(ctx, d.ID)
		assert.Equal(t, []string{"asset:view"}, got.Permissions)
		assert.Equal(t, int64(1), got.DefinitionVersion)
	})
	t.Run("缺依賴允許儲存：回應明示缺少的依賴與無法使用的畫面、不補權、寫入審計", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d, err := e.svc.Create(ctx, e.admin, RoleInput{Name: "dep", Permissions: []string{"credential:manage"}})
		require.NoError(t, err)
		assert.Equal(t, []string{"credential:manage"}, d.Permissions, "不自動補授 asset:view")
		require.Len(t, d.MissingDependencies, 1)
		assert.Equal(t, authz.Permission("credential:manage"), d.MissingDependencies[0].Permission)
		assert.Equal(t, []authz.Permission{authz.PermAssetView}, d.MissingDependencies[0].Missing)
		require.Len(t, d.BlockedScreens, 1)
		assert.Equal(t, "credentials", d.BlockedScreens[0].ID)
		var row model.AuditLog
		require.NoError(t, e.db.Where("resource = ? AND action = ?", string(model.ResourceRole), string(model.ActionRoleDefinitionCreate)).Order("id desc").First(&row).Error)
		var det map[string]any
		require.NoError(t, json.Unmarshal([]byte(row.Details), &det))
		md, ok := det["missing_dependencies"].([]any)
		require.True(t, ok, "審計 details 必須列出缺少的依賴")
		assert.Len(t, md, 1)
		assert.Contains(t, det, "blocked_screens")
		// 讀取與修改路徑同樣明示；補齊後缺漏消失，且審計不再帶該欄
		got, err := e.svc.GetDefinition(ctx, d.ID)
		require.NoError(t, err)
		assert.Len(t, got.MissingDependencies, 1)
		up, err := e.svc.Update(ctx, e.admin, d.ID, 1, RoleInput{Name: "dep", Permissions: []string{"credential:manage", "asset:view"}})
		require.NoError(t, err)
		assert.Empty(t, up.MissingDependencies)
		assert.Empty(t, up.BlockedScreens)
		var row2 model.AuditLog
		require.NoError(t, e.db.Where("resource = ? AND action = ?", string(model.ResourceRole), string(model.ActionRoleDefinitionUpdate)).Order("id desc").First(&row2).Error)
		det = nil
		require.NoError(t, json.Unmarshal([]byte(row2.Details), &det))
		assert.NotContains(t, det, "missing_dependencies")
		// 完整集合建立時回應不含缺漏
		ok2 := e.create(t, "ok", "asset:view", "credential:manage")
		assert.Empty(t, ok2.MissingDependencies)
	})
	t.Run("內建與範本不可改刪、超管不可複製、存量角色鎖定", func(t *testing.T) {
		e := newRoleDefEnv(t)
		for _, name := range []string{"admin", "auditor", "user", "approver", "identity_admin", "security_admin"} {
			_, err := e.svc.Update(ctx, e.admin, e.roles[name], 0, RoleInput{Name: name})
			assert.ErrorIs(t, err, ErrRoleDefinitionLocked, name)
			_, err = e.svc.Update(ctx, e.admin, e.roles[name], 1, RoleInput{Name: name})
			assert.ErrorIs(t, err, ErrRoleDefinitionLocked, name)
			assert.ErrorIs(t, e.svc.Delete(ctx, e.admin, e.roles[name], 1), ErrRoleDefinitionLocked, name)
		}
		_, err := e.svc.Copy(ctx, e.admin, e.roles["admin"], "super-copy", "")
		assert.ErrorIs(t, err, ErrRoleDefinitionLocked)
		legacy := model.Role{Name: "legacy-custom"} // 升級前存量的非內建角色（版本 0）
		require.NoError(t, e.db.Create(&legacy).Error)
		assert.ErrorIs(t, e.svc.Delete(ctx, e.admin, legacy.ID, 0), ErrRoleDefinitionLocked)
		// 複製審核者：只複製空集合，不取得審核資格
		cp, err := e.svc.Copy(ctx, e.admin, e.roles["approver"], "ap-copy", "")
		require.NoError(t, err)
		assert.Empty(t, cp.BuiltinKey)
		assert.Empty(t, cp.Permissions)
	})
	t.Run("新建帶起手來源：懸空、已刪除與超管來源拒絕且不改狀態，合法來源保存", func(t *testing.T) {
		e := newRoleDefEnv(t)
		custom := e.create(t, "src-custom", "asset:view")
		gone := e.create(t, "src-gone", "asset:view")
		require.NoError(t, e.svc.Delete(ctx, e.admin, gone.ID, 1))
		r0, p0, v0, a0 := e.snapshot(t)
		for label, src := range map[string]uint{"懸空": 99999, "已刪除": gone.ID, "超管": e.roles["admin"]} {
			id := src
			_, err := e.svc.Create(ctx, e.admin, RoleInput{Name: "n-" + label, Permissions: []string{"asset:view"}, TemplateRoleID: &id})
			assert.ErrorIs(t, err, ErrRoleDefinitionInput, label)
		}
		r1, p1, v1, a1 := e.snapshot(t)
		assert.Equal(t, []int64{r0, p0, v0, a0}, []int64{r1, p1, v1, a1}, "被拒絕的來源不留角色、不推進版本、不留成功審計")
		for name, src := range map[string]uint{"ok-template": e.roles["identity_admin"], "ok-approver": e.roles["approver"], "ok-custom": custom.ID} {
			id := src
			d, err := e.svc.Create(ctx, e.admin, RoleInput{Name: name, Permissions: []string{"asset:view"}, TemplateRoleID: &id})
			require.NoError(t, err)
			require.NotNil(t, d.TemplateRoleID)
			assert.Equal(t, src, *d.TemplateRoleID)
		}
		st, err := e.svc.State(ctx)
		require.NoError(t, err)
		assert.NoError(t, authz.ValidateRoleDefinitionState(st), "服務寫出的來源參照必須通過還原核對")
	})
	t.Run("名稱規則：空、過長、已被使用皆拒絕，不覆寫既有角色", func(t *testing.T) {
		e := newRoleDefEnv(t)
		for _, n := range []string{"", "   ", string(make([]rune, 51))} {
			_, err := e.svc.Create(ctx, e.admin, RoleInput{Name: n})
			assert.ErrorIs(t, err, ErrRoleDefinitionInput)
		}
		for _, n := range []string{"admin", "identity_admin", "security_admin"} {
			_, err := e.svc.Create(ctx, e.admin, RoleInput{Name: n})
			assert.ErrorIs(t, err, ErrRoleDefinitionConflict, n)
		}
		var key *string
		require.NoError(t, e.db.Raw("SELECT builtin_key FROM roles WHERE name = 'identity_admin'").Scan(&key).Error)
		require.NotNil(t, key)
		assert.Equal(t, model.BuiltinIdentityAdmin, *key)
	})
	t.Run("空集合可保存且不補一般使用者能力", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "empty")
		assert.Empty(t, d.Permissions)
		uid := e.mkUser(t, "u")
		require.NoError(t, e.db.Create(&model.UserRole{UserID: uid, RoleID: d.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		p, err := authz.NewResolver(e.db).ResolveUser(uid, authz.TokenFacts{})
		require.NoError(t, err)
		assert.Empty(t, p.Capabilities())
	})
	t.Run("舊版本提交拒絕，不覆蓋第一筆", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "c", "asset:view")
		_, err := e.svc.Update(ctx, e.admin, d.ID, 1, RoleInput{Name: "c", Permissions: []string{"asset:view", "session:view"}})
		require.NoError(t, err)
		_, err = e.svc.Update(ctx, e.admin, d.ID, 1, RoleInput{Name: "c", Permissions: []string{}})
		assert.ErrorIs(t, err, ErrRoleDefinitionConflict)
		assert.ErrorIs(t, e.svc.Delete(ctx, e.admin, d.ID, 1), ErrRoleDefinitionConflict)
		got, _ := e.svc.GetDefinition(ctx, d.ID)
		assert.Equal(t, []string{"asset:view", "session:view"}, got.Permissions)
		assert.Equal(t, int64(2), got.DefinitionVersion)
	})
	t.Run("被直接指派、群組指派或映射支持的角色不可刪，不級聯撤權", func(t *testing.T) {
		e := newRoleDefEnv(t)
		direct, viaGroup, viaMap := e.create(t, "d"), e.create(t, "g"), e.create(t, "m")
		uid := e.mkUser(t, "u")
		require.NoError(t, e.db.Create(&model.UserRole{UserID: uid, RoleID: direct.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		grp := model.UserGroup{Name: "grp"}
		require.NoError(t, e.db.Create(&grp).Error)
		require.NoError(t, authz.SetUserGroupRoles(e.db, grp.ID, []uint{viaGroup.ID}, uid))
		require.NoError(t, e.db.Create(&model.GroupRoleMapping{RoleID: viaMap.ID, MatchValue: "g1", ExternalGroupID: 1, CreatedBy: uid}).Error)
		for _, d := range []*RoleDefinition{direct, viaGroup, viaMap} {
			assert.ErrorIs(t, e.svc.Delete(ctx, e.admin, d.ID, 1), ErrRoleDefinitionInUse, d.Name)
		}
		var n int64
		e.db.Model(&model.UserRole{}).Where("user_id = ?", uid).Count(&n)
		assert.Equal(t, int64(1), n)
		e.db.Model(&model.UserGroupRole{}).Count(&n)
		assert.Equal(t, int64(1), n)
	})
	t.Run("刪除範本原件僅清說明參照，複本集合與版本不變", func(t *testing.T) {
		e := newRoleDefEnv(t)
		src := e.create(t, "src", "asset:view", "session:view")
		cp, err := e.svc.Copy(ctx, e.admin, src.ID, "cp", "")
		require.NoError(t, err)
		require.NoError(t, e.svc.Delete(ctx, e.admin, src.ID, 1))
		got, err := e.svc.GetDefinition(ctx, cp.ID)
		require.NoError(t, err)
		assert.Nil(t, got.TemplateRoleID)
		assert.Equal(t, cp.Permissions, got.Permissions)
		assert.Equal(t, cp.DefinitionVersion, got.DefinitionVersion)
		// 刪除後的歷史審計仍在
		var n int64
		e.db.Model(&model.AuditLog{}).Where("action = ?", string(model.ActionRoleDefinitionDelete)).Count(&n)
		assert.Equal(t, int64(1), n)
	})
	t.Run("映射入口在相容目錄下：新範本視同不存在，自訂角色不可直接映射", func(t *testing.T) {
		e := newRoleDefEnv(t)
		e.create(t, "custom", "asset:view")
		src := NewIdentitySourceService(e.db, nil)
		for _, name := range []string{"identity_admin", "security_admin"} {
			_, err := src.mappingDirectRole(e.db, name)
			assert.ErrorIs(t, err, ErrMappingRoleUnknown, name)
		}
		_, err := src.mappingDirectRole(e.db, "custom")
		assert.ErrorIs(t, err, ErrMappingRoleNotDirectMappable)
		r, err := src.mappingDirectRole(e.db, "auditor")
		require.NoError(t, err)
		assert.Equal(t, e.roles["auditor"], r.ID)
	})
	t.Run("新角色只能被服務層寫入：list 含全部，舊相容過濾以 definition_version=0 為界", func(t *testing.T) {
		e := newRoleDefEnv(t)
		e.create(t, "custom", "asset:view")
		list, err := e.svc.ListDefinitions(ctx)
		require.NoError(t, err)
		assert.Len(t, list, 7)
		var legacy []model.Role
		require.NoError(t, e.db.Where(legacyRoleCatalogCond).Find(&legacy).Error)
		assert.Len(t, legacy, 4)
	})
}

func authzKeys() []string {
	var out []string
	for _, k := range authz.AssignableKeys() {
		out = append(out, string(k))
	}
	return out
}

// TestRoleDefinitionAtomicEvidence 擋：審計或狀態事件寫入失敗時角色與版本殘留、被拒絕仍留成功事件、
// 舊指派審計變形、秘密進差異。
func TestRoleDefinitionAtomicEvidence(t *testing.T) {
	ctx := context.Background()
	t.Run("四種 mutation 成功各有對應 action、權限差異、兩個版本與狀態事件", func(t *testing.T) {
		e := newRoleDefEnv(t)
		_, _, v0, _ := e.snapshot(t)
		d := e.create(t, "r", "asset:view")
		cp, err := e.svc.Copy(ctx, e.admin, d.ID, "r2", "")
		require.NoError(t, err)
		_, err = e.svc.Update(ctx, e.admin, d.ID, 1, RoleInput{Name: "r", Permissions: []string{"asset:view", "session:view"}})
		require.NoError(t, err)
		require.NoError(t, e.svc.Delete(ctx, e.admin, cp.ID, 1))
		var rows []model.AuditLog
		require.NoError(t, e.db.Where("resource = ?", string(model.ResourceRole)).Order("id").Find(&rows).Error)
		require.Len(t, rows, 4)
		wantActions := []model.AuditAction{model.ActionRoleDefinitionCreate, model.ActionRoleDefinitionCopy, model.ActionRoleDefinitionUpdate, model.ActionRoleDefinitionDelete}
		for i, r := range rows {
			assert.Equal(t, wantActions[i], r.Action)
			assert.Equal(t, e.admin, r.UserID)
		}
		var upd map[string]any
		require.NoError(t, json.Unmarshal([]byte(rows[2].Details), &upd))
		assert.Equal(t, []any{"session:view"}, upd["added"])
		assert.Equal(t, []any{}, upd["removed"])
		assert.EqualValues(t, 2, upd["definition_version"])
		var del map[string]any
		require.NoError(t, json.Unmarshal([]byte(rows[3].Details), &del))
		assert.Equal(t, []any{"asset:view"}, del["removed"])
		_, _, v1, _ := e.snapshot(t)
		assert.Equal(t, v0+4, v1, "每次成功寫入推進一次全域權限版本")
		require.Len(t, e.events.events, 4)
		assert.Equal(t, string(model.ActionRoleDefinitionUpdate), e.events.events[2].Action)
		assert.Equal(t, []string{"asset:view"}, e.events.events[2].Before)
		assert.Equal(t, []string{"asset:view", "session:view"}, e.events.events[2].After)
		assert.Equal(t, v0+3, e.events.events[2].AuthzVersion)
		// 重放：依序套用事件得到現況（依事件還原的集合＝role_permissions）
		replay := map[uint][]string{}
		for _, ev := range e.events.events {
			replay[ev.RoleID] = ev.After
		}
		live, err := e.svc.GetDefinition(ctx, d.ID)
		require.NoError(t, err)
		assert.Equal(t, replay[d.ID], live.Permissions)
	})
	t.Run("注入審計失敗：角色內容、定義版本與全域版本全回滾", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "r", "asset:view")
		boom := errors.New("audit down")
		e.svc.audit = failingSink{err: boom}
		r0, p0, v0, a0 := e.snapshot(t)
		_, err := e.svc.Create(ctx, e.admin, RoleInput{Name: "x", Permissions: []string{"asset:view"}})
		assert.ErrorIs(t, err, boom)
		_, err = e.svc.Copy(ctx, e.admin, d.ID, "x", "")
		assert.ErrorIs(t, err, boom)
		_, err = e.svc.Update(ctx, e.admin, d.ID, 1, RoleInput{Name: "r", Permissions: []string{}})
		assert.ErrorIs(t, err, boom)
		assert.ErrorIs(t, e.svc.Delete(ctx, e.admin, d.ID, 1), boom)
		r1, p1, v1, a1 := e.snapshot(t)
		assert.Equal(t, []int64{r0, p0, v0, a0}, []int64{r1, p1, v1, a1})
		got, _ := e.svc.GetDefinition(ctx, d.ID)
		assert.Equal(t, int64(1), got.DefinitionVersion)
		assert.Equal(t, []string{"asset:view"}, got.Permissions)
	})
	t.Run("注入狀態事件失敗或未注入事件面：同樣整筆回滾（fail-close）", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "r", "asset:view")
		r0, p0, v0, a0 := e.snapshot(t)
		boom := errors.New("event down")
		e.events.fail = boom
		_, err := e.svc.Update(ctx, e.admin, d.ID, 1, RoleInput{Name: "r", Permissions: []string{}})
		assert.ErrorIs(t, err, boom)
		assert.ErrorIs(t, e.svc.Delete(ctx, e.admin, d.ID, 1), boom)
		e.svc.events = nil
		_, err = e.svc.Create(ctx, e.admin, RoleInput{Name: "y"})
		assert.ErrorIs(t, err, ErrRoleStateEventWriterMissing)
		r1, p1, v1, a1 := e.snapshot(t)
		assert.Equal(t, []int64{r0, p0, v0, a0}, []int64{r1, p1, v1, a1})
	})
	t.Run("接權限狀態事件鏈：四種 mutation 各一筆事件含權限差集，直寫先記無來源變動，事件寫入失敗整筆回滾", func(t *testing.T) {
		e := newRoleDefEnv(t)
		audit.SetPermissionSources(authz.PermissionStateAuthzPart, PermissionStateIdentityPart)
		t.Cleanup(func() { audit.SetPermissionSources(nil, nil) })
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			st, err := audit.ReadPermissionState(ctx, tx)
			if err != nil {
				return err
			}
			_, err = audit.EnsurePermissionActivation(ctx, tx, st, 1)
			return err
		}))
		e.svc.events = NewPermissionChainEventWriter()
		kinds := func() map[string]int64 {
			var rows []struct {
				Kind string
				N    int64
			}
			require.NoError(t, e.db.Raw(`SELECT kind, COUNT(*) AS n FROM permission_state_events GROUP BY kind`).Scan(&rows).Error)
			out := map[string]int64{}
			for _, r := range rows {
				out[r.Kind] = r.N
			}
			return out
		}
		k0 := kinds()
		d := e.create(t, "r", "asset:view")
		cp, err := e.svc.Copy(ctx, e.admin, d.ID, "r2", "")
		require.NoError(t, err)
		_, err = e.svc.Update(ctx, e.admin, d.ID, 1, RoleInput{Name: "r", Permissions: []string{"asset:view", "session:view"}})
		require.NoError(t, err)
		require.NoError(t, e.svc.Delete(ctx, e.admin, cp.ID, 1))
		k1 := kinds()
		assert.EqualValues(t, 4, k1[model.PermEventChange]-k0[model.PermEventChange], "四種 mutation 各一筆事件")
		assert.Zero(t, k1[model.PermEventUntraced])
		var evs []model.PermissionStateEvent
		require.NoError(t, e.db.Where("kind = ?", model.PermEventChange).Order("seq").Find(&evs).Error)
		require.Len(t, evs, 4)
		assert.Contains(t, evs[2].Delta, `session:view`, "更新事件的差集含新增的權限鍵")
		assert.Contains(t, evs[2].Delta, `"role_defs"`, "更新事件的差集含定義版本推進")
		assert.Contains(t, evs[3].Delta, `"roles"`, "刪除事件的差集含角色軟刪旗標變動")
		// 兩次合法事件之間有人直改：下一次合法寫入先記無來源變動，差集不混入合法事件
		require.NoError(t, e.db.Create(&model.RolePermission{RoleID: d.ID, PermissionKey: "audit:view"}).Error)
		_, err = e.svc.Update(ctx, e.admin, d.ID, 2, RoleInput{Name: "r", Permissions: []string{"asset:view"}})
		require.NoError(t, err)
		k2 := kinds()
		assert.EqualValues(t, 1, k2[model.PermEventUntraced])
		// 事件寫入失敗：內容與兩個版本整筆回滾
		r0, p0, v0, a0 := e.snapshot(t)
		var n0 int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Count(&n0).Error)
		require.NoError(t, e.db.Callback().Create().Before("gorm:create").Register("fail_perm_event", func(tx *gorm.DB) {
			if tx.Statement.Schema != nil && tx.Statement.Schema.Table == "permission_state_events" {
				_ = tx.AddError(errors.New("chain down"))
			}
		}))
		_, err = e.svc.Create(ctx, e.admin, RoleInput{Name: "z", Permissions: []string{"asset:view"}})
		assert.ErrorContains(t, err, "chain down")
		r1, p1, v1, a1 := e.snapshot(t)
		assert.Equal(t, []int64{r0, p0, v0, a0}, []int64{r1, p1, v1, a1})
		var n1 int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Count(&n1).Error)
		assert.Equal(t, n0, n1)
	})
	t.Run("唯讀與被拒絕操作不產生成功事件也不推進版本", func(t *testing.T) {
		e := newRoleDefEnv(t)
		d := e.create(t, "r", "asset:view")
		n0 := len(e.events.events)
		_, _, v0, a0 := e.snapshot(t)
		_, _ = e.svc.ListDefinitions(ctx)
		_, _ = e.svc.GetDefinition(ctx, d.ID)
		_, _ = e.svc.Update(ctx, e.admin, d.ID, 99, RoleInput{Name: "r"})
		_, _ = e.svc.Create(ctx, 12345, RoleInput{Name: "z"})
		_, _, v1, a1 := e.snapshot(t)
		assert.Equal(t, v0, v1)
		assert.Equal(t, a0, a1)
		assert.Len(t, e.events.events, n0)
	})
	t.Run("既有 role_assign／role_revoke 審計形狀與數量不變；差異不含秘密或自由文字以外的內容", func(t *testing.T) {
		e := newRoleDefEnv(t)
		uid := e.mkUser(t, "u")
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			return model.AssignUserRole(tx, uid, e.roles["user"], model.RoleOriginAPI)
		}))
		var before []model.AuditLog
		require.NoError(t, e.db.Where("resource = ?", string(model.ResourceUserRole)).Find(&before).Error)
		require.Len(t, before, 1)
		e.create(t, "r", "asset:view")
		var after []model.AuditLog
		require.NoError(t, e.db.Where("resource = ?", string(model.ResourceUserRole)).Find(&after).Error)
		assert.Equal(t, before, after, "新服務不增列、不改寫指派審計")
		var rows []model.AuditLog
		require.NoError(t, e.db.Where("resource = ?", string(model.ResourceRole)).Find(&rows).Error)
		for _, r := range rows {
			var m map[string]any
			require.NoError(t, json.Unmarshal([]byte(r.Details), &m))
			for k := range m {
				assert.Contains(t, []string{"role_id", "definition_version", "authz_version", "added", "removed", "template_role_id", "missing_dependencies", "blocked_screens"}, k)
			}
		}
	})
}

func sortedStrings(ps []authz.Permission) []string {
	out := permStrings(ps)
	sort.Strings(out)
	return out
}
