package authz

import (
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newRoleDefDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newPrincipalDB(t)
	require.NoError(t, db.AutoMigrate(&model.RolePermission{}))
	return db
}

// mkCustomRole 建自訂角色（定義版本 1、無內建識別）與其明確集合。
func mkCustomRole(t *testing.T, db *gorm.DB, name string, perms ...Permission) *model.Role {
	t.Helper()
	r := &model.Role{Name: name, DefinitionVersion: 1}
	require.NoError(t, db.Create(r).Error)
	for _, p := range perms {
		require.NoError(t, db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(p)}).Error)
	}
	return r
}

// nonUI 去掉伺服器衍生的 ui: 呈現點，只留可指派權限點。
func nonUI(keys []string) []string {
	out := []string{}
	for _, k := range keys {
		if !strings.HasPrefix(k, UIPrefix) {
			out = append(out, k)
		}
	}
	return out
}

func setStrings(ps []Permission) []string { s := permStrings(ps); sort.Strings(s); return s }

// TestLockedManagementTemplates 擋：範本集合漂移、範本帶入保留能力或身分、指派能力語義分叉、冒認內建識別。
func TestLockedManagementTemplates(t *testing.T) {
	idp, sec := TemplatePermissions(model.BuiltinIdentityAdmin), TemplatePermissions(model.BuiltinSecurityAdmin)

	t.Run("兩範本集合等於凍結表", func(t *testing.T) {
		assert.Equal(t, []string{"identity_source:manage", "ldap:manage", "oidc:manage", "role:assign", "role:view", "user:manage", "usergroup:manage"}, setStrings(idp))
		assert.Equal(t, []string{"alertrule:manage", "instanceguard:view", "key:manage", "notification_channel:manage", "offsite:manage",
			"policygroup:manage", "policygroup:view", "recording:delete", "rotation_schedule:manage", "schedule:manage", "securitypolicy:manage",
			"syslog:manage", "systemalert:manage", "transmission:manage"}, setStrings(sec))
	})
	t.Run("身分範本有指派與身分來源而無通道告警分級；設定範本含通道與分級", func(t *testing.T) {
		have := func(ps []Permission, k Permission) bool {
			for _, p := range ps {
				if p == k {
					return true
				}
			}
			return false
		}
		assert.True(t, have(idp, PermRoleAssign))
		assert.True(t, have(idp, PermIdentitySourceManage))
		for _, k := range []Permission{PermNotificationChannel, PermSystemAlertManage, PermAlertRuleManage, PermSecurityPolicyManage, PermRecordingDelete} {
			assert.False(t, have(idp, k), "身分範本不得含 %s", k)
		}
		assert.True(t, have(sec, PermRecordingDelete), "設定範本含刪除錄影")
		assert.True(t, have(sec, PermNotificationChannel))
		assert.True(t, have(sec, PermSystemAlertManage))
		assert.True(t, have(sec, PermSecurityPolicyManage))
		for _, k := range []Permission{PermRoleAssign, PermUserManage, PermAuthorizationManage, PermAssetCreate} {
			assert.False(t, have(sec, k), "設定範本不得含 %s", k)
		}
	})
	t.Run("集合都在目錄內、都是 global-only、無保留能力名稱", func(t *testing.T) {
		for _, k := range append(append([]Permission{}, idp...), sec...) {
			def, ok := LookupPermission(k)
			require.True(t, ok, "%s 不在目錄", k)
			assert.Equal(t, ScopeGlobalOnly, def.Scope, k)
			assert.NoError(t, ValidatePermissionKey(k))
		}
	})
	t.Run("範本持有者無超管身分、無連線豁免、無審核資格", func(t *testing.T) {
		db := newRoleDefDB(t)
		for _, key := range []string{model.BuiltinIdentityAdmin, model.BuiltinSecurityAdmin} {
			r := mkRole(t, db, key, key)
			require.NoError(t, db.Create(&model.User{Username: "u-" + key, Active: true}).Error)
			var u model.User
			require.NoError(t, db.Where("username = ?", "u-"+key).First(&u).Error)
			assignDirect(t, db, u.ID, r.ID, model.ScopeKindGlobal)
			p, err := NewResolver(db).ResolveUser(u.ID, TokenFacts{})
			require.NoError(t, err)
			assert.False(t, p.IsSuperAdmin())
			assert.False(t, p.IsApprover())
			assert.False(t, p.ConnectionShortcut(model.PermissionConnect))
			assert.Equal(t, LegacyRoleNone, p.LegacyRole(), "範本不折疊成舊主角色")
			assert.ElementsMatch(t, permStrings(TemplatePermissions(key)), permStrings(p.Capabilities()))
		}
	})
	t.Run("自訂角色勾同一指派鍵得到相同能力描述與信任提示，沒有子集委派設定", func(t *testing.T) {
		caps := CapabilityDescriptors()
		// 獨立能力描述：指派角色（含信任提示）、單台存取政策覆寫與刪除錄影（無信任提示），逐鍵核對
		byID := map[string]CapabilityDescriptor{}
		for _, c := range caps {
			byID[c.ID] = c
		}
		require.Len(t, caps, 3)
		require.Contains(t, byID, "role_assign")
		assert.Equal(t, PermRoleAssign, byID["role_assign"].Key)
		assert.True(t, byID["role_assign"].TrustHint)
		require.Contains(t, byID, "access_policy_override")
		assert.Equal(t, PermAccessPolicyManage, byID["access_policy_override"].Key)
		assert.False(t, byID["access_policy_override"].TrustHint)
		require.Contains(t, byID, "recording_delete")
		assert.Equal(t, PermRecordingDelete, byID["recording_delete"].Key)
		assert.False(t, byID["recording_delete"].TrustHint)
		a := SummarizeRole(idp)
		b := SummarizeRole([]Permission{PermRoleAssign, PermRoleView, PermUserManage})
		assert.True(t, a.AssignmentTrustHint)
		assert.True(t, b.AssignmentTrustHint)
		// 指派能力只有一個鍵：目錄內沒有任何 role:assign 的變體（範圍、子集、節點）
		for _, d := range Catalog() {
			if strings.HasPrefix(string(d.Key), "role:") {
				assert.Contains(t, []Permission{PermRoleAssign, PermRoleView}, d.Key)
			}
		}
	})
	t.Run("範本不能經輸入冒認：自訂集合不收範本識別、保留名稱解析不出內建權限", func(t *testing.T) {
		_, err := NormalizeRolePermissions([]string{"identity_admin", "security_admin"})
		assert.True(t, IsInvalidRolePermission(err))
		db := newRoleDefDB(t)
		// 沒有 builtin_key 的同名列：只有自己的明確集合（此處為空），不因名稱得到範本能力
		r := mkCustomRole(t, db, "identity_admin")
		require.NoError(t, db.Create(&model.User{Username: "x", Active: true}).Error)
		var u model.User
		require.NoError(t, db.Where("username = ?", "x").First(&u).Error)
		assignDirect(t, db, u.ID, r.ID, model.ScopeKindGlobal)
		p, err := NewResolver(db).ResolveUser(u.ID, TokenFacts{})
		require.NoError(t, err)
		assert.Empty(t, p.Capabilities())
	})
}

// TestRoleEditorDescriptors 擋：入口狀態漂移、缺依賴被自動補授、固定入口或 ui: 變成可選、摘要誇大。
func TestRoleEditorDescriptors(t *testing.T) {
	entries := EntryDescriptors()
	t.Run("每入口狀態集合：hidden 為空、各態鍵都在目錄、且滿足依賴閉包", func(t *testing.T) {
		ids := map[string]bool{}
		for _, e := range entries {
			require.False(t, ids[e.ID], "入口 %s 重複", e.ID)
			ids[e.ID] = true
			require.GreaterOrEqual(t, len(e.States), 2, e.ID)
			assert.Equal(t, StateHidden, e.States[0].Name)
			assert.Empty(t, e.States[0].Keys)
			for _, stt := range e.States[1:] {
				var keys []string
				for _, k := range stt.Keys {
					keys = append(keys, string(k))
				}
				_, err := NormalizeRolePermissions(keys)
				assert.NoError(t, err, "入口 %s 的 %s 態集合必須自足（依賴已含）", e.ID, stt.Name)
			}
			if len(e.States) > 3 {
				t.Errorf("入口 %s 狀態超過三態", e.ID)
			}
		}
	})
	t.Run("無管理動作的入口只有隱藏與可用兩態；三態入口有 read 與 manage", func(t *testing.T) {
		for _, e := range entries {
			names := []string{}
			for _, s := range e.States {
				names = append(names, s.Name)
			}
			switch len(e.States) {
			case 2:
				assert.Contains(t, []string{StateAvailable, StateManage}, e.States[1].Name, e.ID)
			case 3:
				assert.Equal(t, []string{StateHidden, StateRead, StateManage}, names, e.ID)
			}
		}
		for _, id := range []string{"roles", "audit_logs", "compliance_map", "instance_guard", "checkpoint_verification"} {
			for _, e := range entries {
				if e.ID == id {
					assert.Equal(t, StateAvailable, e.States[1].Name, id)
				}
			}
		}
	})
	t.Run("每個目錄鍵恰好歸屬某入口或獨立能力；固定入口與 ui: 不可選", func(t *testing.T) {
		owned := map[Permission]bool{}
		for _, e := range entries {
			for _, s := range e.States {
				for _, k := range s.Keys {
					owned[k] = true
				}
			}
		}
		for _, c := range CapabilityDescriptors() {
			owned[c.Key] = true
		}
		for _, d := range Catalog() {
			if !IsAssignable(d.Key) {
				assert.False(t, owned[d.Key], "超管保留的鍵 %s 不得出現在任何可勾選的描述中", d.Key)
				continue
			}
			assert.True(t, owned[d.Key], "目錄鍵 %s 沒有任何入口或能力描述", d.Key)
		}
		for k := range owned {
			_, ok := LookupPermission(k)
			assert.True(t, ok, "描述引用目錄外的鍵 %s", k)
			assert.False(t, strings.HasPrefix(string(k), "ui:"))
		}
		for _, f := range FixedEntries() {
			for _, e := range entries {
				assert.NotEqual(t, f, e.ID, "固定入口不得為可指派入口")
			}
		}
		_, err := NormalizeRolePermissions([]string{"ui:nav.users"})
		assert.True(t, IsInvalidRolePermission(err))
	})
	t.Run("依賴明列且不自動補授：缺依賴允許儲存，另行指出缺少的鍵與無法使用的畫面", func(t *testing.T) {
		out, err := NormalizeRolePermissions([]string{"credential:manage"})
		require.NoError(t, err)
		assert.Equal(t, []string{"credential:manage"}, permStrings(out), "沒有補任何鍵")
		md := MissingDependencies(out)
		require.Len(t, md, 1)
		assert.Equal(t, PermCredentialManage, md[0].Permission)
		assert.Equal(t, []Permission{PermAssetView}, md[0].Missing)
		bs := BlockedScreens(out)
		require.Len(t, bs, 1)
		assert.Equal(t, "credentials", bs[0].ID)
		out, err = NormalizeRolePermissions([]string{"role:assign"})
		require.NoError(t, err)
		assert.Equal(t, []Permission{PermRoleView, PermUserManage}, MissingDependencies(out)[0].Missing)
		bs = BlockedScreens(out)
		require.Len(t, bs, 1)
		assert.Equal(t, "role_assign", bs[0].ID)
		ok, err := NormalizeRolePermissions([]string{"asset:view", "credential:manage", "asset:view"})
		require.NoError(t, err)
		assert.Equal(t, []string{"asset:view", "credential:manage"}, permStrings(ok), "去重排序，沒有補任何鍵")
		assert.Empty(t, MissingDependencies(ok))
		assert.Empty(t, BlockedScreens(ok))
		// 審核範圍管理改由專用選擇端點取候選，不再依賴資產檢視與使用者、群組管理
		for _, k := range []Permission{PermAssetView, PermUserManage, PermUserGroupManage} {
			assert.NotContains(t, PermissionDependencies(PermApproverScopeManage), k)
		}
		// 只被別鍵當依賴的鍵不使自己的畫面被標為阻擋
		ug, _ := NormalizeRolePermissions([]string{"usergroup:manage"})
		for _, b := range BlockedScreens(ug) {
			assert.NotEqual(t, "authorizations", b.ID)
			assert.NotEqual(t, "users", b.ID)
		}
		empty, err := NormalizeRolePermissions(nil)
		require.NoError(t, err)
		assert.Empty(t, empty)
	})
	t.Run("第二層細項只有資產、帳號、憑證庫、節點", func(t *testing.T) {
		for _, e := range entries {
			if e.ID != "assets" && e.ID != "credentials" {
				assert.Empty(t, e.Details, e.ID)
			}
		}
		var kinds = map[string]bool{}
		for _, e := range entries {
			for _, d := range e.Details {
				kinds[strings.SplitN(d.ID, ".", 2)[0]] = true
				_, ok := LookupPermission(d.Key)
				assert.True(t, ok)
			}
		}
		assert.Equal(t, map[string]bool{"asset": true, "asset_account": true, "credential": true, "node": true}, kinds)
	})
	t.Run("摘要反映實際鍵、計數取目錄、全權自訂不稱超管或可連線、未上線功能不列為可用", func(t *testing.T) {
		all := AssignableKeys()
		s := SummarizeRole(all)
		assert.Equal(t, len(all), s.PermissionCount)
		assert.Equal(t, len(Catalog()), s.CatalogCount)
		assert.True(t, s.ConnectionSeparate)
		assert.True(t, s.ScopeGlobalOnly)
		assert.True(t, s.AssignmentTrustHint)
		assert.Empty(t, s.Hidden, "全權自訂：入口全數可管理或可用")
		assert.Empty(t, s.Unattributed)
		one := SummarizeRole([]Permission{PermAssetView})
		assert.Equal(t, []string{"assets"}, one.Read, "單一讀取鍵只稱為該入口唯讀")
		assert.NotContains(t, one.Manage, "assets")
		assert.False(t, one.AssignmentTrustHint)
		none := SummarizeRole(nil)
		assert.Equal(t, 0, none.PermissionCount)
		assert.Len(t, none.Hidden, len(entries))
		assert.ElementsMatch(t, []string{"role_preview", "permission_overview"}, DeferredFeatures())
		for _, d := range DeferredFeatures() {
			for _, e := range entries {
				assert.NotEqual(t, d, e.ID)
			}
		}
	})
}

// TestRoleDefinitionUnion 擋：新角色改寫相容結果、跨指派拼權限、空自訂角色補 user、未生效列回退全域、agent 升權。
func TestRoleDefinitionUnion(t *testing.T) {
	g, n := model.ScopeKindGlobal, model.ScopeKindNodes
	newUser := func(t *testing.T, db *gorm.DB, name string) uint {
		u := model.User{Username: name, Active: true}
		require.NoError(t, db.Create(&u).Error)
		return u.ID
	}
	resolve := func(t *testing.T, db *gorm.DB, uid uint, facts TokenFacts) *Principal {
		p, err := NewResolver(db).ResolveUser(uid, facts)
		require.NoError(t, err)
		return p
	}
	t.Run("兩個自訂角色聯集去重且不取得超管或連線豁免", func(t *testing.T) {
		db := newRoleDefDB(t)
		a := mkCustomRole(t, db, "a", PermAssetView, PermAssetCreate)
		b := mkCustomRole(t, db, "b", PermAssetView, PermSessionView)
		uid := newUser(t, db, "u")
		assignDirect(t, db, uid, a.ID, g)
		assignDirect(t, db, uid, b.ID, g)
		p := resolve(t, db, uid, TokenFacts{})
		assert.Equal(t, []string{"asset:create", "asset:view", "session:view"}, setStrings(p.Capabilities()))
		assert.False(t, p.IsSuperAdmin())
		assert.False(t, p.ConnectionShortcut(model.PermissionConnect))
	})
	t.Run("全目錄自訂角色仍非超管、非審核者", func(t *testing.T) {
		db := newRoleDefDB(t)
		r := mkCustomRole(t, db, "all", AssignableKeys()...)
		uid := newUser(t, db, "u")
		assignDirect(t, db, uid, r.ID, g)
		p := resolve(t, db, uid, TokenFacts{})
		assert.Len(t, p.Capabilities(), len(AssignableKeys()))
		assert.False(t, p.IsSuperAdmin())
		assert.False(t, p.IsApprover())
		assert.Equal(t, LegacyRoleNone, p.LegacyRole())
	})
	t.Run("只持空自訂角色不補一般使用者能力；真正零角色與純審核者維持原結果", func(t *testing.T) {
		db := newRoleDefDB(t)
		empty := mkCustomRole(t, db, "empty")
		ap := mkRole(t, db, "approver", model.BuiltinApprover)
		u1, u2, u3 := newUser(t, db, "u1"), newUser(t, db, "u2"), newUser(t, db, "u3")
		assignDirect(t, db, u1, empty.ID, g)
		assignDirect(t, db, u3, ap.ID, g)
		assert.Empty(t, resolve(t, db, u1, TokenFacts{}).Capabilities())
		assert.Equal(t, []string{"asset:view"}, setStrings(resolve(t, db, u2, TokenFacts{}).Capabilities()), "零角色視同 user")
		p3 := resolve(t, db, u3, TokenFacts{})
		assert.Empty(t, p3.Capabilities())
		assert.True(t, p3.IsApprover())
	})
	t.Run("相容主角色與新集合聯集；新集合不改變相容結果", func(t *testing.T) {
		db := newRoleDefDB(t)
		au := mkRole(t, db, "auditor", model.BuiltinAuditor)
		c := mkCustomRole(t, db, "c", PermAssetView, PermAssetCreate)
		uid := newUser(t, db, "u")
		assignDirect(t, db, uid, au.ID, g)
		assignDirect(t, db, uid, c.ID, g)
		p := resolve(t, db, uid, TokenFacts{})
		assert.Equal(t, LegacyRoleAuditor, p.LegacyRole())
		want := append(permStrings(TemplatePermissions(model.BuiltinAuditor)), "asset:create")
		sort.Strings(want)
		assert.Equal(t, want, setStrings(p.Capabilities()))
	})
	t.Run("節點指派不生效也不回退全域；跨 binding 不拼權限", func(t *testing.T) {
		db := newRoleDefDB(t)
		scoped := mkCustomRole(t, db, "scoped", PermAssetView, PermSessionView)
		glob := mkCustomRole(t, db, "glob", PermAuditView)
		uid := newUser(t, db, "u")
		assignDirect(t, db, uid, scoped.ID, n)
		assert.Empty(t, resolve(t, db, uid, TokenFacts{}).Capabilities(), "非全域指派對 scoped-reserved 權限不生效")
		assignDirect(t, db, uid, glob.ID, g)
		assert.Equal(t, []string{"audit:view"}, setStrings(resolve(t, db, uid, TokenFacts{}).Capabilities()), "只取全域那筆")
	})
	t.Run("經群組取得同樣聯集；agent 固定一般使用者能力", func(t *testing.T) {
		db := newRoleDefDB(t)
		c := mkCustomRole(t, db, "c", PermSessionView)
		grp := model.UserGroup{Name: "grp"}
		require.NoError(t, db.Create(&grp).Error)
		uid := newUser(t, db, "u")
		require.NoError(t, db.Create(&model.UserGroupMember{UserGroupID: grp.ID, UserID: uid}).Error)
		require.NoError(t, SetUserGroupRoles(db, grp.ID, []uint{c.ID}, uid))
		assert.Equal(t, []string{"session:view"}, setStrings(resolve(t, db, uid, TokenFacts{}).Capabilities()))
		agent := resolve(t, db, uid, TokenFacts{SubjectKind: model.KindAgent})
		assert.Equal(t, []string{"asset:view"}, setStrings(agent.Capabilities()))
	})
	t.Run("修改自訂角色後下一請求與能力投影採新集合；token 事實不覆蓋結果", func(t *testing.T) {
		db := newRoleDefDB(t)
		c := mkCustomRole(t, db, "c", PermAssetView, PermSessionView)
		uid := newUser(t, db, "u")
		assignDirect(t, db, uid, c.ID, g)
		before := resolve(t, db, uid, TokenFacts{AuthMethod: "password", CredEpoch: 1})
		projBefore := ProjectCapabilities(before, ProjectionInputs{})
		assert.Equal(t, []string{"asset:view", "session:view"}, nonUI(projBefore.Permissions))
		// 模擬服務層 Update 的資料效果：換掉集合列（definition_version 同步遞增）。
		require.NoError(t, db.Where("role_id = ?", c.ID).Delete(&model.RolePermission{}).Error)
		require.NoError(t, db.Create(&model.RolePermission{RoleID: c.ID, PermissionKey: string(PermAuditView)}).Error)
		require.NoError(t, db.Model(&model.Role{}).Where("id = ?", c.ID).Update("definition_version", 2).Error)
		// 同一組 token 事實（模擬沿用舊 JWT）與不同 token 事實，結果都是新集合。
		for _, f := range []TokenFacts{{AuthMethod: "password", CredEpoch: 1}, {}} {
			after := resolve(t, db, uid, f)
			proj := ProjectCapabilities(after, ProjectionInputs{})
			assert.Equal(t, []string{"audit:view"}, nonUI(proj.Permissions))
			assert.Equal(t, []ScopeSummaryEntry{{Permission: "audit:view", BindingScope: BindingScopeGlobal}}, proj.ScopeSummary)
		}
	})
	t.Run("全可指派集合的投影不含連線豁免或審核入口；無 connect 的管理者不能連線", func(t *testing.T) {
		db := newRoleDefDB(t)
		r := mkCustomRole(t, db, "all", CatalogKeys()...)
		uid := newUser(t, db, "u")
		assignDirect(t, db, uid, r.ID, g)
		p := resolve(t, db, uid, TokenFacts{})
		assert.False(t, p.IsSuperAdmin())
		assert.False(t, p.ConnectionShortcut(model.PermissionConnect), "管理能力不產生連線短路")
		assert.False(t, p.ConnectionShortcut(model.PermissionView), "非稽核主角色，也無檢視短路")
		proj := ProjectCapabilities(p, ProjectionInputs{})
		assert.NotContains(t, proj.Permissions, UIConnectBypass, "ui: 呈現點不可指派也不因管理能力出現")
		assert.NotContains(t, proj.Permissions, UIApprovals, "管理能力不產生審核資格")
		for _, k := range proj.Permissions {
			if strings.HasPrefix(k, UIPrefix) {
				assert.Contains(t, []string{UIAssetsGlobal, UISelfServiceActions}, k, "只允許由既有資格值衍生的呈現點")
			}
		}
	})
	t.Run("編輯角色不動連線授權列", func(t *testing.T) {
		db := newRoleDefDB(t)
		require.NoError(t, db.AutoMigrate(&model.AssetAuthorization{}))
		c := mkCustomRole(t, db, "c", PermAssetView)
		uid := newUser(t, db, "u")
		assignDirect(t, db, uid, c.ID, g)
		uidp := uid
		az := model.AssetAuthorization{UserID: &uidp}
		require.NoError(t, db.Session(&gorm.Session{SkipHooks: true}).Omit("Asset", "AssetGroup", "User", "UserGroup").Create(&az).Error)
		var n0 int64
		require.NoError(t, db.Model(&model.AssetAuthorization{}).Count(&n0).Error)
		require.NoError(t, db.Where("role_id = ?", c.ID).Delete(&model.RolePermission{}).Error)
		require.NoError(t, db.Create(&model.RolePermission{RoleID: c.ID, PermissionKey: string(PermUserManage)}).Error)
		var n1 int64
		require.NoError(t, db.Model(&model.AssetAuthorization{}).Count(&n1).Error)
		assert.Equal(t, n0, n1, "角色定義編輯不增刪連線授權")
		p := resolve(t, db, uid, TokenFacts{})
		assert.Equal(t, []string{"user:manage"}, setStrings(p.Capabilities()))
	})
	t.Run("目錄外的鍵（資料遭直改）不授權", func(t *testing.T) {
		db := newRoleDefDB(t)
		c := mkCustomRole(t, db, "c", PermAssetView)
		require.NoError(t, db.Create(&model.RolePermission{RoleID: c.ID, PermissionKey: "superadmin:all"}).Error)
		uid := newUser(t, db, "u")
		assignDirect(t, db, uid, c.ID, g)
		p := resolve(t, db, uid, TokenFacts{})
		assert.Equal(t, []string{"asset:view"}, setStrings(p.Capabilities()))
		assert.False(t, p.IsSuperAdmin())
	})
}

// TestSecurityAdminExclusivePermissions 鎖住系統安全管理員專屬權限點的現值（由範本推導），
// 以及其中指派保護的高風險子集。
// 範本改動使這裡轉紅時，先審新集合是否仍該讓持有者成為保護角色，再更新期望值。
func TestSecurityAdminExclusivePermissions(t *testing.T) {
	got := SecurityAdminExclusivePermissions()
	assert.Equal(t, []string{"alertrule:manage", "instanceguard:view", "key:manage", "notification_channel:manage", "offsite:manage",
		"policygroup:manage", "recording:delete", "rotation_schedule:manage", "schedule:manage", "securitypolicy:manage",
		"syslog:manage", "systemalert:manage", "transmission:manage"}, setStrings(got))
	assert.True(t, HoldsSecurityAdminExclusive([]Permission{PermAssetView, PermRecordingDelete}))
	assert.False(t, HoldsSecurityAdminExclusive([]Permission{PermPolicyGroupView, PermRoleAssign, PermAssetView}), "與其他內建範本共有的點不算專屬")
	assert.False(t, HoldsSecurityAdminExclusive(nil))

	// 指派保護的高風險權限點：內容鎖住，且須為專屬集合的子集——範本改動使某點不再專屬時
	// 這裡轉紅，先審保護集合是否該跟著調整。
	protected := ProtectedAssignmentPermissions()
	assert.Equal(t, []string{"alertrule:manage", "key:manage", "notification_channel:manage", "offsite:manage",
		"policygroup:manage", "recording:delete", "securitypolicy:manage", "syslog:manage", "systemalert:manage"}, setStrings(protected))
	exclusive := map[Permission]bool{}
	for _, p := range got {
		exclusive[p] = true
	}
	for _, p := range protected {
		assert.True(t, exclusive[p], "高風險點 %s 須為系統安全管理員專屬點", p)
	}
	assert.True(t, HoldsProtectedAssignmentPermission([]Permission{PermAssetView, PermRecordingDelete}))
	assert.False(t, HoldsProtectedAssignmentPermission([]Permission{PermInstanceGuardView, PermScheduleManage,
		PermTransmissionManage, PermRotationSchedule, PermAssetView}), "不保護的專屬點不使角色成為保護角色")
	assert.False(t, HoldsProtectedAssignmentPermission(nil))
}
