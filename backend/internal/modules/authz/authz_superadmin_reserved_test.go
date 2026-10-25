package authz

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestAuthzSuperAdminReservedIdentity 擋：持全部權限點的非內建角色被當成超管、連線短路外溢到其他角色。
func TestAuthzSuperAdminReservedIdentity(t *testing.T) {
	g := model.ScopeKindGlobal

	// 連線判定：先看主體的保留身分短路，落空再走正常授權查詢（無任何授權列時一律拒）。
	connect := func(t *testing.T, db *gorm.DB, p *Principal, perm model.PermissionType) bool {
		t.Helper()
		asset := mkAsset(t, db, "a-"+string(perm))
		ok, err := NewAssetAuthorizationService(db).CheckPermissionForPrincipal(p, p.UserID, asset.ID, perm)
		require.NoError(t, err)
		return ok
	}
	resolve := func(t *testing.T, db *gorm.DB, u *model.User) *Principal {
		t.Helper()
		p, err := NewResolver(db).ResolveUser(u.ID, TokenFacts{})
		require.NoError(t, err)
		return p
	}

	t.Run("持全部權限點的非內建角色不是超管且連線判定為拒", func(t *testing.T) {
		db := newPrincipalDB(t)
		custom := mkRole(t, db, "ops", "")
		u := mkUser(t, db, "ops-user")
		assignDirect(t, db, u.ID, custom.ID, g)
		p := resolve(t, db, u)
		// 直接把目錄內全部權限點塞進能力集合，模擬「勾滿所有權限點的自訂角色」
		for _, k := range CatalogKeys() {
			p.caps[k] = true
		}
		require.Len(t, p.Capabilities(), len(CatalogKeys()))
		assert.False(t, p.IsSuperAdmin(), "擁有全部權限點不構成超管")
		assert.False(t, connect(t, db, p, model.PermissionView))
		assert.False(t, connect(t, db, p, model.PermissionConnect))
	})

	t.Run("名稱為 admin 但不是內建範本的角色不是超管", func(t *testing.T) {
		db := newPrincipalDB(t)
		fake := mkRole(t, db, "admin", "") // builtin_key 為空：不依角色名稱判定
		u := mkUser(t, db, "fake-admin")
		assignDirect(t, db, u.ID, fake.ID, g)
		p := resolve(t, db, u)
		assert.False(t, p.IsSuperAdmin())
		assert.False(t, connect(t, db, p, model.PermissionConnect))
		assert.False(t, connect(t, db, p, model.PermissionView))
	})

	t.Run("內建超管連線判定為准（view 與 connect）", func(t *testing.T) {
		db := newPrincipalDB(t)
		adm := mkRole(t, db, "admin", model.BuiltinSuperAdmin)
		u := mkUser(t, db, "root")
		assignDirect(t, db, u.ID, adm.ID, g)
		p := resolve(t, db, u)
		assert.True(t, p.IsSuperAdmin())
		assert.True(t, connect(t, db, p, model.PermissionConnect))
		assert.True(t, connect(t, db, p, model.PermissionView))
	})

	t.Run("稽核員 view 短路依舊主角色，connect 不短路", func(t *testing.T) {
		db := newPrincipalDB(t)
		aud := mkRole(t, db, "auditor", model.BuiltinAuditor)
		u := mkUser(t, db, "aud")
		assignDirect(t, db, u.ID, aud.ID, g)
		p := resolve(t, db, u)
		assert.False(t, p.IsSuperAdmin())
		assert.True(t, connect(t, db, p, model.PermissionView), "view 短路")
		assert.False(t, connect(t, db, p, model.PermissionConnect), "connect 須經正常授權查詢")
		// 顯式授予某資產 connect 者仍可連（落正常授權查詢）
		asset := mkAsset(t, db, "granted")
		grant(t, db, idp(u.ID), nil, idp(asset.ID), nil, model.PermissionConnect, model.AuthorizationSourceManual, nil, nil)
		ok, err := NewAssetAuthorizationService(db).CheckPermissionForPrincipal(p, u.ID, asset.ID, model.PermissionConnect)
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("admin 加 auditor 走 admin 路徑", func(t *testing.T) {
		db := newPrincipalDB(t)
		adm, aud := mkRole(t, db, "admin", model.BuiltinSuperAdmin), mkRole(t, db, "auditor", model.BuiltinAuditor)
		u := mkUser(t, db, "both")
		assignDirect(t, db, u.ID, adm.ID, g)
		assignDirect(t, db, u.ID, aud.ID, g)
		p := resolve(t, db, u)
		assert.True(t, p.IsSuperAdmin())
		assert.True(t, connect(t, db, p, model.PermissionConnect))
	})

	t.Run("短路不外溢：一般使用者、審核者、零角色、agent、節點範圍超管", func(t *testing.T) {
		db := newPrincipalDB(t)
		adm := mkRole(t, db, "admin", model.BuiltinSuperAdmin)
		usr, apv := mkRole(t, db, "user", model.BuiltinUser), mkRole(t, db, "approver", model.BuiltinApprover)
		mk := func(name string, roles ...*model.Role) *Principal {
			u := mkUser(t, db, name)
			for _, r := range roles {
				assignDirect(t, db, u.ID, r.ID, g)
			}
			return resolve(t, db, u)
		}
		for name, p := range map[string]*Principal{
			"user": mk("u1", usr), "approver": mk("u2", apv), "zero": mk("u3"), "user+approver": mk("u4", usr, apv),
		} {
			assert.False(t, connect(t, db, p, model.PermissionView), name)
			assert.False(t, connect(t, db, p, model.PermissionConnect), name)
		}
		// agent：即使角色列有超管範本也不取得短路
		agent := NewPrincipal(900, TokenFacts{SubjectKind: model.KindAgent}, []Assignment{asg(model.BuiltinSuperAdmin, g)})
		assert.False(t, connect(t, db, agent, model.PermissionConnect))
		// 節點範圍的超管指派不生效，故無短路
		nu := mkUser(t, db, "node-admin")
		assignDirect(t, db, nu.ID, adm.ID, model.ScopeKindNodes)
		np := resolve(t, db, nu)
		assert.False(t, np.IsSuperAdmin())
		assert.False(t, connect(t, db, np, model.PermissionConnect))
	})

	t.Run("目錄拒絕以保留能力為名的權限點", func(t *testing.T) {
		for _, key := range []Permission{"superadmin:grant", "super_admin:assign", "role:define", "secret:reveal", "credential:plaintext_read", "connect:shortcut"} {
			err := ValidateCatalog([]PermissionDef{{Key: key, Group: GroupIdentity, Category: CategoryManage, Scope: ScopeGlobalOnly}})
			assert.Error(t, err, string(key))
		}
		assert.NoError(t, ValidateCatalog(Catalog()), "現行目錄通過載入規則")
	})
}
