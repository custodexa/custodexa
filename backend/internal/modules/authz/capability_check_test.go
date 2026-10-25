package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// HasAllCapabilities：服務層重新自資料庫解析主體並判全部能力；不存在、停用、目錄外鍵、
// 空需求皆不得放行；agent 不因角色取得新能力；版本隨判定回報。
func TestHasAllCapabilities(t *testing.T) {
	g := model.ScopeKindGlobal
	db := newRoleDefDB(t)
	r := NewResolver(db)
	mk := func(name string, active bool) uint {
		u := model.User{Username: name, Active: true}
		require.NoError(t, db.Create(&u).Error)
		if !active {
			require.NoError(t, db.Model(&u).Update("active", false).Error)
		}
		return u.ID
	}
	role := mkCustomRole(t, db, "rot", PermAssetView, PermCredentialRotate, PermCredentialDetach)
	uid := mk("rotator", true)
	assignDirect(t, db, uid, role.ID, g)

	d, err := r.HasAllCapabilities(nil, uid, []string{"credential:rotate", "credential:detach"})
	require.NoError(t, err)
	assert.True(t, d.Allowed)
	assert.Equal(t, []string{"direct"}, d.Sources, "判定帶回權限來源種類")

	t.Run("來源種類涵蓋 direct／group／mapped／both", func(t *testing.T) {
		p := &Principal{Assignments: []Assignment{
			{Via: ViaDirect, RoleSource: "manual"}, {Via: ViaDirect, RoleSource: "mapped"},
			{Via: ViaDirect, RoleSource: "both"}, {Via: ViaGroup},
		}}
		assert.Equal(t, []string{"both", "direct", "group", "mapped"}, p.ProvenanceLabels())
	})

	d, err = r.HasAllCapabilities(nil, uid, []string{"credential:rotate", "credential:set-secret"})
	require.NoError(t, err)
	assert.False(t, d.Allowed)
	assert.Equal(t, "credential:set-secret", d.Missing, "回報第一個缺少的鍵")

	t.Run("只持舊 credential:manage 不等於新語義能力", func(t *testing.T) {
		legacy := mkCustomRole(t, db, "legacy", PermAssetView, PermCredentialManage)
		u := mk("legacy-user", true)
		assignDirect(t, db, u, legacy.ID, g)
		d, err := r.HasAllCapabilities(nil, u, []string{"credential:set-secret"})
		require.NoError(t, err)
		assert.False(t, d.Allowed, "舊識別不作萬用放行碼")
	})
	t.Run("非全域指派對 scoped-reserved 的憑證能力不生效", func(t *testing.T) {
		scoped := mkCustomRole(t, db, "scoped", PermAssetView, PermCredentialRotate)
		u := mk("scoped-user", true)
		assignDirect(t, db, u, scoped.ID, model.ScopeKindNodes)
		d, err := r.HasAllCapabilities(nil, u, []string{"credential:rotate"})
		require.NoError(t, err)
		assert.False(t, d.Allowed)
	})
	t.Run("不帶目標的檢核：scoped-enforced 權限點只認全域來源", func(t *testing.T) {
		def, ok := LookupPermission(PermAssetUpdate)
		require.True(t, ok)
		require.Equal(t, ScopeEnforced, def.Scope, "前提：資產編輯已啟用範圍判定")
		node := model.AssetGroup{Name: "cap-node"}
		require.NoError(t, db.Create(&node).Error)
		editor := mkCustomRole(t, db, "cap-node-editor", PermAssetView, PermAssetUpdate)
		credUpd := mkCustomRole(t, db, "cap-cred-update", PermAssetView, PermCredentialUpdate)
		u := mk("cap-node-user", true)
		assignDirect(t, db, u, credUpd.ID, g)
		assignDirect(t, db, u, editor.ID, model.ScopeKindNodes)
		require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser,
			SubjectID: u, RoleID: editor.ID, NodeID: node.ID}).Error)

		p, err := ResolveUserOn(db, u, TokenFacts{})
		require.NoError(t, err)
		require.True(t, p.Has(PermAssetUpdate), "前提：節點範圍來源在有目標的判定生效")
		d, err := r.HasAllCapabilities(nil, u, []string{"credential:update", "asset:update"})
		require.NoError(t, err)
		assert.False(t, d.Allowed, "只有節點範圍來源者，不帶目標的檢核不得放行")
		assert.Equal(t, "asset:update", d.Missing)

		w := mk("cap-global-user", true)
		assignDirect(t, db, w, credUpd.ID, g)
		globalEditor := mkCustomRole(t, db, "cap-global-editor", PermAssetView, PermAssetUpdate)
		assignDirect(t, db, w, globalEditor.ID, g)
		d, err = r.HasAllCapabilities(nil, w, []string{"credential:update", "asset:update"})
		require.NoError(t, err)
		assert.True(t, d.Allowed, "全域來源照常放行")
	})
	t.Run("停用、不存在、空識別不通過", func(t *testing.T) {
		off := mk("off", false)
		assignDirect(t, db, off, role.ID, g)
		for _, id := range []uint{off, 99999, 0} {
			d, err := r.HasAllCapabilities(nil, id, []string{"credential:rotate"})
			require.NoError(t, err)
			assert.False(t, d.Allowed, "user=%d", id)
			assert.Equal(t, "principal", d.Missing)
		}
	})
	t.Run("目錄外鍵與空需求是錯誤而非拒絕", func(t *testing.T) {
		_, err := r.HasAllCapabilities(nil, uid, []string{"credential:nope"})
		assert.ErrorIs(t, err, ErrCapabilityUnknown)
		_, err = r.HasAllCapabilities(nil, uid, nil)
		assert.ErrorIs(t, err, ErrCapabilityEmpty)
	})
	t.Run("超管範本取目錄全部且帶版本", func(t *testing.T) {
		sa := mkRole(t, db, "admin", model.BuiltinSuperAdmin)
		u := mk("root", true)
		assignDirect(t, db, u, sa.ID, g)
		d, err := r.HasAllCapabilities(nil, u, []string{"credential:view", "credential:create", "credential:update", "credential:set-secret",
			"credential:rotate", "credential:convert-scope", "credential:detach", "credential:delete", "credential:bind", "account:rotate"})
		require.NoError(t, err)
		assert.True(t, d.Allowed)
		assert.EqualValues(t, 0, d.Version)
	})
}
