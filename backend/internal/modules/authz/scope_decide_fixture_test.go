package authz

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 判定夾具：一個資料庫同時有主體表與拓撲表。
//
//	節點 n1 ── n2 ── n3；n4 根；n5 根（供刪除）
//	資產 a1 掛 n3；a2 掛 n4；a3 未分組；a4 掛 n2 與 n4；a5 掛 n5
//	帳號 acc1 屬 a1；acc2 屬 a2
//
// 名稱刻意帶有可辨識字串，供「序列化不含名稱」比對。
type decideFixture struct {
	db      *gorm.DB
	topo    *asset.ScopeTopologyReader
	n       [6]uint // 1..5
	a       [6]uint // 1..5
	acc     [3]uint // 1..2
	names   []string
	catView Catalogue // asset:view、asset:update 為 scoped-enforced
	nextID  int
}

const fxSecretPrefix = "zz-fixture-name-"

func newDecideFixture(t *testing.T) *decideFixture {
	t.Helper()
	return newDecideFixtureOn(t, newPrincipalDB(t))
}

// newDecideFixtureOn 在給定的庫上建同一組夾具（db 需已有 newPrincipalDB 的表與 authz_state 列）。
func newDecideFixtureOn(t *testing.T, db *gorm.DB) *decideFixture {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&model.RolePermission{}, &model.AssetAccount{}))
	f := &decideFixture{db: db, topo: asset.NewScopeTopologyReader()}
	name := func(s string) string {
		n := fxSecretPrefix + s
		f.names = append(f.names, n)
		return n
	}
	up := func(i uint) *uint { return &i }
	f.n[1] = mkNode(t, db, name("node1"), nil).ID
	f.n[2] = mkNode(t, db, name("node2"), up(f.n[1])).ID
	f.n[3] = mkNode(t, db, name("node3"), up(f.n[2])).ID
	f.n[4] = mkNode(t, db, name("node4"), nil).ID
	f.n[5] = mkNode(t, db, name("node5"), nil).ID
	for i := 1; i <= 5; i++ {
		f.a[i] = mkAsset(t, db, name("asset"+string(rune('0'+i)))).ID
	}
	for _, m := range [][2]uint{{1, 3}, {2, 4}, {4, 2}, {4, 4}, {5, 5}} {
		require.NoError(t, db.Create(&model.AssetNode{AssetID: f.a[m[0]], NodeID: f.n[m[1]]}).Error)
	}
	for i, as := range []uint{1, 2} {
		acc := &model.AssetAccount{AssetID: f.a[as], CredentialID: uint(i + 1)}
		require.NoError(t, db.Create(acc).Error)
		f.acc[i+1] = acc.ID
	}
	var err error
	f.catView, err = CatalogueWithScopedEnforcedForTest(PermAssetView, PermAssetUpdate)
	require.NoError(t, err)
	return f
}

func (f *decideFixture) uniq(prefix string) string {
	f.nextID++
	return prefix + string(rune('a'+f.nextID/26)) + string(rune('a'+f.nextID%26))
}

func (f *decideFixture) user(t *testing.T) uint {
	t.Helper()
	return mkUser(t, f.db, f.uniq("u")).ID
}

func (f *decideFixture) role(t *testing.T, perms ...Permission) uint {
	t.Helper()
	return mkCustomRole(t, f.db, f.uniq("r"), perms...).ID
}

// bindDirect 使用者直接指派節點範圍角色，綁定給定節點。
func (f *decideFixture) bindDirect(t *testing.T, uid, roleID uint, nodes ...uint) {
	t.Helper()
	assignDirect(t, f.db, uid, roleID, model.ScopeKindNodes)
	for _, n := range nodes {
		require.NoError(t, f.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: uid, RoleID: roleID, NodeID: n}).Error)
	}
}

// bindGroup 使用者經群組取得節點範圍角色。
func (f *decideFixture) bindGroup(t *testing.T, uid, roleID uint, nodes ...uint) {
	t.Helper()
	g := &model.UserGroup{Name: f.uniq("g")}
	require.NoError(t, f.db.Create(g).Error)
	require.NoError(t, f.db.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: uid, Manual: true}).Error)
	require.NoError(t, f.db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: roleID, ScopeKind: model.ScopeKindNodes}).Error)
	for _, n := range nodes {
		require.NoError(t, f.db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUserGroup, SubjectID: g.ID, RoleID: roleID, NodeID: n}).Error)
	}
}

func (f *decideFixture) global(t *testing.T, uid, roleID uint) {
	t.Helper()
	assignDirect(t, f.db, uid, roleID, model.ScopeKindGlobal)
}

func (f *decideFixture) builtinRole(t *testing.T, key string) uint {
	t.Helper()
	var r model.Role
	if err := f.db.Where("builtin_key = ?", key).First(&r).Error; err == nil {
		return r.ID
	}
	return mkRole(t, f.db, key, key).ID
}

func (f *decideFixture) deleteNode(t *testing.T, id uint) {
	t.Helper()
	require.NoError(t, f.db.Delete(&model.AssetGroup{}, id).Error)
}

func (f *decideFixture) evaluator(cat Catalogue) *ScopeEvaluator {
	return NewScopeEvaluator(cat, f.topo)
}

// decide 以 uid 的 token 脈絡呼叫 Decide（傳入主體只提供 UserID 與 Facts）。
func (f *decideFixture) decide(t *testing.T, ev *ScopeEvaluator, uid uint, perm Permission, target ScopeTarget) ScopeResult {
	t.Helper()
	res, err := ev.Decide(f.db, &Principal{UserID: uid}, perm, target)
	require.NoError(t, err)
	return res
}
