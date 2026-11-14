package identity

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/testgate"
)

// API token 的建立與撤銷在帳號層級鎖內進行：名稱占用沒有資料庫索引，唯一性完全依賴這把鎖；
// 刪除帳號持同一把鎖並在同一交易標記 token。兩個交錯以同步點固定，各由一個獨立連線池驅動
// （＝兩個後端副本），只在 PostgreSQL 上有意義：advisory lock 是跨副本序列化的唯一機制。
//
//	TEST_PG_DSN="host=... user=... password=... dbname=... sslmode=disable" \
//	  REQUIRE_INTEGRATION=1 go test ./internal/modules/identity -run 'APIToken.*PG'

const pgAPITokenSchema = "api_token_lock_test"

type apiTokenPGEnv struct {
	dbA, dbB    *gorm.DB
	tokensA     *APITokenService
	tokensB     *APITokenService
	usersB      *UserService
	roles       map[string]uint
	root, owner uint
}

func newAPITokenPGEnv(t *testing.T) *apiTokenPGEnv {
	t.Helper()
	base := testgate.Value(t, testgate.EnvPGDSN)
	admin := openPGRaceDB(t, base)
	drop := "DROP SCHEMA IF EXISTS " + pgAPITokenSchema + " CASCADE"
	require.NoError(t, admin.Exec(drop).Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+pgAPITokenSchema).Error)
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", pgAPITokenSchema, err)
		}
	})
	scoped := base + " search_path=" + pgAPITokenSchema
	dbA := openPGRaceDB(t, scoped)
	dbB := openPGRaceDB(t, scoped)
	require.NoError(t, migrateWithAuthz(dbA, &model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{},
		&model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}, &model.RolePermission{},
		&model.ExternalGroup{}, &model.GroupRoleMapping{}, &model.AuditLog{}, &model.AssetGroup{}, &model.AssetAuthorization{},
		&model.GroupUserGroupMapping{}, &model.UserGroupMappingRuleSupport{}, &model.UserRoleMappingRuleSupport{},
		&model.UserChannelObservation{}, &model.PermissionStateEvent{}, &model.PasswordHistory{},
		&model.RefreshToken{}, &model.UserRoleMapping{}, &model.UserExternalIdentity{},
		&model.APIToken{}, &model.APITokenRole{}))
	seedAuthzState(t, dbA)
	oldDB := database.DB
	database.DB = dbA
	t.Cleanup(func() { database.DB = oldDB })

	e := &apiTokenPGEnv{dbA: dbA, dbB: dbB, roles: map[string]uint{}}
	r := model.Role{Name: "admin"}
	require.NoError(t, dbA.Create(&r).Error) // BeforeCreate 帶入內建識別
	e.roles["admin"] = r.ID
	k := model.BuiltinIdentityAdmin
	ida := model.Role{Name: "identity_admin", BuiltinKey: &k, DefinitionVersion: 1}
	require.NoError(t, dbA.Create(&ida).Error)
	e.roles["identity_admin"] = ida.ID
	mk := func(name, role string) uint {
		u := model.User{Username: name, Active: true}
		require.NoError(t, dbA.Create(&u).Error)
		require.NoError(t, dbA.Create(&model.UserRole{UserID: u.ID, RoleID: e.roles[role], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		return u.ID
	}
	e.root = mk("root", "admin")
	mk("root2", "admin")
	e.owner = mk("owner", "identity_admin")

	rec := &recordingTokenEvents{}
	e.tokensA = NewAPITokenService(dbA, rec)
	e.tokensB = NewAPITokenService(dbB, rec)
	e.usersB = NewUserService(dbB, nil)
	e.usersB.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	e.usersB.SetProtectedAccountOps(NewProtectedAccountOps(audit.NewTxSink(), audit.NewSystemAlertSink(nil)))
	e.usersB.authzRevoker = noopRevoker{}
	return e
}

func (e *apiTokenPGEnv) op(id uint) Operator {
	return Operator{Principal: testSessionPrincipal(id), UserID: id, Username: "op", ClientIP: "127.0.0.1"}
}

func (e *apiTokenPGEnv) create(svc *APITokenService, name string) error {
	_, err := svc.Create(e.op(e.owner), CreateAPITokenInput{Name: name, RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
	return err
}

// waitAdvisoryWaiter 正向證明另一個交易正在等 advisory lock（而不是因其他原因尚未完成）。
func waitAdvisoryWaiter(t *testing.T, db *gorm.DB) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int64
		require.NoError(t, db.Raw(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`).Scan(&n).Error)
		if n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("沒有觀察到等待中的 advisory lock：第二個交易沒有在帳號層級鎖上等待")
}

// holdAt 在同步點擋住第一個走到的交易；回傳「已走到」與「放行」。之後再走到的交易在放行後直接通過。
func holdAt(t *testing.T, hook *func()) (reached <-chan struct{}, release func()) {
	t.Helper()
	r := make(chan struct{})
	rel := make(chan struct{})
	var once, freed sync.Once
	*hook = func() {
		once.Do(func() { close(r) })
		<-rel
	}
	releaseFn := func() { freed.Do(func() { close(rel) }) }
	// 斷言失敗時也放行被擋住的交易，否則 schema 清理會等鎖而掛住整包測試
	t.Cleanup(func() { releaseFn(); *hook = nil })
	return r, releaseFn
}

func awaitReached(t *testing.T, reached <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s 未走到同步點", what)
	}
}

func (e *apiTokenPGEnv) unrevoked(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.dbA.Model(&model.APIToken{}).Where("user_id = ? AND revoked_at IS NULL", e.owner).Count(&n).Error)
	return n
}

// TestAPITokenCreateConcurrentSameNameExactlyOnePG 兩個副本同時以同名建立：第一個已通過名稱檢查、
// 尚未寫入時，第二個在帳號層級鎖上等待；第一個提交後第二個以名稱占用被拒，恰一成功。
func TestAPITokenCreateConcurrentSameNameExactlyOnePG(t *testing.T) {
	e := newAPITokenPGEnv(t)
	reached, release := holdAt(t, &apiTokenPreWriteHook)

	first := make(chan error, 1)
	go func() { first <- e.create(e.tokensA, "terraform-apply") }()
	awaitReached(t, reached, "第一個建立")

	second := make(chan error, 1)
	go func() { second <- e.create(e.tokensB, "terraform-apply") }()
	waitAdvisoryWaiter(t, e.dbA)
	if _, done := waitOrTimeout(second, 300*time.Millisecond); done {
		t.Fatal("第二個建立在第一個提交前就完成：名稱檢查沒有被帳號層級鎖序列化")
	}
	release()

	errA, ok := waitOrTimeout(first, 10*time.Second)
	require.True(t, ok, "第一個建立未完成")
	require.NoError(t, errA)
	errB, ok := waitOrTimeout(second, 10*time.Second)
	require.True(t, ok, "第二個建立未完成")
	assert.ErrorIs(t, errB, ErrAPITokenNameConflict)

	var n int64
	require.NoError(t, e.dbA.Model(&model.APIToken{}).Where("user_id = ? AND name = ?", e.owner, "terraform-apply").Count(&n).Error)
	assert.EqualValues(t, 1, n, "恰一成功")
	require.NoError(t, e.dbA.Model(&model.APITokenRole{}).Count(&n).Error)
	assert.EqualValues(t, 1, n, "失敗的一方不留授權角色列")
}

// TestAPITokenDeleteVsConcurrentCreateLeavesNoUnmarkedTokenPG 刪除帳號與建立 token 兩種先後的交錯，
// 結束後該帳號都沒有未標記撤銷的 token。
func TestAPITokenDeleteVsConcurrentCreateLeavesNoUnmarkedTokenPG(t *testing.T) {
	t.Run("建立先通過判定、刪除在鎖上等待", func(t *testing.T) {
		e := newAPITokenPGEnv(t)
		require.NoError(t, e.create(e.tokensA, "existing"))
		reached, release := holdAt(t, &apiTokenPreWriteHook)

		create := make(chan error, 1)
		go func() { create <- e.create(e.tokensA, "racing") }()
		awaitReached(t, reached, "建立")

		del := make(chan error, 1)
		go func() {
			_, err := e.usersB.DeleteWithSummaryBy(e.op(e.root), e.owner)
			del <- err
		}()
		waitAdvisoryWaiter(t, e.dbA)
		if _, done := waitOrTimeout(del, 300*time.Millisecond); done {
			t.Fatal("刪除在建立提交前就完成：兩者沒有被同一把帳號層級鎖序列化")
		}
		release()

		errC, ok := waitOrTimeout(create, 10*time.Second)
		require.True(t, ok)
		require.NoError(t, errC)
		errD, ok := waitOrTimeout(del, 10*time.Second)
		require.True(t, ok)
		require.NoError(t, errD)

		var total int64
		require.NoError(t, e.dbA.Model(&model.APIToken{}).Where("user_id = ?", e.owner).Count(&total).Error)
		assert.EqualValues(t, 2, total)
		assert.Zero(t, e.unrevoked(t), "刪除在建立之後提交，兩把都被標記")
	})

	t.Run("刪除先通過判定、建立在鎖上等待", func(t *testing.T) {
		e := newAPITokenPGEnv(t)
		require.NoError(t, e.create(e.tokensA, "existing"))
		reached, release := holdAt(t, &userCredentialPreWriteHook)

		del := make(chan error, 1)
		go func() {
			_, err := e.usersB.DeleteWithSummaryBy(e.op(e.root), e.owner)
			del <- err
		}()
		awaitReached(t, reached, "刪除")

		create := make(chan error, 1)
		go func() { create <- e.create(e.tokensA, "racing") }()
		waitAdvisoryWaiter(t, e.dbA)
		if _, done := waitOrTimeout(create, 300*time.Millisecond); done {
			t.Fatal("建立在刪除提交前就完成：兩者沒有被同一把帳號層級鎖序列化")
		}
		release()

		errD, ok := waitOrTimeout(del, 10*time.Second)
		require.True(t, ok)
		require.NoError(t, errD)
		errC, ok := waitOrTimeout(create, 10*time.Second)
		require.True(t, ok)
		assert.ErrorIs(t, errC, ErrAPITokenNotEligible, "帳號已刪除，建立在鎖內重判後被拒")

		var total int64
		require.NoError(t, e.dbA.Model(&model.APIToken{}).Where("user_id = ?", e.owner).Count(&total).Error)
		assert.EqualValues(t, 1, total)
		assert.Zero(t, e.unrevoked(t))
	})
}
