package identity

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/testgate"
)

// 帳號生命週期（停用、刪除、啟用）的「持保護角色者限超管」判定與群組新增保護角色的競態。
//
// 判定在目標的使用者憑證鎖內重讀角色；群組角色替換（含純新增）對全體成員取同一把鎖。
// 兩個交錯以同步點固定，各由一個獨立連線池驅動（＝兩個後端副本），只在 postgres 上有意義：
// advisory lock 是跨副本序列化的唯一機制，sqlite 分流沒有對應語義。
//
//	TEST_PG_DSN="host=... user=... password=... dbname=... sslmode=disable" \
//	  REQUIRE_INTEGRATION=1 go test ./internal/modules/identity -run TestPGLifecycleVsGroupProtectedRole

const pgLifecycleRaceSchema = "lifecycle_race_test"

type lifecycleRaceEnv struct {
	dbA, dbB *gorm.DB
	users    *UserService // 副本 A：帳號生命週期
	groups   *UserGroupService
	roles    map[string]uint
	root     uint // 超管
	ida      uint // 非超管的帳號管理者
	target   uint // 群組成員，初始不持保護角色
	group    uint
}

func openPGRaceDB(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Discard, DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("postgres 連線失敗（TEST_PG_DSN 是否正確？）: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func newLifecycleRaceEnv(t *testing.T, targetActive bool) *lifecycleRaceEnv {
	t.Helper()
	base := testgate.Value(t, testgate.EnvPGDSN)
	admin := openPGRaceDB(t, base)
	drop := "DROP SCHEMA IF EXISTS " + pgLifecycleRaceSchema + " CASCADE"
	require.NoError(t, admin.Exec(drop).Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+pgLifecycleRaceSchema).Error)
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", pgLifecycleRaceSchema, err)
		}
	})
	scoped := base + " search_path=" + pgLifecycleRaceSchema
	dbA := openPGRaceDB(t, scoped)
	dbB := openPGRaceDB(t, scoped)
	require.NoError(t, migrateWithAuthz(dbA, &model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{},
		&model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}, &model.RolePermission{},
		&model.ExternalGroup{}, &model.GroupRoleMapping{}, &model.AuditLog{}, &model.AssetGroup{},
		&model.GroupUserGroupMapping{}, &model.UserGroupMappingRuleSupport{}, &model.UserRoleMappingRuleSupport{},
		&model.UserChannelObservation{}, &model.PermissionStateEvent{}, &model.PasswordHistory{},
		&model.RefreshToken{}, &model.UserRoleMapping{}, &model.UserExternalIdentity{}))
	seedAuthzState(t, dbA)
	oldDB := database.DB
	database.DB = dbA
	t.Cleanup(func() { database.DB = oldDB })

	e := &lifecycleRaceEnv{dbA: dbA, dbB: dbB, roles: map[string]uint{}}
	for _, name := range []string{"admin", "user"} {
		r := model.Role{Name: name}
		require.NoError(t, dbA.Create(&r).Error) // BeforeCreate 帶入內建識別
		e.roles[name] = r.ID
	}
	for _, seed := range []struct{ name, key string }{{"identity_admin", model.BuiltinIdentityAdmin}, {"security_admin", model.BuiltinSecurityAdmin}} {
		k := seed.key
		r := model.Role{Name: seed.name, BuiltinKey: &k, DefinitionVersion: 1}
		require.NoError(t, dbA.Create(&r).Error)
		e.roles[seed.name] = r.ID
	}
	mk := func(name string, active bool, roleNames ...string) uint {
		u := model.User{Username: name, Active: true}
		require.NoError(t, dbA.Create(&u).Error)
		// 欄位有 default:true，建列時零值會被預設覆蓋；停用狀態另以更新寫入
		require.NoError(t, dbA.Model(&model.User{}).Where("id = ?", u.ID).Update("active", active).Error)
		for _, rn := range roleNames {
			require.NoError(t, dbA.Create(&model.UserRole{UserID: u.ID, RoleID: e.roles[rn], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		}
		return u.ID
	}
	e.root = mk("root", true, "admin")
	e.ida = mk("ida", true, "identity_admin")
	e.target = mk("member", targetActive, "user")
	g := model.UserGroup{Name: "ops"}
	require.NoError(t, dbA.Create(&g).Error)
	e.group = g.ID
	require.NoError(t, dbA.Create(&model.UserGroupMember{UserGroupID: g.ID, UserID: e.target, Manual: true}).Error)

	ops := NewProtectedAccountOps(audit.NewTxSink(), audit.NewSystemAlertSink(nil))
	e.users = NewUserService(dbA, nil)
	e.users.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	e.users.SetProtectedAccountOps(ops)
	e.users.authzRevoker = noopRevoker{}
	e.groups = NewUserGroupService(dbB, audit.NewTxSink(), noopRevoker{})
	e.groups.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
	return e
}

func (e *lifecycleRaceEnv) op(id uint) Operator {
	return Operator{UserID: id, Username: "op", ClientIP: "127.0.0.1"}
}

func (e *lifecycleRaceEnv) targetUser(t *testing.T) (model.User, bool) {
	t.Helper()
	var u model.User
	err := e.dbA.First(&u, e.target).Error
	if err == gorm.ErrRecordNotFound {
		return u, false
	}
	require.NoError(t, err)
	return u, true
}

// grantProtected 副本 B 經群組角色替換替目標新增系統安全管理員（純新增，不移除任何角色）。
func (e *lifecycleRaceEnv) grantProtected() error {
	_, err := e.groups.ReplaceRoleBindings(e.op(e.root), e.group, GroupRoleBindingsRequest{RoleIDs: []uint{e.roles["security_admin"]}})
	return err
}

type lifecycleOp struct {
	name         string
	targetActive bool
	run          func(e *lifecycleRaceEnv) error
}

func lifecycleOps() []lifecycleOp {
	return []lifecycleOp{
		{"enable", false, func(e *lifecycleRaceEnv) error { return e.users.UpdateStatusBy(e.op(e.ida), e.target, true) }},
		{"disable", true, func(e *lifecycleRaceEnv) error { return e.users.UpdateStatusBy(e.op(e.ida), e.target, false) }},
		{"delete", true, func(e *lifecycleRaceEnv) error {
			_, err := e.users.DeleteWithSummaryBy(e.op(e.ida), e.target)
			return err
		}},
	}
}

// waitOrTimeout 等 done 或逾時；回 true＝已完成。
func waitOrTimeout(done <-chan error, d time.Duration) (error, bool) {
	select {
	case err := <-done:
		return err, true
	case <-time.After(d):
		return nil, false
	}
}

func TestPGLifecycleVsGroupProtectedRole(t *testing.T) {
	denied := apierror.CodeAuthProtectedAccountOperation

	// 交錯一：生命週期已通過判定、尚未寫入；群組此時新增保護角色 → 群組必須在成員鎖上等，
	// 不得先提交。等生命週期提交後群組才提交（序列化順序＝生命週期在前）。
	for _, op := range lifecycleOps() {
		t.Run("gate-passed-then-group-grants/"+op.name, func(t *testing.T) {
			e := newLifecycleRaceEnv(t, op.targetActive)
			reached := make(chan struct{})
			release := make(chan struct{})
			var once, freed sync.Once
			userCredentialPreWriteHook = func() {
				once.Do(func() { close(reached) })
				<-release
			}
			// 斷言失敗時也放行被擋住的交易，否則 schema 清理會等鎖而掛住整包測試
			defer func() { freed.Do(func() { close(release) }); userCredentialPreWriteHook = nil }()

			lifecycle := make(chan error, 1)
			go func() { lifecycle <- op.run(e) }()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				t.Fatal("生命週期操作未走到判定之後的同步點")
			}

			group := make(chan error, 1)
			go func() { group <- e.grantProtected() }()
			if err, finished := waitOrTimeout(group, 500*time.Millisecond); finished {
				t.Fatalf("群組新增保護角色不得在生命週期判定與寫入之間提交（err=%v）", err)
			}
			freed.Do(func() { close(release) })
			err, finished := waitOrTimeout(lifecycle, 5*time.Second)
			require.True(t, finished, "生命週期操作未返回")
			require.NoError(t, err, "判定時目標尚不持保護角色，操作成功")
			err, finished = waitOrTimeout(group, 5*time.Second)
			require.True(t, finished, "群組操作未返回")
			require.NoError(t, err)
			u, alive := e.targetUser(t)
			switch op.name {
			case "enable":
				assert.True(t, u.Active)
			case "disable":
				assert.False(t, u.Active)
			case "delete":
				assert.False(t, alive)
			}
		})
	}

	// 交錯二：群組已取得成員鎖、尚未提交；生命週期此時進來 → 必須在使用者鎖上等，
	// 群組提交後重讀到保護角色而拒絕，帳號狀態不變。
	for _, op := range lifecycleOps() {
		t.Run("group-commits-first-then-lifecycle-rejects/"+op.name, func(t *testing.T) {
			e := newLifecycleRaceEnv(t, op.targetActive)
			reached := make(chan struct{})
			release := make(chan struct{})
			var once, freed sync.Once
			groupRoleBindingsPreWriteHook = func() {
				once.Do(func() { close(reached) })
				<-release
			}
			defer func() { freed.Do(func() { close(release) }); groupRoleBindingsPreWriteHook = nil }()

			group := make(chan error, 1)
			go func() { group <- e.grantProtected() }()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				t.Fatal("群組操作未走到成員鎖之後的同步點")
			}

			lifecycle := make(chan error, 1)
			go func() { lifecycle <- op.run(e) }()
			if err, finished := waitOrTimeout(lifecycle, 500*time.Millisecond); finished {
				t.Fatalf("生命週期操作不得在群組持有成員鎖期間完成（err=%v）", err)
			}
			freed.Do(func() { close(release) })
			err, finished := waitOrTimeout(group, 5*time.Second)
			require.True(t, finished, "群組操作未返回")
			require.NoError(t, err)
			err, finished = waitOrTimeout(lifecycle, 5*time.Second)
			require.True(t, finished, "生命週期操作未返回")
			assertCode(t, err, denied)
			u, alive := e.targetUser(t)
			require.True(t, alive, "拒絕時帳號仍在")
			assert.Equal(t, op.targetActive, u.Active, "拒絕時啟用狀態不變")
		})
	}
}
