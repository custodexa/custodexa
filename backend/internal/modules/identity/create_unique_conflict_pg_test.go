package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
)

// 同名（或同一個電子郵件）的並行建立與並行改名，在 PostgreSQL 上恰一筆成功，其餘回衝突哨兵，沒有其他錯誤
// （未設 TEST_PG_DSN 即 skip，REQUIRE_INTEGRATION=1 時 skip 轉 fail）。兩個連線池代表兩個後端副本。
//
//	TEST_PG_DSN="host=... user=... password=... dbname=... sslmode=disable" \
//	  REQUIRE_INTEGRATION=1 go test ./internal/modules/identity -run 'ConcurrentUniqueConflictPG'

const pgUniqueConflictRacers = 8

// pgUniqueConflictSchema 建立獨立 schema，回傳兩個指向它的連線池。
func pgUniqueConflictSchema(t *testing.T, schema string) (dbA, dbB *gorm.DB) {
	t.Helper()
	base := testgate.Value(t, testgate.EnvPGDSN)
	admin := openPGRaceDB(t, base)
	drop := "DROP SCHEMA IF EXISTS " + schema + " CASCADE"
	require.NoError(t, admin.Exec(drop).Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", schema, err)
		}
	})
	scoped := base + " search_path=" + schema
	return openPGRaceDB(t, scoped), openPGRaceDB(t, scoped)
}

// raceAll 同時起跑 n 個 fn，回傳成功數；錯誤交給 classify，classify 回 false 即為非預期錯誤。
func raceAll(t *testing.T, n int, fn func(i int) error, classify func(error) bool) (ok, conflicts int) {
	t.Helper()
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = fn(i)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		switch {
		case err == nil:
			ok++
		case classify(err):
			conflicts++
		default:
			t.Errorf("第 %d 個請求回非預期錯誤（呼叫端會得到內部錯誤）: %v", i, err)
		}
	}
	return ok, conflicts
}

func TestUserCreateConcurrentUniqueConflictPG(t *testing.T) {
	dbA, dbB := pgUniqueConflictSchema(t, "user_unique_conflict_test")
	require.NoError(t, migrateWithAuthz(dbA, &model.User{}, &model.Role{}, &model.UserRole{}, &model.PasswordHistory{},
		&model.AuditLog{}, &model.PermissionStateEvent{}, &model.UserGroup{}, &model.UserGroupMember{}, &model.UserGroupRole{},
		&model.RoleBindingNode{}))
	seedAuthzState(t, dbA)
	svcs := []*UserService{NewUserService(dbA, nil), NewUserService(dbB, nil)}

	t.Run("同名", func(t *testing.T) {
		ok, dup := raceAll(t, pgUniqueConflictRacers, func(i int) error {
			_, err := svcs[i%2].Create(&CreateUserRequest{Username: "pg-race-user", Password: "Password12345",
				Email: fmt.Sprintf("pg-race-%d@example.test", i)})
			return err
		}, func(err error) bool { return errors.Is(err, ErrUsernameExists) })
		require.Equal(t, 1, ok, "恰一筆成功")
		require.Equal(t, pgUniqueConflictRacers-1, dup, "其餘都是名稱衝突")
	})
	t.Run("同一個電子郵件（大小寫不同）", func(t *testing.T) {
		ok, dup := raceAll(t, pgUniqueConflictRacers, func(i int) error {
			email := "Pg-Race-Mail@Example.test"
			if i%2 == 1 {
				email = strings.ToLower(email)
			}
			_, err := svcs[i%2].Create(&CreateUserRequest{Username: fmt.Sprintf("pg-mail-%d", i), Password: "Password12345", Email: email})
			return err
		}, func(err error) bool { return errors.Is(err, ErrEmailConflict) })
		require.Equal(t, 1, ok, "恰一筆成功")
		require.Equal(t, pgUniqueConflictRacers-1, dup, "其餘都是電子郵件衝突")
	})
}

func TestRoleDefinitionConcurrentUniqueConflictPG(t *testing.T) {
	dbA, _ := pgUniqueConflictSchema(t, "role_unique_conflict_test")
	e := newRoleDefEnvOn(t, dbA)
	ctx := asSession(context.Background(), e.admin)
	isNameConflict := func(err error) bool {
		return errors.Is(err, ErrRoleDefinitionConflict) && !errors.Is(err, ErrRoleDefinitionVersionConflict)
	}

	t.Run("同名建立", func(t *testing.T) {
		ok, dup := raceAll(t, pgUniqueConflictRacers, func(i int) error {
			_, err := e.svc.Create(ctx, e.admin, RoleInput{Name: "pg-race-role", Permissions: []string{"asset:view"}})
			return err
		}, isNameConflict)
		require.Equal(t, 1, ok, "恰一筆成功")
		require.Equal(t, pgUniqueConflictRacers-1, dup, "其餘都是名稱衝突")
	})
	t.Run("不同角色同時改成同一個名稱", func(t *testing.T) {
		roles := make([]*RoleDefinition, pgUniqueConflictRacers)
		for i := range roles {
			roles[i] = e.create(t, fmt.Sprintf("pg-rename-%d-%d", i, time.Now().UnixNano()), "asset:view")
		}
		ok, dup := raceAll(t, pgUniqueConflictRacers, func(i int) error {
			_, err := e.svc.Update(ctx, e.admin, roles[i].ID, roles[i].DefinitionVersion,
				RoleInput{Name: "pg-renamed", Permissions: []string{"asset:view"}})
			return err
		}, isNameConflict)
		require.Equal(t, 1, ok, "恰一筆成功")
		require.Equal(t, pgUniqueConflictRacers-1, dup, "其餘都是名稱衝突")
	})
}
