package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 名稱與電子郵件已被使用時，建立回對應的衝突哨兵（handler 映射為 409），不是內部錯誤：
//   - 單一請求：建立使用者時電子郵件與既有帳號相同（去除前後空白、不分大小寫）。
//   - 兩個請求同時通過預查：後寫入者撞唯一索引。這裡以寫入前插入同名列重現「預查之後、寫入之前被搶先」，
//     不依賴並行時序；PostgreSQL 的實際並行另見 create_unique_conflict_pg_test.go。

func TestCreateUserEmailAlreadyUsedIsConflict(t *testing.T) {
	users, _, db, _, _ := principalEnv(t)
	_, err := users.Create(&CreateUserRequest{Username: "mail-first", Password: "Password12345", Email: "Taken@Example.test"})
	require.NoError(t, err)
	before := principalCount(t, db, &model.User{})
	for _, email := range []string{"taken@example.test", "TAKEN@EXAMPLE.TEST", "  taken@example.test "} {
		_, err := users.Create(&CreateUserRequest{Username: "mail-second", Password: "Password12345", Email: email})
		assert.ErrorIs(t, err, ErrEmailConflict, "電子郵件 %q 已被使用", email)
	}
	assert.Equal(t, before, principalCount(t, db, &model.User{}), "衝突時不寫入任何帳號")

	// 相鄰行為不變：名稱重複仍是名稱衝突；不同的電子郵件照常建立
	_, err = users.Create(&CreateUserRequest{Username: "mail-first", Password: "Password12345", Email: "other@example.test"})
	assert.ErrorIs(t, err, ErrUsernameExists)
	_, err = users.Create(&CreateUserRequest{Username: "mail-third", Password: "Password12345", Email: "third@example.test"})
	assert.NoError(t, err)
}

// injectBeforeCreate 在 table 的下一次 ORM 建立之前，於同一個交易內先寫入 stmt（只觸發一次）。
func injectBeforeCreate(t *testing.T, db *gorm.DB, name, table, stmt string, args ...any) {
	t.Helper()
	fired := false
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register(name, func(tx *gorm.DB) {
		if fired || tx.Statement.Table != table {
			return
		}
		fired = true
		if err := tx.Session(&gorm.Session{NewDB: true}).Exec(stmt, args...).Error; err != nil {
			tx.AddError(err)
		}
	}))
	t.Cleanup(func() { _ = db.Callback().Create().Remove(name) })
}

func TestCreateUserLosingRaceIsConflict(t *testing.T) {
	now := time.Now()
	t.Run("同名", func(t *testing.T) {
		users, _, db, _, _ := principalEnv(t)
		injectBeforeCreate(t, db, "race-username", "users",
			`INSERT INTO users (username, password, kind, active, created_at, updated_at) VALUES (?, '!', 'human', 1, ?, ?)`,
			"race-user", now, now)
		_, err := users.Create(&CreateUserRequest{Username: "race-user", Password: "Password12345", Email: "race-a@example.test"})
		assert.ErrorIs(t, err, ErrUsernameExists)
	})
	t.Run("同一個電子郵件", func(t *testing.T) {
		users, _, db, _, _ := principalEnv(t)
		injectBeforeCreate(t, db, "race-email", "users",
			`INSERT INTO users (username, password, kind, active, email, created_at, updated_at) VALUES (?, '!', 'human', 1, ?, ?, ?)`,
			"race-other", "race@example.test", now, now)
		_, err := users.Create(&CreateUserRequest{Username: "race-mine", Password: "Password12345", Email: "Race@Example.test"})
		assert.ErrorIs(t, err, ErrEmailConflict)
	})
}

func TestRoleDefinitionLosingRaceIsNameConflict(t *testing.T) {
	ctx := context.Background()
	t.Run("建立", func(t *testing.T) {
		e := newRoleDefEnv(t)
		injectBeforeCreate(t, e.db, "race-role-create", "roles",
			`INSERT INTO roles (name, definition_version, created_at, updated_at) VALUES (?, 1, ?, ?)`, "race-role", time.Now(), time.Now())
		_, err := e.svc.Create(asSession(ctx, e.admin), e.admin, RoleInput{Name: "race-role", Permissions: []string{"asset:view"}})
		assert.ErrorIs(t, err, ErrRoleDefinitionConflict)
		assert.NotErrorIs(t, err, ErrRoleDefinitionVersionConflict)
	})
	t.Run("複製", func(t *testing.T) {
		e := newRoleDefEnv(t)
		src := e.create(t, "race-copy-source", "asset:view")
		injectBeforeCreate(t, e.db, "race-role-copy", "roles",
			`INSERT INTO roles (name, definition_version, created_at, updated_at) VALUES (?, 1, ?, ?)`, "race-copy", time.Now(), time.Now())
		_, err := e.svc.Copy(asSession(ctx, e.admin), e.admin, src.ID, "race-copy", "")
		assert.ErrorIs(t, err, ErrRoleDefinitionConflict)
	})
}

// TestUniqueViolationMapping 只有撞到登錄的那一個唯一索引才轉成衝突哨兵；其他唯一索引與一般錯誤照舊包裝。
func TestUniqueViolationMapping(t *testing.T) {
	pg := func(index string) error {
		return errors.New(`ERROR: duplicate key value violates unique constraint "` + index + `" (SQLSTATE 23505)`)
	}
	lite := func(col string) error { return errors.New("UNIQUE constraint failed: " + col) }
	plain := errors.New("connection reset")

	for _, err := range []error{pg("idx_roles_name"), lite("roles.name")} {
		assert.ErrorIs(t, roleWriteError("建立", err), ErrRoleDefinitionConflict, err.Error())
	}
	for _, err := range []error{pg("uq_roles_builtin_key"), lite("roles.builtin_key"), plain} {
		got := roleWriteError("建立", err)
		assert.NotErrorIs(t, got, ErrRoleDefinitionConflict, err.Error())
		assert.ErrorIs(t, got, err, "其他錯誤保留原錯誤")
	}

	for _, err := range []error{pg("idx_users_username"), lite("users.username")} {
		assert.ErrorIs(t, userCreateError(err), ErrUsernameExists, err.Error())
	}
	for _, err := range []error{pg("idx_users_email"), lite("users.email")} {
		assert.ErrorIs(t, userCreateError(err), ErrEmailConflict, err.Error())
	}
	for _, err := range []error{pg("idx_users_external_subject"), plain} {
		got := userCreateError(err)
		assert.NotErrorIs(t, got, ErrUsernameExists, err.Error())
		assert.NotErrorIs(t, got, ErrEmailConflict, err.Error())
		assert.ErrorIs(t, got, err)
	}
}
