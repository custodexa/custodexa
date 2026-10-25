package audit_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 非 PostgreSQL 路徑與錯誤鏈（SQLite）。

// collectSQL 以 GORM callback 收集此 db 發出的全部 SQL。
func collectSQL(t *testing.T, db *gorm.DB) func() []string {
	t.Helper()
	var mu sync.Mutex
	var stmts []string
	rec := func(tx *gorm.DB) {
		mu.Lock()
		stmts = append(stmts, tx.Statement.SQL.String())
		mu.Unlock()
	}
	require.NoError(t, db.Callback().Raw().After("gorm:raw").Register("seq_retry_collect_raw", rec))
	require.NoError(t, db.Callback().Row().After("gorm:row").Register("seq_retry_collect_row", rec))
	require.NoError(t, db.Callback().Create().After("gorm:create").Register("seq_retry_collect_create", rec))
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), stmts...)
	}
}

func hasSavepoint(stmts []string) bool {
	for _, s := range stmts {
		if strings.Contains(strings.ToUpper(s), "SAVEPOINT") {
			return true
		}
	}
	return false
}

func TestPermissionUntracedSeqRetryUnit(t *testing.T) {
	driftRow := `INSERT INTO user_roles (user_id, role_id, source, scope_kind) VALUES (2, 1, 'manual', 'global')`

	t.Run("no_source_noop", func(t *testing.T) {
		db := newPermDB(t)
		audit.SetPermissionSources(nil, nil)
		stmts := collectSQL(t, db)
		wrote, err := audit.RecordUntracedPermissionDrift(context.Background(), db)
		require.NoError(t, err)
		require.False(t, wrote)
		require.False(t, hasSavepoint(stmts()))
		// SQLite 來源已接、尚無鏈頭
		audit.SetPermissionSources(authz.PermissionStateAuthzPart, identity.PermissionStateIdentityPart)
		wrote, err = audit.RecordUntracedPermissionDrift(context.Background(), db)
		require.NoError(t, err)
		require.False(t, wrote)
		require.False(t, hasSavepoint(stmts()))
	})

	t.Run("sqlite_single_attempt", func(t *testing.T) {
		e := newPermEnv(t)
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		require.NoError(t, e.db.Exec(driftRow).Error)
		stmts := collectSQL(t, e.db)
		require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
			wrote, err := audit.RecordUntracedPermissionDrift(context.Background(), tx)
			require.True(t, wrote)
			return err
		}))
		require.False(t, hasSavepoint(stmts()), "SQLite 不開 savepoint")

		// 注入一般 UNIQUE 錯誤：原樣回傳、只嘗試一次
		e2 := newPermEnv(t)
		seedPerm(t, e2.db, false)
		require.NoError(t, e2.svc.EnsureGenesis())
		require.NoError(t, e2.db.Exec(driftRow).Error)
		require.NoError(t, e2.db.Exec(`CREATE UNIQUE INDEX uq_test_version ON permission_state_events (version)`).Error)
		var conflicts, compares int
		restore := audit.SetUntracedSeqHooksForTest(audit.UntracedSeqHooks{
			AfterCompare:  func(int, int64) { compares++ },
			AfterConflict: func(int) { conflicts++ },
		})
		defer restore()
		err := e2.db.Transaction(func(tx *gorm.DB) error {
			_, err := audit.RecordUntracedPermissionDrift(context.Background(), tx)
			return err
		})
		require.Error(t, err)
		require.False(t, errors.Is(err, audit.ErrPermissionEventContention))
		require.True(t, dberr.IsUniqueViolation(err))
		require.Equal(t, 1, compares)
		require.Equal(t, 1, conflicts)
	})

	t.Run("non_tx_handle_single_attempt", func(t *testing.T) {
		e := newPermEnv(t)
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		require.NoError(t, e.db.Exec(driftRow).Error)
		stmts := collectSQL(t, e.db)
		attempts := 0
		restore := audit.SetUntracedSeqHooksForTest(audit.UntracedSeqHooks{AfterCompare: func(int, int64) { attempts++ }})
		defer restore()
		wrote, err := audit.RecordUntracedPermissionDrift(context.Background(), e.db)
		require.NoError(t, err)
		require.True(t, wrote)
		require.Equal(t, 1, attempts)
		require.False(t, hasSavepoint(stmts()))
	})

	t.Run("contention_error_chain", func(t *testing.T) {
		pgErr := &pgconn.PgError{Code: "23505", ConstraintName: seqUniqueIndex, Message: "duplicate key value violates unique constraint"}
		err := fmt.Errorf("%w: %w", audit.ErrPermissionEventContention, fmt.Errorf("寫入權限狀態事件失敗: %w", pgErr))
		require.True(t, errors.Is(err, audit.ErrPermissionEventContention))
		var got *pgconn.PgError
		require.True(t, errors.As(err, &got))
		require.Equal(t, seqUniqueIndex, got.ConstraintName)
		isUnique := dberr.IsUniqueViolation(err)
		require.True(t, isUnique)
		t.Logf("dberr.IsUniqueViolation(err)=%t", isUnique)
	})
}
