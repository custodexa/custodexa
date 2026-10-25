package audit_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 首次啟用的 PG 整合驗證（TEST_PG_DSN gated；REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
//
// sqlite 單連線已序列化，量不到兩件事：首次啟用與同時進行的合法權限寫入如何交錯
// （REPEATABLE READ 下對快照後被更新的列取鎖回 40001），以及讀權限狀態的 SQL 錯誤使
// 交易進入 aborted 狀態後能否回到 savepoint 繼續封章。兩者只在 PG 上有意義。
//
// 跑法（compose 內，拋棄式 postgres）：
//
//	TEST_PG_DSN="host=<pg> user=postgres password=postgres dbname=postgres port=5432 sslmode=disable" \
//	REQUIRE_INTEGRATION=1 go test ./internal/modules/audit -run 'Postgres' -count=1 -v

func pgSchemaName(prefix string) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}

// newPermEnvPG 與 newPermEnv 同形的 PG 環境（獨立 schema、多連線）。回傳 env 與 schema 名、管理連線。
func newPermEnvPG(t *testing.T) (*permEnv, string, *gorm.DB, string) {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	schema := pgSchemaName("perm_activation")
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema+" application_name=seq_"+schema), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	require.NoError(t, db.AutoMigrate(
		&model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{}, &model.UserGroupMember{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}, &model.AuthzState{}, &model.AssetGroup{},
		&model.GroupRoleMapping{}, &model.GroupUserGroupMapping{}, &model.ExternalGroup{},
		&model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.PermissionStateEvent{},
		&model.RolePermission{}, &model.AuditCheckpoint{}, &model.AuditCheckpointTrim{},
		&model.AuditLog{}, &model.IntegrityBaseline{}, &model.AgentToolCall{}, &model.AgentToken{}))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
	require.NoError(t, db.Create(&model.IntegrityBaseline{ID: 1, BaselineAt: time.Now().UTC(), MaxLogID: 0}).Error)
	audit.SetPermissionSources(authz.PermissionStateAuthzPart, identity.PermissionStateIdentityPart)
	t.Cleanup(func() { audit.SetPermissionSources(nil, nil) })
	audit.SetPermissionActivationLock(authz.LockStateForPermissionActivation)
	t.Cleanup(func() { audit.SetPermissionActivationLock(nil) })
	t.Cleanup(audit.UsePermissionEventTestKey([]byte("permission-event-test-key")))
	t.Cleanup(audit.DrainPendingPermissionStampsForTest)
	audit.SetUserRolesSource(identity.SnapshotUserRolePairs)
	audit.SetPrincipalSource(identity.SnapshotPrincipalStates)
	audit.SetAgentTokenSource(identity.SnapshotAgentTokenStates)
	signer := newPermSigner(t)
	return &permEnv{db: db, signer: signer, svc: audit.NewCheckpointService(db, signer, nil, nil)}, schema, admin, dsn
}

// pgEventSeqsContiguous 事件鏈 seq 自 1 起連續。
func pgEventSeqsContiguous(t *testing.T, db *gorm.DB) []model.PermissionStateEvent {
	t.Helper()
	var evs []model.PermissionStateEvent
	require.NoError(t, db.Order("seq").Find(&evs).Error)
	for i := range evs {
		require.EqualValues(t, i+1, evs[i].Seq, "事件鏈 seq 連續")
	}
	return evs
}

// legalWrite 管理者改使用者狀態（READ COMMITTED，經 AdvanceVersion）。
func legalWrite(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error; err != nil {
			return err
		}
		return authz.AdvanceVersion(tx)
	})
}

func assertActivatedMatch(t *testing.T, e *permEnv) {
	t.Helper()
	var g model.AuditCheckpoint
	require.NoError(t, e.db.Order("seq DESC").First(&g).Error)
	require.NotNil(t, g.PermOrigin)
	require.True(t, isTrue(g.PermOrigin), "起點")
	rec, fs := permRec(e)
	require.Equal(t, "match", rec.ReconcilePermission(context.Background()).State)
	require.Empty(t, fs.permReports(), "未結案單數 0")
	var accepts int64
	require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventAccept).Count(&accepts).Error)
	require.Zero(t, accepts, "不需人工接受")
}

// 首次啟用與合法權限寫入交錯的三種順序皆自動相符。
func TestPermissionActivationInterleavingPostgres(t *testing.T) {
	t.Run("W 先提交：起點即 W 寫完的狀態", func(t *testing.T) {
		e, _, _, _ := newPermEnvPG(t)
		seedPerm(t, e.db, false)
		require.NoError(t, legalWrite(e.db))
		require.NoError(t, e.svc.EnsureGenesis())
		assertActivatedMatch(t, e)
		require.Len(t, pgEventSeqsContiguous(t, e.db), 1)
	})

	t.Run("W 在 S 快照之後、列鎖之前提交：S 收 40001 讓位重試，無殘留且相符", func(t *testing.T) {
		e, _, _, _ := newPermEnvPG(t)
		seedPerm(t, e.db, false)
		var once sync.Once
		calls := 0
		audit.SetSealActivationBarrierForTest(e.svc, func() {
			calls++
			once.Do(func() { require.NoError(t, legalWrite(e.db), "W 不受影響") })
		})
		require.NoError(t, e.svc.EnsureGenesis())
		require.Equal(t, 2, calls, "第一次嘗試讓位、立即重試一次")
		assertActivatedMatch(t, e)
		evs := pgEventSeqsContiguous(t, e.db)
		require.Len(t, evs, 1, "只有一筆啟用事件（第一次嘗試的啟用已回滾）")
		var cps int64
		require.NoError(t, e.db.Model(&model.AuditCheckpoint{}).Count(&cps).Error)
		require.EqualValues(t, 1, cps)
	})

	t.Run("W 在 S 取得列鎖之後才到 AdvanceVersion：W 等待，S 提交後 W 寫 seq 2 變更事件，相符", func(t *testing.T) {
		e, _, admin, _ := newPermEnvPG(t)
		seedPerm(t, e.db, false)
		done := make(chan error, 1)
		audit.SetSealAfterActivationLockForTest(e.svc, func() {
			go func() { done <- legalWrite(e.db) }()
			// 等 W 真的卡在 authz_state 的列鎖上，才讓 S 繼續
			deadline := time.Now().Add(10 * time.Second)
			for {
				var n int64
				require.NoError(t, admin.Raw(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%UPDATE authz_state%'`).Scan(&n).Error)
				if n > 0 {
					return
				}
				require.True(t, time.Now().Before(deadline), "W 未在列鎖上等待")
				time.Sleep(20 * time.Millisecond)
			}
		})
		require.NoError(t, e.svc.EnsureGenesis())
		require.NoError(t, <-done)
		assertActivatedMatch(t, e)
		evs := pgEventSeqsContiguous(t, e.db)
		require.Len(t, evs, 2)
		require.Equal(t, model.PermEventActivate, evs[0].Kind)
		require.Equal(t, model.PermEventChange, evs[1].Kind, "W 以啟用事件為鏈頭寫下自己的變更事件")
		require.Equal(t, evs[0].Digest, evs[1].PrevDigest)
	})

	t.Run("已啟用環境封章不取列鎖，並行的合法寫入不等待", func(t *testing.T) {
		e, _, _, _ := newPermEnvPG(t)
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		var mu sync.Mutex
		var forUpdate []string
		name := "test:capture-for-update"
		capture := func(d *gorm.DB) {
			if sql := d.Statement.SQL.String(); strings.Contains(sql, "FOR UPDATE") {
				mu.Lock()
				forUpdate = append(forUpdate, sql)
				mu.Unlock()
			}
		}
		require.NoError(t, e.db.Callback().Row().After("gorm:row").Register(name, capture))
		require.NoError(t, e.db.Callback().Query().After("gorm:query").Register(name, capture))
		t.Cleanup(func() { _ = e.db.Callback().Row().Remove(name); _ = e.db.Callback().Query().Remove(name) })
		audit.SetSealAfterActivationLockForTest(e.svc, func() { t.Error("已啟用時不應走到啟用路徑") })
		var wg sync.WaitGroup
		wg.Add(1)
		var werr error
		go func() { defer wg.Done(); werr = legalWrite(e.db) }()
		_, err := e.svc.SealNow()
		require.NoError(t, err)
		wg.Wait()
		require.NoError(t, werr)
		require.Empty(t, forUpdate, "已啟用時封章不取 authz_state 列鎖")
		rec, _ := permRec(e)
		require.Equal(t, "match", rec.ReconcilePermission(context.Background()).State)
	})
}

// 交界鎖未注入：PG 上首次啟用 fail-close，不封章、不寫事件，不在無鎖下寫鏈起點。
func TestPermissionActivationLockUnsetPostgres(t *testing.T) {
	e, _, _, _ := newPermEnvPG(t)
	seedPerm(t, e.db, false)
	audit.SetPermissionActivationLock(nil)
	err := e.svc.EnsureGenesis()
	require.ErrorIs(t, err, audit.ErrPermissionActivationLockUnset)
	var evs, cps int64
	require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Count(&evs).Error)
	require.NoError(t, e.db.Model(&model.AuditCheckpoint{}).Count(&cps).Error)
	require.Zero(t, evs, "未取鎖不寫啟用事件")
	require.Zero(t, cps, "未取鎖不封章")
}

// clean() 成立時讀權限狀態收到伺服器端錯誤（權限不足），交易 aborted 後回到 savepoint，
// 封出 perm 為 null 的第四版點並留痕；恢復權限後下一輪為起點且相符。回到 savepoint 本身失敗時
// 整筆失敗、無檢查點、無啟用事件。
func TestPermissionActivationReadErrorPostgres(t *testing.T) {
	limited := func(t *testing.T) (*permEnv, *gorm.DB, *permEnv) {
		e, schema, admin, dsn := newPermEnvPG(t)
		seedPerm(t, e.db, false)
		role := pgSchemaName("perm_reader")
		for _, stmt := range []string{
			"CREATE ROLE " + role + " LOGIN PASSWORD 'reader-pass'",
			"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
			"GRANT ALL ON ALL TABLES IN SCHEMA " + schema + " TO " + role,
			"GRANT ALL ON ALL SEQUENCES IN SCHEMA " + schema + " TO " + role,
			"REVOKE SELECT ON " + schema + ".role_permissions FROM " + role,
		} {
			require.NoError(t, admin.Exec(stmt).Error, stmt)
		}
		t.Cleanup(func() {
			_ = admin.Exec("DROP OWNED BY " + role)
			_ = admin.Exec("DROP ROLE IF EXISTS " + role)
		})
		ldsn := dsn
		for _, kv := range strings.Fields(dsn) {
			if strings.HasPrefix(kv, "user=") || strings.HasPrefix(kv, "password=") {
				ldsn = strings.Replace(ldsn, kv, "", 1)
			}
		}
		ldb, err := gorm.Open(postgres.Open(ldsn+" user="+role+" password=reader-pass search_path="+schema), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		t.Cleanup(func() {
			if s, err := ldb.DB(); err == nil {
				_ = s.Close()
			}
		})
		le := &permEnv{db: ldb, signer: e.signer, svc: audit.NewCheckpointService(ldb, e.signer, nil, nil)}
		return le, admin, e
	}

	t.Run("讀取遭拒：封出 null 點、提交成功、留痕；恢復後起點且相符、結案", func(t *testing.T) {
		le, admin, e := limited(t)
		rec, fs := permRec(le)
		le.svc.SetRoleStateReconciler(rec)
		require.NoError(t, le.svc.EnsureGenesis(), "aborted 交易回到 savepoint 後照常封章")
		var g model.AuditCheckpoint
		require.NoError(t, e.db.First(&g, "seq = 1").Error)
		require.Equal(t, model.AggSchemeV4, g.AggScheme)
		require.Nil(t, g.PermStateSnapshot)
		require.Nil(t, g.PermOrigin)
		var evs int64
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Count(&evs).Error)
		require.Zero(t, evs, "未寫啟用事件")
		require.NotEmpty(t, fs.permReports(), "讀取失敗留痕")
		// 恢復讀取權限
		var role string
		require.NoError(t, le.db.Raw("SELECT current_user").Scan(&role).Error)
		var schema string
		require.NoError(t, le.db.Raw("SELECT current_schema()").Scan(&schema).Error)
		require.NoError(t, admin.Exec("GRANT SELECT ON "+schema+".role_permissions TO "+role).Error)
		cp, err := le.svc.SealNow()
		require.NoError(t, err)
		require.True(t, isTrue(cp.PermOrigin), "null 點不是痕跡：下一輪是起點")
		require.Equal(t, "match", rec.ReconcilePermission(context.Background()).State)
		require.Equal(t, 1, fs.permResolved(), "恢復後結案")
	})

	t.Run("回到 savepoint 失敗：整筆失敗、無檢查點、無啟用事件", func(t *testing.T) {
		le, _, e := limited(t)
		name := "test:fail-rollback-to"
		require.NoError(t, le.db.Callback().Raw().Before("gorm:raw").Register(name, func(d *gorm.DB) {
			if strings.Contains(d.Statement.SQL.String(), "ROLLBACK TO SAVEPOINT") {
				_ = d.AddError(errors.New("injected connection loss"))
			}
		}))
		t.Cleanup(func() { _ = le.db.Callback().Raw().Remove(name) })
		require.Error(t, le.svc.EnsureGenesis())
		var n int64
		require.NoError(t, e.db.Model(&model.AuditCheckpoint{}).Count(&n).Error)
		require.Zero(t, n)
		require.NoError(t, e.db.Model(&model.PermissionStateEvent{}).Count(&n).Error)
		require.Zero(t, n)
	})
}

// 量測（PG）：千點第三版鏈升級後第一次封章（含整鏈逐點驗章）的牆鐘，以及同時間帳本 INSERT 的等待。
func TestPermissionActivationCostPostgres(t *testing.T) {
	e, _, admin, _ := newPermEnvPG(t)
	seedPerm(t, e.db, false)
	audit.SetPermissionSources(nil, nil)
	audit.SetSealSchemeForTest(e.svc, model.AggSchemeV3)
	require.NoError(t, e.svc.EnsureGenesis())
	for i := 1; i < 1000; i++ {
		_, err := e.svc.SealNow()
		require.NoError(t, err)
	}
	audit.SetSealSchemeForTest(e.svc, "")
	newPermDBWire(t)
	// 帳本 INSERT 在封章交易取得帳本表 SHARE 鎖的那一刻發起（輪詢 pg_locks），量它等到封章提交的時間
	done := make(chan time.Duration, 1)
	go func() {
		for i := 0; i < 2000; i++ {
			var n int64
			_ = admin.Raw(`SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation WHERE c.relname = 'agent_tool_calls' AND l.mode = 'ShareLock' AND l.granted`).Scan(&n).Error
			if n > 0 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		t0 := time.Now()
		ierr := e.db.Session(&gorm.Session{SkipHooks: true}).Create(&model.AgentToolCall{Seq: 1, UserID: 1, AgentTokenID: 1, OwnerUserID: 1, Tool: "list_assets", ArgsRedacted: "{}", Decision: model.ToolCallPending, CreatedAt: time.Now().UTC()}).Error
		if ierr != nil {
			t.Errorf("帳本 INSERT 失敗: %v", ierr)
		}
		done <- time.Since(t0)
	}()
	start := time.Now()
	cp, err := e.svc.SealNow()
	elapsed := time.Since(start)
	require.NoError(t, err)
	require.True(t, isTrue(cp.PermOrigin))
	insertWait := <-done
	t.Logf("MEASURE pg chain=1000 升級後首次封章（含整鏈逐點驗章）=%v；封章交易持帳本表鎖時發起的帳本 INSERT 等待=%v", elapsed, insertWait)
}
