package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/testgate"
)

// 兩個範圍化管理範本的啟動資料步驟：以正式的附證來源注入與啟動步驟入口（runScopedTemplateSeed）驗證。

var seedKeys = []string{model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin}

type seedSnap struct {
	roles, perms, version, events, migrations int64
	templateRows                              string
	bindings                                  [4]int64
}

func seedTake(t *testing.T, db *gorm.DB) seedSnap {
	t.Helper()
	var s seedSnap
	require.NoError(t, db.Unscoped().Model(&model.Role{}).Count(&s.roles).Error)
	require.NoError(t, db.Model(&model.RolePermission{}).Count(&s.perms).Error)
	v, err := authz.CurrentVersion(db)
	require.NoError(t, err)
	s.version = v
	require.NoError(t, db.Model(&model.PermissionStateEvent{}).Count(&s.events).Error)
	if db.Migrator().HasTable("schema_migrations") {
		require.NoError(t, db.Table("schema_migrations").Count(&s.migrations).Error)
	}
	var rows []model.Role
	require.NoError(t, db.Unscoped().Where("builtin_key IN ?", seedKeys).Order("id").Find(&rows).Error)
	var parts []string
	for _, r := range rows {
		parts = append(parts, fmt.Sprintf("%d|%s|%s|%d|%t", r.ID, r.Name, *r.BuiltinKey, r.DefinitionVersion, r.DeletedAt.Valid))
	}
	s.templateRows = strings.Join(parts, ";")
	for i, m := range []any{&model.UserRole{}, &model.UserGroupRole{}, &model.GroupRoleMapping{}, &model.RoleBindingNode{}} {
		require.NoError(t, db.Model(m).Count(&s.bindings[i]).Error)
	}
	return s
}

func seedEventKinds(t *testing.T, db *gorm.DB) map[string]int64 {
	t.Helper()
	var rows []struct {
		Kind string
		N    int64
	}
	require.NoError(t, db.Raw(`SELECT kind, COUNT(*) AS n FROM permission_state_events GROUP BY kind`).Scan(&rows).Error)
	out := map[string]int64{}
	for _, r := range rows {
		out[r.Kind] = r.N
	}
	return out
}

func newSeedSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{}, &model.UserGroupMember{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}, &model.AuthzState{}, &model.AssetGroup{}, &model.GroupRoleMapping{},
		&model.GroupUserGroupMapping{}, &model.ExternalGroup{}, &model.UserGroupMappingRuleSupport{},
		&model.UserChannelObservation{}, &model.PermissionStateEvent{}, &model.RolePermission{}, &model.AgentToken{}))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
	// 升級前的存量：內建超管、一個使用者與一個群組指派，用來證明種入不動任何指派。
	admin := model.Role{Name: "admin"}
	require.NoError(t, db.Create(&admin).Error)
	u := model.User{Username: "seed-u", Active: true}
	require.NoError(t, db.Create(&u).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: u.ID, RoleID: admin.ID, Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	g := model.UserGroup{Name: "seed-g"}
	require.NoError(t, db.Create(&g).Error)
	require.NoError(t, db.Create(&model.UserGroupRole{UserGroupID: g.ID, RoleID: admin.ID, ScopeKind: model.ScopeKindGlobal}).Error)
	return db
}

func wireSeedSources(t *testing.T) {
	t.Helper()
	audit.SetPermissionSources(authz.PermissionStateAuthzPart, identity.PermissionStateIdentityPart)
	t.Cleanup(func() { audit.SetPermissionSources(nil, nil) })
}

func activateChain(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		st, err := audit.ReadPermissionState(context.Background(), tx)
		if err != nil {
			return err
		}
		_, err = audit.EnsurePermissionActivation(context.Background(), tx, st, 1)
		return err
	}))
}

func requireTemplatesSeeded(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, k := range seedKeys {
		var r model.Role
		require.NoError(t, db.Where("builtin_key = ?", k).First(&r).Error, k)
		require.Equal(t, k, r.Name)
		require.GreaterOrEqual(t, r.DefinitionVersion, int64(1))
		var n int64
		require.NoError(t, db.Model(&model.RolePermission{}).Where("role_id = ?", r.ID).Count(&n).Error)
		require.Zero(t, n, "集合在程式中，不寫 role_permissions")
		require.True(t, authz.IsLockedManagementTemplate(k))
	}
	require.Equal(t, authz.ScopedTemplateAssetAdminPermissions(), authz.TemplatePermissions(model.BuiltinAssetAdmin))
	require.Equal(t, authz.ScopedTemplateAuthorizationAdminPermissions(), authz.TemplatePermissions(model.BuiltinAuthzAdmin))
}

func TestScopedTemplateSeed(t *testing.T) {
	ctx := context.Background()

	t.Run("chain_enabled", func(t *testing.T) {
		db := newSeedSQLite(t)
		wireSeedSources(t)
		activateChain(t, db)
		before := seedTake(t, db)
		kinds0 := seedEventKinds(t, db)
		rep, err := runScopedTemplateSeed(ctx, db)
		require.NoError(t, err)
		require.True(t, rep.Applied)
		require.True(t, rep.Attestation)
		after := seedTake(t, db)
		requireTemplatesSeeded(t, db)
		require.Equal(t, before.version+1, after.version, "權限版本恰推進一次")
		require.Equal(t, before.events+1, after.events, "事件鏈恰多一筆")
		kinds1 := seedEventKinds(t, db)
		require.EqualValues(t, 1, kinds1[model.PermEventChange]-kinds0[model.PermEventChange])
		require.Zero(t, kinds1[model.PermEventUntraced])
		require.Equal(t, before.bindings, after.bindings, "不建任何指派")
		require.Equal(t, before.perms, after.perms)
		// 重放為現況：鏈頭事後狀態的摘要等於目前狀態
		var head model.PermissionStateEvent
		require.NoError(t, db.Order("seq DESC").First(&head).Error)
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
			cur, err := audit.ReadPermissionState(ctx, tx)
			require.NoError(t, err)
			chain, err := audit.DecodePermissionState([]byte(head.AfterBody))
			require.NoError(t, err)
			cd, err := cur.Digest()
			require.NoError(t, err)
			hd, err := chain.Digest()
			require.NoError(t, err)
			require.Equal(t, cd, hd, "事件鏈的事後狀態等於現況")
			return nil
		}))
		// 之後的一般權限寫入不產生無來源變動事件
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
			if err := authz.BeginPermissionChange(tx); err != nil {
				return err
			}
			if err := tx.Create(&model.Role{Name: "later-custom", DefinitionVersion: 1}).Error; err != nil {
				return err
			}
			return authz.AdvanceVersion(tx)
		}))
		require.Zero(t, seedEventKinds(t, db)[model.PermEventUntraced])
	})

	t.Run("chain_disabled", func(t *testing.T) {
		db := newSeedSQLite(t)
		wireSeedSources(t)
		before := seedTake(t, db)
		rep, err := runScopedTemplateSeed(ctx, db)
		require.NoError(t, err)
		require.True(t, rep.Applied)
		require.False(t, rep.Attestation)
		after := seedTake(t, db)
		requireTemplatesSeeded(t, db)
		require.Equal(t, before.version+1, after.version)
		require.Equal(t, before.events, after.events, "未啟用附證：事件表列數不變")
		require.Equal(t, before.bindings, after.bindings)
	})

	t.Run("rerun_is_noop", func(t *testing.T) {
		db := newSeedSQLite(t)
		wireSeedSources(t)
		activateChain(t, db)
		_, err := runScopedTemplateSeed(ctx, db)
		require.NoError(t, err)
		snap1 := seedTake(t, db)
		second, err := runScopedTemplateSeed(ctx, db)
		require.NoError(t, err)
		require.False(t, second.Applied)
		require.Equal(t, snap1, seedTake(t, db), "重跑前後兩範本列、權限版本、事件數相同")
		require.Equal(t, []string{}, second.Planned)
		require.ElementsMatch(t, seedKeys, second.Existing)
		// 試跑與正式的報告行逐欄相同（同一輸入）
		fresh := newSeedSQLite(t)
		dry, err := identity.SeedScopedTemplates(ctx, fresh, true)
		require.NoError(t, err)
		real, err := identity.SeedScopedTemplates(ctx, fresh, false)
		require.NoError(t, err)
		require.Equal(t, dry.Line(), real.Line())
	})

	t.Run("event_write_failure", func(t *testing.T) {
		db := newSeedSQLite(t)
		wireSeedSources(t)
		activateChain(t, db)
		before := seedTake(t, db)
		const cb = "fail_seed_perm_event"
		require.NoError(t, db.Callback().Create().Before("gorm:create").Register(cb, func(tx *gorm.DB) {
			if tx.Statement.Schema != nil && tx.Statement.Schema.Table == "permission_state_events" {
				_ = tx.AddError(errors.New("event down"))
			}
		}))
		_, err := runScopedTemplateSeed(ctx, db)
		require.ErrorContains(t, err, "event down")
		require.Equal(t, before, seedTake(t, db), "兩列皆不存在且版本不變")
		require.Empty(t, seedTake(t, db).templateRows)
		require.NoError(t, db.Callback().Create().Remove(cb))
	})

	t.Run("conflict", func(t *testing.T) {
		db := newSeedSQLite(t)
		wireSeedSources(t)
		activateChain(t, db)
		// 預設儲存名已被自訂角色使用
		taken := model.Role{Name: model.BuiltinAssetAdmin, DefinitionVersion: 1}
		require.NoError(t, db.Create(&taken).Error)
		before := seedTake(t, db)
		rep, err := runScopedTemplateSeed(ctx, db)
		require.NoError(t, err, "衝突不阻止啟動")
		require.False(t, rep.Applied)
		require.Equal(t, []string{model.BuiltinAssetAdmin + ":name_in_use"}, rep.Conflicts)
		require.Equal(t, before, seedTake(t, db), "整筆不套用：另一個範本也不種、版本不變")
		var same model.Role
		require.NoError(t, db.First(&same, taken.ID).Error)
		require.Nil(t, same.BuiltinKey)
		// 改名後再跑一次資料步驟即種入
		require.NoError(t, db.Model(&model.Role{}).Where("id = ?", taken.ID).Update("name", "renamed-custom").Error)
		rep, err = runScopedTemplateSeed(ctx, db)
		require.NoError(t, err)
		require.True(t, rep.Applied)
		requireTemplatesSeeded(t, db)

		// 同識別但內容不同（多了權限列）：整筆不套用、該列不改
		db2 := newSeedSQLite(t)
		wireSeedSources(t)
		k := model.BuiltinAuthzAdmin
		odd := model.Role{Name: k, BuiltinKey: &k, DefinitionVersion: 1}
		require.NoError(t, db2.Create(&odd).Error)
		require.NoError(t, db2.Create(&model.RolePermission{RoleID: odd.ID, PermissionKey: "asset:view"}).Error)
		before2 := seedTake(t, db2)
		rep, err = runScopedTemplateSeed(ctx, db2)
		require.NoError(t, err)
		require.Equal(t, []string{model.BuiltinAuthzAdmin + ":different_content"}, rep.Conflicts)
		require.Equal(t, before2, seedTake(t, db2))
	})

	t.Run("PostgreSQL", func(t *testing.T) {
		db := newSeedPG(t, "scoped_template_seed")
		fmt.Println("EVIDENCE dialect=" + db.Dialector.Name())
		require.Equal(t, "postgres", db.Dialector.Name(), "實際 dialector 必須是 postgres")
		old := database.DB
		database.DB = db
		t.Cleanup(func() { database.DB = old })
		require.NoError(t, database.RunMigrations(), "正式 migration 失敗")

		// 只跑結構遷移、未跑資料步驟：CHECK 已接受兩值，沒有任何新角色列
		var n int64
		require.NoError(t, db.Unscoped().Model(&model.Role{}).Where("builtin_key IN ?", seedKeys).Count(&n).Error)
		require.Zero(t, n)
		probe := func(key string) error {
			return db.Transaction(func(tx *gorm.DB) error {
				k := key
				if err := tx.Create(&model.Role{Name: "probe-" + key, BuiltinKey: &k, DefinitionVersion: 1}).Error; err != nil {
					return err
				}
				return errors.New("rollback-probe")
			})
		}
		for _, k := range seedKeys {
			require.EqualError(t, probe(k), "rollback-probe", "CHECK 接受 %s，探測列回滾", k)
		}
		require.Error(t, probe("not_a_template"))
		require.NotContains(t, probe("not_a_template").Error(), "rollback-probe", "未知識別被 CHECK 拒絕")
		wireSeedSources(t)
		activateChain(t, db)
		rep, err := runScopedTemplateSeed(ctx, db)
		require.NoError(t, err)
		require.True(t, rep.Applied)
		requireTemplatesSeeded(t, db)
		snap1 := seedTake(t, db)

		// 同一資料庫再跑一次正式 RunMigrations 與資料步驟：內容不變
		require.NoError(t, database.RunMigrations())
		rep2, err := runScopedTemplateSeed(ctx, db)
		require.NoError(t, err)
		require.False(t, rep2.Applied)
		require.Equal(t, snap1, seedTake(t, db))
		require.Equal(t, int64(len(database.MigrationVersions())), snap1.migrations, "schema_migrations 紀錄數等於登記的遷移數")
	})

	t.Run("chain_rerun", func(t *testing.T) {
		// 固定升級前備份是 PostgreSQL 的 plain dump，只能還原到 PostgreSQL；未設 TEST_PG_DSN 時本子案例不跑（REQUIRE_INTEGRATION=1 時轉失敗）。
		if os.Getenv(testgate.EnvPGDSN) == "" {
			t.Log("本子案例從固定升級前備份（PostgreSQL plain dump）還原起跑，SQLite 無法還原該備份")
		}
		testgate.Value(t, testgate.EnvPGDSN)
		dump := readUpgradeBackup(t)
		db := newRestoredPG(t, "scoped_template_chain_restore", dump)
		fmt.Println("EVIDENCE dialect=" + db.Dialector.Name())
		require.Equal(t, "postgres", db.Dialector.Name())
		old := database.DB
		database.DB = db
		t.Cleanup(func() { database.DB = old })
		wireSeedSources(t)

		marker := func() int64 {
			var c int64
			require.NoError(t, db.Table("schema_migrations").Where("version = ?", database.ApproverScopeKeyMarkerVersion).Count(&c).Error)
			return c
		}
		// 還原後即上一個正式版的狀態：遷移紀錄 35 筆止於日簽核、角色沒有內建識別欄、沒有角色權限表、補鍵標記不存在。
		var preCount int64
		var preLast string
		require.NoError(t, db.Table("schema_migrations").Count(&preCount).Error)
		require.NoError(t, db.Raw("SELECT max(version) FROM schema_migrations").Scan(&preLast).Error)
		preKeyCol := db.Migrator().HasColumn(&model.Role{}, "builtin_key")
		prePermTable := db.Migrator().HasTable("role_permissions")
		preMarker := marker()
		fmt.Printf("EVIDENCE restored schema_migrations=%d last=%s roles.builtin_key=%t role_permissions_table=%t approver_scope_marker=%d\n",
			preCount, preLast, preKeyCol, prePermTable, preMarker)
		require.EqualValues(t, 35, preCount)
		require.Equal(t, "20261012_daily_review_signoff", preLast)
		require.False(t, preKeyCol)
		require.False(t, prePermTable)
		require.Zero(t, preMarker)

		// 第一次正式遷移之後、資料步驟之前，造一個需補申請人型管理鍵的自訂角色（上一個正式版沒有角色權限表，備份不可能帶這種角色）。
		require.NoError(t, database.RunMigrations())
		cand := model.Role{Name: "needs-backfill", DefinitionVersion: 1}
		require.NoError(t, db.Create(&cand).Error)
		require.NoError(t, db.Create(&model.RolePermission{RoleID: cand.ID, PermissionKey: string(authz.PermApproverScopeManage)}).Error)

		// 一次啟動的資料步驟，順序同組裝根：補鍵（試跑、未完成才正式），再種入（runScopedTemplateSeed 自身的試跑與正式兩行日誌）。
		boot := func(phase string, migrate bool) identity.ScopedTemplateSeedReport {
			if migrate {
				require.NoError(t, database.RunMigrations())
			}
			events := identity.NewPermissionChainEventWriter()
			dry, err := identity.BackfillApproverScopeManagementKey(ctx, db, audit.NewTxSink(), events, true)
			require.NoError(t, err)
			updated := 0
			if !dry.AlreadyDone {
				rep, err := identity.BackfillApproverScopeManagementKey(ctx, db, audit.NewTxSink(), events, false)
				require.NoError(t, err)
				updated = rep.Updated
			}
			fmt.Printf("EVIDENCE %s approver_scope_key already_done=%t candidates=%d updated=%d\n", phase, dry.AlreadyDone, dry.Candidates, updated)
			var buf bytes.Buffer
			log.SetOutput(io.MultiWriter(os.Stderr, &buf))
			rep, err := runScopedTemplateSeed(ctx, db)
			log.SetOutput(os.Stderr)
			require.NoError(t, err)
			reported := map[string]string{}
			for _, line := range strings.Split(buf.String(), "\n") {
				at, mode := strings.Index(line, "[ScopedTemplateSeed]"), strings.Index(line, " mode=")
				if at < 0 || mode < at {
					continue
				}
				reported[strings.Fields(line[mode+len(" mode="):])[0]] = line[at:mode]
			}
			fmt.Printf("EVIDENCE %s seed dry-run=%q\n", phase, reported["dry-run"])
			fmt.Printf("EVIDENCE %s seed apply=%q applied=%t version_after=%d\n", phase, reported["apply"], rep.Applied, rep.VersionAfter)
			require.NotEmpty(t, reported["dry-run"])
			require.Equal(t, reported["dry-run"], reported["apply"], "試跑與正式報告逐欄相同")
			require.Equal(t, rep.Line(), reported["apply"])
			return rep
		}
		// 跨步驟的資料面：節點樹、憑證歸屬、批次改密範圍、主機指紋位址、指派範圍、補鍵標記與角色權限、兩範本、權限版本、權限狀態事件、審計列、遷移紀錄。
		facts := func() map[string]string {
			out := map[string]string{}
			for label, q := range map[string]string{
				"schema_migrations":   "SELECT version FROM schema_migrations ORDER BY version",
				"marker":              "SELECT count(*) FROM schema_migrations WHERE version = '" + database.ApproverScopeKeyMarkerVersion + "'",
				"roles":               "SELECT id, name, coalesce(builtin_key,'-'), definition_version, deleted_at IS NOT NULL FROM roles ORDER BY id",
				"role_permissions":    "SELECT role_id, permission_key FROM role_permissions ORDER BY role_id, permission_key",
				"authz_state":         "SELECT id, version FROM authz_state ORDER BY id",
				"permission_events":   "SELECT seq, version, kind, after_digest FROM permission_state_events ORDER BY seq",
				"audit_logs":          "SELECT count(*) FROM audit_logs",
				"user_roles":          "SELECT user_id, role_id, scope_kind FROM user_roles ORDER BY 1, 2, 3",
				"user_group_roles":    "SELECT user_group_id, role_id, scope_kind FROM user_group_roles ORDER BY 1, 2, 3",
				"asset_groups":        "SELECT id, name, coalesce(parent_id::text,'-'), deleted_at IS NOT NULL FROM asset_groups ORDER BY id",
				"credentials":         "SELECT id, coalesce(owner_kind,'NULL') FROM credentials ORDER BY id",
				"change_secret_batch": "SELECT id, shared_credential_owner_kind FROM change_secret_batches ORDER BY id",
				"credential_job_auth": "SELECT count(*) FROM credential_job_authorizations",
				"asset_host_keys":     "SELECT asset_id, host, port FROM asset_host_keys ORDER BY asset_id",
				"approver_scopes":     "SELECT count(*) FROM approver_scopes",
				"channel_observation": "SELECT count(*) FROM user_channel_observations",
			} {
				out[label] = sqlRowsText(t, db, q)
			}
			return out
		}
		eventKinds := func(phase string) {
			on, err := audit.PermissionAttestationEnabled(ctx, db)
			require.NoError(t, err)
			fmt.Printf("EVIDENCE %s permission_state_events=%q kinds=%v attestation=%t\n", phase,
				sqlRowsText(t, db, "SELECT seq, kind FROM permission_state_events ORDER BY seq"), seedEventKinds(t, db), on)
		}
		auditCount := func() int64 {
			var c int64
			require.NoError(t, db.Model(&model.AuditLog{}).Count(&c).Error)
			return c
		}
		permKeys := func() []string {
			var ks []string
			require.NoError(t, db.Model(&model.RolePermission{}).Where("role_id = ?", cand.ID).Order("permission_key").Pluck("permission_key", &ks).Error)
			sort.Strings(ks)
			return ks
		}

		// 第一次啟動（遷移已在上面跑過）：附證鏈尚未啟用。
		rep1 := boot("first", false)
		require.True(t, rep1.Applied)
		eventKinds("first")
		require.EqualValues(t, 1, marker())
		require.Contains(t, permKeys(), string(authz.PermApproverScopeApplicantManage), "補鍵第一次發生")
		requireTemplatesSeeded(t, db)
		// 啟動完成後第一次封章才啟用附證鏈（同 EnsurePermissionActivation 的封章路徑）。
		activateChain(t, db)
		eventKinds("activated")
		s1, f1, m1, a1, k1 := seedTake(t, db), facts(), marker(), auditCount(), permKeys()
		for _, label := range []string{"schema_migrations", "marker", "roles", "role_permissions", "authz_state", "permission_events", "audit_logs", "asset_groups", "credentials", "change_secret_batch", "asset_host_keys", "user_roles"} {
			fmt.Printf("EVIDENCE first %s=%q\n", label, f1[label])
		}

		// 第二次啟動：同一資料庫，不重建、不 reset；正式遷移與資料步驟各再跑一次。
		rep2 := boot("second", true)
		require.False(t, rep2.Applied)
		eventKinds("second")
		s2, f2, m2, a2, k2 := seedTake(t, db), facts(), marker(), auditCount(), permKeys()
		require.Equal(t, s1, s2, "第二次後角色、權限版本、事件、migration 紀錄逐項相同")
		require.Equal(t, f1, f2, "第二次後各步驟的資料逐欄相同")
		require.Equal(t, m1, m2)
		require.Equal(t, a1, a2, "審計列數不變")
		require.Equal(t, k1, k2)
		// 資料步驟單獨重跑不改內容
		_, err := runScopedTemplateSeed(ctx, db)
		require.NoError(t, err)
		require.Equal(t, s2, seedTake(t, db))
		require.Equal(t, f2, facts())
	})
}

func newSeedPG(t *testing.T, schema string) *gorm.DB {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	admin := pwloOpen(t, dsn)
	drop := "DROP SCHEMA IF EXISTS " + schema + " CASCADE"
	require.NoError(t, admin.Exec(drop).Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試 schema 清理失敗（請手動 DROP SCHEMA %s CASCADE）: %v", schema, err)
		}
	})
	return pwloOpen(t, dsn+" search_path="+schema)
}
