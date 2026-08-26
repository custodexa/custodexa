package database

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
)

// baseline 的執行語義（PG-gated：未設 TEST_PG_DSN 即 skip；REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
//
// 跑法（compose 內）：
//
//	docker compose exec -T backend sh -c \
//	  'TEST_PG_DSN="host=postgres user=postgres password=postgres dbname=postgres port=5432 sslmode=disable" \
//	   REQUIRE_INTEGRATION=1 go test ./internal/database -run Baseline -count=1 -v'

// schemaObjectCounts 一個 pg schema 的物件計數快照（fail-close 的「零寫入」斷言用）。
type schemaObjectCounts struct {
	Tables   int64
	Indexes  int64
	Checks   int64
	Versions int64
}

func countSchemaObjects(t *testing.T, db *gorm.DB, pgSchema string) schemaObjectCounts {
	t.Helper()
	var c schemaObjectCounts
	scan := func(sql string, dst *int64) {
		if err := db.Raw(sql, pgSchema).Scan(dst).Error; err != nil {
			t.Fatalf("計數失敗（%s）: %v", sql, err)
		}
	}
	scan(`SELECT count(*) FROM information_schema.tables
	      WHERE table_schema = ? AND table_type = 'BASE TABLE'`, &c.Tables)
	scan(`SELECT count(*) FROM pg_indexes WHERE schemaname = ?`, &c.Indexes)
	scan(`SELECT count(*) FROM pg_constraint con
	      JOIN pg_namespace n ON n.oid = con.connamespace
	      WHERE n.nspname = ? AND con.contype = 'c'`, &c.Checks)
	// schema_migrations 可能還不存在（fail-close 的前置狀態除外，此處容錯）
	var exists int64
	scan(`SELECT count(*) FROM information_schema.tables
	      WHERE table_schema = ? AND table_name = 'schema_migrations'`, &exists)
	if exists > 0 {
		if err := db.Raw(`SELECT count(*) FROM schema_migrations`).Scan(&c.Versions).Error; err != nil {
			t.Fatalf("讀取 schema_migrations 列數失敗: %v", err)
		}
	}
	return c
}

// withGlobalDB 暫時把套件全域 DB 指向測試連線（RunMigrations 走全域）。
func withGlobalDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	prev := DB
	DB = db
	t.Cleanup(func() { DB = prev })
}

// legacyVersionsSample 壓縮前那 49 條 migration 的版本值（用於 fail-close 的前置狀態）。
//
// 逐字列出而非「隨便塞幾個字串」：fail-close 要擋的正是這一組實際存在於既有部署的值，
// 訊息裡列出的也是它們。
var legacyVersionsSample = []string{
	"v6.1-rdp-ssh-working", "v7.5", "v7.6", "v7.7", "v7.8", "v7.9", "v7.10",
	"20260612_add_alert_rule_action", "20260613_add_k8s_fields", "20260613_add_session_end_reason",
	"20260613_add_asset_connectivity", "20260619_add_k8s_tls_fields", "20260619_add_session_k8s_snapshot",
	"20260619_add_session_command_k8s", "20260620_alert_rules_protocols", "20260620_add_asset_dbname",
	"20260620_add_asset_db_tls", "20260702_channel_type_slack", "20260702_auth_hardening_r1",
	"20260702_auth_hardening_r2_totp_step", "20260703_auth_hardening_r3_inactivity_exempt",
	"20260703_audit_workflows_alert_review", "20260703_vnc_sftp_sidecar", "20260715_key_mgmt_envelope",
	"20260715_integrity_baseline_max_log_id", "20260717_user_group_authorization",
	"20260718_access_policy_approval", "20260719_break_glass_revocation", "20260720_asset_level_access_policy",
	"20260721_asset_node_tree", "20260722_normalize_asset_tags", "20260723_approval_routing_quorum",
	"20260724_approver_group_side", "20260724_profile_display_name", "20260724_kek_switch_state_guard",
	"20260801_kek_soft_retire", "20260802_kek_id_widen_255", "20260801_failure_event_single_open",
	"20260801_i18n_unification_schema", "20260802_asset_accounts", "20260802_asset_accounts_catchup",
	"20260802_session_account_snapshot", "20260802_authorization_account_scope",
	"20260803_oidc_identity_and_auth_context", "20260804_ldap_directories",
	"20260805_break_glass_overdue_renotify", "20260812_auditor_workbench", "20260813_mssql_web_cli",
	"20260814_audit_pivot_index_convergence",
}

// TestBaselineOnEmptySchemaPostgres 全新安裝的產物與冪等。
func TestBaselineOnEmptySchemaPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "baseline_empty_test"
	db := freshSchema(t, dsn, pgSchema)
	withGlobalDB(t, db)

	if err := RunMigrations(); err != nil {
		t.Fatalf("空 schema 跑 baseline 失敗: %v", err)
	}

	got := countSchemaObjects(t, db, pgSchema)
	// 空庫實測基準（對照組 manifest 第 5 節）：47 表／162 索引／13 CHECK
	// （manifest 寫 10 是漏數了 command_alerts 的兩條與 session_commands 的一條，
	// 具名清單見 baseline_parity_pg_test.go）；baseline 另加 alert_rules.name 唯一索引 → 163。
	// 全新安裝＝baseline＋增量：
	// audit_export_jobs 增 1 表、4 索引（pkey＋兩具名＋pending/running 部分唯一）。
	// source-ip-forensics 再增 1 表（user_source_ips：pkey＋1 具名）與 sessions 的 1 條
	// 索引；command_alerts_kind_check 重建（名稱不變、數量不變）。
	if got.Tables != 49 {
		t.Errorf("表數 = %d, want 49（47 ＋ audit_export_jobs ＋ user_source_ips）", got.Tables)
	}
	if got.Indexes != 170 {
		t.Errorf("索引數 = %d, want 170（舊鏈 162 ＋ uniq_alert_rules_name ＋ audit_export_jobs 的 4 條 ＋ source_ip_forensics 的 3 條）", got.Indexes)
	}
	if got.Checks != 13 {
		t.Errorf("CHECK 約束數 = %d, want 13", got.Checks)
	}

	// schema_migrations 恰好為「baseline＋全部增量」，且**不含** LDAP 執行期 marker。
	// 預插 marker 會讓 LDAP env seed 永遠不執行——表建好了、設定沒進去、無錯誤可查。
	var versions []string
	if err := db.Raw(`SELECT version FROM schema_migrations ORDER BY version`).Scan(&versions).Error; err != nil {
		t.Fatalf("讀取 schema_migrations 失敗: %v", err)
	}
	wantVersions := make([]string, 0, len(migrations))
	for _, m := range migrations {
		wantVersions = append(wantVersions, m.Version)
	}
	sort.Strings(wantVersions)
	if strings.Join(versions, ",") != strings.Join(wantVersions, ",") {
		t.Fatalf("schema_migrations = %v, want 恰好 %v。"+
			"若含 %s，LDAP env seed 會被誤判為已完成而永不執行",
			versions, wantVersions, LDAPSeedMarkerVersion)
	}

	// 12 條種子的 protocols 分佈＝三段疊加的終態
	assertBuiltinAlertRules(t, db)

	// 種子路徑重跑仍是 12 列（唯一索引＋ON CONFLICT DO NOTHING）
	if err := seedBuiltinAlertRules(db); err != nil {
		t.Fatalf("重跑種子失敗（冪等性不成立）: %v", err)
	}
	assertBuiltinAlertRules(t, db)

	// RunMigrations 重跑：baseline 已在已套用集合內 → 整條略過
	if err := RunMigrations(); err != nil {
		t.Fatalf("第二次 RunMigrations 失敗: %v", err)
	}
	assertBuiltinAlertRules(t, db)
	after := countSchemaObjects(t, db, pgSchema)
	if after != got {
		t.Fatalf("第二次 RunMigrations 改變了 schema：%+v → %+v", got, after)
	}
}

// assertBuiltinAlertRules 12 條種子的逐條核對。
//
// **protocols 分佈是本檔最重要的一條斷言**：它是唯一能抓到「三段疊加只做了前兩段」
// 的檢查。schema 等價比對（pg_dump --schema-only）完全看不到種子資料，
// 而漏掉第三段（20260813 把 3 條 SQL 規則擴為含 mssql）的後果是
// MSSQL 會話的危險 SQL 無規則覆蓋，且沒有任何其他測試會紅。
func assertBuiltinAlertRules(t *testing.T, db *gorm.DB) {
	t.Helper()
	var total int64
	if err := db.Raw(`SELECT count(*) FROM alert_rules`).Scan(&total).Error; err != nil {
		t.Fatalf("讀取 alert_rules 失敗: %v", err)
	}
	if total != 12 {
		t.Fatalf("alert_rules = %d 列, want 12", total)
	}

	type row struct {
		Name      string
		Pattern   string
		Severity  string
		Action    string
		Enabled   bool
		Protocols string
	}
	var rows []row
	if err := db.Raw(`SELECT name, pattern, severity, action, enabled, protocols
		FROM alert_rules ORDER BY name`).Scan(&rows).Error; err != nil {
		t.Fatalf("讀取 alert_rules 明細失敗: %v", err)
	}
	byName := map[string]row{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	dist := map[string]int{}
	for _, want := range builtinAlertRules {
		got, ok := byName[want.Name]
		if !ok {
			t.Errorf("內建規則 %q 不在 DB 內", want.Name)
			continue
		}
		if got.Pattern != want.Pattern {
			t.Errorf("%q 的 pattern = %q, want %q", want.Name, got.Pattern, want.Pattern)
		}
		if got.Severity != want.Severity {
			t.Errorf("%q 的 severity = %q, want %q", want.Name, got.Severity, want.Severity)
		}
		if got.Protocols != want.Protocols {
			t.Errorf("%q 的 protocols = %q, want %q", want.Name, got.Protocols, want.Protocols)
		}
		if got.Action != "alert" || !got.Enabled {
			t.Errorf("%q 的 action/enabled = %q/%v, want alert/true", want.Name, got.Action, got.Enabled)
		}
		dist[got.Protocols]++
	}
	want := map[string]int{"ssh,k8s": 8, "mysql,postgres,mssql": 3, "redis": 1}
	for proto, n := range want {
		if dist[proto] != n {
			t.Errorf("protocols=%q 的規則數 = %d, want %d。"+
				"三段疊加的終態是 ssh,k8s×8 / mysql,postgres,mssql×3 / redis×1；"+
				"mysql,postgres（無 mssql）代表漏了 20260813 那一段",
				proto, dist[proto], n)
		}
	}
}

// TestBaselineRefusesLegacyDatabasePostgres fail-close 正向實走。
//
// 斷言的是**拒絕啟動本身**與**零寫入**，不是「規則仍是 12 列」——後者在一個
// 根本還沒建表的資料庫上恆真，證明不了任何東西。
func TestBaselineRefusesLegacyDatabasePostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "baseline_legacy_test"
	db := freshSchema(t, dsn, pgSchema)
	withGlobalDB(t, db)

	// 前置：壓縮前的資料庫＝49 條 migration 版本 ＋ LDAP 執行期 marker
	if err := db.Exec(schemaMigrationsBootstrapDDL).Error; err != nil {
		t.Fatalf("建立 schema_migrations 失敗: %v", err)
	}
	for _, v := range legacyVersionsSample {
		if err := db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			v, time.Now()).Error; err != nil {
			t.Fatalf("塞入舊版本 %s 失敗: %v", v, err)
		}
	}
	if err := db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		LDAPSeedMarkerVersion, time.Now()).Error; err != nil {
		t.Fatalf("塞入 LDAP marker 失敗: %v", err)
	}
	before := countSchemaObjects(t, db, pgSchema)
	if before.Versions != int64(len(legacyVersionsSample)+1) {
		t.Fatalf("前置條件不成立：schema_migrations 只有 %d 列", before.Versions)
	}

	err := RunMigrations()
	if err == nil {
		t.Fatal("既有資料庫未被擋下：baseline 會在既有 schema 上執行，" +
			"最好的結果是建表衝突中止，最壞的結果是種子重複寫入而告警靜默翻倍")
	}
	msg := err.Error()
	for _, want := range []string{"拒絕啟動", "49", BaselineVersion, "不提供", "不是資料庫損毀", "不要手動刪除"} {
		if !strings.Contains(msg, want) {
			t.Errorf("fail-close 訊息缺少 %q：\n%s", want, msg)
		}
	}
	// 訊息不得洩漏連線資訊
	for _, forbidden := range []string{"password=", "sslmode=", "host="} {
		if strings.Contains(msg, forbidden) {
			t.Errorf("fail-close 訊息含連線資訊 %q：\n%s", forbidden, msg)
		}
	}

	// 零寫入：判定發生在任何 Up 之前
	after := countSchemaObjects(t, db, pgSchema)
	if after != before {
		t.Fatalf("拒絕啟動時仍動了資料庫：%+v → %+v", before, after)
	}
	var alertRulesExists int64
	if err := db.Raw(`SELECT count(*) FROM information_schema.tables
		WHERE table_schema = ? AND table_name = 'alert_rules'`, pgSchema).Scan(&alertRulesExists).Error; err != nil {
		t.Fatalf("查表失敗: %v", err)
	}
	if alertRulesExists != 0 {
		t.Fatal("拒絕啟動卻建出了 alert_rules：判定沒有排在 Up 之前")
	}
}

// TestBaselineAllowsRuntimeMarkerOnlyPostgres fail-close 反向實走。
//
// **這條漏了會擋住每一個正常安裝**：LDAP env seed 的 marker 是第一次啟動後才寫入的，
// 若 fail-close 不扣掉執行期 marker，第二次啟動就會被自己擋下。
// 第一次啟動完全正常，所以缺陷的顯現時機是「昨天還好好的，今天起不來」。
func TestBaselineAllowsRuntimeMarkerOnlyPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "baseline_marker_test"
	db := freshSchema(t, dsn, pgSchema)
	withGlobalDB(t, db)

	if err := RunMigrations(); err != nil {
		t.Fatalf("首次啟動失敗: %v", err)
	}
	// 模擬 post-unseal 佇列的 LDAP env seed 寫入 marker（identity 的實際行為）
	if err := db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		LDAPSeedMarkerVersion, time.Now()).Error; err != nil {
		t.Fatalf("寫入 LDAP marker 失敗: %v", err)
	}

	if err := RunMigrations(); err != nil {
		t.Fatalf("第二次啟動被 fail-close 誤擋：%v\n"+
			"執行期 marker 永遠不在 migrations 陣列內，必須登記於 runtimeMarkerVersions", err)
	}
	assertBuiltinAlertRules(t, db)
}

// TestBaselineIgnoresUnknownVersionAfterBaselinePostgres 降版情境不擋。
//
// baseline 已在已套用集合內時，其餘未知版本屬「這個庫被較新版本的程式碼跑過」，
// 沿既有的單向比對語義忽略（proposal 的 Non-goal）。
func TestBaselineIgnoresUnknownVersionAfterBaselinePostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "baseline_downgrade_test"
	db := freshSchema(t, dsn, pgSchema)
	withGlobalDB(t, db)

	if err := RunMigrations(); err != nil {
		t.Fatalf("首次啟動失敗: %v", err)
	}
	if err := db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		"20270101_future_migration", time.Now()).Error; err != nil {
		t.Fatalf("塞入未來版本失敗: %v", err)
	}
	if err := RunMigrations(); err != nil {
		t.Fatalf("已套用 baseline 的資料庫遇到未知版本不應被擋（降版情境）: %v", err)
	}
}

// TestBaselineRollbackIsRefusedPostgres baseline 的 Down 一律拒絕。
func TestBaselineRollbackIsRefusedPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "baseline_rollback_test"
	db := freshSchema(t, dsn, pgSchema)
	withGlobalDB(t, db)

	if err := RunMigrations(); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}
	before := countSchemaObjects(t, db, pgSchema)

	err := RollbackMigration(BaselineVersion)
	if err == nil {
		t.Fatal("baseline 的回滾被接受：那等同丟棄整個資料庫，" +
			"一個看起來像回滾入口、實際是資料庫毀滅按鈕的東西比沒有入口更危險")
	}
	if !strings.Contains(err.Error(), "還原") || !strings.Contains(err.Error(), "備份") {
		t.Errorf("拒絕訊息未指出退路是還原備份：%v", err)
	}

	after := countSchemaObjects(t, db, pgSchema)
	if after != before {
		t.Fatalf("拒絕回滾卻動了資料庫：%+v → %+v", before, after)
	}
}
