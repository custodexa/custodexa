package database

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// model ↔ baseline 的**第 2 層** parity 守衛。
//
// 第 1 層（schema_parity_test.go）只比對欄位名，且不碰資料庫。本層補上型別、長度、
// 可空與預設，以及一組**具名的結構斷言**——那些是壓縮前散落在各 migration 測試裡、
// 對象隨 migration 一併退場但不變式本身沒有消失的東西。
//
// **比對基準是 GORM 自己的產物**，不是手寫的型別對照表：同一組 model 在另一個臨時
// schema 上跑 `AutoMigrate`，兩邊的 information_schema 逐欄比。這樣「model 宣告的型別」
// 不需要在測試裡重新實作一次 gorm 的 dialect 映射——重新實作一次就是製造第三份會漂移的規則。
//
// PG-gated：未設 TEST_PG_DSN 即 skip；REQUIRE_INTEGRATION=1 時 skip 轉 fail。

type columnShape struct {
	Table    string
	Column   string
	DataType string
	Length   int64
	Nullable string
	Default  string
}

var nextvalSchemaRe = regexp.MustCompile(`nextval\('[^.']*\.`)

// baselineShapeExceptions baseline 與「GORM 依 model 建出的形狀」之間**刻意保留**的差異。
//
// 鍵為 `表.欄|面向`（面向 ∈ type／nullable／default）。**燒盡制**：每一列都是
// 「baseline 與 model tag 在這一格上不同，而 baseline 是對的」的具名宣告。
//
// 這三格全部是壓縮前既有的事實，baseline 逐欄複製舊鏈的最終形狀而來，
// **不是本 change 引入的**。把它們改成與 model tag 一致，等於偷偷改變全新部署的
// schema 而繞過等價驗證——那是獨立的裁決，不在壓縮的射程內。
var baselineShapeExceptions = map[string]string{
	"audit_logs.key_version|nullable": "舊鏈的 20260715_key_mgmt_envelope 以 " +
		"`ADD COLUMN ... NOT NULL DEFAULT 0` 補欄，而 model tag 未宣告 not null/default。" +
		"**空庫（嚴格）才是全新部署拿到的形狀**：既有部署因 GORM 對已存在的表新增欄位時" +
		"不補 NOT NULL/DEFAULT，永久停在寬鬆定義（對照組 manifest 第 6 節實測）。" +
		"baseline 取嚴格版本，故此處與 model tag 不同。",
	"audit_logs.key_version|default":          "同上（DEFAULT 0）",
	"integrity_baselines.max_log_id|nullable": "同 audit_logs.key_version（20260715_integrity_baseline_max_log_id）",
	"integrity_baselines.max_log_id|default":  "同上（DEFAULT 0）",
	"ldap_directories.singleton|type":         "舊鏈由 20260804_ldap_directories 的原生 SQL 建為 `INTEGER`，而 `model.LDAPDirectory.Singleton` 是 Go `int` → GORM 在 pg 上映射為 `bigint`。兩者語義等價（值恆為 1，由 CHECK 約束釘住），差異自壓縮前即存在。改型別會使等價驗證出現預期外差異，屬獨立裁決。",
}

func columnShapes(t *testing.T, db *gorm.DB, pgSchema string) map[string]columnShape {
	t.Helper()
	var rows []columnShape
	err := db.Raw(`
		SELECT table_name AS table, column_name AS column, data_type,
		       COALESCE(character_maximum_length, -1) AS length,
		       is_nullable AS nullable,
		       COALESCE(column_default, '') AS default
		FROM information_schema.columns
		WHERE table_schema = ?`, pgSchema).Scan(&rows).Error
	if err != nil {
		t.Fatalf("讀取 information_schema.columns 失敗: %v", err)
	}
	out := map[string]columnShape{}
	for _, r := range rows {
		// 序列的預設值帶 schema 名（nextval('<schema>.x_id_seq'::regclass)），
		// 兩個臨時 schema 必然不同 → 抹除 schema 前綴，但保留「這一欄是自增的」。
		r.Default = nextvalSchemaRe.ReplaceAllString(r.Default, "nextval('")
		out[r.Table+"."+r.Column] = r
	}
	return out
}

// TestBaselineMatchesModelSchemaPostgres 逐欄比對 baseline 與 GORM 依 model 建出的形狀。
func TestBaselineMatchesModelSchemaPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const modelSchema = "parity_model_test"
	const baseSchema = "parity_baseline_test"

	modelDB := freshSchema(t, dsn, modelSchema)
	if err := modelDB.AutoMigrate(schemaParityModels...); err != nil {
		t.Fatalf("以 model 建對照 schema 失敗: %v", err)
	}
	baseDB := freshSchema(t, dsn, baseSchema)
	if err := applyBaseline(baseDB); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}

	want := columnShapes(t, modelDB, modelSchema)
	got := columnShapes(t, baseDB, baseSchema)
	if len(want) < 300 {
		t.Fatalf("model 對照 schema 只有 %d 欄（下界 300）：AutoMigrate 對照組已失真", len(want))
	}
	if len(got) < 450 {
		t.Fatalf("baseline schema 只有 %d 欄（下界 450）：baseline 未完整建立", len(got))
	}

	// 只比對「有 model 對應」的表——baseline 另含 migration 原生建表（alert_rules、
	// command_alerts 等），它們沒有 AutoMigrate 對照物，由第 1 層與等價驗證負責。
	cache := &sync.Map{}
	modelTables := map[string]bool{}
	for _, m := range schemaParityModels {
		sch, err := schema.Parse(m, cache, modelDB.NamingStrategy)
		if err != nil {
			t.Fatalf("解析 model %T 失敗: %v", m, err)
		}
		modelTables[sch.Table] = true
	}

	var problems []string
	compared := 0
	usedExceptions := map[string]bool{}
	for key, w := range want {
		if !modelTables[strings.SplitN(key, ".", 2)[0]] {
			continue
		}
		g, ok := got[key]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s：model 宣告了此欄，baseline 沒有", key))
			continue
		}
		compared++
		excused := func(aspect string) bool {
			_, ok := baselineShapeExceptions[key+"|"+aspect]
			if ok {
				usedExceptions[key+"|"+aspect] = true
			}
			return ok
		}
		if (g.DataType != w.DataType || g.Length != w.Length) && !excused("type") {
			problems = append(problems, fmt.Sprintf(
				"%s 型別不符：model 建出 %s(%d)，baseline 建出 %s(%d)",
				key, w.DataType, w.Length, g.DataType, g.Length))
		}
		if g.Nullable != w.Nullable && !excused("nullable") {
			problems = append(problems, fmt.Sprintf(
				"%s 可空性不符：model 建出 nullable=%s，baseline 建出 nullable=%s",
				key, w.Nullable, g.Nullable))
		}
		if g.Default != w.Default && !excused("default") {
			problems = append(problems, fmt.Sprintf(
				"%s 預設值不符：model 建出 %q，baseline 建出 %q", key, w.Default, g.Default))
		}
	}

	// 反向：例外表不得留下已無對應差異的列。殘留列會讓「例外表＝實際差異集合」
	// 這個前提悄悄失效——差異被修好之後例外仍在，下一次同樣的漂移就會被靜默放行。
	for key := range baselineShapeExceptions {
		if !usedExceptions[key] {
			problems = append(problems, fmt.Sprintf(
				"baselineShapeExceptions 的 %s 已無對應差異：SHALL 移除該列，"+
					"殘留的例外會讓下一次同格的漂移被靜默放行", key))
		}
	}
	if compared < 300 {
		t.Fatalf("只實際比對到 %d 欄（下界 300）：表名對照已失真，比對迴圈由空集合假綠", compared)
	}

	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("baseline 與 model 宣告的欄位形狀不符（共 %d 條）：\n  %s\n\n"+
			"開機 AutoMigrate 已移除，baseline 是 schema 的唯一事實源——"+
			"兩者分岔的症狀是執行期的型別錯誤或靜默截斷，沒有其他測試會紅。\n"+
			"刻意保留的差異 SHALL 登記於 baselineShapeExceptions 並寫明「為何 baseline 才是對的」。",
			len(problems), strings.Join(problems, "\n  "))
	}
	t.Logf("已逐欄比對 %d 欄（model 對照 %d 欄 / baseline %d 欄）", compared, len(want), len(got))
}

// baselineStructuralAssertions 具名的結構不變式。
//
// **每一條都是壓縮前某個 migration 測試守的東西**，其對象（migration 函式）隨壓縮
// 退場，但不變式本身沒有：
//
//	idx_asset_accounts_default 一資產至多一個預設帳號
//	idx_asset_accounts_username       一資產內帳號名唯一（軟刪列不佔名）
//	idx_data_keys_purpose_version_kek 同 slot 至多一列帶材料（重包狀態機／AAD 完備性）
//	idx_failure_events_single_open    一機制至多一個未結案失敗區間（PCI 10.7）
//	idx_ldap_directories_singleton    LDAP 設定單列
//	uniq_alert_rules_name             種子冪等的衝突目標（本 change 新增）
//
// 比對的是 `pg_get_indexdef` 的**完整定義**而非只看名字：partial 條件被拿掉、
// UNIQUE 被拿掉、欄序被換，三者都不會改變索引數量，卻都會讓不變式失效。
var baselineStructuralAssertions = map[string]string{
	"idx_asset_accounts_default": "CREATE UNIQUE INDEX idx_asset_accounts_default ON %s.asset_accounts " +
		"USING btree (asset_id) WHERE ((is_default = true) AND (deleted_at IS NULL))",
	"idx_asset_accounts_username": "CREATE UNIQUE INDEX idx_asset_accounts_username ON %s.asset_accounts " +
		"USING btree (asset_id, username) WHERE (deleted_at IS NULL)",
	"idx_data_keys_purpose_version_kek": "CREATE UNIQUE INDEX idx_data_keys_purpose_version_kek ON %s.data_keys " +
		"USING btree (purpose, version, kek_id) WHERE (kek_retired_at IS NULL)",
	"idx_failure_events_single_open": "CREATE UNIQUE INDEX idx_failure_events_single_open ON %s.audit_failure_events " +
		"USING btree (mechanism) WHERE (ended_at IS NULL)",
	"idx_ldap_directories_singleton": "CREATE UNIQUE INDEX idx_ldap_directories_singleton ON %s.ldap_directories " +
		"USING btree (singleton) WHERE (deleted_at IS NULL)",
	"uniq_alert_rules_name": "CREATE UNIQUE INDEX uniq_alert_rules_name ON %s.alert_rules USING btree (name)",
}

// baselineCheckConstraints 10 條 CHECK 約束的具名清單與定義。
//
// `ldap_directories_singleton_check` 是其中最需要具名的一條：壓縮前它由
// migration 的 inline CHECK 建立，且靠一條 AST 守衛（TestLDAPDirectoryNotInAutoMigrateList）
// 擋住「有人把 model 加進 AutoMigrate 清單」——因為 GORM 不產出 inline CHECK，
// 先被 AutoMigrate 建出的表會讓 CHECK 在生產完全不存在而無外顯症狀。
// AutoMigrate 移除後那條守衛失去對象，保護責任落到這裡：**總量斷言不夠**
// （少一條 CHECK 而多一條別的仍然是 10），故逐條比對定義文字。
var baselineCheckConstraints = map[string]string{
	"alert_rules_action_check":             "alert_rules",
	"alert_rules_severity_check":           "alert_rules",
	"chk_approver_scope_actor":             "approver_scopes",
	"chk_approver_scope_target":            "approver_scopes",
	"chk_auth_target":                      "asset_authorizations",
	"chk_authz_subject_xor":                "asset_authorizations",
	"command_alerts_severity_check":        "command_alerts",
	"ldap_directories_singleton_check":     "ldap_directories",
	"notification_channels_language_check": "notification_channels",
	"notification_channels_type_check":     "notification_channels",
}

func TestBaselineStructuralInvariantsPostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "baseline_structural_test"
	db := freshSchema(t, dsn, pgSchema)
	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}

	// ── 索引定義逐條比對 ──
	type idxRow struct {
		Name string
		Def  string
	}
	var idxRows []idxRow
	if err := db.Raw(`SELECT indexname AS name, indexdef AS def FROM pg_indexes WHERE schemaname = ?`,
		pgSchema).Scan(&idxRows).Error; err != nil {
		t.Fatalf("讀取 pg_indexes 失敗: %v", err)
	}
	if len(idxRows) < 150 {
		t.Fatalf("baseline 只建出 %d 條索引（下界 150）：比對基準已失真", len(idxRows))
	}
	defs := map[string]string{}
	for _, r := range idxRows {
		defs[r.Name] = r.Def
	}
	for name, tmpl := range baselineStructuralAssertions {
		want := fmt.Sprintf(tmpl, pgSchema)
		got, ok := defs[name]
		if !ok {
			t.Errorf("索引 %s 不存在於 baseline 產出的 schema：該索引承載的是資料層不變式，"+
				"缺席的症狀是重複列可以寫進去而沒有任何錯誤", name)
			continue
		}
		if got != want {
			t.Errorf("索引 %s 的定義已改變：\n  實際 %s\n  期望 %s\n"+
				"partial 條件／UNIQUE／欄序被改都不會改變索引數量，卻都會讓不變式失效",
				name, got, want)
		}
	}

	// ── CHECK 約束逐條比對 ──
	type conRow struct {
		Name  string
		Table string
		Def   string
	}
	var conRows []conRow
	if err := db.Raw(`
		SELECT con.conname AS name, rel.relname AS table, pg_get_constraintdef(con.oid) AS def
		FROM pg_constraint con
		JOIN pg_class rel ON rel.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = con.connamespace
		WHERE n.nspname = ? AND con.contype = 'c'`, pgSchema).Scan(&conRows).Error; err != nil {
		t.Fatalf("讀取 pg_constraint 失敗: %v", err)
	}
	if len(conRows) != len(baselineCheckConstraints) {
		t.Errorf("CHECK 約束數 = %d, want %d（具名清單長度）", len(conRows), len(baselineCheckConstraints))
	}
	actualCons := map[string]conRow{}
	for _, r := range conRows {
		actualCons[r.Name] = r
	}
	for name, table := range baselineCheckConstraints {
		got, ok := actualCons[name]
		if !ok {
			t.Errorf("CHECK 約束 %s（%s）不存在於 baseline 產出的 schema", name, table)
			continue
		}
		if got.Table != table {
			t.Errorf("CHECK 約束 %s 掛在 %s，期望 %s", name, got.Table, table)
		}
	}
	// ldap_directories 的單列 CHECK 專屬斷言：不只是「存在」，定義必須真的是 singleton = 1
	if c, ok := actualCons["ldap_directories_singleton_check"]; ok {
		if !strings.Contains(strings.ToLower(c.Def), "singleton = 1") {
			t.Errorf("ldap_directories_singleton_check 的定義不是 (singleton = 1)：%s\n"+
				"CHECK 被放寬時 partial unique index 擋不住 singleton=2，單列保證即失效", c.Def)
		}
	}
}
