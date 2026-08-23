package database

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

// 本檔守衛一類**無症狀**的缺陷：索引的「宣告」與「線上實際定義」不符。
//
// 歷史事故（20260812_auditor_workbench）：migration 宣告
// `CREATE INDEX IF NOT EXISTS idx_audit_asset_created ON audit_logs (asset_id, created_at)`，
// 但 AutoMigrate 先於 RunMigrations 執行、依當時的 gorm tag 已建出同名的單欄
// `(asset_id)`；`IF NOT EXISTS` 只看名字，於是 migration 永久 no-op。
// 結果：任何人讀 model tag 或 migration 都以為複合索引存在，線上卻不是——
// **沒有任何測試會紅**，EXPLAIN 也只表現為「沒走到最好的索引」。
//
// 故守衛不比對 SQL 字面，而是把 gorm tag 解析出的索引欄序，對上 pg 系統目錄裡
// 該索引的實際欄序。兩者只要有一格不同就紅。

// declaredIndex 一條由 gorm tag 宣告的索引（本守衛比對的粒度）
type declaredIndex struct {
	table   string
	name    string
	columns []string
	unique  bool
}

// declaredIndexesFromModels 解析 schemaParityModels 的 gorm tag，取出所有具名索引。
//
// 只收「欄位型」索引：帶 Expression 的索引（如 COALESCE(...)）在 pg 目錄裡不對應
// 具名欄位，欄序比對無意義，交由既有的 migration 測試把關。
func declaredIndexesFromModels(t *testing.T, db *gorm.DB) []declaredIndex {
	t.Helper()
	cache := &sync.Map{}
	var out []declaredIndex
	for _, m := range schemaParityModels {
		sch, err := schema.Parse(m, cache, db.NamingStrategy)
		if err != nil {
			t.Fatalf("解析 model %T 失敗: %v", m, err)
		}
		for name, idx := range sch.ParseIndexes() {
			cols := make([]string, 0, len(idx.Fields))
			expression := false
			for _, f := range idx.Fields {
				if f.Expression != "" || f.Field == nil {
					expression = true
					break
				}
				cols = append(cols, f.DBName)
			}
			if expression || len(cols) == 0 {
				continue
			}
			out = append(out, declaredIndex{
				table:   sch.Table,
				name:    name,
				columns: cols,
				unique:  strings.EqualFold(idx.Class, "UNIQUE"),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// declaredIndexUniqueExceptions gorm tag 的唯一性宣告與 baseline 刻意不同的索引。
//
// **燒盡制**：每一列都是「tag 表達不出 DB 的真實形狀，而 DB 是對的」的具名宣告。
//
// 這一格是壓縮**強化**守衛之後才浮現的：壓縮前本測試的對照組是
// `AutoMigrate(...)` → 樞紐索引收斂 migration，中間跳過了 v7.6 這類「把 AutoMigrate
// 建的索引換掉」的 migration，於是它比對的是「AutoMigrate 的產物」而不是生產實況，
// 差異結構上看不見。改以 baseline（＝生產實況）為對照後才顯形。
var declaredIndexUniqueExceptions = map[string]string{
	"idx_assets_name": "v7.6 把它換成 **partial unique**（`(name) WHERE deleted_at IS NULL`）：" +
		"純唯一索引會把軟刪列一併算進去，資產刪除後同名資產永遠無法重建。" +
		"gorm tag 表達不出 partial 條件——寫 `uniqueIndex` 會宣稱一個比實際更強的約束" +
		"（含軟刪列），寫 `index` 則少了唯一性，兩者都不精確。" +
		"DB 的形狀是對的，故此處以具名例外承認 tag 的表達力缺口，" +
		"而不是把斷言放寬或把 tag 改成另一個同樣不精確的值。",
}

// actualIndex 線上實際索引定義（自 pg 系統目錄讀出，非解析 indexdef 字串）
type actualIndex struct {
	columns []string
	unique  bool
}

// actualIndexesFromPostgres 讀出指定 schema 內所有索引的實際欄序。
//
// 以 `unnest(indkey) WITH ORDINALITY` 取欄序而非解析 `pg_get_indexdef` 文字：
// 目錄欄位是 pg 自己的事實，字串剖析則會被 DESC／COLLATE／型別轉換等修飾干擾。
// 表示式欄（indkey = 0）以 `(expr)` 佔位，使欄數仍然對得上。
func actualIndexesFromPostgres(t *testing.T, db *gorm.DB, pgSchema string) map[string]actualIndex {
	t.Helper()
	type row struct {
		IndexName string
		TableName string
		ColName   string
		IsUnique  bool
	}
	var rows []row
	err := db.Raw(`
		SELECT i.relname AS index_name,
		       t.relname AS table_name,
		       COALESCE(a.attname, '(expr)') AS col_name,
		       x.indisunique AS is_unique
		FROM pg_index x
		JOIN pg_class i ON i.oid = x.indexrelid
		JOIN pg_class t ON t.oid = x.indrelid
		JOIN pg_namespace n ON n.oid = i.relnamespace
		JOIN LATERAL unnest(x.indkey) WITH ORDINALITY AS k(attnum, ord) ON true
		LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
		WHERE n.nspname = ?
		ORDER BY i.relname, k.ord`, pgSchema).Scan(&rows).Error
	if err != nil {
		t.Fatalf("讀取 pg 索引目錄失敗: %v", err)
	}
	out := map[string]actualIndex{}
	for _, r := range rows {
		cur := out[r.IndexName]
		cur.columns = append(cur.columns, r.ColName)
		cur.unique = r.IsUnique
		out[r.IndexName] = cur
	}
	return out
}

// freshSchema 建立一個乾淨的 pg schema 並回傳綁到該 schema 的連線
func freshSchema(t *testing.T, dsn, name string) *gorm.DB {
	t.Helper()
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("postgres 連線失敗: %v", err)
	}
	drop := "DROP SCHEMA IF EXISTS " + name + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		t.Fatalf("清理舊 schema 失敗: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + name).Error; err != nil {
		t.Fatalf("建立 schema 失敗: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.Exec(drop)
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+name), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("scoped 連線失敗: %v", err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	return db
}

// TestDeclaredIndexesMatchDatabasePostgres 全新部署的宣告／實際一致性
// （gating：未設 TEST_PG_DSN 即 skip；REQUIRE_INTEGRATION=1 時 skip 轉 fail）。
//
// 走的是生產路徑：**baseline 建整個 schema**（增量 migration 退場後，
// 開機 AutoMigrate 已不存在，baseline 是 schema 的唯一事實源）。隨後逐條比對每個
// gorm tag 宣告的索引與 pg 目錄裡的欄序、唯一性。
//
// 原本的對照組是 `AutoMigrate(...)` → 樞紐索引收斂 migration；那條 migration 的
// 存在理由是修既有部署的 legacy 漂移，baseline 之後無漂移可修，故一併退場。
// **但本測試的不變式不變**：宣告與線上定義的分岔仍然是無症狀缺陷，只是「線上定義」
// 的來源從 AutoMigrate 換成 baseline。
//
// 跑法（compose 內）：
//
//	docker compose exec -T backend sh -c \
//	  'TEST_PG_DSN="host=postgres user=postgres password=postgres dbname=postgres port=5432 sslmode=disable" \
//	   REQUIRE_INTEGRATION=1 go test ./internal/database -run TestDeclaredIndexes -v'
func TestDeclaredIndexesMatchDatabasePostgres(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const pgSchema = "index_parity_test"
	db := freshSchema(t, dsn, pgSchema)

	if err := applyBaseline(db); err != nil {
		t.Fatalf("baseline 失敗: %v", err)
	}

	declared := declaredIndexesFromModels(t, db)
	// 正向：宣告清單必須掃得到（防「解析不到 → 空清單 → 迴圈零次 → 假綠」）
	if len(declared) < 20 {
		t.Fatalf("自 model tag 掃到的具名索引只有 %d 條：解析已漂移，比對迴圈將由空清單假綠", len(declared))
	}
	actual := actualIndexesFromPostgres(t, db, pgSchema)
	if len(actual) < len(declared) {
		t.Fatalf("pg 目錄只讀到 %d 條索引、少於宣告的 %d 條：目錄查詢已漂移", len(actual), len(declared))
	}

	var problems []string
	usedUniqueExceptions := map[string]bool{}
	for _, d := range declared {
		a, ok := actual[d.name]
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"%s.%s 宣告了 (%s) 但 DB 內不存在",
				d.table, d.name, strings.Join(d.columns, ", ")))
			continue
		}
		if strings.Join(a.columns, ",") != strings.Join(d.columns, ",") {
			problems = append(problems, fmt.Sprintf(
				"%s.%s 宣告 (%s)，DB 實際 (%s)",
				d.table, d.name, strings.Join(d.columns, ", "), strings.Join(a.columns, ", ")))
			continue
		}
		if a.unique != d.unique {
			if _, excused := declaredIndexUniqueExceptions[d.name]; excused {
				usedUniqueExceptions[d.name] = true
			} else {
				problems = append(problems, fmt.Sprintf(
					"%s.%s 宣告 unique=%v，DB 實際 unique=%v", d.table, d.name, d.unique, a.unique))
			}
		}
	}
	// 反向：例外表不得留下已無對應差異的列（殘留列會靜默放行下一次同名索引的漂移）
	for name := range declaredIndexUniqueExceptions {
		if !usedUniqueExceptions[name] {
			problems = append(problems, fmt.Sprintf(
				"declaredIndexUniqueExceptions 的 %s 已無對應差異：SHALL 移除該列", name))
		}
	}
	if len(problems) > 0 {
		t.Fatalf("索引宣告與 DB 實際定義不符（共 %d 條）：\n  %s\n\n"+
			"此類漂移無外顯症狀：讀 model tag 的人會以為索引是宣告的形狀，"+
			"線上卻不是。修法：修正 baseline 的 CREATE INDEX 使其與 gorm tag 的欄序一致"+
			"（baseline 的 DDL 一律無條件，改了就會生效，不會像 `IF NOT EXISTS` 那樣永久 no-op）。",
			len(problems), strings.Join(problems, "\n  "))
	}
}
