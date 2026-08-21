package database

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

// model ↔ baseline 的**第 1 層** parity 守衛（migration-baseline-compression D3）。
//
// # 本檔守的是什麼
//
// 移除開機 AutoMigrate 之後，「改了 model 卻沒改 baseline」成為本 change 新產生的
// 最高頻漂移形態：從此沒有任何東西會依 gorm tag 去補欄，而缺欄的症狀要等到執行期
// 的第一次查詢才會以「column does not exist」出現在生產。
//
// **這一層刻意不碰資料庫**：第 2 層（index_declaration_parity_test.go／
// baseline_parity_pg_test.go）是 PG-gated 的，未設 TEST_PG_DSN 即 skip——而
// 「守衛被 skip 掉」正是 2026-08-12 索引事故能發生的原因，本專案的 CI workflow
// 至今從未執行過（觸發分支寫 main/develop，repo 只有 master）。故最高頻的漂移形態
// 必須由一條**任何人在任何機器上跑 go test 都會執行**的測試承接。
//
// 涵蓋界定（誠實邊界）：本層只比對**欄位名**。型別、可空、預設、索引與約束屬第 2 層。
// 欄位名層級恰好就是「新增／改名欄位忘了同步 baseline」的形態，這是本層的目標。

// baselineColumnExceptions baseline 有、但對應 model 未宣告的欄位。
//
// **燒盡制**：每一列都是「baseline 為某個 model 的表多建了一欄」的宣告，
// 新增一列必須說明那一欄由誰使用。空著才是正常狀態。
// 目前為空：唯一曾登記的 `assets.db_ca_cert`（壓縮前既有的死欄，`model.Asset.DBCACert`
// 的 GORM 欄名其實是 `dbca_cert`）已隨 D6 刻意變更清單第 2 項自 baseline 移除，
// 例外條目同步刪除以免留下殭屍豁免。
var baselineColumnExceptions = map[string]string{}

var createTableRe = regexp.MustCompile(`(?s)^CREATE TABLE (\w+) \((.*)\)$`)

// baselineTableColumns 自 baseline 的 DDL 取出每張表的欄位名集合。
//
// 解析對象是 baselineSchemaStatements() 回傳的**實際執行語句**，不是 Go 原始碼檔——
// 檔案搬家或改名不會使本守衛的射程靜默縮水。
func baselineTableColumns(t *testing.T) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for _, stmt := range baselineSchemaStatements() {
		s := strings.Join(strings.Fields(stmt), " ")
		m := createTableRe.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		table := m[1]
		if _, dup := out[table]; dup {
			t.Fatalf("baseline 內有兩條 CREATE TABLE %s：無條件 DDL 之下第二條必然執行失敗", table)
		}
		cols := map[string]bool{}
		for _, part := range splitTopLevelSQL(m[2]) {
			part = strings.TrimSpace(part)
			if part == "" || strings.HasPrefix(strings.ToUpper(part), "CONSTRAINT ") {
				continue
			}
			cols[strings.Fields(part)[0]] = true
		}
		if len(cols) == 0 {
			t.Fatalf("baseline 的 %s 解析不出任何欄位：CREATE TABLE 解析器已失真", table)
		}
		out[table] = cols
	}
	return out
}

// splitTopLevelSQL 依頂層逗號切分（括號與引號內的逗號不算）。
func splitTopLevelSQL(body string) []string {
	var parts []string
	var cur []rune
	depth := 0
	var quote rune
	for _, ch := range body {
		if quote != 0 {
			cur = append(cur, ch)
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, string(cur))
				cur = nil
				continue
			}
		}
		cur = append(cur, ch)
	}
	if strings.TrimSpace(string(cur)) != "" {
		parts = append(parts, string(cur))
	}
	return parts
}

// TestBaselineCoversAllModelColumns 第 1 層：每個 model 宣告的欄位在 baseline 中都有同名欄。
func TestBaselineCoversAllModelColumns(t *testing.T) {
	tables := baselineTableColumns(t)
	// 防假綠下界：解析器壞掉會讓兩個方向的斷言都變成空集合上的恆真式
	if len(tables) < 40 {
		t.Fatalf("自 baseline 解析到的表只有 %d 張（下界 40）：DDL 解析已失真，"+
			"比對將在空集合上恆真", len(tables))
	}
	if len(schemaParityModels) < 35 {
		t.Fatalf("schemaParityModels 只有 %d 個 model（下界 35）：清單已失真", len(schemaParityModels))
	}

	cache := &sync.Map{}
	ns := schema.NamingStrategy{}
	var problems []string
	checkedModels, checkedColumns := 0, 0
	modelTables := map[string]bool{}

	for _, m := range schemaParityModels {
		sch, err := schema.Parse(m, cache, ns)
		if err != nil {
			t.Fatalf("解析 model %T 失敗: %v", m, err)
		}
		checkedModels++
		modelTables[sch.Table] = true
		cols, ok := tables[sch.Table]
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"model %T 的表 %s 在 baseline 中不存在", m, sch.Table))
			continue
		}
		for _, f := range sch.Fields {
			if f.DBName == "" || f.IgnoreMigration {
				continue // 關聯欄／不落地欄
			}
			checkedColumns++
			if !cols[f.DBName] {
				problems = append(problems, fmt.Sprintf(
					"%s.%s 由 model %T 宣告，但 baseline 的 CREATE TABLE 沒有這一欄",
					sch.Table, f.DBName, m))
			}
		}
	}

	if checkedColumns < 300 {
		t.Fatalf("只比對到 %d 個 model 欄位（下界 300）：model 解析已失真，"+
			"比對迴圈將由空清單假綠", checkedColumns)
	}

	// 反向：baseline 為「有 model 對應的表」多建的欄位，須有具名理由
	for table, cols := range tables {
		if !modelTables[table] {
			continue // 無 model 對應的表（migration 原生建表、m2m 關聯表）不在本層射程
		}
		var declared map[string]bool
		for _, m := range schemaParityModels {
			sch, _ := schema.Parse(m, cache, ns)
			if sch.Table == table {
				declared = map[string]bool{}
				for _, f := range sch.Fields {
					if f.DBName != "" {
						declared[f.DBName] = true
					}
				}
				break
			}
		}
		for col := range cols {
			if declared[col] {
				continue
			}
			if _, ok := baselineColumnExceptions[table+"."+col]; ok {
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"baseline 的 %s.%s 沒有對應的 model 欄位：若刻意如此 SHALL 登記於 baselineColumnExceptions 並寫明由誰使用",
				table, col))
		}
	}

	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("model 與 baseline 的欄位已漂移（共 %d 條）：\n  %s\n\n"+
			"開機 AutoMigrate 已移除，沒有任何東西會依 gorm tag 補欄——"+
			"缺欄的症狀要到執行期的第一次查詢才會以 column does not exist 出現在生產。\n"+
			"修法：把欄位補進對應的 baseline_schema_*.go 的 CREATE TABLE，"+
			"或（若該欄本來就不該落地）在 model 上標明。",
			len(problems), strings.Join(problems, "\n  "))
	}
	t.Logf("已比對 %d 個 model、%d 個欄位、%d 張 baseline 表", checkedModels, checkedColumns, len(tables))
}
