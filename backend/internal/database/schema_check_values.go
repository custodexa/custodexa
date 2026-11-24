package database

import (
	"regexp"
	"strings"
)

// SchemaCheckInValues 回傳 schema DDL（baseline＋增量，依執行順序）中最後一次定義的具名 CHECK
// 約束 `<name> CHECK (<欄> IN (...))` 的值集合；找不到或不是 IN 清單時 ok=false。
//
// **不是生產路徑**：與 SchemaParityModels 相同，存在的理由是跨套件的一致性守衛（例如通道型別登錄
// 與兩條型別約束的值域核對）。約束被重建時以最後一次定義為準，與實際執行結果相同。
func SchemaCheckInValues(constraint string) ([]string, bool) {
	re := regexp.MustCompile(regexp.QuoteMeta(constraint) + `\s+CHECK\s*\(\s*\w+\s+IN\s*\(([^)]*)\)\s*\)`)
	var last string
	found := false
	for _, stmt := range schemaDDLStatements() {
		for _, m := range re.FindAllStringSubmatch(stmt, -1) {
			last, found = m[1], true
		}
	}
	if !found {
		return nil, false
	}
	var out []string
	for _, part := range strings.Split(last, ",") {
		out = append(out, strings.Trim(strings.TrimSpace(part), "'"))
	}
	return out, true
}

// SchemaCheckDefinition 回傳 schema DDL 中最後一次定義的具名 CHECK 約束括號內的條件文字；找不到時 ok=false。
// 用途同 SchemaCheckInValues（跨套件的一致性守衛），只取 `ADD CONSTRAINT <name> CHECK (...)` 形式。
func SchemaCheckDefinition(constraint string) (string, bool) {
	marker := "ADD CONSTRAINT " + constraint + " CHECK ("
	var last string
	found := false
	for _, stmt := range schemaDDLStatements() {
		if i := strings.Index(stmt, marker); i >= 0 && strings.HasSuffix(stmt, ")") {
			last, found = stmt[i+len(marker):len(stmt)-1], true
		}
	}
	return last, found
}
