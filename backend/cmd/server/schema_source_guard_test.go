package main

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
	"testing"
)

// schema 事實源的單一性守衛。
//
// # 本檔守的是什麼
//
// 壓縮後 schema 只有一個事實源：`internal/database` 的 baseline DDL。
// 任何一處 `AutoMigrate` 都會製造第二個事實源，而它的失效方式是**無症狀**的：
//
//   - AutoMigrate 依 gorm tag 建表／補欄，先於或後於 baseline 都可能，
//     兩者的差異（欄序、CHECK 缺席、索引欄序）不會有任何測試變紅；
//   - 2026-08-12 的索引事故正是這個形態——AutoMigrate 先建出同名的單欄索引，
//     migration 的 `CREATE INDEX IF NOT EXISTS` 從此永久 no-op；
//   - `ldap_directories` 的 `CHECK (singleton = 1)` 也是同一形態：GORM 不產出
//     inline CHECK，先被 AutoMigrate 建出的表會讓 CHECK 在生產完全不存在。
//
// 故本守衛的判準是**零**，且**無例外條目**：`schema_migrations` 追蹤表的雞生蛋問題
// 已由 `RunMigrations` 的原生 `CREATE TABLE IF NOT EXISTS` 承擔，不需要豁免。
//
// 射程界定：只掃非測試檔。單元測試在 sqlite `:memory:` 上仍以 GORM 建表
// （baseline 是 postgres 專屬 DDL），那是刻意的分工，不在本守衛射程內
// ——測試庫的形狀由 internal/database 的 parity 守衛在真 pg 上把關。
func TestNoAutoMigrateInProductionCode(t *testing.T) {
	root := auditPointModuleRoot(t)
	files, scanned := parseModuleFiles(t, root)
	if scanned < minScannedGoFiles {
		t.Fatalf("只掃到 %d 個非測試 .go 檔（下限 %d）：掃描根或走訪邏輯已失真，"+
			"「零 AutoMigrate」在空集合上恆真", scanned, minScannedGoFiles)
	}

	var hits []string
	for _, pf := range files {
		ast.Inspect(pf.File, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				name := ""
				switch fun := node.Fun.(type) {
				case *ast.SelectorExpr:
					name = fun.Sel.Name
				case *ast.Ident:
					name = fun.Name
				}
				if name == "AutoMigrate" {
					hits = append(hits, fmt.Sprintf("%s:%d 呼叫 AutoMigrate",
						pf.Rel, pf.Fset.Position(node.Pos()).Line))
				}
			case *ast.FuncDecl:
				if node.Name != nil && node.Name.Name == "AutoMigrate" {
					hits = append(hits, fmt.Sprintf("%s:%d 宣告了名為 AutoMigrate 的函式",
						pf.Rel, pf.Fset.Position(node.Pos()).Line))
				}
			}
			return true
		})
	}

	sort.Strings(hits)
	if len(hits) > 0 {
		t.Errorf("產品程式碼出現 %d 處 AutoMigrate：\n  %s\n\n"+
			"schema 的唯一事實源 SHALL 是 internal/database 的 baseline DDL。"+
			"AutoMigrate 會依 gorm tag 另建一套結構，兩者的分岔沒有任何測試會紅"+
			"（2026-08-12 索引事故、ldap_directories 的 CHECK 缺席皆為此形態）。\n"+
			"需要新增表或欄位時 SHALL 改 baseline_schema_*.go 的 DDL，"+
			"**本守衛沒有例外清單**——追蹤表 schema_migrations 的雞生蛋問題已由 "+
			"RunMigrations 的原生 CREATE TABLE IF NOT EXISTS 承擔。",
			len(hits), strings.Join(hits, "\n  "))
	}
}
