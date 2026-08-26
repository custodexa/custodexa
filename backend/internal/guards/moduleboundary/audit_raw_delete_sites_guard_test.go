package moduleboundary

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 審計類表的原生 SQL 刪除入口清冊（audit-checkpoint-chain
//「audit_logs 刪除入口唯一性」的**放寬方向**守衛）。
//
// 為何需要本守衛：`model.AuditLog.BeforeDelete`／`AuditCheckpoint.BeforeDelete`
// 只擋得住 ORM 路徑，retention 的清除刻意走原生 SQL 繞過它們。既有的
// `TestAuditLogDeleteGuard` 證明「拿掉 hook 會紅」，但它對**新增一處原生
// SQL 刪除**毫無反應——而那正是實務上最可能發生的形態（有人為了寫個
// 清理工具、修資料的一次性腳本，在別處補一句 `DELETE FROM audit_logs`）。
// 檢查點鏈的價值全押在「刪列必留痕、必現形」，多一個未經 tombstone 的
// 刪除入口就是多一條把竊取洗成合法清除的路。
//
// 清冊是**精確集合**：多一處未登記的刪除點要紅，登記了卻已不存在的條目
// 也要紅（否則清冊會慢慢腐爛成一張放行任何事的白名單）。
var auditRawDeleteSites = map[string]string{
	"internal/modules/audit/retention_service.go#(*RetentionService).purgeTable": "" +
		"retention 逐列清除的唯一原生語句（表名來自 retentionTargets，故以 %s 動態組裝）",
	"internal/modules/audit/retention_checkpoint.go#(*CheckpointPurger).PurgeInterval": "" +
		"區間清除：與 tombstone 簽章同一交易，刪除後才寫 purged_at",
	"internal/modules/audit/retention_checkpoint.go#(*CheckpointPurger).TrimChain": "" +
		"檢查點自身到期修剪：自鏈頭連續刪除，另寫簽章修剪記錄錨定殘鏈",
	"internal/database/migration_source_ip_forensics.go#rollbackSourceIPForensics": "" +
		"migration 20260826_source_ip_forensics 的反序：舊 CHECK 值域不含 new_source_ip，" +
		"約束加不回去之前必須先刪掉該類告警列。**這一處不留 tombstone，是清冊上的誠實債務**——" +
		"它成立的前提是路徑本身：Down 只能由 RollbackMigration 指名版本觸發（開發庫限定），" +
		"生產回退一律還原升級前備份（docs/ops/upgrade-sop.md §4）而不經此函式；" +
		"且同一函式接著 DROP TABLE／DROP COLUMN，屬結構整體回退而非逐列清除——" +
		"回退後那張庫的檢查點鏈本來就不再與回退前的鏈同源",
	"scripts/retention_smoke.go#main": "" +
		"dev 一次性驗證腳本（//go:build ignore，不入產品二進位），只刪自己造的 marker 列。" +
		"仍登記而非排除 build-ignore 檔：排除等於開一扇「加個 build tag 就不受清冊管」的門",
}

// auditRawDeleteTables 觸發登記義務的表名。
//
// 只列「受檢查點鏈或審計完整性保護」的表——本守衛的射程不是「所有 DELETE」，
// 是「刪掉會使證據鏈失去可驗性的那些表」
var auditRawDeleteTables = []string{
	"audit_logs", "audit_checkpoints", "audit_checkpoint_trims",
	"session_commands", "command_alerts", "audit_failures",
}

// TestAuditRawDeleteSitesAreExact 審計類表的原生 SQL 刪除點與清冊逐條相符。
func TestAuditRawDeleteSitesAreExact(t *testing.T) {
	root := lifecycleModuleRoot(t)
	fset := token.NewFileSet()
	scanned := 0
	found := map[string][]string{} // 清冊鍵 → file:line

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "tmp", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("解析 %s 失敗：守衛拒絕在殘缺的 AST 上作判定: %v", rel, perr)
		}
		scanned++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			owner := rel + "#" + funcQualifiedName(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				text, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					text = lit.Value
				}
				if !isAuditRawDelete(text) {
					return true
				}
				found[owner] = append(found[owner],
					rel+":"+itoa(fset.Position(lit.Pos()).Line))
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("掃描失敗: %v", err)
	}

	// 掃描量下界：掃不到檔案時本測會「無違規」而假綠
	if scanned < 200 {
		t.Fatalf("只掃到 %d 個 .go 檔（現況遠多於此）：掃描根或過濾條件已失真", scanned)
	}
	if len(found) < len(auditRawDeleteSites) {
		t.Fatalf("只找到 %d 個原生刪除點（清冊登記 %d）：字面比對條件已失真，本守衛正在放行一切",
			len(found), len(auditRawDeleteSites))
	}

	for owner, sites := range found {
		if _, ok := auditRawDeleteSites[owner]; !ok {
			t.Errorf("未登記的審計類表原生刪除入口 %s（%s）：\n"+
				"  刪列若不經 tombstone 簽章，驗證端無從區分合法清除與竊取。\n"+
				"  若確為必要路徑，登記於 auditRawDeleteSites 並寫明它如何留下可驗證的痕跡",
				owner, strings.Join(sites, "、"))
		}
	}
	missing := []string{}
	for owner := range auditRawDeleteSites {
		if _, ok := found[owner]; !ok {
			missing = append(missing, owner)
		}
	}
	sort.Strings(missing)
	for _, owner := range missing {
		t.Errorf("清冊登記了 %s 但該處已無原生刪除語句：清冊腐爛即等於白名單放行一切，請刪除該條目", owner)
	}
}

// isAuditRawDelete 該字面是否為「對審計類表的原生刪除語句」。
//
// `DELETE FROM %s`（動態表名）一律視為命中：靜態分析判不出它會被填進哪張表，
// 而判不出就必須登記——這個方向的保守是刻意的
func isAuditRawDelete(text string) bool {
	upper := strings.ToUpper(text)
	if !strings.Contains(upper, "DELETE FROM") {
		return false
	}
	if strings.Contains(text, "DELETE FROM %s") || strings.Contains(text, "DELETE FROM \"%s\"") {
		return true
	}
	for _, table := range auditRawDeleteTables {
		if strings.Contains(text, table) {
			return true
		}
	}
	return false
}
