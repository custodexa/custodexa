package audit

import (
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/modules/policy"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// fakeAuditLogger 收集留痕 entries 供斷言
type fakeAuditLogger struct {
	entries []*AuditLogEntry
}

func (f *fakeAuditLogger) Log(entry *AuditLogEntry) {
	f.entries = append(f.entries, entry)
}

// setupRetentionDB timestamptz 欄位 sqlite scan 陷阱：session_commands/command_alerts
// 以原生 SQL 建 datetime 等價表（purge 只走 SQL 層不經 model scan）；
// audit_logs/security_policies 無 timestamptz tag，走 AutoMigrate
func setupRetentionDB(t *testing.T) (*RetentionService, *gorm.DB, *fakeAuditLogger) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, stmt := range []string{
		"CREATE TABLE session_commands (id INTEGER PRIMARY KEY AUTOINCREMENT, executed_at DATETIME NOT NULL)",
		"CREATE TABLE command_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, triggered_at DATETIME NOT NULL)",
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("建表: %v", err)
		}
	}
	audit := &fakeAuditLogger{}
	svc := NewRetentionService(db, policy.NewSecurityPolicyService(db), nil, audit)
	return svc, db, audit
}

func seedRows(t *testing.T, db *gorm.DB, table, timeCol string, age time.Duration, n int) {
	t.Helper()
	ts := time.Now().Add(-age)
	for i := 0; i < n; i++ {
		stmt := fmt.Sprintf("INSERT INTO %s (%s) VALUES (?)", table, timeCol)
		if err := db.Exec(stmt, ts).Error; err != nil {
			t.Fatalf("seed %s: %v", table, err)
		}
	}
}

func countRows(t *testing.T, db *gorm.DB, table string) int64 {
	t.Helper()
	var n int64
	if err := db.Raw("SELECT COUNT(*) FROM " + table).Scan(&n).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestRetentionDefaultNoPurge 出廠預設（0=永久）不刪任何資料
func TestRetentionDefaultNoPurge(t *testing.T) {
	svc, db, audit := setupRetentionDB(t)
	seedRows(t, db, "session_commands", "executed_at", 400*24*time.Hour, 3)

	results := svc.PurgeAll()
	if len(results) != 0 {
		t.Errorf("預設政策下應無清除結果, got %+v", results)
	}
	if n := countRows(t, db, "session_commands"); n != 3 {
		t.Errorf("列數 = %d, want 3（未刪）", n)
	}
	if len(audit.entries) != 0 {
		t.Errorf("無清除不應留痕, got %d entries", len(audit.entries))
	}
}

// TestRetentionPurgeExpired 過期邊界：只刪早於 cutoff 的列，且清除入審計
func TestRetentionPurgeExpired(t *testing.T) {
	svc, db, audit := setupRetentionDB(t)
	seedRows(t, db, "session_commands", "executed_at", 40*24*time.Hour, 3) // 過期
	seedRows(t, db, "session_commands", "executed_at", 10*24*time.Hour, 2) // 未過期
	if _, err := svc.policy.Update(policy.PolicyRetentionSessionCommandDays, "30", "test"); err != nil {
		t.Fatalf("set policy: %v", err)
	}

	results := svc.PurgeAll()
	if len(results) != 1 || results[0].Deleted != 3 || results[0].Partial {
		t.Errorf("results = %+v, want session_commands 刪 3 非 partial", results)
	}
	if n := countRows(t, db, "session_commands"); n != 2 {
		t.Errorf("剩餘列數 = %d, want 2", n)
	}

	// 清除留痕：resource=retention、action=delete、details 含筆數
	if len(audit.entries) != 1 {
		t.Fatalf("留痕數 = %d, want 1", len(audit.entries))
	}
	e := audit.entries[0]
	if e.Resource != model.ResourceRetention || e.Action != model.ActionDelete || e.Status != model.StatusSuccess {
		t.Errorf("留痕欄位錯誤: %+v", e)
	}
	var detail PurgeResult
	if err := json.Unmarshal([]byte(e.Details), &detail); err != nil || detail.Deleted != 3 || detail.Target != "session_commands" {
		t.Errorf("留痕 details = %s, want deleted=3 target=session_commands", e.Details)
	}
}

// TestRetentionBatchLimit 單次上限：達 maxPerRun 即停，標 partial，次輪繼續
func TestRetentionBatchLimit(t *testing.T) {
	svc, db, _ := setupRetentionDB(t)
	svc.batchSize, svc.maxPerRun = 5, 10
	seedRows(t, db, "command_alerts", "triggered_at", 40*24*time.Hour, 12)
	if _, err := svc.policy.Update(policy.PolicyRetentionAlertDays, "30", "test"); err != nil {
		t.Fatalf("set policy: %v", err)
	}

	results := svc.PurgeAll()
	if len(results) != 1 || results[0].Deleted != 10 || !results[0].Partial {
		t.Errorf("results = %+v, want 刪 10 且 partial", results)
	}
	if n := countRows(t, db, "command_alerts"); n != 2 {
		t.Errorf("剩餘 = %d, want 2", n)
	}

	// 次輪清完
	results = svc.PurgeAll()
	if len(results) != 1 || results[0].Deleted != 2 || results[0].Partial {
		t.Errorf("次輪 results = %+v, want 刪 2 非 partial", results)
	}
}

// TestRetentionExactLimitNotPartial 回歸：過期筆數恰等於 maxPerRun
// 時最後一批填滿但已清完，留痕不得誤報 partial（審計軌跡誠實性）
func TestRetentionExactLimitNotPartial(t *testing.T) {
	svc, db, _ := setupRetentionDB(t)
	svc.batchSize, svc.maxPerRun = 5, 10
	seedRows(t, db, "command_alerts", "triggered_at", 40*24*time.Hour, 10) // 恰等於上限
	if _, err := svc.policy.Update(policy.PolicyRetentionAlertDays, "30", "test"); err != nil {
		t.Fatalf("set policy: %v", err)
	}

	results := svc.PurgeAll()
	if len(results) != 1 || results[0].Deleted != 10 || results[0].Partial {
		t.Errorf("results = %+v, want 刪 10 且非 partial（已清完）", results)
	}
	if n := countRows(t, db, "command_alerts"); n != 0 {
		t.Errorf("剩餘 = %d, want 0", n)
	}
}

// TestRetentionPurgeAuditLogs audit_logs 本身可被清除（原生 SQL 繞過 BeforeDelete 守衛），
// 且清除後寫入的留痕列不受影響
func TestRetentionPurgeAuditLogs(t *testing.T) {
	svc, db, audit := setupRetentionDB(t)
	old := time.Now().Add(-400 * 24 * time.Hour)
	for i := 0; i < 4; i++ {
		if err := db.Exec(
			"INSERT INTO audit_logs (created_at, action, resource, status, user_id, username) VALUES (?, 'create', 'asset', 'success', 1, 'admin')",
			old).Error; err != nil {
			t.Fatalf("seed audit_logs: %v", err)
		}
	}
	if _, err := svc.policy.Update(policy.PolicyRetentionAuditLogDays, "365", "test"); err != nil {
		t.Fatalf("set policy: %v", err)
	}

	results := svc.PurgeAll()
	if len(results) != 1 || results[0].Deleted != 4 {
		t.Errorf("results = %+v, want audit_logs 刪 4", results)
	}
	if n := countRows(t, db, "audit_logs"); n != 0 {
		t.Errorf("audit_logs 剩餘 = %d, want 0", n)
	}
	if len(audit.entries) != 1 || !strings.Contains(audit.entries[0].Details, `"audit_logs"`) {
		t.Errorf("留痕缺失或錯誤: %+v", audit.entries)
	}
}

// TestRetentionPurgeAdvancesWatermarks 保留水位由**清除執行本身**前進。
//
// **為什麼不直呼 `Advance`**：既有的水位測試（timeline_service_test.go）全部
// 自行 `wm.Advance(...)` 造資料，驗的是讀取端如何呈現水位；沒有任何一支走過
// 「retention 跑完 → 水位就位」這條生產路徑。缺這一支的代價已實證：
// `SetWatermarks`（原名 `WithWatermarks`）自建立起**全 repo 零呼叫點**，
// `recordWatermark` 因 `s.watermarks == nil` 永遠早退，而全樹測試照樣全綠——
// 工作台於是把真的清除過的區間回成 present＋空白，把「已依政策清除」
// 呈現成「本來就沒發生」，正是這項能力要防止的誤報，方向還反了。
//
// 三條斷言：(1) 未接水位時清除不寫任何列（nil 不得 panic，且冷啟動語義成立）；
// (2) 接上後每個**確有清除**的類別各得一列；(3) 水位上界＝cutoff（now−days）
// 而非 now——上界寫成 now 會把「尚未過期、仍在庫」的區間一併宣稱為已清除。
func TestRetentionPurgeAdvancesWatermarks(t *testing.T) {
	svc, db, _ := setupRetentionDB(t)
	if err := db.AutoMigrate(&model.AuditRetentionWatermark{}); err != nil {
		t.Fatalf("migrate watermark: %v", err)
	}
	seedRows(t, db, "session_commands", "executed_at", 40*24*time.Hour, 3)
	seedRows(t, db, "command_alerts", "triggered_at", 40*24*time.Hour, 2)
	if _, err := svc.policy.UpdateBatch(map[string]string{
		policy.PolicyRetentionSessionCommandDays: "30",
		policy.PolicyRetentionAlertDays:          "30",
	}, "test"); err != nil {
		t.Fatalf("set policy: %v", err)
	}

	wm := NewRetentionWatermarkService(db)

	// (1) 未接水位：跑完一輪清除，水位表必須仍為空
	if results := svc.PurgeAll(); len(results) != 2 {
		t.Fatalf("未接水位的清除結果 = %+v, want 2 類", results)
	}
	before, err := wm.Load()
	if err != nil {
		t.Fatalf("load watermarks: %v", err)
	}
	if len(before) != 0 {
		t.Fatalf("未接水位卻寫入 %d 列：nil 早退失效", len(before))
	}

	// (2)(3) 接上後再跑一輪（資料已清空，但 Deleted=0 的執行同樣要記水位——
	// 「這輪確實掃過並清到 cutoff」與「這輪沒發生」是不同事實）
	seedRows(t, db, "session_commands", "executed_at", 40*24*time.Hour, 3)
	seedRows(t, db, "command_alerts", "triggered_at", 40*24*time.Hour, 2)
	svc.SetWatermarks(wm)
	runAt := time.Now()
	if results := svc.PurgeAll(); len(results) != 2 {
		t.Fatalf("接上水位後的清除結果 = %+v, want 2 類", results)
	}

	after, err := wm.Load()
	if err != nil {
		t.Fatalf("load watermarks: %v", err)
	}
	for _, class := range []model.RetentionClass{
		model.RetentionClassSessionCommand, model.RetentionClassCommandAlert,
	} {
		row, ok := after[class]
		if !ok {
			t.Fatalf("類別 %s 無水位列：retention 執行後水位未前進，"+
				"工作台會把已清除區間呈現為 present＋空白（＝「本來就沒發生」）", class)
		}
		if row.PolicyDays != 30 {
			t.Errorf("%s policy_days = %d, want 30", class, row.PolicyDays)
		}
		if row.Partial {
			t.Errorf("%s partial = true, want false（本輪已清完）", class)
		}
		// 上界必須是 cutoff（runAt−30d）而非 runAt；容許 ±1h 的執行漂移
		wantThrough := runAt.AddDate(0, 0, -30)
		if diff := row.PurgedThroughAt.Sub(wantThrough); diff > time.Hour || diff < -time.Hour {
			t.Errorf("%s purged_through_at = %v, want ≈ %v（cutoff＝now−30d）；"+
				"寫成 now 會把仍在庫的區間一併宣稱為已清除", class, row.PurgedThroughAt, wantThrough)
		}
	}
	// audit_logs 保留天數仍為 0（永久），不得憑空產生水位列
	if _, ok := after[model.RetentionClassAuditLog]; ok {
		t.Errorf("audit_logs 為永久保留卻有水位列：憑空製造「此前已清除」的宣稱")
	}
}
