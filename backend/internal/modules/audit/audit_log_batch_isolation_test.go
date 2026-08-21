package audit

// 批次寫入的失敗隔離守衛（audit-coverage-closure 批 1-R，缺陷 F1 第二層）。
//
// # 釘的是什麼
//
// 審計走非同步批次，而多列 INSERT 是**單一語句**：任一列違反欄位約束，整批
// 一起回滾。實測 9 發 401 中夾 1 發超長路徑 → 入庫 3/9，6 列合法審計列被連帶
// 沖掉。批 1 讓這條路徑變成**零憑證即可觸發**，於是「夾帶一發畸形請求，把同批
// 的真實攻擊記錄一併抹掉」成為可行的清除證據手段。
//
// 第一層（欄位收口，`model.BoundAuditLogFields`）讓審計列不再產生超界欄位；
// 本層釘的是**縱深**：任何來源的任何約束違反，都不得使同批其他列一併丟失。
//
// # 突變自檢
//
//	flushBatch 拿掉 retryRowsIndividually（失敗即整批降級）
//	  → TestFlushBatchIsolatesConstraintViolatingRow 轉紅（入庫 0 列而非 4 列）
//	retryRowsIndividually 改為「一失敗就中止剩餘重試」
//	  → 同上轉紅（違規列之後的合法列不會入庫）
//	dropped 計數改回整批筆數
//	  → TestFlushBatchReportsOnlyActuallyDroppedRows 轉紅

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// installBatchIsolationDB 裝一個最小的 database.DB。
// sqlite `:memory:` 每條新連線是獨立的空 DB，連線池必須收到 1
func installBatchIsolationDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取底層 sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	return db
}

// batchRow 一列合法的審計列
func batchRow(path string) *model.AuditLog {
	return &model.AuditLog{
		Action: model.ActionLogin, Resource: model.ResourceAuth,
		Status: model.StatusFailure, Method: "GET", Path: path,
		ClientIP: "203.0.113.9", StatusCode: 401,
	}
}

// violatingRow 一列必然違反約束的列。
//
// **以唯一索引製造違約而非超長欄位**：sqlite 完全不強制 varchar 長度，拿長度
// 當觸發器的測試在 sqlite 下恆為綠（假綠）。唯一索引在 sqlite 與 Postgres 上
// 行為一致，且它證明的正是本測試要證明的事——「任何來源的約束違反都不得
// 波及同批其他列」，不限於長度那一種
func violatingRow(dup string) *model.AuditLog {
	r := batchRow("/api/v1/duplicate")
	r.IdempotencyUUID = &dup
	return r
}

func newBatchService(t *testing.T, fallbackDir string) *AuditLogService {
	t.Helper()
	if fallbackDir != "" {
		t.Setenv("AUDIT_LOG_PATH", fallbackDir)
	}
	return NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled:     true,
		AsyncAuditEnabled:   false, // 不啟 worker：本測試直接驅動 flushBatch
		AuditFallbackToFile: fallbackDir != "",
	})
}

func countBatchIsolationRows(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Unscoped().Model(&model.AuditLog{}).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestFlushBatchIsolatesConstraintViolatingRow 一列違約不得使同批其他列一併丟失。
//
// 這是驗收條件 1 的機械化：批次裡混一列寫不進去的，其餘列必須照樣入庫。
func TestFlushBatchIsolatesConstraintViolatingRow(t *testing.T) {
	db := installBatchIsolationDB(t)
	svc := newBatchService(t, "")

	// 先種一列佔住冪等鍵，使批次裡的同鍵列必然違約
	dup := "batch-isolation-duplicate-key"
	seed := batchRow("/api/v1/seed")
	seed.IdempotencyUUID = &dup
	if err := db.Create(seed).Error; err != nil {
		t.Fatalf("種子列: %v", err)
	}

	batch := []*model.AuditLog{
		batchRow("/api/v1/first"),
		batchRow("/api/v1/second"),
		violatingRow(dup), // 夾在中間：違約列之後的列也必須入庫
		batchRow("/api/v1/fourth"),
		batchRow("/api/v1/fifth"),
	}

	svc.flushBatch(0, batch)

	// 種子 1 ＋ 合法 4 ＝ 5；隔離失效時只有種子那 1 列
	if got := countBatchIsolationRows(t, db); got != 5 {
		t.Fatalf("入庫 %d 列，應為 5（種子 1 ＋ 批內合法 4）——"+
			"一列違約使同批合法審計列一併丟失時，攻擊者可夾帶一發畸形請求"+
			"把同批的真實攻擊記錄一起沖掉", got)
	}
	for _, p := range []string{"/api/v1/first", "/api/v1/second", "/api/v1/fourth", "/api/v1/fifth"} {
		var n int64
		db.Unscoped().Model(&model.AuditLog{}).Where("path = ?", p).Count(&n)
		if n != 1 {
			t.Errorf("%s 未入庫（%d 列）", p, n)
		}
	}
}

// TestFlushBatchReportsOnlyActuallyDroppedRows 遺失計數與降級落檔只涵蓋
// **真正沒進去**的列。
//
// 隔離之後「整批筆數」與「遺失筆數」不再相等，報整批等於把已入庫的列謊報為
// 遺失——失效告警的數字一旦不可信，稽核就無法據以判斷損失範圍。
func TestFlushBatchReportsOnlyActuallyDroppedRows(t *testing.T) {
	db := installBatchIsolationDB(t)
	dir := t.TempDir()
	svc := newBatchService(t, dir)

	dup := "batch-isolation-fallback-key"
	seed := batchRow("/api/v1/seed")
	seed.IdempotencyUUID = &dup
	if err := db.Create(seed).Error; err != nil {
		t.Fatalf("種子列: %v", err)
	}

	batch := []*model.AuditLog{
		batchRow("/api/v1/kept-one"),
		violatingRow(dup),
		batchRow("/api/v1/kept-two"),
	}
	svc.flushBatch(0, batch)

	if got := countBatchIsolationRows(t, db); got != 3 {
		t.Fatalf("入庫 %d 列，應為 3（種子 1 ＋ 批內合法 2）", got)
	}

	lines := readFallbackLines(t, dir)
	if len(lines) != 1 {
		t.Fatalf("降級檔案有 %d 列，應恰為 1（只有真正寫不進去的那列）——"+
			"把已入庫的列也寫進降級檔會製造重複事件", len(lines))
	}
	if !strings.Contains(lines[0], "/api/v1/duplicate") {
		t.Errorf("降級檔案落的不是違約列：%s", lines[0])
	}
}

// TestFlushBatchSucceedsWithoutRetry 正常路徑不得受隔離機制影響：全批合法時
// 一次寫入即完成，不落降級檔。
func TestFlushBatchSucceedsWithoutRetry(t *testing.T) {
	db := installBatchIsolationDB(t)
	dir := t.TempDir()
	svc := newBatchService(t, dir)

	batch := []*model.AuditLog{
		batchRow("/api/v1/ok-one"),
		batchRow("/api/v1/ok-two"),
	}
	rest := svc.flushBatch(0, batch)

	if got := countBatchIsolationRows(t, db); got != 2 {
		t.Fatalf("入庫 %d 列，應為 2", got)
	}
	if len(rest) != 0 {
		t.Errorf("flushBatch 應回傳清空後的 slice，實得長度 %d", len(rest))
	}
	if lines := readFallbackLines(t, dir); len(lines) != 0 {
		t.Errorf("全批成功卻落了 %d 列降級檔", len(lines))
	}
}

func readFallbackLines(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("讀降級目錄: %v", err)
	}
	var out []string
	for _, e := range entries {
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("開降級檔: %v", err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				out = append(out, line)
			}
		}
		f.Close()
	}
	return out
}
