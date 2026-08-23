package identity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 聚合列的欄位契約（`oidc-auth` spec「OIDC 失敗留痕的欄位完整性與狀態語義」的
// **聚合列例外**段）。
//
// # 為什麼補這一檔
//
// spec 寫「聚合列的路徑、方法與狀態碼 SHALL 留空；SHALL 保留來源位址（取自
// 聚合鍵）、次數與起訖時間」，而現有測試（`internal/api/oidc_abuse_guard_test.go`）
// 是對一個**記錄用替身** sink 斷言，只看得到 event／ip／count／status——落地成
// 資料列之後那四個欄位長什麼樣，整段例外**沒有任何斷言**。
// 行為早已實作，缺的是驗證：沒有斷言的規格條文與「還沒做」在證據上無從分辨。
//
// # 為什麼「留空」是實質而非省事
//
// 一個聚合列涵蓋一個時間窗內的多個請求。結清該窗的請求並非事主——把它的路徑、
// 方法、狀態碼填上去，等於宣稱這一列描述的是**那一個**請求，稽核追過去會追到
// 一個無辜的時間點。來源位址則相反：它是聚合鍵本身，必須保留，否則整列失去歸戶。
//
// # 突變自檢
//
// 於 `LogAggregatedFailure` 補上 `Path`／`Method`／`StatusCode` 任一欄 ⇒ 本檔
// 「三欄留空」格轉紅；拿掉 details 的 `count`／`first_at`／`last_at` 任一鍵，
// 或改以「結清當下的請求位址」取代聚合鍵 ⇒ 「來源與計數保留」格轉紅。

// newAggregateRowAuditDB 最小落地面：真 `AuditLogService` ＋ 真 sqlite。
// 替身 sink 看不到列上的欄位，而本檔要驗的正是列。
func newAggregateRowAuditDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// 單連線：sqlite :memory: 每條連線是各自獨立的庫（既有 flaky 真因 ff51836）
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	return db
}

// writeAggregateRow 走生產路徑落一筆聚合列並讀回。
// 審計服務刻意同步（`AsyncAuditEnabled: false`）：非同步下「等不到」與「根本沒寫」
// 在失敗訊息上無從分辨。
func writeAggregateRow(t *testing.T, event, keyIP string,
	status model.AuditStatus, count int, firstAt, lastAt time.Time) model.AuditLog {
	t.Helper()
	db := newAggregateRowAuditDB(t)
	svc := NewOIDCLoginService(db, nil, nil, nil, audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	}))
	svc.LogAggregatedFailure(event, keyIP, status, count, firstAt, lastAt)

	var rows []model.AuditLog
	if err := db.Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("查 audit_logs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("聚合列 = %d 列, want 1（0＝結清後什麼都沒落，>1＝一個窗落了多列）", len(rows))
	}
	return rows[0]
}

// TestOIDCAggregateRowLeavesRequestScopedColumnsEmpty 聚合列的三個「單一請求」欄位必須留空。
func TestOIDCAggregateRowLeavesRequestScopedColumnsEmpty(t *testing.T) {
	first := time.Date(2026, 8, 14, 3, 0, 0, 0, time.UTC)
	last := first.Add(90 * time.Second)
	row := writeAggregateRow(t, "oidc_callback_rate_limited", "198.51.100.7",
		model.StatusDenied, 42, first, last)

	if row.Path != "" {
		t.Errorf("path = %q, want 空。一個窗涵蓋多個請求，填上結清那一發的路徑"+
			"等於宣稱本列描述的是那一個請求", row.Path)
	}
	if row.Method != "" {
		t.Errorf("method = %q, want 空（理由同 path）", row.Method)
	}
	if row.StatusCode != 0 {
		t.Errorf("status_code = %d, want 0（理由同 path）", row.StatusCode)
	}
}

// TestOIDCAggregateRowKeepsSourceCountAndWindow 聚合列必須保留來源、次數與起訖。
//
// 這是「留空」的另一半：三欄留空不是因為聚合列可以少寫東西，而是因為它換了一組
// 欄位承載事實。少了任何一項，聚合列就退化成「某處發生過一些失敗」——
// 有界的代價換到的偵測價值歸零。
func TestOIDCAggregateRowKeepsSourceCountAndWindow(t *testing.T) {
	const keyIP = "198.51.100.7"
	first := time.Date(2026, 8, 14, 3, 0, 0, 0, time.UTC)
	last := first.Add(90 * time.Second)
	row := writeAggregateRow(t, "oidc_callback_rate_limited", keyIP,
		model.StatusDenied, 42, first, last)

	// 來源位址取**聚合鍵**：結清該窗的請求可能來自別處，拿它的脈絡蓋上去是錯的歸屬
	if row.ClientIP != keyIP {
		t.Errorf("client_ip = %q, want %q（來源位址須取自聚合鍵，非結清當下的請求）",
			row.ClientIP, keyIP)
	}
	if row.Resource != model.ResourceAuth {
		t.Errorf("resource = %q, want %q（認證流程的結果，不是對某個使用者資源的操作）",
			row.Resource, model.ResourceAuth)
	}
	if row.Action != model.ActionLogin {
		t.Errorf("action = %q, want %q", row.Action, model.ActionLogin)
	}
	if row.Status != model.StatusDenied {
		t.Errorf("status = %q, want %q（限流拒絕屬授權拒絕，由呼叫端給定）",
			row.Status, model.StatusDenied)
	}

	var d map[string]any
	if err := json.Unmarshal([]byte(row.Details), &d); err != nil {
		t.Fatalf("details 應為合法 JSON，實得 %q: %v", row.Details, err)
	}
	if got, _ := d["event"].(string); got != "oidc_abuse_aggregate" {
		t.Errorf("details.event = %q, want oidc_abuse_aggregate（聚合列與逐筆列必須分得出來）", got)
	}
	if got, _ := d["reason"].(string); got != "oidc_callback_rate_limited" {
		t.Errorf("details.reason = %q, want oidc_callback_rate_limited", got)
	}
	if got, _ := d["count"].(float64); int(got) != 42 {
		t.Errorf("details.count = %v, want 42（沒有次數，聚合列答不出「敲了幾次」）", d["count"])
	}
	if got, _ := d["client_ip"].(string); got != keyIP {
		t.Errorf("details.client_ip = %q, want %q", got, keyIP)
	}
	// 起訖時間：以 RFC3339／UTC 落地，兩者不得相同（那會使窗長度消失）
	gotFirst, _ := d["first_at"].(string)
	gotLast, _ := d["last_at"].(string)
	if gotFirst != first.UTC().Format(time.RFC3339) {
		t.Errorf("details.first_at = %q, want %q", gotFirst, first.UTC().Format(time.RFC3339))
	}
	if gotLast != last.UTC().Format(time.RFC3339) {
		t.Errorf("details.last_at = %q, want %q", gotLast, last.UTC().Format(time.RFC3339))
	}
	if gotFirst == gotLast {
		t.Errorf("first_at 與 last_at 相同（%q）：窗的長度消失，"+
			"「三分鐘內敲 42 次」與「三天內敲 42 次」變成同一件事", gotFirst)
	}
}
