package database

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// TestReleaseModeDoesNotLogSQL 釘住「release 模式的資料庫日誌不逐條輸出 SQL」的組裝。
//
// 非 release 的日誌會把每一條 SQL 連同參數值寫到 stdout；稽核內容與憑證欄位因此會被複寫到
// 保留政策與完整性控制之外。把組裝改回無條件的 Info 只是一行的事，其他測試不會轉紅。
// 行為面（實際輸出）由 TestGormLoggerReleaseOmitsParameterValues 驗證。
func TestReleaseModeDoesNotLogSQL(t *testing.T) {
	src, err := os.ReadFile("database.go")
	if err != nil {
		t.Fatalf("讀取 database.go 失敗: %v", err)
	}
	code := string(src)

	if !strings.Contains(code, "NewGormLogger(cfg.IsReleaseMode()") {
		t.Error("正式組裝未以部署模式決定資料庫日誌：InitDatabase 應經 NewGormLogger(cfg.IsReleaseMode(), ...)")
	}
	if strings.Contains(code, "logger.Default.LogMode(logger.Info)") {
		t.Error("偵測到無條件的 logger.Info 寫死")
	}
}

// openLoggedSQLite 以指定模式的資料庫日誌開一個記憶體資料庫，日誌寫進 buf。
// 建一張帶檢查條件的表，用來刻意造出失敗的 INSERT。
func openLoggedSQLite(t *testing.T, release bool, buf *bytes.Buffer) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), NewGormConfig(NewGormLogger(release, buf)))
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.Exec(`CREATE TABLE zz_log_probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL CHECK (value NOT LIKE 'reject-%'))`).Error; err != nil {
		t.Fatalf("建表: %v", err)
	}
	buf.Reset()
	return db
}

type zzLogProbe struct {
	ID    uint
	Value string
}

func (zzLogProbe) TableName() string { return "zz_log_probe" }

// TestGormLoggerReleaseOmitsParameterValues release 模式的資料庫日誌：成功的語句不輸出；
// 失敗的語句輸出錯誤與帶佔位符的 SQL，但不帶參數值。非 release 帶參數值（對照組，
// 證明這裡觀察的確實是資料庫日誌的輸出）。
func TestGormLoggerReleaseOmitsParameterValues(t *testing.T) {
	const okValue = "zz-ok-marker-6f1d"
	const rejectValue = "reject-zz-marker-93ab"

	t.Run("release", func(t *testing.T) {
		var buf bytes.Buffer
		db := openLoggedSQLite(t, true, &buf)
		if err := db.Create(&zzLogProbe{Value: okValue}).Error; err != nil {
			t.Fatalf("PRECONDITION: 合格的寫入應成功: %v", err)
		}
		if err := db.Create(&zzLogProbe{Value: rejectValue}).Error; err == nil {
			t.Fatalf("PRECONDITION: 違反檢查條件的寫入應失敗")
		}
		out := buf.String()
		if !strings.Contains(out, "zz_log_probe") {
			t.Fatalf("PRECONDITION: 失敗的語句應留下錯誤日誌（含表名），實際輸出:\n%s", out)
		}
		if strings.Contains(out, rejectValue) {
			t.Errorf("release 模式的錯誤日誌帶出了參數值")
		}
		if strings.Contains(out, okValue) {
			t.Errorf("release 模式輸出了成功語句的參數值")
		}
	})

	t.Run("non_release_control", func(t *testing.T) {
		var buf bytes.Buffer
		db := openLoggedSQLite(t, false, &buf)
		if err := db.Create(&zzLogProbe{Value: okValue}).Error; err != nil {
			t.Fatalf("PRECONDITION: 合格的寫入應成功: %v", err)
		}
		if !strings.Contains(buf.String(), okValue) {
			t.Fatalf("對照組：非 release 模式應逐條輸出含參數值的 SQL，實際輸出:\n%s", buf.String())
		}
	})
}
