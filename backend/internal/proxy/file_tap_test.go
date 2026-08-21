package proxy

import (
	"encoding/base64"
	"github.com/custodexa/backend/internal/modules/audit"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupFileTapDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}, &model.User{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// b64 以 base64 包裝 payload（模擬 guac blob）
func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// waitAuditCount 輪詢等待非同步審計入庫（record 走 goroutine）
func waitAuditCount(t *testing.T, db *gorm.DB, want int64) int64 {
	t.Helper()
	var count int64
	for i := 0; i < 50; i++ {
		db.Model(&model.AuditLog{}).Where("action = ?", model.ActionFileUpload).Count(&count)
		if count >= want {
			return count
		}
		time.Sleep(20 * time.Millisecond)
	}
	return count
}

// TestFileTapRecordsUpload put→blob→end 完整序列寫一筆 file_upload 審計，含檔名與大小
func TestFileTapRecordsUpload(t *testing.T) {
	db := setupFileTapDB(t)
	db.Create(&model.User{Username: "alice"}) // id 1
	aid := uint(7)
	tap := NewFileTap(db, audit.NewDirectSink(db), 100, 1, &aid, "vnc")

	tap.Observe(inst("put", "0", "s1", "text/plain", "report.txt"))
	tap.Observe(inst("blob", "s1", b64("hello")))
	tap.Observe(inst("blob", "s1", b64("world")))
	tap.Observe(inst("end", "s1"))

	if got := waitAuditCount(t, db, 1); got != 1 {
		t.Fatalf("審計筆數 = %d, want 1", got)
	}
	var entry model.AuditLog
	db.Where("action = ?", model.ActionFileUpload).First(&entry)
	if entry.Path != "report.txt" {
		t.Errorf("檔名 = %q, want report.txt", entry.Path)
	}
	if entry.Username != "alice" {
		t.Errorf("username = %q, want alice（反查）", entry.Username)
	}
	if entry.ResourceID == nil || *entry.ResourceID != 7 {
		t.Errorf("assetID 未帶入")
	}
	// details 應含 size:10（hello+world）與 via:guac-sftp
	if !contains(entry.Details, `"size":10`) || !contains(entry.Details, `"via":"guac-sftp"`) {
		t.Errorf("details 內容錯誤: %s", entry.Details)
	}
}

// TestFileTapRdpVia RDP 協議標記為 guac-drive
func TestFileTapRdpVia(t *testing.T) {
	db := setupFileTapDB(t)
	db.Create(&model.User{Username: "bob"})
	tap := NewFileTap(db, audit.NewDirectSink(db), 101, 1, nil, "rdp")
	tap.Observe(inst("put", "0", "s2", "application/octet-stream", "a.bin"))
	tap.Observe(inst("blob", "s2", b64("x")))
	tap.Observe(inst("end", "s2"))
	waitAuditCount(t, db, 1)
	var entry model.AuditLog
	db.Where("action = ?", model.ActionFileUpload).First(&entry)
	if !contains(entry.Details, `"via":"guac-drive"`) {
		t.Errorf("RDP via 應為 guac-drive: %s", entry.Details)
	}
}

// TestFileTapIgnoresUnrelated 非上傳指令與未知 stream 不產生審計
func TestFileTapIgnoresUnrelated(t *testing.T) {
	db := setupFileTapDB(t)
	db.Create(&model.User{Username: "carol"})
	tap := NewFileTap(db, audit.NewDirectSink(db), 102, 1, nil, "vnc")
	// 沒有 put 先開流，blob/end 應被忽略
	tap.Observe(inst("blob", "sX", b64("orphan")))
	tap.Observe(inst("end", "sX"))
	tap.Observe(inst("mouse", "10", "20"))
	if got := waitAuditCount(t, db, 1); got != 0 {
		t.Errorf("不應產生審計, got %d", got)
	}
}

// TestFileTapNilSafe nil / 無 session 安全 no-op
func TestFileTapNilSafe(t *testing.T) {
	var tap *FileTap
	tap.Observe(inst("put", "0", "s", "m", "n")) // 不 panic
	empty := &FileTap{}
	empty.Observe(inst("put", "0", "s", "m", "n")) // db nil → no-op
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
