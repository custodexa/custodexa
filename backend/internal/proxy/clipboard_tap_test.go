package proxy

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/guacamole"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupClipboardDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// `:memory:` 的每條連線是**各自獨立的空 DB**。ClipboardTap 的寫入在另一個
	// goroutine，連線池一旦開出第二條連線，該次寫入就落到沒有 clipboard_events
	// 表的新 DB，測試看到 0 筆事件。全套件併發較高時必現（曾被誤判為計時 flaky）。
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取得 sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	if err := db.AutoMigrate(&model.ClipboardEvent{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func inst(opcode string, args ...string) *guacamole.Instruction {
	return &guacamole.Instruction{Opcode: opcode, Args: args}
}

func waitEvents(t *testing.T, db *gorm.DB, want int) []model.ClipboardEvent {
	t.Helper()
	var events []model.ClipboardEvent
	for i := 0; i < 50; i++ {
		db.Order("id").Find(&events)
		if len(events) >= want {
			return events
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("events = %d, want %d", len(events), want)
	return nil
}

func TestClipboardTapReassembly(t *testing.T) {
	db := setupClipboardDB(t)
	tap := NewClipboardTap(db, 42, "send")

	payload := base64.StdEncoding.EncodeToString([]byte("secret-paste"))
	tap.Observe(inst("clipboard", "3", "text/plain"))
	tap.Observe(inst("blob", "3", payload))
	tap.Observe(inst("end", "3"))

	events := waitEvents(t, db, 1)
	if events[0].SessionID != 42 || events[0].Direction != "send" {
		t.Errorf("event meta = %+v", events[0])
	}
	if events[0].Content != "secret-paste" {
		t.Errorf("content = %q", events[0].Content)
	}
}

func TestClipboardTapIgnoresNonText(t *testing.T) {
	db := setupClipboardDB(t)
	tap := NewClipboardTap(db, 42, "recv")

	tap.Observe(inst("clipboard", "1", "image/png"))
	tap.Observe(inst("blob", "1", base64.StdEncoding.EncodeToString([]byte{1, 2, 3})))
	tap.Observe(inst("end", "1"))
	// 其他 opcode 無作用
	tap.Observe(inst("mouse", "1", "2"))

	time.Sleep(50 * time.Millisecond)
	var count int64
	db.Model(&model.ClipboardEvent{}).Count(&count)
	if count != 0 {
		t.Errorf("non-text should not persist, got %d", count)
	}
}

func TestClipboardTapTruncates(t *testing.T) {
	db := setupClipboardDB(t)
	tap := NewClipboardTap(db, 42, "send")

	big := strings.Repeat("A", 40*1024)
	tap.Observe(inst("clipboard", "9", "text/plain"))
	tap.Observe(inst("blob", "9", base64.StdEncoding.EncodeToString([]byte(big))))
	tap.Observe(inst("blob", "9", base64.StdEncoding.EncodeToString([]byte(big)))) // 累計 80KB > 64KB
	tap.Observe(inst("end", "9"))

	events := waitEvents(t, db, 1)
	if len(events[0].Content) != clipboardMaxBytes {
		t.Errorf("content len = %d, want %d", len(events[0].Content), clipboardMaxBytes)
	}
}
