package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync/atomic"
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

// stubClipboardEncrypt 可觀察、可注入失敗的加密器。
// calls 證明注入點真的走到——失敗態測試若沒有這個計數，
// 「沒明文落庫」分不出是加密路徑真的走到並失敗，還是前置早退根本沒進來。
type stubClipboardEncrypt struct {
	calls atomic.Int64
	err   error
}

func (s *stubClipboardEncrypt) fn() ClipboardEncryptor {
	return func(_ context.Context, plaintext string) (string, error) {
		s.calls.Add(1)
		if s.err != nil {
			return "", s.err
		}
		return "enc:test:" + base64.StdEncoding.EncodeToString([]byte(plaintext)), nil
	}
}

func stubDecrypt(t *testing.T, enc string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(enc, "enc:test:"))
	if err != nil {
		t.Fatalf("stub 密文格式不符: %q (%v)", enc, err)
	}
	return string(raw)
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

// TestClipboardTapReassembly 重組後**密文**落庫：DB 直查不見明文、
// content_length 與 content_status 為事實欄
func TestClipboardTapReassembly(t *testing.T) {
	db := setupClipboardDB(t)
	enc := &stubClipboardEncrypt{}
	tap := NewClipboardTap(db, enc.fn(), 42, "send")

	payload := base64.StdEncoding.EncodeToString([]byte("secret-paste"))
	tap.Observe(inst("clipboard", "3", "text/plain"))
	tap.Observe(inst("blob", "3", payload))
	tap.Observe(inst("end", "3"))

	events := waitEvents(t, db, 1)
	ev := events[0]
	if ev.SessionID != 42 || ev.Direction != "send" {
		t.Errorf("event meta = %+v", ev)
	}
	if ev.ContentStatus != model.ClipboardContentAvailable {
		t.Errorf("content_status = %q, want %q", ev.ContentStatus, model.ClipboardContentAvailable)
	}
	if ev.ContentLength != len("secret-paste") {
		t.Errorf("content_length = %d, want %d", ev.ContentLength, len("secret-paste"))
	}
	// 落庫即密文：content_enc 不得等於明文，且經 stub 解密可還原
	if ev.ContentEnc == "secret-paste" || strings.Contains(ev.ContentEnc, "secret-paste") {
		t.Fatalf("content_enc 含明文: %q", ev.ContentEnc)
	}
	if got := stubDecrypt(t, ev.ContentEnc); got != "secret-paste" {
		t.Errorf("解密回讀 = %q, want %q", got, "secret-paste")
	}
	// DB 原始列層級再驗一次：任何欄位都不得殘留明文
	var raw []map[string]interface{}
	if err := db.Raw("SELECT * FROM clipboard_events").Scan(&raw).Error; err != nil {
		t.Fatalf("raw scan: %v", err)
	}
	for col, val := range raw[0] {
		if s, ok := val.(string); ok && strings.Contains(s, "secret-paste") {
			t.Errorf("DB 欄位 %s 殘留明文: %q", col, s)
		}
	}
}

// TestClipboardTapEncryptFailureLeavesGapRecord 加密失敗＝缺口紀錄：
// 事實齊（會話、方向、長度、時間）、內容缺席、失敗標記；不明文降級、
// 不整筆丟棄。注入點走到以 stub 計數為證。
func TestClipboardTapEncryptFailureLeavesGapRecord(t *testing.T) {
	db := setupClipboardDB(t)
	enc := &stubClipboardEncrypt{err: errors.New("kek unavailable (injected)")}
	tap := NewClipboardTap(db, enc.fn(), 77, "recv")

	tap.Observe(inst("clipboard", "1", "text/plain"))
	tap.Observe(inst("blob", "1", base64.StdEncoding.EncodeToString([]byte("doomed-content"))))
	tap.Observe(inst("end", "1"))

	events := waitEvents(t, db, 1)
	if enc.calls.Load() == 0 {
		t.Fatal("加密注入點未走到（stub 零呼叫）——本測試失去證明力")
	}
	ev := events[0]
	if ev.ContentStatus != model.ClipboardContentFailed {
		t.Errorf("content_status = %q, want %q（缺口失敗標記）", ev.ContentStatus, model.ClipboardContentFailed)
	}
	if ev.ContentEnc != "" {
		t.Errorf("缺口紀錄的 content_enc 應缺席（空），got %q", ev.ContentEnc)
	}
	if ev.SessionID != 77 || ev.Direction != "recv" || ev.ContentLength != len("doomed-content") {
		t.Errorf("缺口紀錄事實欄不齊: %+v", ev)
	}
	// 不明文降級：整列任何欄位不得含明文
	var raw []map[string]interface{}
	if err := db.Raw("SELECT * FROM clipboard_events").Scan(&raw).Error; err != nil {
		t.Fatalf("raw scan: %v", err)
	}
	for col, val := range raw[0] {
		if s, ok := val.(string); ok && strings.Contains(s, "doomed-content") {
			t.Errorf("DB 欄位 %s 殘留明文（明文降級）: %q", col, s)
		}
	}
	// 會話不中斷：同一 tap 再觀察一筆仍正常運作（Observe 未 panic、未失能）
	enc.err = nil
	tap.Observe(inst("clipboard", "2", "text/plain"))
	tap.Observe(inst("blob", "2", base64.StdEncoding.EncodeToString([]byte("after-failure"))))
	tap.Observe(inst("end", "2"))
	events = waitEvents(t, db, 2)
	if events[1].ContentStatus != model.ClipboardContentAvailable {
		t.Errorf("失敗後續留存應恢復 available，got %q", events[1].ContentStatus)
	}
}

// TestClipboardTapNilEncryptorLeavesGap 組裝缺線（encrypt=nil）視同加密不可用：
// 留缺口、不明文降級
func TestClipboardTapNilEncryptorLeavesGap(t *testing.T) {
	db := setupClipboardDB(t)
	tap := NewClipboardTap(db, nil, 5, "send")

	tap.Observe(inst("clipboard", "1", "text/plain"))
	tap.Observe(inst("blob", "1", base64.StdEncoding.EncodeToString([]byte("no-encryptor"))))
	tap.Observe(inst("end", "1"))

	events := waitEvents(t, db, 1)
	if events[0].ContentStatus != model.ClipboardContentFailed || events[0].ContentEnc != "" {
		t.Errorf("nil 加密器應留缺口: %+v", events[0])
	}
}

func TestClipboardTapIgnoresNonText(t *testing.T) {
	db := setupClipboardDB(t)
	enc := &stubClipboardEncrypt{}
	tap := NewClipboardTap(db, enc.fn(), 42, "recv")

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
	enc := &stubClipboardEncrypt{}
	tap := NewClipboardTap(db, enc.fn(), 42, "send")

	big := strings.Repeat("A", 40*1024)
	tap.Observe(inst("clipboard", "9", "text/plain"))
	tap.Observe(inst("blob", "9", base64.StdEncoding.EncodeToString([]byte(big))))
	tap.Observe(inst("blob", "9", base64.StdEncoding.EncodeToString([]byte(big)))) // 累計 80KB > 64KB
	tap.Observe(inst("end", "9"))

	events := waitEvents(t, db, 1)
	if events[0].ContentLength != clipboardMaxBytes {
		t.Errorf("content_length = %d, want %d", events[0].ContentLength, clipboardMaxBytes)
	}
	if got := stubDecrypt(t, events[0].ContentEnc); len(got) != clipboardMaxBytes {
		t.Errorf("解密回讀長度 = %d, want %d", len(got), clipboardMaxBytes)
	}
}
