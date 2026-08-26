package session

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 剪貼簿明文欄 → 加密欄轉換的三個面：
// 舊形狀轉換成功（回填可解密、明文欄消失）、回填失敗 fail-close（不刪欄、
// 明文原樣保留，注入點以計數為證）、終態冪等 no-op。

func setupOldShapeDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取得 sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	// 舊形狀（baseline 壓縮後、本 change 前）：明文 content 欄
	if err := db.Exec(`CREATE TABLE clipboard_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id INTEGER NOT NULL,
		direction VARCHAR(8) NOT NULL,
		content TEXT,
		created_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("建舊形狀表: %v", err)
	}
	return db
}

type migrationStubCodec struct {
	encryptCalls int
	encryptErr   error
}

func (s *migrationStubCodec) EncryptFor(_ context.Context, _ crypto.CipherRef, plaintext string) (string, error) {
	s.encryptCalls++
	if s.encryptErr != nil {
		return "", s.encryptErr
	}
	return "enc:test:" + plaintext, nil
}

func (s *migrationStubCodec) DecryptFor(_ context.Context, _ crypto.CipherRef, ciphertext string) (string, error) {
	return strings.TrimPrefix(ciphertext, "enc:test:"), nil
}

// bareContentColRe 與轉換實作同語義的裸 `content` 欄判定（測試自持一份，
// 實作版已內聯進 clipboardPlaintextColumnExists）
var bareContentColRe = regexp.MustCompile(`\bcontent\b`)

func clipboardColumns(t *testing.T, db *gorm.DB) map[string]bool {
	t.Helper()
	var ddl string
	if err := db.Raw(`SELECT sql FROM sqlite_master WHERE type='table' AND name='clipboard_events'`).
		Scan(&ddl).Error; err != nil {
		t.Fatalf("讀表定義: %v", err)
	}
	cols := map[string]bool{}
	for _, name := range []string{"content_enc", "content_length", "content_status"} {
		cols[name] = strings.Contains(ddl, name)
	}
	cols["content"] = bareContentColRe.MatchString(ddl)
	return cols
}

func TestClipboardMigrationConvertsOldShape(t *testing.T) {
	db := setupOldShapeDB(t)
	for _, row := range []struct {
		session uint
		dir     string
		content string
	}{{10, "send", "legacy-secret-one"}, {10, "recv", "legacy-secret-two"}} {
		if err := db.Exec(`INSERT INTO clipboard_events (session_id, direction, content) VALUES (?, ?, ?)`,
			row.session, row.dir, row.content).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	codec := &migrationStubCodec{}

	if err := runClipboardContentEncryption(db, codec); err != nil {
		t.Fatalf("轉換失敗: %v", err)
	}

	cols := clipboardColumns(t, db)
	if cols["content"] {
		t.Error("明文 content 欄應已移除")
	}
	for _, c := range []string{"content_enc", "content_length", "content_status"} {
		if !cols[c] {
			t.Errorf("缺新欄 %s", c)
		}
	}
	type outRow struct {
		ContentEnc    string
		ContentLength int
		ContentStatus string
	}
	var rows []outRow
	if err := db.Raw(`SELECT content_enc, content_length, content_status FROM clipboard_events ORDER BY id`).
		Scan(&rows).Error; err != nil {
		t.Fatalf("讀回: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("列數 = %d, want 2（不整筆丟棄）", len(rows))
	}
	wants := []string{"legacy-secret-one", "legacy-secret-two"}
	for i, r := range rows {
		if r.ContentStatus != "available" || r.ContentLength != len(wants[i]) {
			t.Errorf("row%d 事實欄不符: %+v", i, r)
		}
		if got, _ := codec.DecryptFor(context.Background(), crypto.CipherRef{}, r.ContentEnc); got != wants[i] {
			t.Errorf("row%d 解密回讀 = %q, want %q", i, got, wants[i])
		}
		if strings.Contains(r.ContentEnc, wants[i]) && !strings.HasPrefix(r.ContentEnc, "enc:test:") {
			t.Errorf("row%d 疑似明文殘留: %q", i, r.ContentEnc)
		}
	}

	// 冪等：終態下再跑一次為 no-op（codec 不再被呼叫）
	before := codec.encryptCalls
	if err := runClipboardContentEncryption(db, codec); err != nil {
		t.Fatalf("冪等重跑失敗: %v", err)
	}
	if codec.encryptCalls != before {
		t.Errorf("終態重跑不應再加密（%d → %d）", before, codec.encryptCalls)
	}
}

// TestClipboardMigrationBackfillFailureKeepsPlaintextColumn fail-close：
// 回填失敗 → 中止不刪欄、整段回滾（新欄也不殘留）、明文原樣可讀。
// 注入點走到以 encryptCalls 為證。
func TestClipboardMigrationBackfillFailureKeepsPlaintextColumn(t *testing.T) {
	db := setupOldShapeDB(t)
	if err := db.Exec(`INSERT INTO clipboard_events (session_id, direction, content) VALUES (10, 'send', 'survivor')`).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	codec := &migrationStubCodec{encryptErr: errors.New("kek unavailable (injected)")}

	err := runClipboardContentEncryption(db, codec)
	if err == nil {
		t.Fatal("回填失敗 MUST 中止轉換")
	}
	if codec.encryptCalls == 0 {
		t.Fatal("加密注入點未走到——故障從未觸發，本測試失去證明力")
	}
	cols := clipboardColumns(t, db)
	if !cols["content"] {
		t.Error("fail-close 違反：明文欄被刪")
	}
	if cols["content_enc"] || cols["content_length"] || cols["content_status"] {
		t.Errorf("交易應整段回滾，新欄不得殘留: %+v", cols)
	}
	var content string
	if err := db.Raw(`SELECT content FROM clipboard_events WHERE id = 1`).Scan(&content).Error; err != nil {
		t.Fatalf("讀明文欄: %v", err)
	}
	if content != "survivor" {
		t.Errorf("明文應原樣保留, got %q", content)
	}
}
