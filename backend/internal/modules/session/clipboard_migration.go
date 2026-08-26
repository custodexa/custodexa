package session

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 剪貼簿明文欄 → 信封加密欄的一次性轉換。
//
// # 為何是 post-unseal 佇列項而非 versioned migration
//
// versioned migration 跑在啟動段 1，該段**沒有 codec**（B/ui 模式下 KEK 要等
// 解封後的段 2）；「需要 codec 的資料 migration SHALL 登記進 post-unseal 佇列」
// 是既有架構裁決（keyvault/post_unseal_migration.go 檔頭）。全新資料庫由
// baseline 直接建出終態形狀（content_enc/content_length/content_status、無
// content 欄），本轉換在其上為 no-op；只有「baseline 壓縮後、本 change 前」
// 建立的既有資料庫（帶明文 content 欄）會實際轉換。
//
// # 冪等閘＝content 欄是否存在
//
// 不用 schema_migrations marker：欄位存在性本身就是完備的終態判準（轉換的最後
// 一步是刪欄），且對 baseline 已是終態的全新庫天然 no-op，無需在 baseline 種 marker。
// 探測沿 ldapSeedTableExists 的紀律——只在「確定不存在」時回 no-op，任何查詢
// 錯誤一律上傳，讓佇列記一筆失敗、下次啟動重試；不用 GORM Migrator 的 bool-only API
// （基礎設施故障與「確實不存在」無從區分）。
//
// # fail-close：回填失敗中止、不刪欄
//
// 加欄→逐筆加密回填→刪欄全程包在單一交易內（postgres 與 sqlite 的 DDL 皆可
// 交易回滾）：任一筆 EncryptFor 失敗即整段 rollback，明文欄原樣保留，
// 佇列回報失敗待下次啟動重試。**次序寫死**：刪欄永遠在全部回填成功之後。

// PostUnsealMigrationClipboardContent 內建佇列項名（組裝根登記用具名常數，
// 沿 identity.PostUnsealMigrationLDAPSeed 慣例——登記名不得走字面量字串）。
const PostUnsealMigrationClipboardContent = "clipboard_content_encryption"

// RegisterClipboardContentMigration 登記剪貼簿內容加密轉換（組裝根經
// keyvault.RegisterPostUnsealBuiltin 呼叫）。
func RegisterClipboardContentMigration() {
	keyvault.RegisterPostUnsealMigration(keyvault.PostUnsealMigration{
		Name: PostUnsealMigrationClipboardContent,
		Run:  runClipboardContentEncryption,
	})
}

// clipboardPlaintextColumnExists 判定 clipboard_events 是否仍帶明文 content 欄。
//
// dialect 白名單 fail-close（沿 ldapSeedTableExists）：未知 dialect 不猜，直接回錯。
// 生產為 postgres、單元測試為 sqlite。表本身不存在時回 (false, nil)——那是測試
// 夾具未建表的情形，schema 缺失會在後續模型查詢時大聲失敗，不屬本轉換的射程。
func clipboardPlaintextColumnExists(db *gorm.DB) (bool, error) {
	switch db.Dialector.Name() {
	case "postgres":
		var n int64
		if err := db.Raw(`SELECT count(*) FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = 'clipboard_events'
			AND column_name = 'content'`).Scan(&n).Error; err != nil {
			return false, err
		}
		return n > 0, nil
	case "sqlite":
		var ddl string
		if err := db.Raw(`SELECT COALESCE(MAX(sql), '') FROM sqlite_master
			WHERE type = 'table' AND name = 'clipboard_events'`).Scan(&ddl).Error; err != nil {
			return false, err
		}
		// 於 CREATE TABLE 原文中判定裸 `content` 欄。`\b` 視底線為字元：
		// content_enc／content_length／content_status 皆不命中。
		// regex 建在函式內非包級——包級全域須登記 lifecycle manifest，
		// 本函式每次啟動僅呼叫一次，編譯成本可忽略
		return regexp.MustCompile(`\bcontent\b`).MatchString(ddl), nil
	default:
		return false, fmt.Errorf("不支援的資料庫 dialect %q：無法安全判定 clipboard_events 的 content 欄是否存在",
			db.Dialector.Name())
	}
}

// runClipboardContentEncryption 執行轉換本體（佇列項執行體）。
func runClipboardContentEncryption(db *gorm.DB, codec crypto.ColumnCodec) error {
	hasPlain, err := clipboardPlaintextColumnExists(db)
	if err != nil {
		return fmt.Errorf("探測 clipboard_events.content 欄失敗: %w", err)
	}
	if !hasPlain {
		return nil // 終態（全新庫或已轉換），冪等 no-op
	}

	var migrated int64
	err = db.Transaction(func(tx *gorm.DB) error {
		// DEFAULT 僅供既有列過渡（NOT NULL 加欄需要），回填後即卸除，
		// 使轉換後形狀與 baseline 終態逐欄一致。
		// SQL 逐句字面量：moduleboundary 的表名靜態解析 fail-close，
		// 變數迴圈形態會被判為未受管
		if err := tx.Exec(`ALTER TABLE clipboard_events ADD COLUMN content_enc text`).Error; err != nil {
			return fmt.Errorf("加欄失敗: %w", err)
		}
		if err := tx.Exec(`ALTER TABLE clipboard_events ADD COLUMN content_length bigint NOT NULL DEFAULT 0`).Error; err != nil {
			return fmt.Errorf("加欄失敗: %w", err)
		}
		if err := tx.Exec(`ALTER TABLE clipboard_events ADD COLUMN content_status varchar(16) NOT NULL DEFAULT 'available'`).Error; err != nil {
			return fmt.Errorf("加欄失敗: %w", err)
		}

		// 逐筆加密回填（keyset 分頁防大表全載；任一筆失敗即整段回滾）
		type row struct {
			ID      uint
			Content string
		}
		ctx := context.Background()
		lastID := uint(0)
		for {
			var batch []row
			if err := tx.Raw(`SELECT id, COALESCE(content, '') AS content FROM clipboard_events
				WHERE id > ? ORDER BY id LIMIT 500`, lastID).Scan(&batch).Error; err != nil {
				return fmt.Errorf("掃描既有列失敗: %w", err)
			}
			if len(batch) == 0 {
				break
			}
			for _, r := range batch {
				lastID = r.ID
				enc, err := codec.EncryptFor(ctx, keyvault.RefClipboardContent, r.Content)
				if err != nil {
					// fail-close：中止不刪欄。不落明文本身，只落位置線索
					return fmt.Errorf("加密回填 clipboard_events#%d 失敗（中止轉換、保留明文欄）: %w", r.ID, err)
				}
				if err := tx.Exec(`UPDATE clipboard_events SET content_enc = ?, content_length = ?, content_status = ? WHERE id = ?`,
					enc, len(r.Content), "available", r.ID).Error; err != nil {
					return fmt.Errorf("回填 clipboard_events#%d 失敗: %w", r.ID, err)
				}
				migrated++
			}
		}

		// 全部回填成功後才刪明文欄（次序寫死；本 change 的不可逆點）
		if err := tx.Exec(`ALTER TABLE clipboard_events DROP COLUMN content`).Error; err != nil {
			return fmt.Errorf("刪除明文欄失敗: %w", err)
		}
		// 卸除過渡 DEFAULT（sqlite 無 ALTER COLUMN，測試庫保留 DEFAULT 無礙——
		// 生產形狀等價的權威驗證面是 postgres 的 baseline parity）
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec(`ALTER TABLE clipboard_events ALTER COLUMN content_length DROP DEFAULT`).Error; err != nil {
				return fmt.Errorf("卸除過渡 DEFAULT 失敗: %w", err)
			}
			if err := tx.Exec(`ALTER TABLE clipboard_events ALTER COLUMN content_status DROP DEFAULT`).Error; err != nil {
				return fmt.Errorf("卸除過渡 DEFAULT 失敗: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	log.Printf("[ClipboardMigration] 剪貼簿內容加密轉換完成：%d 筆既有列已回填，明文欄已移除", migrated)
	return nil
}
