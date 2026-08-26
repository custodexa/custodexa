package audit

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"gorm.io/gorm"
)

// 證據包的剪貼簿內容段。
//
// **與錄影本體同格**：證據包承載證物本體，剪貼簿內容解密後逐筆入包；
// 事件報告（audit_export_report.go 的 writeReportClipboard）維持只給事實、
// 不含內容——兩條路徑的界線由 TestReportClipboardExcludesContent 守著。
//
// 匯出即解密的留痕＝既有匯出審計（exporter、範圍）＋manifest 記名，
// 不另加逐筆審計（一包本就是一次批次取得，批次留痕已完整）。

// maxExportClipboardEvents 剪貼簿段自己的上限與自己的截斷標示
// （每類別各自上限，不共用總上限——共用會使「哪一類被截斷」不可辨識）
const maxExportClipboardEvents = 50000

// exportClipboardSection manifest 的剪貼簿段鍵名（Counts／Truncated 用）
const exportClipboardSection = "clipboard_contents"

// DisclosureClipboardPlaintext 「本包含剪貼簿明文內容」的機器碼揭露：
// 收包方須知所持有者為機密（spec：含明文內容一事 SHALL 於 manifest 明載）。
// 三語文字由 i18n 依碼提供（碼即契約，後端零散文出站）
const DisclosureClipboardPlaintext = "export.contains.clipboard_plaintext"

// ExportClipboardStats 剪貼簿段三數。Events 為本包**收錄**的事件數（截斷後），
// 與 manifest.Counts[clipboard_contents] 同值；範圍內真實筆數在 Totals
type ExportClipboardStats struct {
	// Events 收錄事件總數（可用＋缺口）
	Events int `json:"events"`
	// ContentAvailable 其中帶解密全文者
	ContentAvailable int `json:"content_available"`
	// ContentFailed 其中留存失敗的缺口列（狀態標示、內容欄缺席）
	ContentFailed int `json:"content_failed"`
}

// clipboardBundleRow 剪貼簿內容檔的單列投影（DB 掃描用）
type clipboardBundleRow struct {
	ID            uint
	SessionID     uint
	Direction     string
	CreatedAt     time.Time
	ContentLength int
	ContentStatus string
	ContentEnc    string
}

// clipboardBundleEntry 剪貼簿內容檔的單筆輸出。
//
// Content 用指標＋omitempty：缺口列（content_status=failed）鍵**缺席**，
// 不以空字串冒充內容——空字串是「拷貝了空內容」的合法值，兩者必須可分辨
type clipboardBundleEntry struct {
	// RecordRef 與稽核調查時間軸同源的紀錄編號（clipboard:<id>）
	RecordRef     string    `json:"record_ref"`
	ID            uint      `json:"id"`
	SessionID     uint      `json:"session_id"`
	OccurredAt    time.Time `json:"occurred_at"`
	Direction     string    `json:"direction"`
	ContentStatus string    `json:"content_status"`
	ContentLength int       `json:"content_length"`
	Content       *string   `json:"content,omitempty"`
}

// clipboardBundleScope 證據包範圍內的剪貼簿事件查詢。
//
// 範圍語義與包內其他段對齊：指定 session 即該會話全部事件；否則
// user/asset 經所屬會話解析（clipboard_events 無主體欄，JOIN sessions——
// 與時間軸聚合同一條既登記的資料層讀取），時間窗套在**事件時刻**
// （ce.created_at，與事件報告同基準）而非會話起點——證物的時點是事件發生時
func (s *AuditExportService) clipboardBundleScope(filter *ExportFilter) func() *gorm.DB {
	return func() *gorm.DB {
		q := s.db.Table("clipboard_events AS ce").
			Select("ce.id, ce.session_id, ce.direction, ce.created_at, " +
				"ce.content_length, ce.content_status, ce.content_enc").
			Joins("JOIN sessions AS se ON se.id = ce.session_id")
		if filter.SessionID != nil {
			return q.Where("ce.session_id = ?", *filter.SessionID)
		}
		if filter.UserID != nil {
			q = q.Where("se.user_id = ?", *filter.UserID)
		}
		if filter.AssetID != nil {
			q = q.Where("se.asset_id = ?", *filter.AssetID)
		}
		if filter.StartTime != nil {
			q = q.Where("ce.created_at >= ?", *filter.StartTime)
		}
		if filter.EndTime != nil {
			q = q.Where("ce.created_at <= ?", *filter.EndTime)
		}
		return q
	}
}

// writeClipboardContents 寫 clipboard_contents.json（JSON 陣列，逐筆含事件識別、
// 時間、方向、content_status、解密全文；缺口列狀態標示且內容欄缺席）。
//
// **解密失敗＝整包失敗（fail-close）**：DB 宣稱 available 卻解不開是金鑰
// 基礎設施異常，靜默略過會產出「看起來完整、實則缺證物」的包。
// codec 未注入而範圍內存在可用內容，同判——見 SetClipboardCodec 註解。
func (s *AuditExportService) writeClipboardContents(zw *zip.Writer, filter *ExportFilter, manifest *ExportManifest) error {
	base := s.clipboardBundleScope(filter)

	var total int64
	if err := base().Count(&total).Error; err != nil {
		return fmt.Errorf("統計剪貼簿事件範圍失敗: %w", err)
	}

	stats := ExportClipboardStats{}
	ctx := context.Background()
	var truncated bool
	err := s.writeEntry(zw, "clipboard_contents.json", manifest, func(out io.Writer) error {
		if _, err := io.WriteString(out, "[\n"); err != nil {
			return err
		}
		n, tr, err := pageExportN(base, "ce.created_at", "ce.id", maxExportClipboardEvents,
			func(r *clipboardBundleRow) (time.Time, uint) { return r.CreatedAt, r.ID },
			func(rows []clipboardBundleRow) error {
				for i := range rows {
					r := rows[i]
					entry := clipboardBundleEntry{
						RecordRef:     recordRef(TimelineTypeClipboard, r.ID),
						ID:            r.ID,
						SessionID:     r.SessionID,
						OccurredAt:    r.CreatedAt,
						Direction:     r.Direction,
						ContentStatus: r.ContentStatus,
						ContentLength: r.ContentLength,
					}
					if r.ContentStatus == model.ClipboardContentAvailable {
						if s.clipboardCodec == nil {
							return fmt.Errorf("剪貼簿事件 #%d 內容可用但解密器未注入，拒絕產出缺證物的包", r.ID)
						}
						plain, err := s.clipboardCodec.DecryptFor(ctx, keyvault.RefClipboardContent, r.ContentEnc)
						if err != nil {
							return fmt.Errorf("解密剪貼簿事件 #%d 失敗: %w", r.ID, err)
						}
						entry.Content = &plain
						stats.ContentAvailable++
					} else {
						stats.ContentFailed++
					}
					if stats.Events > 0 {
						if _, err := io.WriteString(out, ",\n"); err != nil {
							return err
						}
					}
					stats.Events++
					data, err := json.Marshal(entry)
					if err != nil {
						return fmt.Errorf("序列化剪貼簿事件 #%d 失敗: %w", r.ID, err)
					}
					if _, err := out.Write(data); err != nil {
						return err
					}
				}
				return nil
			})
		if err != nil {
			return err
		}
		truncated = tr
		_ = n // 收錄數以 stats.Events 為準（同值）
		_, err = io.WriteString(out, "\n]\n")
		return err
	})
	if err != nil {
		return err
	}

	manifest.Counts[exportClipboardSection] = stats.Events
	manifest.Truncated[exportClipboardSection] = truncated
	if manifest.Totals == nil {
		manifest.Totals = map[string]int64{}
	}
	manifest.Totals[exportClipboardSection] = total
	manifest.Clipboard = &stats
	// 含明文內容的揭露：包內真的裝了解密全文才宣告——全缺口或零事件的包
	// 不含明文，宣告了反而是假警報
	if stats.ContentAvailable > 0 {
		manifest.Disclosures = append(manifest.Disclosures,
			ExportDisclosure{Code: DisclosureClipboardPlaintext})
	}
	return nil
}
