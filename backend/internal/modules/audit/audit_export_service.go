package audit

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"gorm.io/gorm"
)

// 匯出上限：同步串流的保護，超過即截斷並在 manifest 標明（不靜默截斷）。
// 錄影檔可能很大，數量上限最緊
const (
	maxExportAuditLogs  = 50000
	maxExportCommands   = 50000
	maxExportRecordings = 100
	exportPageSize      = 1000
	// auditLogPageSize AuditLogService.List 對 PageSize>100 會砍成 20，故此段用 100
	auditLogPageSize = 100
)

// ExportFilter 證據匯出篩選：user/asset/time 或指定 session
type ExportFilter struct {
	UserID    *uint
	AssetID   *uint
	StartTime *time.Time
	EndTime   *time.Time
	SessionID *uint // 指定單一會話（優先於 user/asset/time）

	// Subject 樞紐宣告：非空即進入
	// **事件報告模式**——六來源的事件事實報告，不含任何內容本體（剪貼簿內容、
	// 檔案本體、錄影檔）。空＝維持既有證據包模式，行為與本欄位出現前完全相同。
	// 樞紐 id 沿用 UserID／AssetID，不另立參數
	Subject TimelineSubject
	// Types 事件報告的類別篩選（空＝六類全收）；值域與時間軸同一套，
	// 未知值由 handler 擋在門外（不靜默忽略）
	Types []TimelineEventType
}

// 匯出模式（manifest.mode）：包裡有什麼，讀者不必靠檔名猜
const (
	// ExportModeEvidenceBundle 既有證據包：操作日誌＋指令流＋錄影檔本體
	ExportModeEvidenceBundle = "evidence_bundle"
	// ExportModeEventReport 事件報告：六來源事件事實，無任何內容本體
	ExportModeEventReport = "event_report"
)

// IsEventReport 是否為事件報告模式
func (f *ExportFilter) IsEventReport() bool {
	return f.Subject != ""
}

// SubjectID 樞紐 id（沿用 UserID／AssetID；0＝未指定，由 Normalize 擋下）
func (f *ExportFilter) SubjectID() uint {
	switch f.Subject {
	case SubjectAsset:
		if f.AssetID != nil {
			return *f.AssetID
		}
	case SubjectUser:
		if f.UserID != nil {
			return *f.UserID
		}
	}
	return 0
}

// ExportedFile manifest 中的單檔記錄（保管鏈：名稱、大小、SHA-256）
type ExportedFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ExportManifest 證據包 manifest（保管鏈證據）
type ExportManifest struct {
	// Mode 包裡有什麼（evidence_bundle｜event_report）。**放在最前面**：
	// 讀者判讀任何一段之前，得先知道自己拿到的是哪一種包
	Mode         string            `json:"mode"`
	ExportedBy   string            `json:"exported_by"`
	ExportedByID uint              `json:"exported_by_id"`
	ExportedAt   time.Time         `json:"exported_at"`
	Filter       map[string]string `json:"filter"`
	// Scope 事件報告的涵蓋範圍（樞紐、時間區間、類別）。讀者據此判斷
	// 「這份報告是不是全部」——只給筆數不給範圍，讀者會誤信自己看完了
	Scope *ExportScope   `json:"scope,omitempty"`
	Files []ExportedFile `json:"files"`
	// Counts 本包**收錄**的筆數
	Counts map[string]int `json:"counts"`
	// Totals 範圍內的**真實**筆數（不受單類別上限影響）。與 Counts 不等
	// 即代表該類別被截斷——只給收錄數的報告會讓讀者以為自己看完了
	Totals map[string]int64 `json:"totals,omitempty"`
	// Truncated 標明哪些部分達上限被截斷（不靜默截斷，PCI 證據完整性）
	Truncated map[string]bool `json:"truncated"`
	// Coverage 逐類別的保留覆蓋狀態（與工作台畫面同一判定來源）。
	// **沒有這段，一段空白會被讀成「這段期間沒發生過這類事」**
	Coverage []ExportCoverage `json:"coverage,omitempty"`
	// Signed 本包是否已簽章；未簽時 SignedReason 給機器碼。
	// 靜默不寫簽章檔會讓讀者無從分辨「未啟用」與「簽章被刪」
	Signed       bool   `json:"signed"`
	SignedReason string `json:"signed_reason,omitempty"`
	// Disclosures 這個包能證明什麼、不能證明什麼（機器碼＋說明）
	Disclosures []ExportDisclosure `json:"disclosures,omitempty"`
	// NoteCodes 各段的範圍說明**機器碼**（如 audit_logs 的資產關聯起始邊界）。
	// 存碼不存散文：這份包的說明文字須能三語呈現，且須受 i18n 守衛檢查
	NoteCodes map[string]string `json:"note_codes,omitempty"`
}

// AuditExportService 稽核證據匯出打包（PCI 10.5.1）
type AuditExportService struct {
	db         *gorm.DB
	auditLogs  *AuditLogService
	commands   *SessionCommandService
	recordings RecordingReader
	// timeline 事件報告模式的取數與覆蓋狀態來源。**刻意複用工作台的服務**：
	// 報告的範圍條件、逐類別筆數與保留覆蓋三態必須與畫面同一段程式碼算出來，
	// 否則「包內範圍 ≠ 畫面範圍」會在兩份實作各自漂移時無聲發生
	timeline *TimelineService
	// signing manifest Ed25519 簽章；
	// nil = 不簽（單測與降級相容），SetSigning 注入
	signing *keyvault.ExportSigningService
}

// SetSigning 注入 manifest 簽章服務
func (s *AuditExportService) SetSigning(signing *keyvault.ExportSigningService) {
	s.signing = signing
}

// NewAuditExportService 建立匯出服務（複用既有讀取服務）
func NewAuditExportService(db *gorm.DB, auditLogs *AuditLogService, commands *SessionCommandService, recordings RecordingReader) *AuditExportService {
	return &AuditExportService{
		db: db, auditLogs: auditLogs, commands: commands, recordings: recordings,
		timeline: NewTimelineService(db),
	}
}

// hashingWriter 包裝 zip entry writer：邊寫邊算 SHA-256 與位元組數
type hashingWriter struct {
	w      io.Writer
	hasher hash.Hash
	n      int64
}

func (hw *hashingWriter) Write(p []byte) (int, error) {
	n, err := hw.w.Write(p)
	hw.hasher.Write(p[:n])
	hw.n += int64(n)
	return n, err
}

// Export 串流 ZIP 證據包到 w，回傳 manifest（含每檔 SHA-256、截斷標記）。
// 寫入順序：操作日誌 → 指令流 → 錄影 → manifest（manifest 最後寫，含前面各檔雜湊，本身不入雜湊）
func (s *AuditExportService) Export(w io.Writer, filter *ExportFilter, exporterID uint, exporterName string) (*ExportManifest, error) {
	if filter.IsEventReport() {
		return s.exportEventReport(w, filter, exporterID, exporterName)
	}

	zw := zip.NewWriter(w)
	defer zw.Close()

	manifest := s.newManifest(filter, exporterID, exporterName, ExportModeEvidenceBundle)

	// 1. 操作日誌 → audit_logs.json
	if err := s.writeAuditLogs(zw, filter, manifest); err != nil {
		return nil, err
	}
	// 2. 指令流 → commands.csv
	if err := s.writeCommands(zw, filter, manifest); err != nil {
		return nil, err
	}
	// 3. 錄影 → recordings/session-<id>.<ext>
	if err := s.writeRecordings(zw, filter, manifest); err != nil {
		return nil, err
	}
	// 4. manifest.json（最後寫，內含前三者雜湊）
	if err := s.writeManifest(zw, manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

// newManifest 兩種模式共用的 manifest 骨架（含簽章可用性揭露）
func (s *AuditExportService) newManifest(filter *ExportFilter, exporterID uint, exporterName, mode string) *ExportManifest {
	m := &ExportManifest{
		Mode:         mode,
		ExportedBy:   exporterName,
		ExportedByID: exporterID,
		ExportedAt:   time.Now(),
		Filter:       filterToMap(filter),
		Files:        []ExportedFile{},
		Counts:       map[string]int{},
		Truncated:    map[string]bool{},
		NoteCodes:    map[string]string{},
		Signed:       s.signing != nil,
	}
	if s.signing == nil {
		// 未簽的原因以機器碼給，不給散文——讀者要能分辨「本系統未啟用簽章」
		// 與「有人把簽章檔刪了」，這個分辨不能靠猜
		m.SignedReason = SignedReasonServiceUnavailable
	}
	return m
}

// writeEntry 建 zip entry 並以 producer 寫入，邊寫邊算 SHA-256，記入 manifest
func (s *AuditExportService) writeEntry(zw *zip.Writer, name string, manifest *ExportManifest, producer func(io.Writer) error) error {
	entry, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("建立 zip entry %s 失敗: %w", name, err)
	}
	hw := &hashingWriter{w: entry, hasher: sha256.New()}
	if err := producer(hw); err != nil {
		return fmt.Errorf("寫入 %s 失敗: %w", name, err)
	}
	manifest.Files = append(manifest.Files, ExportedFile{
		Name: name, Size: hw.n, SHA256: fmt.Sprintf("%x", hw.hasher.Sum(nil)),
	})
	return nil
}

// writeAuditLogs 分頁撈操作日誌（至上限），寫 JSON 陣列。
// AuditLogService.List 對 PageSize>100 會靜默砍成 20，故此處用
// auditLogPageSize(=100)；truncated 由 res.Total 與已收集數推導（不可用「回傳數<請求
// pageSize」判最後一頁——被砍頁時恆成立、會誤判未截斷）。
// 一項**訂正**：立案當時 audit_logs 確實
// 無資產維度，故原實作只套 user/time 並標註「asset 篩選未及於此段」。`audit_logs.asset_id`
// 已由 auditor-workbench 補上，若仍照原文放行，資產樞紐的匯出會回傳該時段**全體使用者**
// 的操作日誌——那不是標註問題，是實質過度揭露。現改為**套用**資產維度，並改標其
// 歷史邊界（該欄自該功能上線起才寫入，之前的歷史列不帶資產關聯故不在包內）
func (s *AuditExportService) writeAuditLogs(zw *zip.Writer, filter *ExportFilter, manifest *ExportManifest) error {
	var logs []*model.AuditLog
	page := 1
	truncated := false
	var total int64
	for {
		res, err := s.auditLogs.List(&AuditLogFilter{
			UserID: filter.UserID, AssetID: filter.AssetID,
			StartTime: filter.StartTime, EndTime: filter.EndTime,
			Page: page, PageSize: auditLogPageSize,
		})
		if err != nil {
			return err
		}
		total = res.Total
		logs = append(logs, res.Data...)
		// 達匯出上限：截斷並誠實標明
		if len(logs) >= maxExportAuditLogs {
			logs = logs[:maxExportAuditLogs]
			truncated = int64(maxExportAuditLogs) < total
			break
		}
		// 收齊全部（以 Total 為準，不靠回傳數判斷）
		if int64(len(logs)) >= total || len(res.Data) == 0 {
			break
		}
		page++
	}
	manifest.Counts["audit_logs"] = len(logs)
	manifest.Truncated["audit_logs"] = truncated
	// 資產維度已套用，但其歷史邊界須誠實標註
	if filter.AssetID != nil {
		manifest.NoteCodes["audit_logs"] = NoteCodeAuditLogAssetBoundary
	}
	return s.writeEntry(zw, "audit_logs.json", manifest, func(out io.Writer) error {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(logs)
	})
}

// writeCommands 撈指令流寫 CSV（session 指定用 ListBySession，否則 Search 分頁）
func (s *AuditExportService) writeCommands(zw *zip.Writer, filter *ExportFilter, manifest *ExportManifest) error {
	var rows [][]string
	header := []string{"session_id", "user_id", "asset_id", "seq", "command", "executed_at"}
	truncated := false

	appendCmd := func(c *model.SessionCommand) {
		assetID := ""
		if c.AssetID != nil {
			assetID = strconv.FormatUint(uint64(*c.AssetID), 10)
		}
		rows = append(rows, []string{
			strconv.FormatUint(uint64(c.SessionID), 10),
			strconv.FormatUint(uint64(c.UserID), 10),
			assetID,
			strconv.Itoa(c.Seq),
			c.Command,
			c.ExecutedAt.Format(time.RFC3339),
		})
	}

	if filter.SessionID != nil {
		cmds, err := s.commands.ListBySession(*filter.SessionID)
		if err != nil {
			return err
		}
		for i := range cmds {
			appendCmd(&cmds[i])
		}
	} else {
		page := 1
		for len(rows) < maxExportCommands {
			res, err := s.commands.Search(&SessionCommandFilter{
				UserID: filter.UserID, AssetID: filter.AssetID,
				StartTime: filter.StartTime, EndTime: filter.EndTime,
				Page: page, PageSize: exportPageSize,
			})
			if err != nil {
				return err
			}
			for i := range res.Data {
				appendCmd(&res.Data[i].SessionCommand)
			}
			if len(res.Data) < exportPageSize || int64(len(rows)) >= res.Total {
				break
			}
			if len(rows) >= maxExportCommands {
				truncated = true
				rows = rows[:maxExportCommands]
				break
			}
			page++
		}
	}

	manifest.Counts["commands"] = len(rows)
	manifest.Truncated["commands"] = truncated
	return s.writeEntry(zw, "commands.csv", manifest, func(out io.Writer) error {
		cw := csv.NewWriter(out)
		if err := cw.Write(header); err != nil {
			return err
		}
		if err := cw.WriteAll(rows); err != nil {
			return err
		}
		cw.Flush()
		return cw.Error()
	})
}

// writeRecordings 解析範圍內有錄影的 session，逐檔塞入 recordings/
func (s *AuditExportService) writeRecordings(zw *zip.Writer, filter *ExportFilter, manifest *ExportManifest) error {
	sessionIDs, truncated, err := s.resolveRecordingSessions(filter)
	if err != nil {
		return err
	}

	written := 0
	for _, sid := range sessionIDs {
		protocol, err := s.recordings.RecordingProtocol(sid)
		if err != nil {
			continue // 無錄影或檔案缺失，跳過（不阻斷整包）
		}
		stream, err := s.recordings.GetRecordingStream(sid)
		if err != nil {
			continue
		}
		name := fmt.Sprintf("recordings/session-%d%s", sid, recordingExt(protocol))
		writeErr := s.writeEntry(zw, name, manifest, func(out io.Writer) error {
			_, copyErr := io.Copy(out, stream)
			return copyErr
		})
		stream.Close()
		if writeErr != nil {
			return writeErr
		}
		written++
	}
	manifest.Counts["recordings"] = written
	manifest.Truncated["recordings"] = truncated
	return nil
}

// resolveRecordingSessions 範圍內有錄影的 session id（指定 session 則只該筆）
func (s *AuditExportService) resolveRecordingSessions(filter *ExportFilter) ([]uint, bool, error) {
	if filter.SessionID != nil {
		return []uint{*filter.SessionID}, false, nil
	}
	q := s.db.Model(&model.Session{}).Where("has_recording = ?", true)
	if filter.UserID != nil {
		q = q.Where("user_id = ?", *filter.UserID)
	}
	if filter.AssetID != nil {
		q = q.Where("asset_id = ?", *filter.AssetID)
	}
	if filter.StartTime != nil {
		q = q.Where("start_time >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		q = q.Where("start_time <= ?", *filter.EndTime)
	}
	var ids []uint
	if err := q.Order("start_time DESC").Limit(maxExportRecordings+1).Pluck("id", &ids).Error; err != nil {
		return nil, false, fmt.Errorf("解析錄影會話失敗: %w", err)
	}
	truncated := false
	if len(ids) > maxExportRecordings {
		ids = ids[:maxExportRecordings]
		truncated = true
	}
	return ids, truncated, nil
}

func (s *AuditExportService) writeManifest(zw *zip.Writer, manifest *ExportManifest) error {
	// 先 marshal 成固定位元組：manifest.json 檔案內容與簽章對象必須是同一份
	// bytes，驗證者才能對「ZIP 內的 manifest.json 檔案」直接驗簽
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 manifest 失敗: %w", err)
	}
	data = append(data, '\n')

	entry, err := zw.Create("manifest.json")
	if err != nil {
		return fmt.Errorf("建立 manifest 失敗: %w", err)
	}
	if _, err := entry.Write(data); err != nil {
		return fmt.Errorf("寫入 manifest 失敗: %w", err)
	}

	// manifest.sig：Ed25519 簽章（base64）。
	// 驗證：以公鑰對 manifest.json 檔案位元組驗 base64 簽章
	if s.signing != nil {
		sigEntry, err := zw.Create("manifest.sig")
		if err != nil {
			return fmt.Errorf("建立 manifest.sig 失敗: %w", err)
		}
		if _, err := sigEntry.Write([]byte(s.signing.Sign(data))); err != nil {
			return fmt.Errorf("寫入 manifest.sig 失敗: %w", err)
		}
	}
	return nil
}

// recordingExt 依協議回錄影副檔名（SSH/文字=.cast，圖形=.guac）
func recordingExt(protocol string) string {
	switch protocol {
	case "rdp", "vnc":
		return ".guac"
	default:
		return ".cast"
	}
}

// filterToMap 篩選條件字串化（進 manifest 保管鏈）
func filterToMap(f *ExportFilter) map[string]string {
	m := map[string]string{}
	if f.SessionID != nil {
		m["session_id"] = strconv.FormatUint(uint64(*f.SessionID), 10)
	}
	if f.UserID != nil {
		m["user_id"] = strconv.FormatUint(uint64(*f.UserID), 10)
	}
	if f.AssetID != nil {
		m["asset_id"] = strconv.FormatUint(uint64(*f.AssetID), 10)
	}
	if f.StartTime != nil {
		m["start_time"] = f.StartTime.Format(time.RFC3339)
	}
	if f.EndTime != nil {
		m["end_time"] = f.EndTime.Format(time.RFC3339)
	}
	if f.Subject != "" {
		m["subject"] = string(f.Subject)
	}
	if len(f.Types) > 0 {
		names := make([]string, 0, len(f.Types))
		for _, t := range f.Types {
			names = append(names, string(t))
		}
		m["types"] = strings.Join(names, ",")
	}
	return m
}
