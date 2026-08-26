package audit

import (
	"archive/zip"
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 事件報告模式（2026-08-13 使用者裁決）。
//
// **報告 ≠ 資料傾印**：稽核要的是「誰、何時、對哪個資產、做了什麼」的可查證紀錄，
// 不是把剪貼簿內容、檔案本體與錄影檔再複製一份帶出系統。內容本體改由介面上的
// 個別下載取得（另有其權限與留痕），故本模式只輸出事件事實。
const (
	// maxExportReportRows 每個類別**各自**的上限。共用一個總上限會讓
	// 「哪一類被截斷」不可辨識，那正是讀者最需要知道的一件事
	maxExportReportRows = 50000
	reportPageSize      = 1000
)

// SignedReasonServiceUnavailable 未簽章原因：本系統未啟用匯出簽章
const SignedReasonServiceUnavailable = "signing_service_unavailable"

// 說明文字的機器碼（後端零散文出站）。**碼即契約**：三語文字由 i18n 依碼提供，
// 後端只負責說出「是哪一種情況」與「佐證數值是多少」。
//
// 之所以連匯出包內的說明也走碼：包會離開系統、會被轉交，若文字在 Go 裡硬編，
// 這份包就永遠只有一種語言，且那段話不受任何 i18n 守衛檢查（改了沒人發現）
const (
	// CoverageNoteCodePresent 區間內此類別未被清除
	CoverageNoteCodePresent = "export.coverage.present"
	// CoverageNoteCodePurged 區間內有一段已依保留政策清除——空白是清除的結果，
	// 不是「沒事發生」。參數：policy_days／purged_through_at／last_purge_at／
	// archive_unit_from／archive_unit_to／partial
	CoverageNoteCodePurged = "export.coverage.purged"
	// CoverageNoteCodeNotRetained 此類別不在自動清除範圍內（資料一直都在），
	// 其空白才是確無此類事件。**與 purged 語義相反，不可混同**
	CoverageNoteCodeNotRetained = "export.coverage.not_retained"
	// NoteCodeAuditLogAssetBoundary 資產維度的歷史邊界
	NoteCodeAuditLogAssetBoundary = "export.limit.asset_scope"
)

// ExportScope 報告涵蓋範圍。
//
// **沒有這一段，讀者無從判斷「這份報告是不是全部」**——只給筆數不給範圍，
// 讀者會誤信自己看完了（與工作台「已顯示 N 筆」不給總數是同一種誤導）
type ExportScope struct {
	Subject     string    `json:"subject"` // user | asset
	SubjectID   uint      `json:"subject_id"`
	SubjectName string    `json:"subject_name,omitempty"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	Types       []string  `json:"types"`
}

// ExportCoverage 逐類別的保留覆蓋狀態（判定來源與工作台時間軸同一段程式碼）。
//
// **說明文字不由後端產生**：`NoteCode`＋`NoteParams` 是機器碼與參數，
// 對外文字由 i18n 決定（後端零散文出站，三語才可能齊備）
type ExportCoverage struct {
	Type  string `json:"type"`
	State string `json:"state"` // present | purged | not_retained
	// ArchiveUnitRange 已清除區間對應的**封存單位編號**區間，供獨立查核
	ArchiveUnitRange *CheckpointSeqRange `json:"archive_unit_range,omitempty"`
	PurgedThroughAt  *time.Time          `json:"purged_through_at,omitempty"`
	PolicyDays       *int                `json:"policy_days,omitempty"`
	LastPurgeAt      *time.Time          `json:"last_purge_at,omitempty"`
	Partial          bool                `json:"partial,omitempty"`
	NoteCode         string              `json:"note_code"`
	NoteParams       map[string]string   `json:"note_params,omitempty"`
}

// ExportDisclosure 這個包能證明什麼、不能證明什麼（機器碼＋參數）。
//
// **只出碼不出散文**：文字由 i18n 決定。碼的命名本身帶語義分組——
// `export.proves.*` 為能證明什麼，`export.limit.*` 為邊界，讀取端據此分段呈現
type ExportDisclosure struct {
	Code   string            `json:"code"`
	Params map[string]string `json:"params,omitempty"`
}

// reportFileName 各類別的輸出檔名
func reportFileName(t TimelineEventType) string {
	switch t {
	case TimelineTypeAlert:
		return "alerts.csv"
	case TimelineTypeAuditLog:
		return "audit_logs.csv"
	case TimelineTypeClipboard:
		return "clipboard_events.csv"
	case TimelineTypeCommand:
		return "commands.csv"
	case TimelineTypeFileTransfer:
		return "file_transfers.csv"
	case TimelineTypeSession:
		return "sessions.csv"
	}
	return string(t) + ".csv"
}

// exportEventReport 六來源事件報告：逐類別一個 CSV，末尾 manifest（含範圍、
// 逐類別收錄數與範圍內總數、保留覆蓋三態、簽章狀態與誠實邊界）
func (s *AuditExportService) exportEventReport(w io.Writer, filter *ExportFilter, exporterID uint, exporterName string) (*ExportManifest, error) {
	q := TimelineQuery{
		Subject:   filter.Subject,
		SubjectID: filter.SubjectID(),
		Types:     append([]TimelineEventType(nil), filter.Types...),
	}
	if filter.StartTime != nil {
		q.From = *filter.StartTime
	}
	if filter.EndTime != nil {
		q.To = *filter.EndTime
	}
	// 與時間軸同一套校驗：樞紐、區間、類別值域（未知類別不靜默忽略）
	if err := q.Normalize(); err != nil {
		return nil, err
	}

	zw := zip.NewWriter(w)
	defer zw.Close()

	m := s.newManifest(filter, exporterID, exporterName, ExportModeEventReport)
	m.Totals = map[string]int64{}
	m.Scope = &ExportScope{
		Subject:     string(q.Subject),
		SubjectID:   q.SubjectID,
		SubjectName: s.subjectName(q),
		From:        q.From,
		To:          q.To,
		Types:       typeNames(q.Types),
	}

	for _, t := range q.Types {
		if err := s.writeReportSource(zw, t, q, m); err != nil {
			return nil, err
		}
		// 範圍內真實筆數：**不受單類別上限影響**，與收錄數並列，
		// 讀者一眼看得出自己拿到的是不是全部
		n, err := s.timeline.countSource(t, q)
		if err != nil {
			return nil, err
		}
		m.Totals[string(t)] = n
	}

	cov, err := s.timeline.buildCoverage(q)
	if err != nil {
		return nil, err
	}
	m.Coverage = toExportCoverage(cov)
	if q.Subject == SubjectAsset {
		m.NoteCodes[string(TimelineTypeAuditLog)] = NoteCodeAuditLogAssetBoundary
	}
	m.Disclosures = reportDisclosures(m)

	if err := s.writeManifest(zw, m); err != nil {
		return nil, err
	}
	return m, nil
}

// subjectName 樞紐顯示名（含軟刪：調查對象常已離職或下架）
func (s *AuditExportService) subjectName(q TimelineQuery) string {
	if q.Subject == SubjectAsset {
		return s.timeline.lookupAssetNames([]uint{q.SubjectID})[q.SubjectID]
	}
	return s.timeline.lookupUserNames([]uint{q.SubjectID})[q.SubjectID]
}

func typeNames(types []TimelineEventType) []string {
	out := make([]string, 0, len(types))
	for _, t := range types {
		out = append(out, string(t))
	}
	return out
}

func (s *AuditExportService) writeReportSource(zw *zip.Writer, t TimelineEventType, q TimelineQuery, m *ExportManifest) error {
	switch t {
	case TimelineTypeSession:
		return s.writeReportSessions(zw, q, m)
	case TimelineTypeCommand:
		return s.writeReportCommands(zw, q, m)
	case TimelineTypeAlert:
		return s.writeReportAlerts(zw, q, m)
	case TimelineTypeClipboard:
		return s.writeReportClipboard(zw, q, m)
	case TimelineTypeAuditLog, TimelineTypeFileTransfer:
		return s.writeReportAuditLogs(zw, t, q, m)
	}
	return fmt.Errorf("未支援的匯出來源: %s", t)
}

// writeReportCSV 建檔、寫表頭、由 fill 串流寫列，並記入 manifest 的收錄數與截斷旗標
func (s *AuditExportService) writeReportCSV(zw *zip.Writer, t TimelineEventType, header []string,
	m *ExportManifest, fill func(emit func([]string) error) (int, bool, error)) error {
	var count int
	var truncated bool
	err := s.writeEntry(zw, reportFileName(t), m, func(out io.Writer) error {
		cw := csv.NewWriter(out)
		if err := cw.Write(header); err != nil {
			return err
		}
		n, tr, err := fill(cw.Write)
		count, truncated = n, tr
		if err != nil {
			return err
		}
		cw.Flush()
		return cw.Error()
	})
	if err != nil {
		return err
	}
	m.Counts[string(t)] = count
	m.Truncated[string(t)] = truncated
	return nil
}

// pageExport 以 (時間, id) keyset 逐頁取數並交給 emit 串流輸出（報告模式上限）。
//
// **截斷判定不靠「回傳數等於上限」猜**：取滿上限後再多探一筆，有殘餘才標 truncated——
// 恰好等於上限的資料被誤標成截斷，與截斷卻不標，都是對讀者說謊
func pageExport[T any](base func() *gorm.DB, tsCol, idCol string,
	key func(*T) (time.Time, uint), emit func([]T) error) (int, bool, error) {
	return pageExportN(base, tsCol, idCol, maxExportReportRows, key, emit)
}

// pageExportN 同 pageExport，上限由呼叫端供給（各類別自帶自己的上限；
// 證據包剪貼簿段沿用本機制但上限獨立）
func pageExportN[T any](base func() *gorm.DB, tsCol, idCol string, maxRows int,
	key func(*T) (time.Time, uint), emit func([]T) error) (int, bool, error) {
	order := fmt.Sprintf("%s ASC, %s ASC", tsCol, idCol)
	after := fmt.Sprintf("(%s > ?) OR (%s = ? AND %s > ?)", tsCol, tsCol, idCol)

	n := 0
	var lastTS time.Time
	var lastID uint
	first := true
	for n < maxRows {
		size := reportPageSize
		if remaining := maxRows - n; remaining < size {
			size = remaining
		}
		tx := base().Order(order).Limit(size)
		if !first {
			tx = tx.Where(after, lastTS, lastTS, lastID)
		}
		var rows []T
		if err := tx.Find(&rows).Error; err != nil {
			return n, false, err
		}
		if len(rows) == 0 {
			return n, false, nil
		}
		if err := emit(rows); err != nil {
			return n, false, err
		}
		n += len(rows)
		lastTS, lastID = key(&rows[len(rows)-1])
		first = false
		if len(rows) < size {
			return n, false, nil
		}
	}

	var extra []T
	if err := base().Order(order).Where(after, lastTS, lastTS, lastID).Limit(1).Find(&extra).Error; err != nil {
		return n, false, err
	}
	return n, len(extra) > 0, nil
}

// recordRef 紀錄編號：「類別:編號」，讀者可持此回系統查對原始紀錄。
// 格式與工作台時間軸的事件 id 完全相同，兩邊指的是同一筆
func recordRef(t TimelineEventType, id uint) string {
	return fmt.Sprintf("%s:%d", t, id)
}

func uintStr(v uint) string { return strconv.FormatUint(uint64(v), 10) }

func uintPtrStr(v *uint) string {
	if v == nil {
		return ""
	}
	return uintStr(*v)
}

func timeStr(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func timePtrStr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return timeStr(*t)
}

// pageNames 逐頁批次解析對造顯示名（避免逐列 N+1）
func (s *AuditExportService) pageNames(userIDs, assetIDs []uint) (map[uint]string, map[uint]string) {
	return s.timeline.lookupUserNames(userIDs), s.timeline.lookupAssetNames(assetIDs)
}

func (s *AuditExportService) writeReportSessions(zw *zip.Writer, q TimelineQuery, m *ExportManifest) error {
	// 錄影狀態與工作台跨度條同一判定（清除水位的時間近似，非逐檔查核）
	wm, err := s.timeline.watermarks.Load()
	if err != nil {
		return err
	}
	recWM, hasRecWM := wm[model.RetentionClassRecording]

	header := []string{"record_ref", "occurred_at", "session_id", "session_uid", "user_id", "username",
		"asset_id", "asset_name", "account_username", "protocol", "client_ip", "end_time",
		"duration_sec", "status", "end_reason", "recording_state", "recording_error"}
	base := func() *gorm.DB {
		return s.db.Model(&model.Session{}).
			Where("start_time >= ? AND start_time < ?", q.From, q.To).
			Where(subjectColumn(q.Subject)+" = ?", q.SubjectID)
	}
	return s.writeReportCSV(zw, TimelineTypeSession, header, m,
		func(emit func([]string) error) (int, bool, error) {
			return pageExport(base, "start_time", "id",
				func(r *model.Session) (time.Time, uint) { return r.StartTime, r.ID },
				func(rows []model.Session) error {
					userIDs := make([]uint, 0, len(rows))
					assetIDs := make([]uint, 0, len(rows))
					for i := range rows {
						userIDs = append(userIDs, rows[i].UserID)
						if rows[i].AssetID != nil {
							assetIDs = append(assetIDs, *rows[i].AssetID)
						}
					}
					users, assets := s.pageNames(userIDs, assetIDs)
					for i := range rows {
						r := rows[i]
						assetName := ""
						if r.AssetID != nil {
							assetName = assets[*r.AssetID]
						}
						state := RecordingStateNone
						switch {
						case !r.HasRecording:
							state = RecordingStateNone
						case hasRecWM && r.EndTime != nil && r.EndTime.Before(recWM.PurgedThroughAt):
							state = RecordingStatePurged
						default:
							state = RecordingStateAvailable
						}
						if err := emit([]string{
							recordRef(TimelineTypeSession, r.ID), timeStr(r.StartTime),
							uintStr(r.ID), r.SessionID, uintStr(r.UserID), users[r.UserID],
							uintPtrStr(r.AssetID), assetName, r.AccountUsername,
							string(r.Protocol), r.ClientIP, timePtrStr(r.EndTime),
							strconv.Itoa(r.Duration), string(r.Status), r.EndReason,
							state, r.RecordingError,
						}); err != nil {
							return err
						}
					}
					return nil
				})
		})
}

func (s *AuditExportService) writeReportCommands(zw *zip.Writer, q TimelineQuery, m *ExportManifest) error {
	header := []string{"record_ref", "occurred_at", "session_id", "user_id", "username",
		"asset_id", "asset_name", "command_seq", "command"}
	base := func() *gorm.DB {
		return s.db.Model(&model.SessionCommand{}).
			Where("executed_at >= ? AND executed_at < ?", q.From, q.To).
			Where(subjectColumn(q.Subject)+" = ?", q.SubjectID)
	}
	return s.writeReportCSV(zw, TimelineTypeCommand, header, m,
		func(emit func([]string) error) (int, bool, error) {
			return pageExport(base, "executed_at", "id",
				func(r *model.SessionCommand) (time.Time, uint) { return r.ExecutedAt, r.ID },
				func(rows []model.SessionCommand) error {
					userIDs := make([]uint, 0, len(rows))
					assetIDs := make([]uint, 0, len(rows))
					for i := range rows {
						userIDs = append(userIDs, rows[i].UserID)
						if rows[i].AssetID != nil {
							assetIDs = append(assetIDs, *rows[i].AssetID)
						}
					}
					users, assets := s.pageNames(userIDs, assetIDs)
					for i := range rows {
						r := rows[i]
						assetName := ""
						if r.AssetID != nil {
							assetName = assets[*r.AssetID]
						}
						if err := emit([]string{
							recordRef(TimelineTypeCommand, r.ID), timeStr(r.ExecutedAt),
							uintStr(r.SessionID), uintStr(r.UserID), users[r.UserID],
							uintPtrStr(r.AssetID), assetName, strconv.Itoa(r.Seq), r.Command,
						}); err != nil {
							return err
						}
					}
					return nil
				})
		})
}

func (s *AuditExportService) writeReportAlerts(zw *zip.Writer, q TimelineQuery, m *ExportManifest) error {
	header := []string{"record_ref", "occurred_at", "session_id", "user_id", "username",
		"asset_id", "asset_name", "kind", "reason_code", "rule_id", "rule_name",
		"severity", "blocked", "disposition", "reviewed_by", "reviewed_at", "command"}
	base := func() *gorm.DB {
		return s.db.Model(&model.CommandAlert{}).
			Where("triggered_at >= ? AND triggered_at < ?", q.From, q.To).
			Where(subjectColumn(q.Subject)+" = ?", q.SubjectID)
	}
	return s.writeReportCSV(zw, TimelineTypeAlert, header, m,
		func(emit func([]string) error) (int, bool, error) {
			return pageExport(base, "triggered_at", "id",
				func(r *model.CommandAlert) (time.Time, uint) { return r.TriggeredAt, r.ID },
				func(rows []model.CommandAlert) error {
					userIDs := make([]uint, 0, len(rows))
					assetIDs := make([]uint, 0, len(rows))
					for i := range rows {
						userIDs = append(userIDs, rows[i].UserID)
						if rows[i].AssetID != nil {
							assetIDs = append(assetIDs, *rows[i].AssetID)
						}
					}
					users, assets := s.pageNames(userIDs, assetIDs)
					for i := range rows {
						r := rows[i]
						assetName := ""
						if r.AssetID != nil {
							assetName = assets[*r.AssetID]
						}
						if err := emit([]string{
							recordRef(TimelineTypeAlert, r.ID), timeStr(r.TriggeredAt),
							uintStr(r.SessionID), uintStr(r.UserID), users[r.UserID],
							// kind／reason_code：降級類告警沒有規則可指（rule_id 為空），
							// 少了這兩欄，匯出的稽核報告分不出「規則命中」與「該輪無法還原」
							uintPtrStr(r.AssetID), assetName, r.Kind, r.ReasonCode,
							uintPtrStr(r.RuleID), r.RuleName,
							r.Severity, strconv.FormatBool(r.Blocked), r.Disposition,
							uintPtrStr(r.ReviewedBy), timePtrStr(r.ReviewedAt), r.Command,
						}); err != nil {
							return err
						}
					}
					return nil
				})
		})
}

// clipboardExportRow 剪貼簿事件的匯出投影。
//
// **不含內容欄**：內容是機密（落庫即密文），把它寫進可轉交的事件報告等於把
// 機密再複製一份帶出系統。報告只給事件事實（時間、操作者、資產、方向、
// 內容長度）；要看內容者走**會話詳情的剪貼簿調閱面**（單筆解密、逐筆留痕）
// 或**證據包匯出**（解密後入包、匯出留痕）——兩條路徑各有自己的權限與留痕
type clipboardExportRow struct {
	ID            uint
	SessionID     uint
	Direction     string
	CreatedAt     time.Time
	ContentLength int
	UserID        uint
	AssetID       *uint
}

func (s *AuditExportService) writeReportClipboard(zw *zip.Writer, q TimelineQuery, m *ExportManifest) error {
	header := []string{"record_ref", "occurred_at", "session_id", "user_id", "username",
		"asset_id", "asset_name", "direction", "content_length"}
	base := func() *gorm.DB {
		return s.db.Table("clipboard_events AS ce").
			// content_length 讀事實欄（信封加密後密文長度非事實；長度於落庫時
			// 以明文位元組計，見 model.ClipboardEvent）
			Select("ce.id, ce.session_id, ce.direction, ce.created_at, " +
				"ce.content_length, se.user_id, se.asset_id").
			Joins("JOIN sessions AS se ON se.id = ce.session_id").
			Where("ce.created_at >= ? AND ce.created_at < ?", q.From, q.To).
			Where("se."+subjectColumn(q.Subject)+" = ?", q.SubjectID)
	}
	return s.writeReportCSV(zw, TimelineTypeClipboard, header, m,
		func(emit func([]string) error) (int, bool, error) {
			return pageExport(base, "ce.created_at", "ce.id",
				func(r *clipboardExportRow) (time.Time, uint) { return r.CreatedAt, r.ID },
				func(rows []clipboardExportRow) error {
					userIDs := make([]uint, 0, len(rows))
					assetIDs := make([]uint, 0, len(rows))
					for i := range rows {
						userIDs = append(userIDs, rows[i].UserID)
						if rows[i].AssetID != nil {
							assetIDs = append(assetIDs, *rows[i].AssetID)
						}
					}
					users, assets := s.pageNames(userIDs, assetIDs)
					for i := range rows {
						r := rows[i]
						assetName := ""
						if r.AssetID != nil {
							assetName = assets[*r.AssetID]
						}
						if err := emit([]string{
							recordRef(TimelineTypeClipboard, r.ID), timeStr(r.CreatedAt),
							uintStr(r.SessionID), uintStr(r.UserID), users[r.UserID],
							uintPtrStr(r.AssetID), assetName, r.Direction,
							strconv.Itoa(r.ContentLength),
						}); err != nil {
							return err
						}
					}
					return nil
				})
		})
}

// writeReportAuditLogs 操作日誌與檔案傳輸（同一張表、互斥的 WHERE，
// 由 timeline 的 auditLogScope 切分——兩邊各自寫一次條件遲早會漂移）
func (s *AuditExportService) writeReportAuditLogs(zw *zip.Writer, t TimelineEventType, q TimelineQuery, m *ExportManifest) error {
	header := []string{"record_ref", "occurred_at", "user_id", "username", "action", "resource",
		"resource_id", "asset_id", "asset_name", "status", "status_code", "method", "path",
		"client_ip", "details", "error_msg"}
	base := func() *gorm.DB { return s.timeline.auditLogScope(t, q) }
	return s.writeReportCSV(zw, t, header, m,
		func(emit func([]string) error) (int, bool, error) {
			return pageExport(base, "created_at", "id",
				func(r *model.AuditLog) (time.Time, uint) { return r.CreatedAt, r.ID },
				func(rows []model.AuditLog) error {
					assetIDs := make([]uint, 0, len(rows))
					for i := range rows {
						if rows[i].AssetID != nil {
							assetIDs = append(assetIDs, *rows[i].AssetID)
						}
					}
					_, assets := s.pageNames(nil, assetIDs)
					for i := range rows {
						r := rows[i]
						assetName := ""
						if r.AssetID != nil {
							assetName = assets[*r.AssetID]
						}
						if err := emit([]string{
							recordRef(t, r.ID), timeStr(r.CreatedAt), uintStr(r.UserID), r.Username,
							string(r.Action), string(r.Resource), uintPtrStr(r.ResourceID),
							uintPtrStr(r.AssetID), assetName, string(r.Status),
							strconv.Itoa(r.StatusCode), r.Method, r.Path, r.ClientIP,
							r.Details, r.ErrorMsg,
						}); err != nil {
							return err
						}
					}
					return nil
				})
		})
}

// toExportCoverage 覆蓋三態轉為包內形態，每態各自寫明「空白代表什麼」。
//
// **not_retained 不是「沒留下來」**：它指這個類別不在自動清除範圍內，
// 資料一直都在，故空白就是確無此類事件。措辭必須把這件事講死——
// 光給狀態值，讀者會照字面讀成「沒有留存」
func toExportCoverage(cov []TimelineCoverage) []ExportCoverage {
	out := make([]ExportCoverage, 0, len(cov))
	for _, c := range cov {
		e := ExportCoverage{
			Type:             string(c.Type),
			State:            c.State,
			PurgedThroughAt:  c.PurgedThroughAt,
			PolicyDays:       c.PolicyDays,
			LastPurgeAt:      c.LastPurgeAt,
			Partial:          c.Partial,
			ArchiveUnitRange: c.CheckpointSeqRange,
		}
		switch c.State {
		case CoveragePurged:
			// 已清除區間：四項佐證同時出碼，讀取端才能把「這裡的空白是清除的結果」
			// 講到可查核的程度（保留幾天、清到哪、最近何時清、對應哪段封存單位編號）
			e.NoteCode = CoverageNoteCodePurged
			e.NoteParams = map[string]string{}
			if c.PolicyDays != nil {
				e.NoteParams["policy_days"] = strconv.Itoa(*c.PolicyDays)
			}
			if c.PurgedThroughAt != nil {
				e.NoteParams["purged_through_at"] = timeStr(*c.PurgedThroughAt)
			}
			if c.LastPurgeAt != nil {
				e.NoteParams["last_purge_at"] = timeStr(*c.LastPurgeAt)
			}
			if c.CheckpointSeqRange != nil {
				e.NoteParams["archive_unit_from"] = uintStr(c.CheckpointSeqRange.From)
				e.NoteParams["archive_unit_to"] = uintStr(c.CheckpointSeqRange.To)
			}
			if c.Partial {
				// 上次清除未完成：該區間仍可能有殘留，與「已清乾淨」是不同的話
				e.NoteParams["partial"] = "true"
			}
		case CoverageNotRetained:
			e.NoteCode = CoverageNoteCodeNotRetained
		default:
			e.NoteCode = CoverageNoteCodePresent
		}
		out = append(out, e)
	}
	return out
}

// reportDisclosures 這個包能證明什麼、不能證明什麼——**只出碼**。
//
// 順序刻意：`export.proves.*` 全部排在 `export.limit.*` 之前。反過來寫，
// 讀者會先讀到一串免責，讀不出這份報告到底能拿來做什麼。
//
// 對外文字由 i18n 依碼決定：後端硬編中文會把語言釘死在後端，且違反零散文出站
func reportDisclosures(m *ExportManifest) []ExportDisclosure {
	out := []ExportDisclosure{
		{Code: "export.proves.record_ref"},
		{Code: "export.proves.scope"},
		{Code: "export.proves.export_logged"},
	}
	if m.Signed {
		out = append(out, ExportDisclosure{Code: "export.proves.signature"})
	}
	out = append(out,
		ExportDisclosure{Code: "export.limit.scope_is_query_range"},
		ExportDisclosure{Code: "export.limit.payload_excluded"},
		ExportDisclosure{Code: "export.limit.coverage_states"},
		ExportDisclosure{Code: "export.limit.recording_state"},
		ExportDisclosure{Code: "export.limit.manifest_required"},
		ExportDisclosure{Code: "export.limit.no_offline_tool"},
	)
	if !m.Signed {
		// 未簽章的原因一併帶出：讀者要能分辨「未啟用」與「簽章被移除」
		out = append(out, ExportDisclosure{
			Code:   "export.limit.not_signed",
			Params: map[string]string{"reason": m.SignedReason},
		})
	}
	if m.Scope != nil && m.Scope.Subject == string(SubjectAsset) {
		out = append(out, ExportDisclosure{Code: NoteCodeAuditLogAssetBoundary})
	}
	return out
}
