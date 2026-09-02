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
	"github.com/custodexa/backend/pkg/crypto"
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
	// Types 類別篩選（空＝六類全收）；值域與時間軸同一套，
	// 未知值由 handler 擋在門外（不靜默忽略）。
	// **兩種包型都適用**（2026-08-25 使用者裁決）：事件報告決定出哪幾個 csv，
	// 證據包決定收哪幾段證物（有本體者裝本體，無本體者以事件事實 csv 列入）
	Types []TimelineEventType

	// Pack 明示包型（ExportModeEventReport｜ExportModeEvidenceBundle）。
	// 空＝沿既有推斷（Subject 非空即事件報告），既有呼叫端行為逐位不變。
	//
	// **為何需要明示**：證據包自 2026-08-25 起也吃樞紐與類別，Subject 不再
	// 分辨得出包型；只靠推斷會把「帶樞紐的證據包發起」誤判為事件報告而拒絕
	Pack string
}

// 匯出模式（manifest.mode）：包裡有什麼，讀者不必靠檔名猜
const (
	// ExportModeEvidenceBundle 既有證據包：操作日誌＋指令流＋錄影檔本體
	ExportModeEvidenceBundle = "evidence_bundle"
	// ExportModeEventReport 事件報告：六來源事件事實，無任何內容本體
	ExportModeEventReport = "event_report"
)

// IsEventReport 是否為事件報告模式（Pack 明示優先，缺席沿 Subject 推斷）
func (f *ExportFilter) IsEventReport() bool {
	switch f.Pack {
	case ExportModeEventReport:
		return true
	case ExportModeEvidenceBundle:
		return false
	}
	return f.Subject != ""
}

// SelectsType 本包是否收錄類別 t（Types 空＝六類全收，既有呼叫端行為不變）
func (f *ExportFilter) SelectsType(t TimelineEventType) bool {
	if len(f.Types) == 0 {
		return true
	}
	for _, x := range f.Types {
		if x == t {
			return true
		}
	}
	return false
}

// selectsTypeExplicitly 呼叫端**明寫**了此類別（Types 非空且含 t）。
//
// 與 SelectsType 的差別只在「參數缺席＝全收」那一態：缺席時產不出來的段
// 可以略過（既有呼叫端不知道有這兩段，略過即維持原行為）；明寫了卻略過，
// 就是靜默不給人家指名要的證物
func (f *ExportFilter) selectsTypeExplicitly(t TimelineEventType) bool {
	return len(f.Types) > 0 && f.SelectsType(t)
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
	Mode         string    `json:"mode"`
	ExportedBy   string    `json:"exported_by"`
	ExportedByID uint      `json:"exported_by_id"`
	ExportedAt   time.Time `json:"exported_at"`
	// JobRequestedAt 非同步 job 的**發起**時刻；ExportedAt 是**實際打包**時刻。
	// 兩時戳並列（雙時戳），收包方才能判斷內容對應的資料時點——排隊期間
	// 新落庫的事件會在包內，只看發起時刻會誤判涵蓋範圍。同步報告無此欄
	JobRequestedAt *time.Time        `json:"job_requested_at,omitempty"`
	Filter         map[string]string `json:"filter"`
	// Scope 事件報告的涵蓋範圍（樞紐、時間區間、類別）。讀者據此判斷
	// 「這份報告是不是全部」——只給筆數不給範圍，讀者會誤信自己看完了
	Scope *ExportScope `json:"scope,omitempty"`
	// SelectedTypes 證據包的類別篩選：六類中實際收錄哪幾類。
	// **參數缺席時展開為全部六類**，讀者不必去推斷「沒寫是全收還是沒記」。
	// 事件報告的同一資訊在 Scope.Types（該模式恆有樞紐與時間窗可寫）
	SelectedTypes []string       `json:"selected_types,omitempty"`
	Files         []ExportedFile `json:"files"`
	// Counts 本包**收錄**的筆數
	Counts map[string]int `json:"counts"`
	// Totals 範圍內的**真實**筆數（不受單類別上限影響）。與 Counts 不等
	// 即代表該類別被截斷——只給收錄數的報告會讓讀者以為自己看完了
	Totals map[string]int64 `json:"totals,omitempty"`
	// Truncated 標明哪些部分達上限被截斷（不靜默截斷，PCI 證據完整性）
	Truncated map[string]bool `json:"truncated"`
	// Clipboard 證據包剪貼簿段的三數（事件總數／內容可用數／留存失敗數，
	// #R2-2）：讀者據此分得出「收了幾筆事件」與「其中幾筆真的帶內容、
	// 幾筆是留存失敗的缺口」——只給一個總數會讓缺口與可用混同
	Clipboard *ExportClipboardStats `json:"clipboard,omitempty"`
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
	// clipboardCodec 剪貼簿內容解密器：
	// 證據包裝入剪貼簿明文時解密 content_enc。nil 時遇到可用內容即整包失敗
	// ——「宣稱帶內容的包靜默缺內容」是對收包方說謊，fail-close
	clipboardCodec crypto.ColumnCodec
}

// SetSigning 注入 manifest 簽章服務
func (s *AuditExportService) SetSigning(signing *keyvault.ExportSigningService) {
	s.signing = signing
}

// SetClipboardCodec 注入剪貼簿內容解密器（組裝根呼叫）
func (s *AuditExportService) SetClipboardCodec(codec crypto.ColumnCodec) {
	s.clipboardCodec = codec
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
// 寫入順序：操作日誌 → 指令流 → 剪貼簿內容 → 錄影 → manifest
// （manifest 最後寫，含前面各檔雜湊，本身不入雜湊）
func (s *AuditExportService) Export(w io.Writer, filter *ExportFilter, exporterID uint, exporterName string) (*ExportManifest, error) {
	if filter.IsEventReport() {
		return s.exportEventReport(w, filter, exporterID, exporterName)
	}
	return s.exportBundle(w, filter, exporterID, exporterName, nil)
}

// ExportForJob 非同步 job 的打包入口：
// 僅接受證據包模式，requestedAt 為 job 發起時刻，與實際打包時刻一併寫入
// manifest（雙時戳）。
func (s *AuditExportService) ExportForJob(w io.Writer, filter *ExportFilter,
	exporterID uint, exporterName string, requestedAt time.Time) (*ExportManifest, error) {
	if filter.IsEventReport() {
		return nil, fmt.Errorf("非同步匯出僅接受證據包模式，事件報告走既有同步端點")
	}
	return s.exportBundle(w, filter, exporterID, exporterName, &requestedAt)
}

// exportBundle 證據包本體（同步與 job 共用；jobRequestedAt 非 nil 時為 job 打包）
func (s *AuditExportService) exportBundle(w io.Writer, filter *ExportFilter,
	exporterID uint, exporterName string, jobRequestedAt *time.Time) (*ExportManifest, error) {
	zw := zip.NewWriter(w)
	defer zw.Close()

	manifest := s.newManifest(filter, exporterID, exporterName, ExportModeEvidenceBundle)
	manifest.JobRequestedAt = jobRequestedAt
	manifest.SelectedTypes = bundleSelectedTypes(filter)

	// 各段依類別篩選收錄（2026-08-25 使用者裁決）：**未被選取的類別段不入包**，
	// 且其 Counts／Truncated 鍵一併缺席——寫個 0 會讓「沒選」與「選了但範圍內沒有」
	// 看起來是同一回事。類別參數缺席＝全部類別，既有呼叫端行為逐位不變。
	//
	// 1. 操作日誌 → audit_logs.json
	if filter.SelectsType(TimelineTypeAuditLog) {
		if err := s.writeAuditLogs(zw, filter, manifest); err != nil {
			return nil, err
		}
	}
	// 2. 指令流 → commands.csv
	if filter.SelectsType(TimelineTypeCommand) {
		if err := s.writeCommands(zw, filter, manifest); err != nil {
			return nil, err
		}
	}
	// 3. 剪貼簿內容 → clipboard_contents.json（解密全文；缺口列內容欄缺席）
	if filter.SelectsType(TimelineTypeClipboard) {
		if err := s.writeClipboardContents(zw, filter, manifest); err != nil {
			return nil, err
		}
	}
	// 4. 錄影 → recordings/session-<id>.<ext>
	if filter.SelectsType(TimelineTypeSession) {
		if err := s.writeRecordings(zw, filter, manifest); err != nil {
			return nil, err
		}
	}
	// 5. 無本體之類別（告警、檔案傳輸）以事件事實 csv 列入
	if err := s.writeBundleFactSections(zw, filter, manifest); err != nil {
		return nil, err
	}
	// 6. 逐類別的保留覆蓋狀態與範圍內真實筆數（spec「清單檔內容」要求兩者，
	//    且不分包型）。**必須在 manifest 之前**——寫出去就補不上了
	if err := s.fillBundleCoverageAndTotals(filter, manifest); err != nil {
		return nil, err
	}
	// 7. manifest.json（最後寫，內含前面各檔雜湊）
	if err := s.writeManifest(zw, manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

// bundleSelectedTypes 本包實際收錄的類別清單（缺席＝展開為全部六類）
func bundleSelectedTypes(f *ExportFilter) []string {
	return typeNames(selectedTimelineTypes(f))
}

// selectedTimelineTypes 本包實際收錄的類別（缺席＝展開為全部六類）
func selectedTimelineTypes(f *ExportFilter) []TimelineEventType {
	if len(f.Types) == 0 {
		return append([]TimelineEventType(nil), allTimelineTypes...)
	}
	return append([]TimelineEventType(nil), f.Types...)
}

// fillBundleCoverageAndTotals 補齊證據包 manifest 的 coverage 與 totals。
//
// **重用事件報告的產生器**（`buildCoverage`／`countSource`）：兩種包對同一段
// 期間講的保留狀態與真實筆數若各算一份，遲早會出現「同一個時間窗、兩個包
// 說法不同」——那正是稽核最難解釋的落差。
//
// 涵蓋**被選類別全體**，不只事實段：指令段與剪貼簿段各有自己的上限與清除
// 政策，少了它們的 coverage，一段空白會被讀成「這段期間沒發生過這類事」。
//
// 無樞紐時（既有的指定 session 匯出）整段缺席：coverage 與 totals 都以
// 樞紐＋時間窗為前提，產不出來就不寫——寫半套比缺席更難判讀
func (s *AuditExportService) fillBundleCoverageAndTotals(filter *ExportFilter, m *ExportManifest) error {
	q, err := bundlePivotQuery(filter)
	if err != nil {
		return nil
	}
	q.Types = selectedTimelineTypes(filter)

	cov, cErr := s.timeline.buildCoverage(q)
	if cErr != nil {
		return cErr
	}
	m.Coverage = toExportCoverage(cov)

	if m.Totals == nil {
		m.Totals = map[string]int64{}
	}
	for _, t := range q.Types {
		// 事實段已算過的不重複打 COUNT（同一查詢、同一結果）
		if _, ok := m.Totals[string(t)]; ok {
			continue
		}
		n, nErr := s.timeline.countSource(t, q)
		if nErr != nil {
			return nErr
		}
		m.Totals[string(t)] = n
	}
	return nil
}

// writeBundleFactSections 無本體之類別（告警、檔案傳輸）以事件事實 csv 入包。
//
// **重用事件報告的寫入器**：同一類別在兩種包裡的欄位集若各寫一份遲早漂移，
// 而「同一件事在報告與證據包裡長得不一樣」正是稽核最難解釋的一種落差。
//
// 報告寫入器以 TimelineQuery 取數（樞紐＋時間窗），故此段需要樞紐。樞紐缺席時：
// 類別參數也缺席（＝全收）就略過這兩段——既有呼叫端（指定 session 匯出）
// 不知道有這兩段，略過即維持原行為；**明寫了卻無樞紐則整包失敗**，
// 靜默不給人家指名要的證物比失敗糟得多
func (s *AuditExportService) writeBundleFactSections(zw *zip.Writer, filter *ExportFilter, m *ExportManifest) error {
	factTypes := []TimelineEventType{TimelineTypeAlert, TimelineTypeFileTransfer}
	wanted := make([]TimelineEventType, 0, len(factTypes))
	for _, t := range factTypes {
		if filter.SelectsType(t) {
			wanted = append(wanted, t)
		}
	}
	if len(wanted) == 0 {
		return nil
	}

	q, err := bundlePivotQuery(filter)
	if err != nil {
		for _, t := range factTypes {
			if filter.selectsTypeExplicitly(t) {
				return fmt.Errorf("類別 %s 須有樞紐與時間窗才能收錄: %w", t, err)
			}
		}
		return nil
	}

	for _, t := range wanted {
		if err := s.writeReportSource(zw, t, q, m); err != nil {
			return err
		}
		// 範圍內真實筆數與收錄數並列（截斷語義沿事件報告既有作法）
		n, cErr := s.timeline.countSource(t, q)
		if cErr != nil {
			return cErr
		}
		if m.Totals == nil {
			m.Totals = map[string]int64{}
		}
		m.Totals[string(t)] = n
	}
	return nil
}

// bundlePivotQuery 由證據包篩選組出樞紐查詢（供重用報告寫入器）。
// 校驗走 TimelineQuery.Normalize——與事件報告同一套，兩邊各寫一份遲早漂移
func bundlePivotQuery(f *ExportFilter) (TimelineQuery, error) {
	q := TimelineQuery{Subject: f.Subject, SubjectID: f.SubjectID()}
	if f.StartTime != nil {
		q.From = *f.StartTime
	}
	if f.EndTime != nil {
		q.To = *f.EndTime
	}
	if err := q.Normalize(); err != nil {
		return TimelineQuery{}, err
	}
	return q, nil
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
	header := []string{"session_id", "user_id", "asset_id", "seq", "command", "executed_at",
		"event_id", "target_database", "result_status", "result_reason",
		"result_rows", "rows_affected", "result_sets", "error_code",
		"duration_ms", "result_truncated", "tx_state_after"}
	truncated := false

	appendCmd := func(c *model.SessionCommand) {
		assetID := ""
		if c.AssetID != nil {
			assetID = strconv.FormatUint(uint64(*c.AssetID), 10)
		}
		row := []string{
			strconv.FormatUint(uint64(c.SessionID), 10),
			strconv.FormatUint(uint64(c.UserID), 10),
			assetID,
			strconv.Itoa(c.Seq),
			c.Command,
			c.ExecutedAt.Format(time.RFC3339),
		}
		rows = append(rows, append(row, commandResultFacts(c)...))
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

// commandResultFacts 查詢主控台的結果事實欄（十一欄，順序同表頭尾段）。
//
// **文字終端的列一律留空**，判別鍵是 `ResultStatus`——空字串在該欄的語義就是
// 「這不是主控台列」。留空而非填 `0`／`false`：稽核讀到 0 影響列與讀到空白
// 是兩件事，前者宣稱「查過、是零」，後者才是「這一欄對這種列不適用」。
//
// 可空的數值欄同理：NULL 表示不適用或未回填，寫成空白，不折成 0。
func commandResultFacts(c *model.SessionCommand) []string {
	if c.ResultStatus == "" {
		return make([]string, 11)
	}
	i64 := func(v *int64) string {
		if v == nil {
			return ""
		}
		return strconv.FormatInt(*v, 10)
	}
	i32 := func(v *int32) string {
		if v == nil {
			return ""
		}
		return strconv.FormatInt(int64(*v), 10)
	}
	return []string{
		c.EventID,
		c.TargetDatabase,
		c.ResultStatus,
		c.ResultReason,
		i64(c.ResultRows),
		i64(c.RowsAffected),
		i32(c.ResultSets),
		c.ErrorCode,
		i32(c.DurationMS),
		strconv.FormatBool(c.ResultTruncated),
		c.TxStateAfter,
	}
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
