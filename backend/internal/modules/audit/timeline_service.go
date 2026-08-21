package audit

import (
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// TimelineEventType 時間軸事件類別。
//
// **字串值同時是排序鍵的一段**（見 TimelineCursor），故值一旦上線就不可改名——
// 改名會讓既有游標的相對序改變，正在分頁的客戶端會跳段。
type TimelineEventType string

const (
	// TimelineTypeAlert 指令告警（command_alerts）
	TimelineTypeAlert TimelineEventType = "alert"
	// TimelineTypeAuditLog 操作日誌（audit_logs，**排除 resource='file'**）
	TimelineTypeAuditLog TimelineEventType = "audit_log"
	// TimelineTypeClipboard 剪貼簿留存（clipboard_events，經 sessions 解析主體）
	TimelineTypeClipboard TimelineEventType = "clipboard"
	// TimelineTypeCommand 指令流（session_commands）
	TimelineTypeCommand TimelineEventType = "command"
	// TimelineTypeFileTransfer 檔案傳輸（audit_logs where resource='file'）。
	// 與 audit_log 同表不同類：兩者的 WHERE 互斥，否則同一列會出現兩次
	TimelineTypeFileTransfer TimelineEventType = "file_transfer"
	// TimelineTypeSession 會話建立（sessions；同時是跨度條的來源）
	TimelineTypeSession TimelineEventType = "session"
)

// allTimelineTypes 全部類別。**順序即字典序**，與 keysetWhere 的比較同源
var allTimelineTypes = []TimelineEventType{
	TimelineTypeAlert,
	TimelineTypeAuditLog,
	TimelineTypeClipboard,
	TimelineTypeCommand,
	TimelineTypeFileTransfer,
	TimelineTypeSession,
}

// IsTimelineEventType 值域檢查（未知型別一律回 400，不靜默忽略——
// 靜默忽略會讓打錯字的查詢回一份看似完整的較少資料）
func IsTimelineEventType(s string) bool {
	for _, t := range allTimelineTypes {
		if string(t) == s {
			return true
		}
	}
	return false
}

// TimelineSubject 樞紐種類
type TimelineSubject string

const (
	SubjectUser  TimelineSubject = "user"
	SubjectAsset TimelineSubject = "asset"
)

// 錯誤（handler 轉為 apierror 碼；service 層不回散文給前端）
var (
	ErrInvalidSubject   = errors.New("invalid timeline subject")
	ErrInvalidRange     = errors.New("invalid timeline range")
	ErrUnknownEventType = errors.New("unknown timeline event type")
)

// TimelineQuery 一次查詢的全部輸入
type TimelineQuery struct {
	Subject   TimelineSubject
	SubjectID uint
	From      time.Time
	To        time.Time
	Types     []TimelineEventType // 空＝全部
	Cursor    *TimelineCursor
	Limit     int
}

// Counterpart 每列的對造：人樞紐標「在哪台」，資產樞紐標「誰做的」
type Counterpart struct {
	Kind string `json:"kind"` // user | asset
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// TimelineRefs 事件可跳往的既有頁面
type TimelineRefs struct {
	SessionID *uint `json:"session_id,omitempty"`
	AlertID   *uint `json:"alert_id,omitempty"`
	AssetID   *uint `json:"asset_id,omitempty"`
}

// TimelineEvent 六類資料的統一封裝。
//
// **摘要一律碼化**（`SummaryCode`＋`Params`）：後端零散文出站是既有紅線，
// 且時間軸的每一列都要能在三語下呈現，回句子等於把翻譯釘死在後端
type TimelineEvent struct {
	ID          string            `json:"id"` // "<type>:<source_id>"，前端 key 用
	TS          time.Time         `json:"ts"`
	Type        TimelineEventType `json:"type"`
	SummaryCode string            `json:"summary_code"`
	Params      map[string]string `json:"params,omitempty"`
	Counterpart *Counterpart      `json:"counterpart,omitempty"`
	Refs        TimelineRefs      `json:"refs"`
	Severity    string            `json:"severity,omitempty"`

	// SourceID 來源表主鍵，游標與排序用（不出站——它在跨類別間沒有意義，
	// 暴露只會誘導客戶端自行拼游標）
	SourceID uint `json:"-"`
}

// TimelineSpan 會話跨度（只有會話類有跨度，其餘五類是點事件）
type TimelineSpan struct {
	SessionID      uint       `json:"session_id"`
	UserID         uint       `json:"user_id"`
	UserName       string     `json:"user_name"`
	AssetID        *uint      `json:"asset_id,omitempty"`
	AssetName      string     `json:"asset_name,omitempty"`
	Account        string     `json:"account,omitempty"`
	Protocol       string     `json:"protocol"`
	Start          time.Time  `json:"start"`
	End            *time.Time `json:"end,omitempty"` // nil＝進行中
	Status         string     `json:"status"`
	RecordingState string     `json:"recording_state"` // available | purged | none
}

// 錄影三態（D5）
const (
	RecordingStateAvailable = "available"
	RecordingStatePurged    = "purged"
	RecordingStateNone      = "none"
)

// 保留期三態（D5）
const (
	CoveragePresent     = "present"
	CoveragePurged      = "purged"
	CoverageNotRetained = "not_retained"
)

// TimelineCoverage 逐類別的保留期狀態。
//
// **空白區間不得無標記**：沒有這份 coverage，一段空白會被稽核員讀成
// 「紀錄被刪」，工作台自己製造竄改誤報
type TimelineCoverage struct {
	Type            TimelineEventType `json:"type"`
	State           string            `json:"state"`
	PurgedThroughAt *time.Time        `json:"purged_through_at,omitempty"`
	PolicyDays      *int              `json:"policy_days,omitempty"`
	LastPurgeAt     *time.Time        `json:"last_purge_at,omitempty"`
	Partial         bool              `json:"partial,omitempty"`
	// CheckpointSeqRange audit_logs 類專屬：對應已清除區間的檢查點 seq 範圍，
	// 供 UI 連往 /checkpoint-verification。**唯讀取用，工作台不做任何驗證**
	CheckpointSeqRange *CheckpointSeqRange `json:"checkpoint_seq_range,omitempty"`
}

// CheckpointSeqRange 檢查點 seq 區間（含兩端）
type CheckpointSeqRange struct {
	From uint `json:"from"`
	To   uint `json:"to"`
}

// TimelineResult 端點回應
type TimelineResult struct {
	Events     []TimelineEvent               `json:"events"`
	Spans      []TimelineSpan                `json:"spans"`
	Coverage   []TimelineCoverage            `json:"coverage"`
	Counts     map[TimelineEventType]int64   `json:"counts"`
	NextCursor string                        `json:"next_cursor,omitempty"`
	Truncated  bool                          `json:"truncated"`
}

const (
	timelineDefaultLimit = 200
	timelineMaxLimit     = 500
)

// TimelineService 六來源聚合（auditor-workbench D7）
type TimelineService struct {
	db         *gorm.DB
	watermarks *RetentionWatermarkService
}

func NewTimelineService(db *gorm.DB) *TimelineService {
	return &TimelineService{db: db, watermarks: NewRetentionWatermarkService(db)}
}

// Normalize 校驗並補預設。回錯誤即 400（未知型別不靜默忽略）
func (q *TimelineQuery) Normalize() error {
	if q.Subject != SubjectUser && q.Subject != SubjectAsset {
		return ErrInvalidSubject
	}
	if q.SubjectID == 0 {
		return ErrInvalidSubject
	}
	if q.From.IsZero() || q.To.IsZero() || !q.To.After(q.From) {
		return ErrInvalidRange
	}
	for _, t := range q.Types {
		if !IsTimelineEventType(string(t)) {
			return ErrUnknownEventType
		}
	}
	if len(q.Types) == 0 {
		q.Types = append([]TimelineEventType(nil), allTimelineTypes...)
	}
	if q.Limit <= 0 {
		q.Limit = timelineDefaultLimit
	}
	if q.Limit > timelineMaxLimit {
		q.Limit = timelineMaxLimit
	}
	return nil
}

// Query 執行一次時間軸查詢
func (s *TimelineService) Query(q TimelineQuery) (*TimelineResult, error) {
	if err := q.Normalize(); err != nil {
		return nil, err
	}

	enabled := make(map[TimelineEventType]bool, len(q.Types))
	for _, t := range q.Types {
		enabled[t] = true
	}

	// 六來源各自 keyset 取 limit+1 筆。
	//
	// **為何是 limit+1 而非 limit**：合併輸出的 limit 筆最壞情況全部來自
	// 同一個來源，故每來源至少要備妥 limit 筆才不會因「自己備得不夠」
	// 而讓後面的列被誤判為不存在；多取的那 1 筆用來判定 truncated——
	// 沒有它就得再打一次 COUNT，而 COUNT 與資料查詢之間的並發寫入會讓
	// truncated 與 events 不一致
	fetch := q.Limit + 1
	streams := make([][]TimelineEvent, 0, len(allTimelineTypes))
	for _, t := range allTimelineTypes {
		if !enabled[t] {
			continue
		}
		rows, err := s.fetchSource(t, q, fetch)
		if err != nil {
			return nil, err
		}
		if len(rows) > 0 {
			streams = append(streams, rows)
		}
	}

	events, truncated := mergeStreams(streams, q.Limit)

	result := &TimelineResult{
		Events:    events,
		Truncated: truncated,
		Counts:    map[TimelineEventType]int64{},
	}
	if truncated && len(events) > 0 {
		last := events[len(events)-1]
		result.NextCursor = TimelineCursor{TS: last.TS, Type: last.Type, ID: last.SourceID}.Encode()
	}

	// **counts 不受 limit 影響**（截斷誠實，沿匯出 spec 既有語義）：
	// 使用者必須能看出「這裡還有 8 萬筆，你只看到 200 筆」，
	// 否則截斷後的時間軸看起來就是一份完整的時間軸
	for _, t := range q.Types {
		n, err := s.countSource(t, q)
		if err != nil {
			return nil, err
		}
		result.Counts[t] = n
	}

	spans, err := s.fetchSpans(q)
	if err != nil {
		return nil, err
	}
	result.Spans = spans

	cov, err := s.buildCoverage(q)
	if err != nil {
		return nil, err
	}
	result.Coverage = cov

	return result, nil
}

// mergeStreams k-way merge。
//
// 每個 stream 內部已由 SQL 排成全序，故只需反覆挑出「所有 head 中最小的一筆」。
// 來源固定六個，線性挑選（O(6) 每筆）比維護 heap 更短且無隱含 bug 面。
//
// **truncated 的判定**：任一 stream 尚有殘餘即為 true——包含「輸出已滿 limit」
// 與「某來源自己就取滿了 limit+1」兩種情形
func mergeStreams(streams [][]TimelineEvent, limit int) ([]TimelineEvent, bool) {
	out := make([]TimelineEvent, 0, limit)
	idx := make([]int, len(streams))
	for len(out) < limit {
		best := -1
		for i := range streams {
			if idx[i] >= len(streams[i]) {
				continue
			}
			if best == -1 || lessEvent(streams[i][idx[i]], streams[best][idx[best]]) {
				best = i
			}
		}
		if best == -1 {
			return out, false // 全部取完，沒有截斷
		}
		out = append(out, streams[best][idx[best]])
		idx[best]++
	}
	for i := range streams {
		if idx[i] < len(streams[i]) {
			return out, true
		}
	}
	return out, false
}

// subjectColumn 樞紐鍵在各來源上的欄名
func subjectColumn(subject TimelineSubject) string {
	if subject == SubjectAsset {
		return "asset_id"
	}
	return "user_id"
}

// fetchSource 單一來源的 keyset 查詢＋統一封裝
func (s *TimelineService) fetchSource(t TimelineEventType, q TimelineQuery, fetch int) ([]TimelineEvent, error) {
	switch t {
	case TimelineTypeAuditLog, TimelineTypeFileTransfer:
		return s.fetchAuditLogs(t, q, fetch)
	case TimelineTypeSession:
		return s.fetchSessions(q, fetch)
	case TimelineTypeCommand:
		return s.fetchCommands(q, fetch)
	case TimelineTypeAlert:
		return s.fetchAlerts(q, fetch)
	case TimelineTypeClipboard:
		return s.fetchClipboard(q, fetch)
	}
	return nil, fmt.Errorf("未支援的時間軸來源: %s", t)
}

// auditLogScope audit_logs 兩個類別的共同 where。
//
// 資產樞紐**只認 asset_id 欄**，SHALL NOT 退回 (resource, resource_id)：
// 後者會把「改密計畫 130」「授權列 130」當成資產 130 的事件（D1.3(a)）
func (s *TimelineService) auditLogScope(t TimelineEventType, q TimelineQuery) *gorm.DB {
	tx := s.db.Model(&model.AuditLog{}).
		Where("created_at >= ? AND created_at < ?", q.From, q.To)
	if q.Subject == SubjectAsset {
		tx = tx.Where("asset_id = ?", q.SubjectID)
	} else {
		tx = tx.Where("user_id = ?", q.SubjectID)
	}
	// 兩類互斥切分同一張表：漏掉任一邊的條件，檔案傳輸列就會同時
	// 以 audit_log 與 file_transfer 出現兩次
	if t == TimelineTypeFileTransfer {
		return tx.Where("resource = ?", model.ResourceFile)
	}
	return tx.Where("resource <> ?", model.ResourceFile)
}

func (s *TimelineService) fetchAuditLogs(t TimelineEventType, q TimelineQuery, fetch int) ([]TimelineEvent, error) {
	tx := s.auditLogScope(t, q)
	if where, args := keysetWhere("created_at", "id", t, q.Cursor); where != "" {
		tx = tx.Where(where, args...)
	}
	var rows []model.AuditLog
	if err := tx.Order("created_at ASC, id ASC").Limit(fetch).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]TimelineEvent, 0, len(rows))
	for i := range rows {
		r := rows[i]
		ev := TimelineEvent{
			ID:          fmt.Sprintf("%s:%d", t, r.ID),
			TS:          r.CreatedAt,
			Type:        t,
			SourceID:    r.ID,
			SummaryCode: "timeline.audit_log." + string(r.Action),
			Params: map[string]string{
				"resource": string(r.Resource),
				"status":   string(r.Status),
				"path":     r.Path,
			},
			Refs: TimelineRefs{AssetID: r.AssetID},
		}
		if q.Subject == SubjectAsset {
			ev.Counterpart = &Counterpart{Kind: "user", ID: r.UserID, Name: r.Username}
		} else if r.AssetID != nil {
			ev.Counterpart = &Counterpart{Kind: "asset", ID: *r.AssetID}
		}
		out = append(out, ev)
	}
	s.resolveAssetNames(out)
	return out, nil
}

func (s *TimelineService) fetchSessions(q TimelineQuery, fetch int) ([]TimelineEvent, error) {
	tx := s.db.Model(&model.Session{}).
		Where("start_time >= ? AND start_time < ?", q.From, q.To).
		Where(subjectColumn(q.Subject)+" = ?", q.SubjectID)
	if where, args := keysetWhere("start_time", "id", TimelineTypeSession, q.Cursor); where != "" {
		tx = tx.Where(where, args...)
	}
	var rows []model.Session
	if err := tx.Order("start_time ASC, id ASC").Limit(fetch).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]TimelineEvent, 0, len(rows))
	for i := range rows {
		r := rows[i]
		id := r.ID
		ev := TimelineEvent{
			ID:          fmt.Sprintf("session:%d", r.ID),
			TS:          r.StartTime,
			Type:        TimelineTypeSession,
			SourceID:    r.ID,
			SummaryCode: "timeline.session.start",
			Params: map[string]string{
				"protocol": string(r.Protocol),
				"account":  r.AccountUsername,
				"status":   string(r.Status),
			},
			Refs: TimelineRefs{SessionID: &id, AssetID: r.AssetID},
		}
		if q.Subject == SubjectAsset {
			ev.Counterpart = &Counterpart{Kind: "user", ID: r.UserID}
		} else if r.AssetID != nil {
			ev.Counterpart = &Counterpart{Kind: "asset", ID: *r.AssetID}
		}
		out = append(out, ev)
	}
	s.resolveNames(out)
	return out, nil
}

func (s *TimelineService) fetchCommands(q TimelineQuery, fetch int) ([]TimelineEvent, error) {
	tx := s.db.Model(&model.SessionCommand{}).
		Where("executed_at >= ? AND executed_at < ?", q.From, q.To).
		Where(subjectColumn(q.Subject)+" = ?", q.SubjectID)
	if where, args := keysetWhere("executed_at", "id", TimelineTypeCommand, q.Cursor); where != "" {
		tx = tx.Where(where, args...)
	}
	var rows []model.SessionCommand
	if err := tx.Order("executed_at ASC, id ASC").Limit(fetch).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]TimelineEvent, 0, len(rows))
	for i := range rows {
		r := rows[i]
		sid := r.SessionID
		ev := TimelineEvent{
			ID:          fmt.Sprintf("command:%d", r.ID),
			TS:          r.ExecutedAt,
			Type:        TimelineTypeCommand,
			SourceID:    r.ID,
			SummaryCode: "timeline.command.executed",
			// 指令原文照登：它是稽核標的本身，摘要碼化的紅線約束的是
			// **系統產生的敘述**，不是被稽核的使用者輸入
			Params: map[string]string{"command": r.Command},
			Refs:   TimelineRefs{SessionID: &sid, AssetID: r.AssetID},
		}
		if q.Subject == SubjectAsset {
			ev.Counterpart = &Counterpart{Kind: "user", ID: r.UserID}
		} else if r.AssetID != nil {
			ev.Counterpart = &Counterpart{Kind: "asset", ID: *r.AssetID}
		}
		out = append(out, ev)
	}
	s.resolveNames(out)
	return out, nil
}

func (s *TimelineService) fetchAlerts(q TimelineQuery, fetch int) ([]TimelineEvent, error) {
	tx := s.db.Model(&model.CommandAlert{}).
		Where("triggered_at >= ? AND triggered_at < ?", q.From, q.To).
		Where(subjectColumn(q.Subject)+" = ?", q.SubjectID)
	if where, args := keysetWhere("triggered_at", "id", TimelineTypeAlert, q.Cursor); where != "" {
		tx = tx.Where(where, args...)
	}
	var rows []model.CommandAlert
	if err := tx.Order("triggered_at ASC, id ASC").Limit(fetch).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]TimelineEvent, 0, len(rows))
	for i := range rows {
		r := rows[i]
		sid, aid := r.SessionID, r.ID
		ev := TimelineEvent{
			ID:          fmt.Sprintf("alert:%d", r.ID),
			TS:          r.TriggeredAt,
			Type:        TimelineTypeAlert,
			SourceID:    r.ID,
			SummaryCode: "timeline.alert.triggered",
			Params: map[string]string{
				"rule":        r.RuleName,
				"command":     r.Command,
				"disposition": r.Disposition,
			},
			Severity: r.Severity,
			Refs:     TimelineRefs{SessionID: &sid, AlertID: &aid, AssetID: r.AssetID},
		}
		if q.Subject == SubjectAsset {
			ev.Counterpart = &Counterpart{Kind: "user", ID: r.UserID}
		} else if r.AssetID != nil {
			ev.Counterpart = &Counterpart{Kind: "asset", ID: *r.AssetID}
		}
		out = append(out, ev)
	}
	s.resolveNames(out)
	return out, nil
}

// clipboardRow clipboard_events 無主體欄，一律經 sessions 解析（D1.2）
type clipboardRow struct {
	ID        uint
	SessionID uint
	Direction string
	CreatedAt time.Time
	UserID    uint
	AssetID   *uint
}

func (s *TimelineService) fetchClipboard(q TimelineQuery, fetch int) ([]TimelineEvent, error) {
	tx := s.db.Table("clipboard_events AS ce").
		Select("ce.id, ce.session_id, ce.direction, ce.created_at, se.user_id, se.asset_id").
		Joins("JOIN sessions AS se ON se.id = ce.session_id").
		Where("ce.created_at >= ? AND ce.created_at < ?", q.From, q.To).
		Where("se."+subjectColumn(q.Subject)+" = ?", q.SubjectID)
	if where, args := keysetWhere("ce.created_at", "ce.id", TimelineTypeClipboard, q.Cursor); where != "" {
		tx = tx.Where(where, args...)
	}
	var rows []clipboardRow
	if err := tx.Order("ce.created_at ASC, ce.id ASC").Limit(fetch).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]TimelineEvent, 0, len(rows))
	for i := range rows {
		r := rows[i]
		sid := r.SessionID
		ev := TimelineEvent{
			ID:          fmt.Sprintf("clipboard:%d", r.ID),
			TS:          r.CreatedAt,
			Type:        TimelineTypeClipboard,
			SourceID:    r.ID,
			SummaryCode: "timeline.clipboard." + r.Direction,
			// 剪貼簿內容**不入時間軸**：它是明文且永久留存（無保留政策），
			// 逐列外送等於把最敏感的一類資料攤在聚合查詢的回應裡。
			// 需要內容者走既有的 per-session 端點（有其自身的權限與留痕）
			Refs: TimelineRefs{SessionID: &sid, AssetID: r.AssetID},
		}
		if q.Subject == SubjectAsset {
			ev.Counterpart = &Counterpart{Kind: "user", ID: r.UserID}
		} else if r.AssetID != nil {
			ev.Counterpart = &Counterpart{Kind: "asset", ID: *r.AssetID}
		}
		out = append(out, ev)
	}
	s.resolveNames(out)
	return out, nil
}

// countSource 窗內真實筆數（不套游標、不套 limit）
func (s *TimelineService) countSource(t TimelineEventType, q TimelineQuery) (int64, error) {
	var n int64
	switch t {
	case TimelineTypeAuditLog, TimelineTypeFileTransfer:
		return n, s.auditLogScope(t, q).Count(&n).Error
	case TimelineTypeSession:
		return n, s.db.Model(&model.Session{}).
			Where("start_time >= ? AND start_time < ?", q.From, q.To).
			Where(subjectColumn(q.Subject)+" = ?", q.SubjectID).Count(&n).Error
	case TimelineTypeCommand:
		return n, s.db.Model(&model.SessionCommand{}).
			Where("executed_at >= ? AND executed_at < ?", q.From, q.To).
			Where(subjectColumn(q.Subject)+" = ?", q.SubjectID).Count(&n).Error
	case TimelineTypeAlert:
		return n, s.db.Model(&model.CommandAlert{}).
			Where("triggered_at >= ? AND triggered_at < ?", q.From, q.To).
			Where(subjectColumn(q.Subject)+" = ?", q.SubjectID).Count(&n).Error
	case TimelineTypeClipboard:
		return n, s.db.Table("clipboard_events AS ce").
			Joins("JOIN sessions AS se ON se.id = ce.session_id").
			Where("ce.created_at >= ? AND ce.created_at < ?", q.From, q.To).
			Where("se."+subjectColumn(q.Subject)+" = ?", q.SubjectID).Count(&n).Error
	}
	return 0, fmt.Errorf("未支援的時間軸來源: %s", t)
}

// fetchSpans 跨度條資料。
//
// **與事件軸的取窗條件刻意不同**：事件軸問「這個時刻落在窗內嗎」，
// 跨度條問「這段區間與窗有交集嗎」——只取 start_time 落在窗內的會話，
// 會讓「昨天開、今天還在線」的長會話在今天的窗內整條消失，
// 而那正是稽核最想看到的一種會話
func (s *TimelineService) fetchSpans(q TimelineQuery) ([]TimelineSpan, error) {
	tx := s.db.Model(&model.Session{}).
		Where("start_time < ?", q.To).
		Where("(end_time IS NULL OR end_time >= ?)", q.From).
		Where(subjectColumn(q.Subject)+" = ?", q.SubjectID)
	var rows []model.Session
	// 上限與事件軸同階：跨度條是視覺元件，數千條列的畫面本身已不可讀，
	// 真實筆數由 counts[session] 誠實呈現
	if err := tx.Order("start_time ASC, id ASC").Limit(timelineMaxLimit).Find(&rows).Error; err != nil {
		return nil, err
	}
	wm, err := s.watermarks.Load()
	if err != nil {
		return nil, err
	}
	recWM, hasRecWM := wm[model.RetentionClassRecording]

	out := make([]TimelineSpan, 0, len(rows))
	assetIDs := make([]uint, 0, len(rows))
	userIDs := make([]uint, 0, len(rows))
	for i := range rows {
		r := rows[i]
		span := TimelineSpan{
			SessionID: r.ID,
			UserID:    r.UserID,
			AssetID:   r.AssetID,
			Account:   r.AccountUsername,
			Protocol:  string(r.Protocol),
			Start:     r.StartTime,
			End:       r.EndTime,
			Status:    string(r.Status),
		}
		// 錄影三態（D5）：has_recording=false 一律 none（從未錄或錄失敗）；
		// 有錄影但結束時刻早於錄影清除水位者判 purged。
		// **這是時間近似而非逐檔事實**（Q6）：單檔清除失敗時會誤標為 purged。
		// 誤標方向刻意選在此側——把仍在的檔標成已清除，使用者點下去會發現它還在；
		// 反過來把已清除的標成可回放，使用者只會得到一個無解釋的回放失敗
		switch {
		case !r.HasRecording:
			span.RecordingState = RecordingStateNone
		case hasRecWM && r.EndTime != nil && r.EndTime.Before(recWM.PurgedThroughAt):
			span.RecordingState = RecordingStatePurged
		default:
			span.RecordingState = RecordingStateAvailable
		}
		out = append(out, span)
		userIDs = append(userIDs, r.UserID)
		if r.AssetID != nil {
			assetIDs = append(assetIDs, *r.AssetID)
		}
	}
	users := s.lookupUserNames(userIDs)
	assets := s.lookupAssetNames(assetIDs)
	for i := range out {
		out[i].UserName = users[out[i].UserID]
		if out[i].AssetID != nil {
			out[i].AssetName = assets[*out[i].AssetID]
		}
	}
	return out, nil
}

// coverageClass 各事件類別對應的保留水位類別。
//
// sessions 表**不在任何 retention 目標內**（retentionTargets 只有三張表），
// 剪貼簿同樣不在——兩者一律 not_retained，其空白就是真的沒發生。
// 這不是本 change 的設計選擇，是現況的誠實呈現
func coverageClass(t TimelineEventType) (model.RetentionClass, bool) {
	switch t {
	case TimelineTypeAuditLog, TimelineTypeFileTransfer:
		// 檔案傳輸就住在 audit_logs 內，與操作日誌同一份保留政策
		return model.RetentionClassAuditLog, true
	case TimelineTypeCommand:
		return model.RetentionClassSessionCommand, true
	case TimelineTypeAlert:
		return model.RetentionClassCommandAlert, true
	}
	return "", false
}

func (s *TimelineService) buildCoverage(q TimelineQuery) ([]TimelineCoverage, error) {
	wm, err := s.watermarks.Load()
	if err != nil {
		return nil, err
	}
	out := make([]TimelineCoverage, 0, len(q.Types))
	for _, t := range q.Types {
		cov := TimelineCoverage{Type: t, State: CoveragePresent}
		class, retained := coverageClass(t)
		if !retained {
			cov.State = CoverageNotRetained
			out = append(out, cov)
			continue
		}
		w, ok := wm[class]
		// 冷啟動：無水位列＝從未清除過＝完整，**不是 unknown**
		if !ok || !w.PurgedThroughAt.After(q.From) {
			out = append(out, cov)
			continue
		}
		cov.State = CoveragePurged
		through := w.PurgedThroughAt
		days := w.PolicyDays
		last := w.LastPurgeAt
		cov.PurgedThroughAt = &through
		cov.PolicyDays = &days
		cov.LastPurgeAt = &last
		cov.Partial = w.Partial
		if class == model.RetentionClassAuditLog {
			rng, err := s.checkpointRange(q.From, minTime(q.To, through))
			if err != nil {
				return nil, err
			}
			cov.CheckpointSeqRange = rng
		}
		out = append(out, cov)
	}
	return out, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// checkpointRange 已清除區間對應的檢查點 seq 範圍（tasks 3.4）。
//
// **唯讀**：本函式（與整個工作台）不寫入也不驗證檢查點——完整性主張由
// /checkpoint-verification 獨佔（2026-08-11 劃界裁決），此處只提供跳轉座標
func (s *TimelineService) checkpointRange(from, to time.Time) (*CheckpointSeqRange, error) {
	if !to.After(from) {
		return nil, nil
	}
	var row struct {
		MinSeq *uint
		MaxSeq *uint
	}
	err := s.db.Model(&model.AuditCheckpoint{}).
		Select("MIN(seq) AS min_seq, MAX(seq) AS max_seq").
		Where("purged_at IS NOT NULL").
		Where("min_created_at < ? AND max_created_at >= ?", to, from).
		Scan(&row).Error
	if err != nil {
		return nil, err
	}
	if row.MinSeq == nil || row.MaxSeq == nil {
		return nil, nil
	}
	return &CheckpointSeqRange{From: *row.MinSeq, To: *row.MaxSeq}, nil
}

// resolveNames 補上 counterpart 的顯示名（批次查，避免逐列 N+1）
func (s *TimelineService) resolveNames(events []TimelineEvent) {
	s.resolveAssetNames(events)
	s.resolveUserNames(events)
}

func (s *TimelineService) resolveAssetNames(events []TimelineEvent) {
	ids := make([]uint, 0, len(events))
	for _, e := range events {
		if e.Counterpart != nil && e.Counterpart.Kind == "asset" && e.Counterpart.Name == "" {
			ids = append(ids, e.Counterpart.ID)
		}
	}
	if len(ids) == 0 {
		return
	}
	names := s.lookupAssetNames(ids)
	for i := range events {
		cp := events[i].Counterpart
		if cp != nil && cp.Kind == "asset" && cp.Name == "" {
			cp.Name = names[cp.ID]
		}
	}
}

func (s *TimelineService) resolveUserNames(events []TimelineEvent) {
	ids := make([]uint, 0, len(events))
	for _, e := range events {
		if e.Counterpart != nil && e.Counterpart.Kind == "user" && e.Counterpart.Name == "" {
			ids = append(ids, e.Counterpart.ID)
		}
	}
	if len(ids) == 0 {
		return
	}
	names := s.lookupUserNames(ids)
	for i := range events {
		cp := events[i].Counterpart
		if cp != nil && cp.Kind == "user" && cp.Name == "" {
			cp.Name = names[cp.ID]
		}
	}
}

// lookupAssetNames 含**軟刪**資產（Unscoped）：調查對象常已下架，
// 查得到事件卻顯示不出名字，會讓稽核員以為資料壞了。
// 實作抽至 subject_names.go——告警通知需要同一份解析，同模組內不留兩套等價查詢。
func (s *TimelineService) lookupAssetNames(ids []uint) map[uint]string {
	return lookupAssetNamesDB(s.db, ids)
}

// lookupUserNames 同上，含軟刪使用者（離職者仍是調查對象）
func (s *TimelineService) lookupUserNames(ids []uint) map[uint]string {
	return lookupUserNamesDB(s.db, ids)
}
