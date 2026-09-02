package sshproxy

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 結構化操作事件的 kind（審計列的 RequestBody 首鍵）。
//
// **一律走既有的 action／resource 枚舉**，以 kind 區分事件種類：新增枚舉值會
// 觸發枚舉守衛、前端 label 表、工作台篩選三處連動，而這些事件對稽核的語義都是
// 「在某個會話上做了某件事」——資訊增量不在動作名而在細節裡
const (
	consoleKindConnect         = "db_console_connect"
	consoleKindAdmission       = "db_console_admission"
	consoleKindTree            = "db_console_tree"
	consoleKindSwitch          = "db_console_switch"
	consoleKindTargetDenied    = "db_console_target_denied"
	consoleKindCancel          = "db_console_cancel"
	consoleKindConnectionClose = "db_console_connection_closed"
	consoleKindReconnect       = "db_console_reconnect"
	consoleKindSessionEndTxOpn = "db_console_session_end_tx_open"
	consoleKindResultExport    = "db_console_result"
)

// 目標受限拒絕的觸發點
const (
	consoleTriggerExecute   = "execute"
	consoleTriggerDrift     = "drift"
	consoleTriggerBootstrap = "bootstrap"
	// consoleTriggerSwitch 切庫請求被清單擋下。與 execute 分值：切庫當下
	// 沒有任何執行單位，記成 execute 會讓稽核以為使用者送了一句語句
	consoleTriggerSwitch = "switch"
)

// consoleAuditContext 一場主控台會話的審計脈絡。
//
// 建立時釘住，之後不再變動：使用者、資產與會話三個主鍵是這些列的歸屬，
// 而它們在會話期間本來就不會變
type consoleAuditContext struct {
	svc       *audit.AuditLogService
	userID    uint
	username  string
	assetID   uint
	sessionID uint
	clientIP  string
	method    string
	path      string
	requestID string
}

// log 寫一列結構化事件。RequestBody 由 map 經 json.Marshal 產生，
// 不以格式化字串拼——欄位值含使用者可控的資料庫名，手拼會產生無效 JSON
func (a *consoleAuditContext) log(action model.AuditAction, resource model.AuditResource,
	status model.AuditStatus, statusCode int, body map[string]any) {
	if a == nil || a.svc == nil {
		// 本路由不掛認證中介層，中介層恆整筆跳過：審計服務缺席即回到零留痕，不得靜默
		log.Printf("[DBConsole] 審計服務未注入，事件未留痕（kind=%v status=%s）", body["kind"], status)
		return
	}
	raw, err := json.Marshal(body)
	if err != nil {
		log.Printf("[DBConsole] 事件細節序列化失敗: %v", err)
		raw = []byte(`{}`)
	}
	// 資產主體鍵直接進字面量：資產樞紐只讀 asset_id，這一欄的處置必須看得見。
	// 資產未知時寫 NULL 而非 0——0 會被讀成「編號 0 的資產」
	var assetID *uint
	if a.assetID != 0 {
		aid := a.assetID
		assetID = &aid
	}
	entry := &audit.AuditLogEntry{
		UserID:      a.userID,
		Username:    a.username,
		Action:      action,
		Resource:    resource,
		AssetID:     assetID,
		Status:      status,
		Method:      a.method,
		Path:        a.path,
		ClientIP:    a.clientIP,
		StatusCode:  statusCode,
		RequestID:   a.requestID,
		RequestBody: string(raw),
	}
	if a.sessionID != 0 {
		sid := a.sessionID
		entry.ResourceID = &sid
	}
	entry.Resource = resource
	a.svc.Log(entry)
}

// sessionEvent 會話面的事件（action=execute、resource=session）
func (a *consoleAuditContext) sessionEvent(status model.AuditStatus, statusCode int, body map[string]any) {
	a.log(model.ActionExecute, model.ResourceSession, status, statusCode, body)
}

// auditConnectFailure 起始連線失敗。**不建立會話列**，故這一列是該次嘗試的
// 唯一痕跡；class 是分類不是原文（原文只進伺服端日誌）
func (a *consoleAuditContext) auditConnectFailure(class string) {
	a.sessionEvent(model.StatusFailure, http.StatusBadGateway,
		map[string]any{"kind": consoleKindConnect, "class": class})
}

// auditAdmissionDenied admission 逾限
func (a *consoleAuditContext) auditAdmissionDenied(d consoleAdmissionDenial) {
	a.sessionEvent(model.StatusDenied, http.StatusTooManyRequests, map[string]any{
		"kind": consoleKindAdmission, "scope": d.Scope,
		"current": d.Current, "limit": d.Limit,
	})
}

// consoleTreeAudit 一次目錄瀏覽的事實
type consoleTreeAudit struct {
	Level     string
	Database  string
	Schema    string
	Table     string
	NodeCount int
	Truncated bool
	Class     string
}

// auditTree 樹瀏覽留痕。「看過哪些表」是稽核會問的問題，
// 量級與檔案列表同型（每次展開一筆）
func (a *consoleAuditContext) auditTree(t consoleTreeAudit, ok bool) {
	body := map[string]any{
		"kind": consoleKindTree, "level": t.Level, "database": t.Database,
		"node_count": t.NodeCount, "truncated": t.Truncated,
	}
	if t.Schema != "" {
		body["schema"] = t.Schema
	}
	if t.Table != "" {
		body["table"] = t.Table
	}
	status, code := model.StatusSuccess, http.StatusOK
	if !ok {
		status, code = model.StatusFailure, http.StatusBadGateway
		body["class"] = t.Class
	}
	a.log(model.ActionRead, model.ResourceSession, status, code, body)
}

// auditSwitch 切庫。class 只在失敗時有值，gate 只在重過閘被拒時有值
func (a *consoleAuditContext) auditSwitch(from, to string, status model.AuditStatus,
	statusCode int, class, gate string) {
	body := map[string]any{"kind": consoleKindSwitch, "from": from, "to": to}
	if class != "" {
		body["class"] = class
	}
	if gate != "" {
		body["gate"] = gate
	}
	a.sessionEvent(status, statusCode, body)
}

// auditTargetDenied 目標受限拒絕（清單外執行、漂移、起始庫不在清單）
func (a *consoleAuditContext) auditTargetDenied(requested, current, trigger string) {
	a.sessionEvent(model.StatusDenied, http.StatusForbidden, map[string]any{
		"kind": consoleKindTargetDenied, "requested_database": requested,
		"current_database": current, "trigger": trigger,
	})
}

// auditCancel 取消請求。confirmed 記的是目標端有沒有確認——
// 那正是 cancelled 與 effect_unknown 的分界
func (a *consoleAuditContext) auditCancel(eventID string, confirmed bool) {
	a.sessionEvent(model.StatusSuccess, http.StatusOK, map[string]any{
		"kind": consoleKindCancel, "event_id": eventID, "confirmed": confirmed,
	})
}

// auditConnectionClosed 目標連線關閉或慢速消費者關閉
func (a *consoleAuditContext) auditConnectionClosed(reason string) {
	a.sessionEvent(model.StatusFailure, http.StatusBadGateway, map[string]any{
		"kind": consoleKindConnectionClose, "reason": reason,
	})
}

// auditReconnect 客戶端重連自報。declared_by=client 是實質標記：
// 這兩個值伺服端不驗證、不據以授權，只記錄客戶端說了什麼
func (a *consoleAuditContext) auditReconnect(previousSessionID uint, pendingEventID string) {
	a.sessionEvent(model.StatusSuccess, http.StatusOK, map[string]any{
		"kind": consoleKindReconnect, "previous_session_id": previousSessionID,
		"pending_event_id": pendingEventID, "declared_by": "client",
	})
}

// auditSessionEndTxOpen 會話結束時交易仍未提交。
// 目標端將回滾是協議既定行為——本事件記的是「結束時交易還開著」這個事實，
// 不記推測；探詢已不可得時 tx_state 為 unknown
func (a *consoleAuditContext) auditSessionEndTxOpen(lastEventID, txState string) {
	a.sessionEvent(model.StatusSuccess, http.StatusOK, map[string]any{
		"kind": consoleKindSessionEndTxOpn, "last_event_id": lastEventID, "tx_state": txState,
	})
}

// ---------------------------------------------------------------------------
// 語句紀錄列
// ---------------------------------------------------------------------------

// consoleResultFacts 回填時要寫的結果事實。
//
// 指標欄的 nil 語義是「不適用或未回填」，與零值不同：`result_rows=0` 是
// 「查了但沒有列」，`result_rows=NULL` 是「這個問題不適用」
type consoleResultFacts struct {
	Status       string
	Reason       string
	ResultRows   *int64
	RowsAffected *int64
	ResultSets   *int32
	ErrorCode    string
	DurationMS   *int32
	Truncated    bool
	TxState      string
}

// consoleCommandRecorder 語句紀錄的落地面。
//
// 抽成介面是為了讓「INSERT 早於任何目標端效果」這條順序不變式可以被斷言：
// 測試以同一個 stub 同時記錄紀錄寫入與 driver 呼叫的先後，斷言的是順序本身，
// 不是「最後結果看起來對」
type consoleCommandRecorder interface {
	// Insert 寫入語句列。**失敗即不得執行**——回錯是唯一的失敗表達
	Insert(row *model.SessionCommand) error
	// Backfill 以 `WHERE result_status='running'` 條件更新結果事實，
	// 使狀態只能自 running 單向轉入終態
	Backfill(rowID uint, facts consoleResultFacts) error
}

// consoleCommandStore 語句紀錄的資料庫實作。
//
// **同步寫入，不走命令列的非同步佇列**：佇列滿即丟，與 fail-close 相斥。
// 主控台的執行者是伺服器自己，「語句已對目標生效但沒有留痕」在本路徑沒有第二個
// 真相來源可補
type consoleCommandStore struct{ db *gorm.DB }

func newConsoleCommandStore(db *gorm.DB) *consoleCommandStore {
	return &consoleCommandStore{db: db}
}

func (s *consoleCommandStore) Insert(row *model.SessionCommand) error {
	return s.db.Create(row).Error
}

func (s *consoleCommandStore) Backfill(rowID uint, f consoleResultFacts) error {
	updates := map[string]any{
		"result_status":    f.Status,
		"result_reason":    f.Reason,
		"error_code":       f.ErrorCode,
		"result_truncated": f.Truncated,
		"tx_state_after":   f.TxState,
		"result_rows":      f.ResultRows,
		"rows_affected":    f.RowsAffected,
		"result_sets":      f.ResultSets,
		"duration_ms":      f.DurationMS,
	}
	return s.db.Model(&model.SessionCommand{}).
		Where("id = ? AND result_status = ?", rowID, model.ResultStatusRunning).
		Updates(updates).Error
}

// consoleCommandRow 組一列語句紀錄的共同欄位。
// degraded 恆為 false、degrade_reason 恆為空——那組欄位回答的是命令列重組的
// 可信度問題，主控台的語句是使用者原樣送出的，沒有重組這一步
func consoleCommandRow(sessionID, userID uint, assetID *uint, seq int,
	eventID, database, text string) *model.SessionCommand {
	return &model.SessionCommand{
		SessionID:      sessionID,
		UserID:         userID,
		AssetID:        assetID,
		Command:        text,
		Seq:            seq,
		ExecutedAt:     time.Now(),
		EventID:        eventID,
		TargetDatabase: database,
	}
}
