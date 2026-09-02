package sshproxy

import (
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/dbconsole"
)

// 查詢主控台的 WebSocket 訊息協議。
//
// 與 SSH 分頁的 bridge 幀刻意不同源：後者是位元組流加上少數控制幀，主控台則是
// 純 JSON 的請求／回應通道。兩者共用同一條 WebSocket 實作沒有任何好處——
// 位元組流的形狀會逼結構化訊息走 base64，而結構化訊息的形狀會逼終端資料多一層
// 封裝，兩邊都變差。

// 客戶端訊息型別
const (
	consoleMsgHello  = "hello"
	consoleMsgQuery  = "query"
	consoleMsgCancel = "cancel"
	consoleMsgTree   = "tree"
	consoleMsgSwitch = "switch"
)

// 伺服端訊息型別
const (
	consoleMsgReady       = "ready"
	consoleMsgUnitStarted = "unit_started"
	consoleMsgResult      = "result"
	consoleMsgError       = "error"
	consoleMsgNotice      = "notice"
	consoleMsgClosed      = "closed"
	consoleMsgTreeResult  = "tree_result"
)

// 樹的層級
const (
	consoleTreeLevelDatabases = "databases"
	consoleTreeLevelTables    = "tables"
	consoleTreeLevelColumns   = "columns"
)

// notice 的碼（非錯誤的伺服端告知）。與 apierror 分離是刻意的：
// 這些不是被拒絕的請求，而是「狀態變了，畫面該跟著變」
const (
	consoleNoticeDatabaseNotAllowed  = "database_not_allowed"
	consoleNoticeDatabaseDriftDenied = "database_drift_denied"
	consoleNoticeDatabaseSwitched    = "database_switched"
)

// closed 的原因碼
const (
	consoleClosedTargetClosed = "target_closed"
	consoleClosedSlowConsumer = "slow_consumer"
	consoleClosedIdleTimeout  = "idle_timeout"
	consoleClosedMaxDuration  = "max_duration"
	consoleClosedTerminated   = "terminated"
	consoleClosedClientGone   = "client_gone"
)

// consoleClientMessage 客→服的聯集型別。
//
// 用單一結構而非逐型別解碼：訊息集小且欄位互不衝突，兩段式解碼（先讀 type
// 再依型別重解）只是多一次反序列化，卻讓「新增欄位忘了接」多一個藏身處
type consoleClientMessage struct {
	Type string `json:"type"`

	// hello：重連時客戶端自報上一場會話與未收到結果的事件。
	// **伺服端只記錄不信任**——它只用來查本人的既有列，不做任何授權推導
	PreviousSessionID uint   `json:"previous_session_id,omitempty"`
	PendingEventID    string `json:"pending_event_id,omitempty"`

	// query：執行單位的原文（編輯器全文或選取範圍）。
	// 目標庫＝當前庫，不再帶 database 參數——那會與 switch 的語義重疊
	SQL string `json:"sql,omitempty"`

	// cancel：要取消的事件
	EventID string `json:"event_id,omitempty"`

	// tree：只對當前庫
	Level  string `json:"level,omitempty"`
	Schema string `json:"schema,omitempty"`
	Table  string `json:"table,omitempty"`

	// switch：目標資料庫（必須是伺服器目錄剛回傳的名稱）
	Database string `json:"database,omitempty"`
}

// consoleLimits 送給前端的上限投影（畫面用來寫橫幅與提示的數值）
type consoleLimits struct {
	StatementBytes  int `json:"statement_bytes"`
	RowsPerUnit     int `json:"rows_per_unit"`
	BytesPerSubmit  int `json:"bytes_per_submission"`
	CellBytes       int `json:"cell_bytes"`
	TreeNodes       int `json:"tree_nodes_per_level"`
	StatementTimout int `json:"statement_timeout_seconds"`
}

func consoleLimitsProjection() consoleLimits {
	return consoleLimits{
		StatementBytes:  dbconsole.MaxStatementBytes,
		RowsPerUnit:     dbconsole.MaxRowsPerUnit,
		BytesPerSubmit:  dbconsole.MaxBytesPerSubmission,
		CellBytes:       dbconsole.MaxCellBytes,
		TreeNodes:       dbconsole.MaxTreeNodesPerLevel,
		StatementTimout: int(dbconsole.StatementTimeout.Seconds()),
	}
}

// consolePendingResult 重連時對客戶端自報的 pending 事件的回覆。
// **只回狀態與原因碼，不回結果資料**——結果快取隨舊會話釋放，
// 而把「未知」更新為真相不需要資料本身
type consolePendingResult struct {
	EventID string `json:"event_id"`
	Status  string `json:"status"`
	Reason  string `json:"result_reason,omitempty"`
}

// consoleReadyMessage 會話就緒。能力投影會過期，它永遠不是授權真相——
// 匯出端點每次都重驗政策
type consoleReadyMessage struct {
	Type            string                   `json:"type"`
	SessionID       uint                     `json:"session_id"`
	Dialect         string                   `json:"dialect"`
	Database        string                   `json:"database"`
	DatabaseAllowed bool                     `json:"database_allowed"`
	Databases       []dbconsole.DatabaseInfo `json:"databases"`
	Capabilities    map[string]bool          `json:"capabilities"`
	TxState         string                   `json:"tx_state"`
	Limits          consoleLimits            `json:"limits"`
	PendingResult   *consolePendingResult    `json:"pending_result,omitempty"`
}

// consoleUnitStartedMessage 單位開始送出。先於執行送出，
// 使畫面在多批次時能逐批對應
type consoleUnitStartedMessage struct {
	Type       string `json:"type"`
	EventID    string `json:"event_id"`
	Seq        int    `json:"seq"`
	BatchIndex int    `json:"batch_index"`
	BatchCount int    `json:"batch_count"`
}

// consoleResultMessage 單位的結果事實。與審計列同源——
// 兩者由同一個 ExecOutcome 生出，不各自判讀 driver 錯誤
type consoleResultMessage struct {
	Type         string                `json:"type"`
	EventID      string                `json:"event_id"`
	Seq          int                   `json:"seq"`
	Status       string                `json:"status"`
	ResultReason string                `json:"result_reason,omitempty"`
	Sets         []dbconsole.ResultSet `json:"sets"`
	RowsAffected int64                 `json:"rows_affected"`
	DurationMS   int32                 `json:"duration_ms"`
	Truncated    bool                  `json:"truncated"`
	TxState      string                `json:"tx_state,omitempty"`
	DBError      *dbconsole.DBError    `json:"db_error,omitempty"`
}

// consoleErrorMessage 被拒絕或失敗的請求。
// code 是機器碼，db_error 只在「已建連線上、使用者自己語句的 SQL 層錯誤」
// 才帶 message
type consoleErrorMessage struct {
	Type    string             `json:"type"`
	EventID string             `json:"event_id,omitempty"`
	Code    apierror.ErrCode   `json:"code"`
	Params  map[string]any     `json:"params,omitempty"`
	DBError *dbconsole.DBError `json:"db_error,omitempty"`
}

// consoleNoticeMessage 狀態告知（非錯誤）
type consoleNoticeMessage struct {
	Type   string         `json:"type"`
	Code   string         `json:"code"`
	Params map[string]any `json:"params,omitempty"`
}

// consoleClosedMessage 會話結束
type consoleClosedMessage struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// consoleTreeMessage 目錄樹一層的結果
type consoleTreeMessage struct {
	Type      string                   `json:"type"`
	Level     string                   `json:"level"`
	Database  string                   `json:"database"`
	Schema    string                   `json:"schema,omitempty"`
	Table     string                   `json:"table,omitempty"`
	Databases []dbconsole.DatabaseInfo `json:"databases,omitempty"`
	Tables    []dbconsole.TableInfo    `json:"tables,omitempty"`
	Columns   []dbconsole.ColumnInfo   `json:"columns,omitempty"`
	Truncated bool                     `json:"truncated"`
}
