package sshproxy

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// consoleHelloGrace 等待客戶端首則 `hello` 的寬限。
//
// `hello` 是選填的：它帶著重連時未收到結果的事件識別，而伺服端要在 `ready`
// 裡回覆該事件的終態。等它是為了讓那份回覆能搭上同一則 `ready`；等不到就照常
// 送出 `ready`——不送的話，沒有實作 `hello` 的客戶端會停在「連線中」
const consoleHelloGrace = 2 * time.Second

// consoleStatementMatcher 主控台的阻斷比對面。
//
// 與命令列共用同一個比對器（同一份規則快取、同一套協議分流），
// 差別只在**不可用時的方向**：命令列的 nil 比對器是直通，主控台是 fail-close。
// 理由是這條路徑的執行者是伺服器自己——放行一個沒被比對過的語句，
// 等於「刪掉規則就能關掉阻斷」
type consoleStatementMatcher interface {
	MatchBlock(command, protocol string) (*model.AlertRule, bool)
	MatchAndStore(cmds []model.SessionCommand, protocol string)
	consoleMatcherHealth
}

// consoleMatcherHealth 比對器自陳可用性。
//
// **列為必要面而非可選面**：比對器「活著但拿不到規則」與「活著且規則齊備」
// 在比對結果上同形（都是未命中），可用性因此只能由比對器自己說。做成可選面時，
// 少實作它的比對器會靜默取得「恆可用」的待遇，而 fail-close 分支只剩測試替身
// 到得了——那條分支要防的正好是生產路徑上的規則載入失敗
type consoleMatcherHealth interface {
	BlockerHealth() error
}

// consoleSession 一場主控台會話的執行期狀態。
//
// 生命週期與 WebSocket 同進退，只有一個例外：**進行中的執行單位不隨 WS 結束**
// （D 的「送出後斷線」條款）。若 WS 一斷就取消，一條已經生效的 DML 會被記成
// 「已取消」——那比「未知」更糟，因為它是一句錯的話而不是一句誠實的話
type consoleSession struct {
	handler *Handler
	// ginCtx 兌換當下的請求脈絡。PostgreSQL 的切庫要重跑整段閘序，
	// 而閘序表的每一道閘都以它取角色、來源位址與授權脈絡——
	// 會話期間本函式仍在 handler 的呼叫堆疊上，故它一直有效
	ginCtx *gin.Context
	// grant 兌換的票所帶的主體與客體。重跑閘序需要它，
	// 且它**不帶角色**（角色一律現查）
	grant proxy.ConnectGrant
	ws    *websocket.Conn
	sess     *model.Session
	// dialectMu 守著 dialect 本身的替換：PostgreSQL 的切庫是換一條連線，
	// 而 `cancel` 與匯出可能同時在讀它
	dialectMu sync.RWMutex
	dialect   dbconsole.Dialect
	protocol  dbconsole.Protocol
	userID   uint
	assetID  uint

	auditCtx   *consoleAuditContext
	transcript *consoleTranscript
	recorder   consoleCommandRecorder
	matcher    consoleStatementMatcher
	alerts     gatewayapi.AlertSink
	cache      *consoleResultCache

	// out 外送佇列。**有界且滿即關閉**——無界緩衝把一個慢客戶端變成
	// 整個行程的記憶體風險
	outMu     sync.Mutex
	out       chan []byte
	outClosed bool

	closeOnce sync.Once
	endMu     sync.Mutex
	endReason string

	readyOnce sync.Once

	// stateMu 守著會話的可變狀態：序號、受限態、最後一次探詢到的交易態與事件
	stateMu    sync.Mutex
	seq        int
	restricted bool
	txState    string
	lastEvent  string

	// busy 單一進行中的送出。第二個 query 直接回 BUSY，
	// 不排隊——排隊會讓使用者以為第二句已經在跑
	busyMu sync.Mutex
	busy   bool
	inWork sync.WaitGroup

	// lastActivity 閒置計時的起點：**自上一則客戶端訊息起算**，
	// 不含伺服端的送出。一條跑了五十分鐘的語句不該讓會話被判為閒置
	activityMu   sync.Mutex
	lastActivity time.Time
}

// ---------------------------------------------------------------------------
// 送出與收尾
// ---------------------------------------------------------------------------

// send 送一則訊息。佇列滿即判定為慢速消費者並收線——
// 背壓的方向必須是關掉這一條連線，不是讓它拖垮行程
func (s *consoleSession) send(v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		log.Printf("[DBConsole] 訊息序列化失敗: %v", err)
		return
	}
	overflow := false
	s.outMu.Lock()
	if s.outClosed {
		s.outMu.Unlock()
		return
	}
	select {
	case s.out <- raw:
	default:
		overflow = true
	}
	s.outMu.Unlock()

	if overflow {
		log.Printf("[DBConsole] 外送佇列已滿，關閉會話 (SessionID=%d)", s.sessionID())
		s.auditCtx.auditConnectionClosed(consoleClosedSlowConsumer)
		s.finish(consoleClosedSlowConsumer, model.EndReasonSlowConsumer)
	}
}

func (s *consoleSession) sendError(eventID string, code apierror.ErrCode,
	params map[string]any, dbErr *dbconsole.DBError) {
	s.send(consoleErrorMessage{Type: consoleMsgError, EventID: eventID,
		Code: code, Params: params, DBError: dbErr})
}

func (s *consoleSession) sendNotice(code string, params map[string]any) {
	s.send(consoleNoticeMessage{Type: consoleMsgNotice, Code: code, Params: params})
}

// finish 收尾一次。closeReason 進 `closed` 訊息（給使用者看），
// endReason 進會話列（給稽核看）——兩者刻意分開：前者要能解釋畫面上發生了什麼，
// 後者的值域被會話表的欄位釘死
func (s *consoleSession) finish(closeReason, endReason string) {
	s.closeOnce.Do(func() {
		s.endMu.Lock()
		s.endReason = endReason
		s.endMu.Unlock()

		raw, err := json.Marshal(consoleClosedMessage{Type: consoleMsgClosed, Reason: closeReason})
		s.outMu.Lock()
		if !s.outClosed {
			if err == nil {
				select {
				case s.out <- raw:
				default:
				}
			}
			s.outClosed = true
			close(s.out)
		}
		s.outMu.Unlock()
	})
}

// EndReason 會話列要寫的斷線原因
func (s *consoleSession) EndReason() string {
	s.endMu.Lock()
	defer s.endMu.Unlock()
	return s.endReason
}

// currentDialect 取當前的方言連線
func (s *consoleSession) currentDialect() dbconsole.Dialect {
	s.dialectMu.RLock()
	defer s.dialectMu.RUnlock()
	return s.dialect
}

// swapDialect 換上新連線並關掉舊的（PostgreSQL 切庫）
func (s *consoleSession) swapDialect(next dbconsole.Dialect) {
	s.dialectMu.Lock()
	prev := s.dialect
	s.dialect = next
	s.dialectMu.Unlock()
	if prev != nil {
		_ = prev.Close()
	}
}

func (s *consoleSession) sessionID() uint {
	if s.sess != nil {
		return s.sess.ID
	}
	return 0
}

// writePump 唯一的 WebSocket 寫入者（gorilla 禁止併發寫）。
// 佇列關閉後把剩餘訊息送完再關連線——`closed` 是最後一則，
// 它送不出去，使用者就只會看到連線莫名其妙斷了
func (s *consoleSession) writePump() {
	defer s.ws.Close()
	for raw := range s.out {
		_ = s.ws.SetWriteDeadline(time.Now().Add(dbconsole.WriteDeadline))
		if err := s.ws.WriteMessage(websocket.TextMessage, raw); err != nil {
			if isWriteTimeout(err) {
				log.Printf("[DBConsole] 單則寫入逾期，關閉會話 (SessionID=%d)", s.sessionID())
				s.auditCtx.auditConnectionClosed(consoleClosedSlowConsumer)
				s.finish(consoleClosedSlowConsumer, model.EndReasonSlowConsumer)
			}
			return
		}
	}
}

// isWriteTimeout 寫入期限到期與連線本身壞掉是兩件事：
// 前者是慢速消費者（我方主動收線並留痕），後者只是客戶端走了。
//
// **判定必須走 `net.Error.Timeout()`**：WebSocket 函式庫在寫入失敗時會把底層的
// 期限錯誤換成自己的錯誤型別（同樣自陳 timeout，但不再包住 `os.ErrDeadlineExceeded`），
// 只比對哨兵值會讓這條分支永遠不成立——收線照樣發生，但原因會被記成客戶端自己離開。
// 沿本套件既有的同型判定（`conn.go` 的閒置逾時）
func isWriteTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// terminate Registry 的收線回呼（資產停用、管理端終止、授權撤銷）。
// end_reason 留給 SessionService.Terminate 已寫的值——那一側才知道是誰終止的
func (s *consoleSession) terminate() error {
	s.finish(consoleClosedTerminated, "")
	return nil
}

func (s *consoleSession) touch() {
	s.activityMu.Lock()
	s.lastActivity = time.Now()
	s.activityMu.Unlock()
}

// consoleTimeoutTick 逾時檢查的取樣間隔。
//
// var 而非 const：政策值以分鐘為單位，測試若要走真實的計時路徑就得等一整個
// 取樣週期。沿監看寫入逾時（`monitorWriteTimeout`）的既有做法，讓測試縮短取樣
var consoleTimeoutTick = 15 * time.Second

// watchTimeouts 閒置與最大時長。與命令列會話共用同一組政策值——
// 一處設定全協議生效是既有契約
func (s *consoleSession) watchTimeouts(idle, max time.Duration, start time.Time, done <-chan struct{}) {
	if idle <= 0 && max <= 0 {
		return
	}
	tick := time.NewTicker(consoleTimeoutTick)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-tick.C:
			if max > 0 && now.Sub(start) >= max {
				s.finish(consoleClosedMaxDuration, endReasonMaxDuration)
				return
			}
			s.activityMu.Lock()
			last := s.lastActivity
			s.activityMu.Unlock()
			if idle > 0 && now.Sub(last) >= idle {
				s.finish(consoleClosedIdleTimeout, endReasonIdleTimeout)
				return
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 目標範圍（每次動作重讀，不快照）
// ---------------------------------------------------------------------------

// allowedDatabases 重讀資產的允許清單。
//
// **不快照**：管理者縮限清單後，既有會話的下一次動作就該受限。
// 讀取失敗時回錯而非回空清單——空清單的語義是「不限制」，
// 把讀取失敗當成不限制，會讓資料庫故障變成一次靜默的權限放寬
func (s *consoleSession) allowedDatabases() (model.StringList, error) {
	assetRow, err := s.handler.AssetService.GetByID(s.assetID)
	if err != nil {
		return nil, err
	}
	return assetRow.AllowedDatabases, nil
}

// databaseAllowed 目標庫是否在清單內。清單為空＝不限制
func databaseAllowed(allowed model.StringList, name string) bool {
	if len(allowed) == 0 {
		return true
	}
	return allowed.Contains(name)
}

// filterDatabases 樹只列交集——被排除的名稱不送出。
// 在伺服端過濾而不是讓前端隱藏：前端隱藏的東西仍在回應裡
func filterDatabases(list []dbconsole.DatabaseInfo, allowed model.StringList) []dbconsole.DatabaseInfo {
	if len(allowed) == 0 {
		return list
	}
	out := make([]dbconsole.DatabaseInfo, 0, len(list))
	for _, d := range list {
		if allowed.Contains(d.Name) {
			out = append(out, d)
		}
	}
	return out
}

func (s *consoleSession) setRestricted(v bool) {
	s.stateMu.Lock()
	s.restricted = v
	s.stateMu.Unlock()
}

func (s *consoleSession) isRestricted() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.restricted
}

func (s *consoleSession) setTxState(v string) {
	if v == "" {
		return
	}
	s.stateMu.Lock()
	s.txState = v
	s.stateMu.Unlock()
}

func (s *consoleSession) currentTxState() string {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.txState
}

func (s *consoleSession) noteEvent(id string) {
	s.stateMu.Lock()
	s.lastEvent = id
	s.stateMu.Unlock()
}

func (s *consoleSession) lastEventID() string {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.lastEvent
}

func (s *consoleSession) nextSeq() int {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.seq++
	return s.seq
}

// ---------------------------------------------------------------------------
// 訊息迴圈
// ---------------------------------------------------------------------------

// run 讀取迴圈。回傳時 WS 已不再有客戶端訊息，但**進行中的執行單位可能仍在跑**
func (s *consoleSession) run() {
	done := make(chan struct{})
	defer close(done)

	idle, max := s.handler.sessionTimeouts()
	s.touch()
	go s.watchTimeouts(idle, max, time.Now(), done)

	// 首則寬限：等 hello 或逾時，兩者都會讓 ready 送出
	graceTimer := time.AfterFunc(consoleHelloGrace, func() { s.ensureReady(nil) })
	defer graceTimer.Stop()

	for {
		_, raw, err := s.ws.ReadMessage()
		if err != nil {
			return
		}
		s.touch()

		var msg consoleClientMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			s.ensureReady(nil)
			s.sendError("", apierror.CodeBadRequestFormat, nil, nil)
			continue
		}
		s.dispatch(msg)
	}
}

func (s *consoleSession) dispatch(msg consoleClientMessage) {
	if msg.Type == consoleMsgHello {
		s.handleHello(msg)
		return
	}
	// 其餘訊息一律先確保 ready 已送出：客戶端可能根本不實作 hello
	s.ensureReady(nil)

	switch msg.Type {
	case consoleMsgQuery:
		s.handleQuery(msg.SQL)
	case consoleMsgCancel:
		s.handleCancel(msg.EventID)
	case consoleMsgTree:
		s.handleTree(msg)
	case consoleMsgSwitch:
		s.handleSwitch(msg.Database)
	default:
		s.sendError("", apierror.CodeBadRequestFormat, nil, nil)
	}
}

// handleHello 重連自報。兩個欄位都是**客戶端說的**，伺服端只記錄不信任：
// pending 事件的查詢一律加上「屬於本人」的條件，previous_session_id 除了進審計
// 之外不參與任何判定
func (s *consoleSession) handleHello(msg consoleClientMessage) {
	s.auditCtx.auditReconnect(msg.PreviousSessionID, msg.PendingEventID)
	s.ensureReady(s.lookupPendingResult(msg.PendingEventID))
}

// lookupPendingResult 查客戶端自報的事件是否已回填終態。
// **只回狀態與原因碼**——結果資料隨舊會話的快取一起釋放了，
// 而把「未知」更新成真相不需要資料本身
func (s *consoleSession) lookupPendingResult(eventID string) *consolePendingResult {
	if eventID == "" || s.handler.DB == nil {
		return nil
	}
	var row model.SessionCommand
	err := s.handler.DB.Where("event_id = ? AND user_id = ?", eventID, s.userID).
		First(&row).Error
	if err != nil || row.ResultStatus == "" || row.ResultStatus == model.ResultStatusRunning {
		return nil
	}
	return &consolePendingResult{EventID: row.EventID, Status: row.ResultStatus, Reason: row.ResultReason}
}

// ensureReady 送出 `ready`（至多一次）。
//
// 資料庫清單與交易態都要一次目標端往返，故它不是純粹的組字：ready 送出之前
// 會話還不能收語句，這也是「單一進行中」互斥從這裡就開始的原因
func (s *consoleSession) ensureReady(pending *consolePendingResult) {
	s.readyOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), dbconsole.ProbeTimeout)
		defer cancel()

		allowed, err := s.allowedDatabases()
		if err != nil {
			log.Printf("[DBConsole] 允許清單重讀失敗 (SessionID=%d): %v", s.sessionID(), err)
		}
		current := s.currentDialect().CurrentDatabase()

		var databases []dbconsole.DatabaseInfo
		if list, lerr := s.currentDialect().ListDatabases(ctx); lerr == nil {
			databases = filterDatabases(list, allowed)
		} else {
			log.Printf("[DBConsole] 起始目錄列出失敗 (SessionID=%d): %v", s.sessionID(), lerr)
		}

		txState := dbconsole.TxStateUnknown
		if st, perr := s.currentDialect().ProbeState(ctx); perr == nil {
			if st.Database != "" {
				current = st.Database
			}
			txState = st.TxState
		}
		s.setTxState(txState)

		allowedNow := databaseAllowed(allowed, current)
		s.setRestricted(!allowedNow)

		s.send(consoleReadyMessage{
			Type:            consoleMsgReady,
			SessionID:       s.sessionID(),
			Dialect:         string(s.protocol),
			Database:        current,
			DatabaseAllowed: allowedNow,
			Databases:       databases,
			Capabilities:    s.capabilities(),
			TxState:         txState,
			Limits:          consoleLimitsProjection(),
			PendingResult:   pending,
		})

		if !allowedNow {
			// 起始庫落在清單外：會話仍成立，但沒有可執行的目標，
			// 直到使用者切到清單內的庫
			s.auditCtx.auditTargetDenied(current, current, consoleTriggerBootstrap)
			s.sendNotice(consoleNoticeDatabaseNotAllowed, map[string]any{"database": current})
		}
	})
}

// capabilities 能力投影。**永遠不是授權真相**——匯出端點每次都重驗政策；
// 它只決定畫面上的按鈕是不是停用態
func (s *consoleSession) capabilities() map[string]bool {
	caps := map[string]bool{"file_download": false}
	if s.handler.DataTransfer == nil {
		// 政策服務未注入等同全通道未設限（既有測試與獨立部署路徑）
		caps["file_download"] = true
		return caps
	}
	allowed, err := s.handler.DataTransfer.AllowsAction(context.Background(), s.userID, s.assetID,
		policy.TransferChannelWeb, policy.TransferActionFileDownload)
	if err != nil {
		// fail-close：傳輸能力解析失敗一律呈現為不可匯出
		log.Printf("[DBConsole] 傳輸能力解析失敗（投影為停用）: %v", err)
		return caps
	}
	caps["file_download"] = allowed
	return caps
}

// ---------------------------------------------------------------------------
// 目錄樹
// ---------------------------------------------------------------------------

func (s *consoleSession) handleTree(msg consoleClientMessage) {
	if !s.acquire() {
		s.sendError("", apierror.CodeDBConsoleBusy, nil, nil)
		return
	}
	defer s.release()

	ctx, cancel := context.WithTimeout(context.Background(), dbconsole.StatementTimeout)
	defer cancel()

	current := s.currentDialect().CurrentDatabase()
	ev := consoleTreeAudit{Level: msg.Level, Database: current, Schema: msg.Schema, Table: msg.Table}

	switch msg.Level {
	case consoleTreeLevelDatabases:
		allowed, err := s.allowedDatabases()
		if err != nil {
			s.failTree(ev, err)
			return
		}
		list, err := s.currentDialect().ListDatabases(ctx)
		if err != nil {
			s.failTree(ev, err)
			return
		}
		list = filterDatabases(list, allowed)
		list, truncated := capSlice(list, dbconsole.MaxTreeNodesPerLevel)
		ev.NodeCount, ev.Truncated = len(list), truncated
		s.auditCtx.auditTree(ev, true)
		s.send(consoleTreeMessage{Type: consoleMsgTreeResult, Level: msg.Level,
			Database: current, Databases: list, Truncated: truncated})
	case consoleTreeLevelTables:
		list, err := s.currentDialect().ListTables(ctx, msg.Schema)
		if err != nil {
			s.failTree(ev, err)
			return
		}
		list, truncated := capSlice(list, dbconsole.MaxTreeNodesPerLevel)
		ev.NodeCount, ev.Truncated = len(list), truncated
		s.auditCtx.auditTree(ev, true)
		s.send(consoleTreeMessage{Type: consoleMsgTreeResult, Level: msg.Level,
			Database: current, Schema: msg.Schema, Tables: list, Truncated: truncated})
	case consoleTreeLevelColumns:
		list, err := s.currentDialect().ListColumns(ctx, msg.Schema, msg.Table)
		if err != nil {
			s.failTree(ev, err)
			return
		}
		list, truncated := capSlice(list, dbconsole.MaxTreeNodesPerLevel)
		ev.NodeCount, ev.Truncated = len(list), truncated
		s.auditCtx.auditTree(ev, true)
		s.send(consoleTreeMessage{Type: consoleMsgTreeResult, Level: msg.Level,
			Database: current, Schema: msg.Schema, Table: msg.Table,
			Columns: list, Truncated: truncated})
	default:
		s.sendError("", apierror.CodeBadRequestFormat, nil, nil)
	}
}

func (s *consoleSession) failTree(ev consoleTreeAudit, err error) {
	ev.Class = string(dbconsole.ClassifyConnect(s.protocol, err))
	s.auditCtx.auditTree(ev, false)
	if dbconsole.IsConnectionLost(err) {
		s.targetConnectionLost()
		return
	}
	s.sendError("", apierror.CodeDBConsoleDatabaseUnavailable, nil,
		dbconsole.DBErrorOf(s.protocol, err, false))
}

// capSlice 每層節點上限。截斷回報給畫面而不是靜默丟棄——
// 「這個庫只有兩千張表」與「這個庫有更多但我們只給兩千」是兩回事
func capSlice[T any](list []T, limit int) ([]T, bool) {
	if len(list) <= limit {
		return list, false
	}
	return list[:limit], true
}

// ---------------------------------------------------------------------------
// 切換資料庫
// ---------------------------------------------------------------------------

// handleSwitch 切庫。
//
// PostgreSQL 的連線綁死資料庫，切庫就是換一條連線——那意味著**重跑整段閘序、
// 重新解封憑證**。不重跑等於用一張已經兌換過的票開第二條連線，而授權在這段
// 期間可能已經被撤銷
func (s *consoleSession) handleSwitch(target string) {
	if target == "" {
		s.sendError("", apierror.CodeBadRequestFormat, nil, nil)
		return
	}
	if !s.acquire() {
		s.sendError("", apierror.CodeDBConsoleBusy, nil, nil)
		return
	}
	defer s.release()

	from := s.currentDialect().CurrentDatabase()

	allowed, err := s.allowedDatabases()
	if err != nil {
		s.auditCtx.auditSwitch(from, target, model.StatusFailure, http.StatusBadGateway, "unknown", "")
		s.sendError("", apierror.CodeDBConsoleDatabaseUnavailable, nil, nil)
		return
	}
	if !databaseAllowed(allowed, target) {
		s.auditCtx.auditSwitch(from, target, model.StatusDenied, http.StatusForbidden, "", "")
		s.auditCtx.auditTargetDenied(target, from, consoleTriggerSwitch)
		s.sendError("", apierror.CodeDBConsoleDatabaseNotAllowed, nil, nil)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbconsole.ConnectTimeout)
	defer cancel()

	err = s.currentDialect().Switch(ctx, target)
	if errors.Is(err, dbconsole.ErrSwitchRequiresReconnect) {
		s.switchByReconnect(from, target)
		return
	}
	if err != nil {
		class := string(dbconsole.ClassifyConnect(s.protocol, err))
		s.auditCtx.auditSwitch(from, target, model.StatusFailure, http.StatusBadGateway, class, "")
		s.transcript.SwitchFailed(class)
		// 切庫的回應永遠只帶碼不帶訊息
		s.sendError("", apierror.CodeDBConsoleDatabaseUnavailable, nil,
			dbconsole.DBErrorOf(s.protocol, err, false))
		return
	}

	s.afterSwitch(from, target)
}

// afterSwitch 切庫成功後的共同收尾（兩種切法共用）
func (s *consoleSession) afterSwitch(from, to string) {
	s.setRestricted(false)
	s.auditCtx.auditSwitch(from, to, model.StatusSuccess, http.StatusOK, "", "")
	s.transcript.Switched(to)
	s.sendNotice(consoleNoticeDatabaseSwitched, map[string]any{"database": to})
}

// ---------------------------------------------------------------------------
// 取消
// ---------------------------------------------------------------------------

// handleCancel 取消進行中的單位。
//
// **confirmed 是本函式唯一要弄清楚的事**：目標端確認取消＝該語句確定沒有生效
// （記 cancelled），沒確認＝我們不知道（記 effect_unknown）。
// 兩者對稽核是完全不同的兩句話
func (s *consoleSession) handleCancel(eventID string) {
	ctx, cancel := context.WithTimeout(context.Background(), dbconsole.ProbeTimeout)
	defer cancel()

	confirmed, err := s.currentDialect().Cancel(ctx)
	if errors.Is(err, dbconsole.ErrNoStatementInFlight) {
		return
	}
	s.auditCtx.auditCancel(eventID, confirmed)
	if err != nil && !confirmed {
		log.Printf("[DBConsole] 取消請求未獲確認 (SessionID=%d): %v", s.sessionID(), err)
	}
}

// ---------------------------------------------------------------------------
// 單一進行中
// ---------------------------------------------------------------------------

func (s *consoleSession) acquire() bool {
	s.busyMu.Lock()
	defer s.busyMu.Unlock()
	if s.busy {
		return false
	}
	s.busy = true
	return true
}

func (s *consoleSession) release() {
	s.busyMu.Lock()
	s.busy = false
	s.busyMu.Unlock()
}

// targetConnectionLost 目標連線關閉：**不重撥**。
// 重撥要重新解封憑證，而那是一次沒有票、沒有閘序的連線建立
func (s *consoleSession) targetConnectionLost() {
	s.auditCtx.auditConnectionClosed(consoleClosedTargetClosed)
	s.transcript.ConnectionClosed(consoleClosedTargetClosed)
	s.sendError("", apierror.CodeDBConsoleConnectionLost, nil, nil)
	s.finish(consoleClosedTargetClosed, model.EndReasonTargetClosed)
}
