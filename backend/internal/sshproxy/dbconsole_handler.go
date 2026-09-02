package sshproxy

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// HandleDBConsole 處理 `GET /api/v1/db-console` 的 WebSocket 連線。
//
// 與 `/ssh` 同一條兌換路徑：同一種一次性票、同一張閘序表、同一個唯一解封點、
// 同樣的會話記錄 fail-close。差別只有兩處——**多兩道閘**（協議與 admission）
// 與**連線形態**（driver 直連而非啟子程序）。
//
// 閘序表逐字共用不是為了少寫程式碼，是為了讓「兩個入口的判定不同」變成不可能：
// 主控台若自己重寫一組 if 鏈，任何一次閘序更新都得記得改兩個地方，而漏掉的那次
// 不會有任何東西轉紅
func (h *Handler) HandleDBConsole(c *gin.Context) {
	ct := c.Query("connect_token")
	if ct == "" {
		h.auditRedeemDenied(c, proxy.ConnectDenial{
			Reason: string(proxy.RedeemDenyMissing), HTTPStatus: http.StatusUnauthorized},
			proxy.ViaDBConsole)
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeConnectTokenMissing, nil)
		return
	}
	grant, denyReason := h.ConnectTokens.RedeemConnectTokenWithReason(c.Request.Context(), ct)
	if denyReason != proxy.RedeemDenyNone {
		h.auditRedeemDenied(c, proxy.ConnectDenial{
			Reason: string(denyReason), HTTPStatus: http.StatusUnauthorized},
			proxy.ViaDBConsole)
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeConnectTokenInvalid, nil)
		return
	}

	st := &redeemState{grant: grant}
	subj := st.contractSubject(sourceip.Of(c))
	auditCtx := h.consoleAuditContext(c, grant.UserID, grant.AssetID)

	// admission 名額於閘序內佔用。任何後續失敗都必須釋放，否則一次被拒的兌換
	// 會永久吃掉一個名額——那是使用者無法自救的狀態
	var releaseAdmission func()
	keep := false
	defer func() {
		if releaseAdmission != nil && !keep {
			releaseAdmission()
		}
	}()

	var gate gatewayapi.PolicyGate = connectgate.NewSequence(
		func(s gatewayapi.ConnectSubject) []connectgate.Gate {
			return h.consolePreResolveGates(c, s, st)
		},
		func(s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject) []connectgate.Gate {
			return h.consoleResolvedAccountGates(c, s, o, st, auditCtx, &releaseAdmission)
		},
	)
	reqCtx := c.Request.Context()
	if out := gate.AuthorizePreResolve(reqCtx, subj, gatewayapi.StageRedeemTerminal); out != nil {
		h.writeRedeemOutcome(c, out, st, proxy.ViaDBConsole)
		return
	}
	userID, assetID := grant.UserID, grant.AssetID

	// 唯一解封點：與 `/ssh` 共用同一個呼叫，帳號於簽發後被刪除或改隸他資產者
	// 在此 fail-close，絕不靜默退回預設帳號
	creds, err := h.AssetService.GetWithCredentialsForAccount(assetID, grant.AccountID)
	if err != nil {
		log.Printf("[DBConsole] 取得資產憑證失敗: assetID=%d, accountID=%d, err=%v",
			assetID, grant.AccountID, err)
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetCredentialUnavailable, nil)
		return
	}
	st.creds = creds
	resolved := st.contractObject()
	if out := gate.AuthorizeResolvedAccount(reqCtx, subj, resolved,
		gatewayapi.StageRedeemTerminal); out != nil {
		h.writeRedeemOutcome(c, out, st, proxy.ViaDBConsole)
		return
	}

	assetRow := creds.Asset
	protocol := dbconsole.Protocol(assetRow.Protocol)

	// 建立目標連線。密碼的所有權移交 dbconsole：Open 返回時我方副本已清零
	dialCtx, cancelDial := context.WithTimeout(context.Background(), dbconsole.ConnectTimeout)
	dialect, err := dbconsole.Open(dialCtx, dbconsole.Config{
		Protocol: protocol,
		Host:     assetRow.Host,
		Port:     assetRow.Port,
		Username: creds.Username,
		Password: []byte(creds.Password),
		Database: assetRow.DBName,
		TLSMode:  assetRow.DBTLSMode,
		CACert:   assetRow.DBCACert,
	})
	cancelDial()
	if err != nil {
		// 起始連線失敗一律泛化：連線階段的錯誤字串含主機、埠、憑證主體與
		// 主機端規則，那些是我們的拓撲不是使用者的產品內容。**不建立會話列**
		class := dbconsole.ClassifyConnect(protocol, err)
		log.Printf("[DBConsole] 目標連線失敗: assetID=%d class=%s err=%v", assetID, class, err)
		auditCtx.auditConnectFailure(string(class))
		h.writeConsoleDialError(c, consoleConnectCode(class),
			dbconsole.DBErrorOf(protocol, err, false))
		return
	}

	// 會話記錄 fail-close：無 session 主鍵即無註冊表、錄影、語句審計與監看，
	// 一律拒連——admin 亦不豁免
	sess := h.createSession(userID, assetID, assetRow.Protocol, sourceip.Of(c), nil,
		accountSnapshot{ID: creds.AccountID, Username: creds.Username},
		authProvenance{ProviderID: grant.ProviderID, AuthEpoch: grant.AuthEpoch,
			AuthMethod: grant.AuthMethod, CredEpoch: grant.CredEpoch}, true)
	if sess == nil {
		_ = dialect.Close()
		log.Printf("[DBConsole] session 記錄建立失敗，連線已拒 (userID=%d assetID=%d)", userID, assetID)
		if failure := audit.GetAuditFailure(); failure != nil {
			failure.Report(model.MechanismSessionRecord, model.CauseSessionRecordCreateFailed,
				map[string]string{
					"user_id":  strconv.FormatUint(uint64(userID), 10),
					"asset_id": strconv.FormatUint(uint64(assetID), 10),
				})
		}
		writeSessionRecordFailed(c)
		return
	}
	auditCtx.sessionID = sess.ID
	h.observeSourceIP(c, sess, userID, assetID)

	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[DBConsole] WebSocket 升級失敗: %v", err)
		_ = dialect.Close()
		h.closeSession(sess, "")
		return
	}
	keep = true

	cs := h.newConsoleSession(c, ws, sess, dialect, protocol, grant, auditCtx)
	h.runConsoleSession(cs, releaseAdmission)
}

// consoleConnectCode 起始連線錯誤分類到對外機器碼的映射。
// 只有拓撲類帶目標端錯誤碼——其餘三類連碼都不帶，因為那些碼本身就在說
// 「認證失敗」或「TLS 驗不過」，等於把分類洩漏出去
func consoleConnectCode(class dbconsole.ErrorClass) apierror.ErrCode {
	if class == dbconsole.ClassTopology {
		return apierror.CodeDBConsoleDatabaseUnavailable
	}
	return apierror.CodeDBConsoleConnectFailed
}

// writeConsoleDialError 目標連線失敗的透傳。
//
// WebSocket 握手失敗的 HTTP body 瀏覽器讀不到，故先升級再以主控台自己的
// `error` 訊息送出原因後關閉；非升級請求維持一般 HTTP 語義
func (h *Handler) writeConsoleDialError(c *gin.Context, code apierror.ErrCode, dbErr *dbconsole.DBError) {
	if !websocket.IsWebSocketUpgrade(c.Request) {
		apierror.Respond(c, http.StatusBadGateway, code, nil)
		return
	}
	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[DBConsole] 錯誤透傳升級失敗: %v", err)
		return
	}
	defer ws.Close()
	if code != apierror.CodeDBConsoleDatabaseUnavailable {
		dbErr = nil
	}
	if raw, encErr := json.Marshal(consoleErrorMessage{
		Type: consoleMsgError, Code: code, DBError: dbErr}); encErr == nil {
		_ = ws.SetWriteDeadline(time.Now().Add(dbconsole.WriteDeadline))
		_ = ws.WriteMessage(websocket.TextMessage, raw)
	}
	_ = ws.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// consolePreResolveGates 兌換側「憑證解封之前」的閘序。
//
// 與 `/ssh` 逐字共用，只**移除終端尺寸閘**：那一道解析的是要開多大的 PTY，
// 而主控台沒有 PTY——它的轉錄用固定的虛擬尺寸。要求客戶端送一個沒有意義的
// 尺寸參數，只會讓「忘了帶尺寸」變成一個看起來像授權失敗的錯誤。
// **被移除的是請求形狀閘，不是任何一道判定閘**：角色現查、來源限定與憑證世代
// 三道原樣保留
func (h *Handler) consolePreResolveGates(c *gin.Context,
	s gatewayapi.ConnectSubject, st *redeemState) []connectgate.Gate {
	base := h.redeemPreResolveGates(c, s, st)
	out := make([]connectgate.Gate, 0, len(base))
	for _, g := range base {
		if g.Name == consoleTerminalSizeGate {
			continue
		}
		out = append(out, g)
	}
	return out
}

// consoleTerminalSizeGate 終端尺寸閘的名稱（唯一被主控台略過的閘）。
// 具名常數而非字面值：閘改名時本檔的略過會靜默失效，而那時主控台會開始
// 要求一個不存在的參數
const consoleTerminalSizeGate = "G-S5"

// consoleResolvedAccountGates 兌換側「憑證解封之後」的閘序，
// 在 G-S8（文字終端）之後插入兩道主控台專屬的閘。
//
// **插在中間而不是接在最後**：G-C1 判的是「這個資產根本不該走這個入口」，
// 那個判定不必先過授權與政策；G-C2 佔名額，佔在授權之前會讓一次注定被拒的
// 兌換也吃掉名額
func (h *Handler) consoleResolvedAccountGates(c *gin.Context,
	s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject, st *redeemState,
	auditCtx *consoleAuditContext, release *func()) []connectgate.Gate {
	base := h.redeemResolvedAccountGates(c, s, o, st)
	extra := []connectgate.Gate{
		{Name: "G-C1", Eval: func() *connectgate.Outcome {
			if !dbconsole.Protocol(o.Protocol).Supported() {
				return connectgate.Deny(http.StatusBadRequest,
					string(apierror.CodeDBConsoleUnsupportedProtocol), nil)
			}
			return nil
		}},
		{Name: "G-C2", Eval: func() *connectgate.Outcome {
			rel, denial := h.consoleAdmission().acquire(s.UserID)
			if denial != nil {
				auditCtx.auditAdmissionDenied(*denial)
				return connectgate.Deny(http.StatusTooManyRequests,
					string(apierror.CodeDBConsoleLimitReached), nil)
			}
			*release = rel
			return nil
		}},
	}
	return insertGatesAfter(base, "G-S8", extra)
}

// insertGatesAfter 在指定閘之後插入。找不到錨點時附在最後——
// 閘序表改名時寧可多跑兩道閘，也不要靜默地把它們丟掉
func insertGatesAfter(base []connectgate.Gate, anchor string, extra []connectgate.Gate) []connectgate.Gate {
	out := make([]connectgate.Gate, 0, len(base)+len(extra))
	inserted := false
	for _, g := range base {
		out = append(out, g)
		if g.Name == anchor {
			out = append(out, extra...)
			inserted = true
		}
	}
	if !inserted {
		log.Printf("[DBConsole] 閘序錨點 %s 不存在，主控台閘已附於序尾", anchor)
		out = append(out, extra...)
	}
	return out
}

// consoleAuditContext 建立本場會話的審計脈絡（會話主鍵於建立後補上）
func (h *Handler) consoleAuditContext(c *gin.Context, userID, assetID uint) *consoleAuditContext {
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	username := ""
	if h.AuthService != nil {
		if info, err := h.AuthService.GetUserByID(userID); err == nil && info != nil {
			username = info.Username
		}
	}
	return &consoleAuditContext{
		svc: h.AuditService, userID: userID, username: username, assetID: assetID,
		clientIP: sourceip.Of(c), method: c.Request.Method, path: path,
		requestID: c.GetString("request_id"),
	}
}

// newConsoleSession 組裝會話的執行期狀態
func (h *Handler) newConsoleSession(c *gin.Context, ws *websocket.Conn, sess *model.Session,
	dialect dbconsole.Dialect, protocol dbconsole.Protocol, grant proxy.ConnectGrant,
	auditCtx *consoleAuditContext) *consoleSession {
	return &consoleSession{
		handler:  h,
		ginCtx:   c,
		grant:    grant,
		ws:       ws,
		sess:     sess,
		dialect:  dialect,
		protocol: protocol,
		userID:   sess.UserID,
		assetID:  auditCtx.assetID,
		auditCtx: auditCtx,
		recorder: newConsoleCommandStore(database.DB),
		matcher:  consoleMatcherOf(audit.GetAlertMatcher()),
		alerts:   h.AlertSink,
		cache:    newConsoleResultCache(),
		out:      make(chan []byte, dbconsole.OutboundQueueDepth),
	}
}

// consoleMatcherOf 具體型別的 nil 指標裝進介面後不等於 nil，
// 而主控台把「比對器缺席」當成 fail-close 的訊號——不濾掉這種值，
// fail-close 會在第一次比對時變成 panic
func consoleMatcherOf(m *audit.AlertMatcher) consoleStatementMatcher {
	if m == nil {
		return nil
	}
	return m
}

// runConsoleSession 會話的完整生命週期：錄影與監看掛載 → 註冊表登記 →
// 訊息迴圈 → 收尾。收尾順序與命令列會話同構
func (h *Handler) runConsoleSession(cs *consoleSession, releaseAdmission func()) {
	sess := cs.sess
	defer func() {
		if releaseAdmission != nil {
			releaseAdmission()
		}
	}()

	// 轉錄錄影：啟動失敗不斷線（fail-close 只掛簽發點），但不得沉默
	var recTap *recordingTap
	if tap, recErr := newRecordingTap(h.RecordingPath, sess.ID,
		consoleTranscriptCols, consoleTranscriptRows); recErr != nil {
		session.ReportSessionRecordingFailure(sess.ID, model.MechanismRecordingText,
			model.CauseRecordingStartFailed,
			map[string]string{model.CauseParamDetail: recErr.Error()})
	} else {
		recTap = tap
		sid := sess.ID
		recTap.SetOnFailure(func(causeCode string, params map[string]string) {
			session.ReportSessionRecordingFailure(sid, model.MechanismRecordingText, causeCode, params)
		})
		if err := h.SessionService.SetRecordingStartedAt(sess.ID, recTap.startTime); err != nil {
			log.Printf("[DBConsole] 錄影起始時刻寫入失敗 (SessionID=%d): %v", sess.ID, err)
		}
		if failure := audit.GetAuditFailure(); failure != nil {
			failure.Resolve(model.MechanismRecordingText)
		}
	}
	room := h.Monitor.OpenRoom(sess.ID, consoleTranscriptCols, consoleTranscriptRows)
	cs.transcript = newConsoleTranscript(recTap, room)

	h.Registry.Register(sess.ID, cs.terminate)
	if h.SessionService.IsTerminated(sess.ID) {
		// 停用／撤銷落在「會話已建立、註冊表尚未登記」的窗口內時，
		// 那一側的收線是 no-op；此處的複查即該殘留窗口的封口
		log.Printf("[DBConsole] session 於建立後即被收線，拒絕啟動 (SessionID=%d)", sess.ID)
		cs.finish(consoleClosedTerminated, "")
	}
	h.consoleSessionsRef().Store(sess.ID, cs)

	go cs.writePump()
	cs.run()

	// 讀取迴圈結束不等於執行單位結束：語句的 ctx 不綁 WebSocket，
	// 等它跑完才關連線，否則已生效的 DML 會被記成一個假的終態
	cs.inWork.Wait()
	cs.finish(consoleClosedClientGone, "")

	cs.auditSessionEndTransaction()
	cs.cache.release()
	h.consoleSessionsRef().Delete(sess.ID)
	if d := cs.currentDialect(); d != nil {
		_ = d.Close()
	}
	if recTap != nil {
		recTap.Close(h.SessionService, sess.ID)
	}
	h.Monitor.CloseRoom(sess.ID)
	h.Registry.Unregister(sess.ID)
	h.Shares.Revoke(sess.ID)
	h.closeSession(sess, cs.EndReason())
	log.Printf("[DBConsole] 會話已結束: assetID=%d reason=%s", cs.assetID, cs.EndReason())
}

// auditSessionEndTransaction 會話結束時交易仍未提交即留一筆事實。
//
// 目標端將回滾是協議既定行為——本事件記的是「結束時交易還開著」，
// 不記推測。稽核讀到最後一筆 `ok` 時，據此知道那筆的命運是回滾
func (s *consoleSession) auditSessionEndTransaction() {
	tx := s.currentTxState()
	if tx != model.TxStateActive && tx != model.TxStateFailed {
		return
	}
	s.auditCtx.auditSessionEndTxOpen(s.lastEventID(), tx)
}

// switchByReconnect PostgreSQL 的切庫＝關閉並重連。
//
// **重跑整段閘序、重新解封憑證**：不重跑等於用一張已經兌換過的票再開一條連線，
// 而授權、資產狀態與存取政策在這段期間都可能已經變了。舊連線在新連線建立成功
// 之前不關——閘序被拒或撥號失敗時，使用者的會話應該原封不動留在原本的庫上
func (s *consoleSession) switchByReconnect(from, to string) {
	c := s.ginCtx
	st := &redeemState{grant: s.grant}
	subj := st.contractSubject(sourceip.Of(c))
	h := s.handler

	// 前置閘序取主控台版：判定閘（角色現查、來源限定、憑證世代）逐道重跑，
	// 只少那道終端尺寸閘——它解析的是要開多大的 PTY，而主控台的協議裡沒有
	// 尺寸這回事。用終端版的話，每一次切庫都會被一個客戶端不可能帶的參數擋下
	var gate gatewayapi.PolicyGate = connectgate.NewSequence(
		func(cs gatewayapi.ConnectSubject) []connectgate.Gate {
			return h.consolePreResolveGates(c, cs, st)
		},
		func(cs gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject) []connectgate.Gate {
			return h.redeemResolvedAccountGates(c, cs, o, st)
		},
	)
	ctx := context.Background()
	if out := gate.AuthorizePreResolve(ctx, subj, gatewayapi.StageRedeemTerminal); out != nil {
		s.denySwitch(from, to, out)
		return
	}
	creds, err := h.AssetService.GetWithCredentialsForAccount(s.assetID, s.grant.AccountID)
	if err != nil {
		log.Printf("[DBConsole] 切庫時取得憑證失敗: assetID=%d err=%v", s.assetID, err)
		s.auditCtx.auditSwitch(from, to, model.StatusFailure, http.StatusBadGateway, "unknown", "")
		s.transcript.SwitchFailed("unknown")
		s.sendError("", apierror.CodeDBConsoleDatabaseUnavailable, nil, nil)
		return
	}
	st.creds = creds
	if out := gate.AuthorizeResolvedAccount(ctx, subj, st.contractObject(),
		gatewayapi.StageRedeemTerminal); out != nil {
		s.denySwitch(from, to, out)
		return
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), dbconsole.ConnectTimeout)
	next, err := dbconsole.Open(dialCtx, dbconsole.Config{
		Protocol: s.protocol,
		Host:     creds.Asset.Host,
		Port:     creds.Asset.Port,
		Username: creds.Username,
		Password: []byte(creds.Password),
		Database: to,
		TLSMode:  creds.Asset.DBTLSMode,
		CACert:   creds.Asset.DBCACert,
	})
	cancel()
	if err != nil {
		class := string(dbconsole.ClassifyConnect(s.protocol, err))
		log.Printf("[DBConsole] 切庫重連失敗: assetID=%d class=%s err=%v", s.assetID, class, err)
		s.auditCtx.auditSwitch(from, to, model.StatusFailure, http.StatusBadGateway, class, "")
		s.transcript.SwitchFailed(class)
		// 切庫的回應永遠只帶碼不帶訊息
		s.sendError("", apierror.CodeDBConsoleDatabaseUnavailable, nil,
			dbconsole.DBErrorOf(s.protocol, err, false))
		return
	}
	s.swapDialect(next)
	// 新連線＝新交易脈絡：未提交的交易與暫存態在舊連線上一起消失了
	s.setTxState(dbconsole.TxStateNone)
	s.afterSwitch(from, to)
}

// denySwitch 切庫時閘序被拒：會話維持原庫，留痕帶被拒的閘與其判定碼
func (s *consoleSession) denySwitch(from, to string, out *connectgate.Outcome) {
	s.auditCtx.auditSwitch(from, to, model.StatusDenied, out.Status, "", out.Decision.Code)
	s.sendError("", apierror.ErrCode(out.Decision.Code), nil, nil)
}
