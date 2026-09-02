package sshproxy

import (
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"gorm.io/gorm"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/dbproxy"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"golang.org/x/crypto/ssh"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		// 與既有 guacd 路徑一致：開發環境允許所有來源，生產應檢查 Origin
		return true
	},
}

// dialErrorCode 將 classifyDialError 的 sentinel 映射為 apierror code
// 僅 SSH 撥號分支使用
func dialErrorCode(err error) apierror.ErrCode {
	switch {
	case errors.Is(err, asset.ErrHostKeyChanged):
		return apierror.CodeSSHHostKeyChanged
	case errors.Is(err, ErrAuthFailed):
		return apierror.CodeSSHAuthFailed
	case errors.Is(err, ErrDialTimeout):
		return apierror.CodeSSHDialTimeout
	default:
		return apierror.CodeSSHUnreachable
	}
}

// k8sDialCode 將 k8sproxy 的錯誤分類（K8sError.Kind）映為 apierror 碼。
//
// 映射本體已移入 k8sproxy.ErrCodeOf——WS 撥號與
// HTTP pod 列表（api.ListK8sPods）共用同一份，避免兩處分頭維護時漏配
// 新 Kind。本函式保留為套件內薄別名，呼叫點與既有測試不動。
func k8sDialCode(err error) apierror.ErrCode {
	return k8sproxy.ErrCodeOf(err)
}

// writeDialError 對瀏覽器透傳升級前的終端連線建立失敗：
// WS 握手失敗的 HTTP body 瀏覽器讀不到，故先升級再以 MsgError（code＋zh
// fallback）送出原因後關閉。非 WS 升級請求維持既有 HTTP 502 JSON 語義。
//
// code 為 apierror.ErrCode 必填（原「空字串＝尚未 code 化」的 k8s/database
// 分支已補碼）；msg 為 zh fallback，撥號類傳底層已分類的具體訊息。
func writeDialError(c *gin.Context, code apierror.ErrCode, msg string) {
	if !websocket.IsWebSocketUpgrade(c.Request) {
		// 非 WS 分支同步碼化：error 欄由碼的 ZhFallback 渲染，
		// msg（撥號分類後的具體訊息）只服務 WS 幀的 Data fallback
		apierror.Respond(c, http.StatusBadGateway, code, nil)
		return
	}
	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		// Upgrade 失敗時 gorilla 已自行寫入 HTTP 錯誤回應，不可再疊寫
		log.Printf("[SSHProxy] 錯誤透傳升級失敗: %v", err)
		return
	}
	defer ws.Close()
	if raw, encErr := EncodeErrorMessage(code, msg); encErr == nil {
		_ = ws.WriteMessage(websocket.TextMessage, raw)
	}
	_ = ws.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// ---------------------------------------------------------------------------
// 連線決策閘出口
//
// 這些回應除 {error, code} 外還帶 reason/policy 等**機器欄**：前端 connect.js
// 以 `resp.data.reason` 做控制流分支（彈事由輸入框／錄影異常提示／申請核准流），
// 欄位名與值一字不可改。apierror.Write 的 Meta 平鋪到封套 top-level
//（見 apierror.Write：`body[k] = v`），故遷移後讀法完全不變。
// ---------------------------------------------------------------------------

// writeSessionRecordFailed 會話記錄 fail-close
func writeSessionRecordFailed(c *gin.Context) {
	apierror.Write(c, http.StatusForbidden, apierror.ErrorResponse{
		Code: apierror.CodeSessionRecordFailed,
		Meta: map[string]any{"reason": "session_unavailable"},
	})
}

// transmissionGateCode 把傳輸安全閘的等級映為碼（strict＝無條件拒絕、
// warn＝需同意；狀態碼仍由 decision.Status 決定，不隨本映射改變）
func transmissionGateCode(level string) apierror.ErrCode {
	if level == policy.TransportLevelStrict {
		return apierror.CodeTransmissionStrictReject
	}
	return apierror.CodeTransmissionConsentRequired
}

// accessGateCode 把存取政策閘的 reason 映為碼（原為兩段中文散文）
func accessGateCode(reason string) apierror.ErrCode {
	if reason == policy.AccessGateReasonRequired {
		return apierror.CodeAccessReasonRequired
	}
	return apierror.CodeAccessApprovalRequired
}

// Handler 原生 SSH 終端的 WebSocket 處理器
//
// 與 guacd 路徑的根本差異：endpoint 只收 token + asset_id，
// 憑證由後端解密注入，前端與 URL 全程不出現明文密碼。
type Handler struct {
	AssetService         *asset.AssetService
	AuthService          *identity.AuthService
	AuthorizationService *authz.AssetAuthorizationService
	SessionService       *session.SessionService
	Registry             *proxy.ConnectionRegistry
	RecordingPath        string
	Monitor              *MonitorHub
	Shares               *ShareManager
	ConnectTokens        *proxy.ConnectTokenManager
	HostKeys             *asset.HostKeyService
	// TransmissionConsent 傳輸安全連線閘＋同意立據；
	// nil 時閘不生效（既有測試與獨立部署路徑，等同全通道 off）
	TransmissionConsent *policy.TransmissionConsentService
	// AccessPolicy 存取政策閘：簽發點第三道閘，
	// 授權檢查之後、傳輸閘之前。組裝端一律注入（不掛功能開關）；
	// nil 僅限既有測試路徑，等同全域段位 open
	AccessPolicy *policy.AccessPolicyService
	// TimeoutPolicy 會話閒置/最大時長來源：由組裝端注入
	// 安全政策讀取（session_idle_minutes/session_max_minutes，政策改動新連線即生效）；
	// nil 時退回環境變數（既有測試與獨立部署路徑）
	TimeoutPolicy func() (idle, max time.Duration)
	// RecordingFailClose 錄影 fail-close 政策讀取：
	// 組裝端注入；nil 視為關閉（既有測試路徑）。偵測/告警不受此開關影響
	RecordingFailClose func() bool
	// AlertSink 指令告警落地面：阻斷告警的入庫、
	// 通知與 syslog 離機轉發共用出口。組裝端一律注入且於啟動時自檢
	//（cmd/server/audit_sinks.go 的 requireAlertSink）；nil 僅限既有測試路徑，
	// 該情形下阻斷仍生效、告警落地失敗會留 log，SHALL NOT 靜默丟棄
	AlertSink gatewayapi.AlertSink
	// AuditService 本 handler 自寫留痕的出口：監看／分享觀看加入
	//與 `GET /api/v1/ssh` 的**兌換拒絕**。
	//
	// **為何非有不可**：`/ssh`、`/sessions/:id/monitor`、`/sessions/share/:code/ws`
	// 三條路由都不掛 AuthMiddleware（WebSocket 只能以 query token／connect_token
	// 認證，見 `authenticate` 檔頭），身分於 handler 內自解析；`AuditLogMiddleware`
	// 缺 userID／username 時整筆跳過，故這些路徑在中介層永遠是零列。組裝端一律注入；
	// nil 僅限既有測試路徑，該情形下 `auditObserverJoin`／`auditRedeemDenied` 記 log，
	// SHALL NOT 靜默略過
	AuditService *audit.AuditLogService
	// SourceIPBaseline 帳號 × 來源位址的「已見」基準與新來源位址告警。
	//
	// 建線成功、session 主鍵已得之後觀察一次；首次自該位址建線者在同一交易內
	// 得到一筆告警列。**失敗不阻連線**（旁路功能無權殺主流程），但也不靜默——
	// 一律記 log，且交易失敗即整筆回滾，下次自同位址建線會補發。
	// nil 僅限既有測試路徑，該情形下不觀察、不告警
	SourceIPBaseline *audit.SourceIPBaseline
	// DataTransfer 資料傳輸政策：查詢主控台的結果匯出走 `file_download`
	// 這一條既有判定鍵（第四個強制點）。nil 僅限既有測試路徑，
	// 該情形下等同全通道未設限
	DataTransfer *policy.DataTransferService
	// DB 查詢主控台自寫的語句紀錄與 pending 事件回查的資料庫控制代碼。
	// 命令列那一側走 CommandStore 的非同步佇列，主控台則是同步 fail-close，
	// 兩者的落地面因此不同源
	DB *gorm.DB
	// statsClients 活躍會話的 ssh.Client（session-stats）：sessionID -> *ssh.Client
	statsClients sync.Map
	// consoleAdmissionOnce/consoleAdmissionReg 主控台名額登記表（運行時計數）。
	// 惰性建立是因為既有測試以裸結構建 Handler（不走 NewHandler），
	// 而少一個名額登記表就等於 admission 閘靜默失效
	consoleAdmissionOnce sync.Once
	consoleAdmissionReg  *consoleAdmission
	// consoleSessions 活躍主控台會話：sessionID -> *consoleSession。
	// 結果匯出端點靠它找到快取——快取只存在於行程記憶體，
	// 會話結束即釋放，那正是匯出鈕在會話結束後停用的原因
	consoleSessions sync.Map
}

// consoleAdmission 名額登記表（惰性建立）
func (h *Handler) consoleAdmission() *consoleAdmission {
	h.consoleAdmissionOnce.Do(func() {
		h.consoleAdmissionReg = newConsoleAdmission()
	})
	return h.consoleAdmissionReg
}

// consoleSessionsRef 活躍主控台會話表
func (h *Handler) consoleSessionsRef() *sync.Map {
	return &h.consoleSessions
}

// NewHandler 建立 SSH 終端處理器。
//
// auditService 走建構子而非組裝根的裸欄位注入：
// 監看留痕是本產品最敏感的稽核項，缺席即「誰旁觀了誰」不可查；建構子參數使
// 「漏接」成為編譯錯誤，比登記表更早一步。既有測試路徑傳 nil，該情形下記 log
// 不靜默。
func NewHandler(
	assetService *asset.AssetService,
	authService *identity.AuthService,
	authorizationService *authz.AssetAuthorizationService,
	sessionService *session.SessionService,
	registry *proxy.ConnectionRegistry,
	recordingPath string,
	auditService *audit.AuditLogService,
) *Handler {
	return &Handler{
		AssetService:         assetService,
		AuthService:          authService,
		AuthorizationService: authorizationService,
		SessionService:       sessionService,
		Registry:             registry,
		RecordingPath:        recordingPath,
		AuditService:         auditService,
		Monitor:              NewMonitorHub(),
		Shares:               NewShareManager(),
		ConnectTokens:        proxy.NewConnectTokenManager(),
	}
}

// HandleSSH 處理 GET /api/v1/ssh 的 WebSocket 連線
//
// 流程：驗 token → 授權檢查 → 取憑證（記憶體解密）→ SSH Dial →
// 建 Session 記錄 → 升級 WebSocket → 雙向 pump → 斷線清理。
// SSH 握手在 WS 升級前完成，失敗時能以一般 HTTP 錯誤回應。
func (h *Handler) HandleSSH(c *gin.Context) {
	// 1-3. 身分與授權：connect_token 一次性簽發即焚，
	// 唯一連線入口——授權與傳輸政策閘都在簽發時完成。舊 query-JWT 直連
	// 模式已收口（繞過簽發閘＝繞過傳輸政策）
	ct := c.Query("connect_token")
	if ct == "" {
		// 兌換拒絕留痕（connection-gating spec）：
		// 與 `/connect` 共用 `proxy.AuditConnectDenied` 這一個寫入點
		h.auditRedeemDenied(c, proxy.ConnectDenial{
			Reason: string(proxy.RedeemDenyMissing), HTTPStatus: http.StatusUnauthorized}, proxy.ViaSSH)
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeConnectTokenMissing, nil)
		return
	}
	// 拒絕原因取內部版本：對外仍是同一則「token 無效」（不給票證存在性探測面），
	// 審計則分得出偽造票與過期票——前者是探測訊號，後者多半只是慢了一步
	grant, denyReason := h.ConnectTokens.RedeemConnectTokenWithReason(c.Request.Context(), ct)
	if denyReason != proxy.RedeemDenyNone {
		h.auditRedeemDenied(c, proxy.ConnectDenial{
			Reason: string(denyReason), HTTPStatus: http.StatusUnauthorized}, proxy.ViaSSH)
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeConnectTokenInvalid, nil)
		return
	}

	// 兩階段閘序：AuthorizePreResolve → 憑證解封 → AuthorizeResolvedAccount。
	// 閘序表在 connect_gates.go，順序即該表的列序（G-S* 編號的定義亦在該檔）
	st := &redeemState{grant: grant}
	// 主體＝票證所帶的溯源脈絡。**ClaimedRole 留空是實質**：grant 刻意不攜帶角色
	// （見 proxy/connect_token.go），兌換側的角色一律由 G-S3 現查
	subj := st.contractSubject(sourceip.Of(c))
	var gate gatewayapi.PolicyGate = connectgate.NewSequence(
		func(s gatewayapi.ConnectSubject) []connectgate.Gate {
			return h.redeemPreResolveGates(c, s, st)
		},
		func(s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject) []connectgate.Gate {
			return h.redeemResolvedAccountGates(c, s, o, st)
		},
	)
	reqCtx := c.Request.Context()
	if out := gate.AuthorizePreResolve(reqCtx, subj, gatewayapi.StageRedeemTerminal); out != nil {
		h.writeRedeemOutcome(c, out, st, proxy.ViaSSH)
		return
	}
	userID, assetID := grant.UserID, grant.AssetID
	cols, rows := st.cols, st.rows

	// 4. 取資產與憑證（記憶體內解密，永不出後端）——**兩階段之間的唯一解封點**。
	// 以 grant 所帶帳號取憑證（0＝預設帳號）。
	// 帳號於簽發後被刪除／改隸他資產者在此 fail-close 拒絕——**絕不靜默退回
	// 預設帳號**（那等於以另一組憑證建線，且跨資產注入即可拿到目標預設憑證）
	creds, err := h.AssetService.GetWithCredentialsForAccount(assetID, grant.AccountID)
	if err != nil {
		log.Printf("[SSHProxy] 取得資產憑證失敗: assetID=%d, accountID=%d, err=%v", assetID, grant.AccountID, err)
		if errors.Is(err, asset.ErrAssetAccountNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetAccountNotFound, nil)
			return
		}
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetCredentialUnavailable, nil)
		return
	}
	st.creds = creds
	// 已解析客體：AccountID 維持 grant 帶的**選擇器**值（0＝預設帳號，K8s 閘 G-S12
	// 判的正是這個請求值）；Username 為解封後實際會用的帳號名，即 G-S13 的判定對象
	resolved := st.contractObject()
	if out := gate.AuthorizeResolvedAccount(reqCtx, subj, resolved,
		gatewayapi.StageRedeemTerminal); out != nil {
		h.writeRedeemOutcome(c, out, st, proxy.ViaSSH)
		return
	}
	assetRow, password, privateKey := creds.Asset, creds.Password, creds.PrivateKey

	// 5. 建立終端連線：SSH 走遠端 PTY；資料庫協議走本地 CLI PTY（database-protocol），
	// 兩者同實作 TerminalConn，後續審計鏈完全一致
	var conn TerminalConn
	var sshClient *ssh.Client
	var k8sSnapshot *k8sproxy.PodSnapshot
	var k8sLogsMode bool
	if assetRow.Protocol == model.ProtocolSSH {
		sshConn, err := Dial(ConnConfig{
			Host: assetRow.Host,
			Port: assetRow.Port,
			// username 與憑證同取自同一帳號；不再讀 assetRow.Username
			Username:   creds.Username,
			Password:   password,
			PrivateKey: privateKey,
			Cols:       cols,
			Rows:       rows,
			HostKey:    h.HostKeys.Callback(assetID),
		})
		if err != nil {
			log.Printf("[SSHProxy] SSH 連線失敗: assetID=%d, err=%v", assetID, err)
			// Dial 已分類為使用者語言（逾時/認證/不可達）；
			// 僅「解析私鑰失敗: %w」帶庫原文，截斷至動作描述避免洩漏
			msg := err.Error()
			if idx := strings.Index(msg, ": "); idx > 0 {
				msg = msg[:idx]
			}
			writeDialError(c, dialErrorCode(err), msg)
			return
		}
		conn = sshConn
		sshClient = sshConn.Client()
	} else if assetRow.Protocol == model.ProtocolK8s {
		// 連線時選 pod：namespace 取自資產（server-trusted），pod/container/模態由前端帶入
		target := k8sproxy.Target{
			Server:    fmt.Sprintf("https://%s:%d", assetRow.Host, assetRow.Port),
			Token:     password,
			Namespace: assetRow.K8sNamespace,
			Pod:       c.Query("k8s_pod"),
			Container: c.Query("k8s_container"),
			CACert:    assetRow.K8sCACert,
			Insecure:  assetRow.K8sInsecureSkipTLS,
			Mode:      k8sproxy.Mode(c.Query("k8s_mode")),
		}
		// one-shot 單指令尚未實裝 argv 側指令審計與阻斷（列 v1.1）：在此一律拒絕，
		// 避免單指令繞過指令阻斷器（只看 PTY 串流）與審計（security review HIGH）。
		if target.Mode == k8sproxy.ModeOneShot || c.Query("k8s_command") != "" {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeK8sOneShotDisabled, nil)
			return
		}
		if target.Pod == "" {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeK8sPodRequired, nil)
			return
		}
		// 釘 session 快照（同時驗證 pod 存在/可達/權限），錯誤已分類為六類（各配一碼）
		snap, gerr := k8sproxy.GetPod(c.Request.Context(), target)
		if gerr != nil {
			log.Printf("[K8sProxy] GetPod 失敗: assetID=%d, pod=%s, err=%v", assetID, target.Pod, gerr)
			writeDialError(c, k8sDialCode(gerr), gerr.Error())
			return
		}
		target.Container = snap.Container // 解析後的實際容器（default annotation/第一個）
		k8sConn, err := k8sproxy.Start(target, cols, rows)
		if err != nil {
			log.Printf("[K8sProxy] kubectl 啟動失敗: assetID=%d, err=%v", assetID, err)
			writeDialError(c, apierror.CodeK8sStartFailed, zhFallbackOf(apierror.CodeK8sStartFailed))
			return
		}
		conn = k8sConn
		k8sSnapshot = snap
		k8sLogsMode = target.Mode == k8sproxy.ModeLogs
	} else {
		dbConn, err := dbproxy.Start(dbproxy.Target{
			Protocol: string(assetRow.Protocol),
			Host:     assetRow.Host,
			Port:     assetRow.Port,
			// username 與憑證同取自同一帳號；不再讀 assetRow.Username
			Username: creds.Username,
			Password: password,
			DBName:   assetRow.DBName,
			TLSMode:  assetRow.DBTLSMode,
			CACert:   assetRow.DBCACert,
		}, cols, rows)
		if err != nil {
			// Start 僅在程式缺失/PTY 失敗時出錯（不含目標連線失敗），記詳情回泛化訊息
			log.Printf("[DBProxy] CLI 啟動失敗: assetID=%d, err=%v", assetID, err)
			writeDialError(c, apierror.CodeDBClientStartFailed, zhFallbackOf(apierror.CodeDBClientStartFailed))
			return
		}
		conn = dbConn
	}

	// 6. Session 記錄 fail-close：能走到此步證明 DB 讀正常（前置
	// CheckUserConnectable/GetWithCredentials 皆已過），故 session INSERT 失敗＝
	// 部分故障。無 session 主鍵即無 registry/錄影/指令審計/監看，一律拒連——admin
	// 亦不豁免（完全無審計歸屬，與錄影 fail-close 的 admin 例外刻意不同）
	// 帳號雙快照：帶入連線當下實際使用的帳號 ID 與 username
	// 認證溯源（1.9）：provider/世代自 grant 原樣帶入，SSH/K8s/DB 三協議共此一路徑
	sess := h.createSession(userID, assetID, assetRow.Protocol, sourceip.Of(c), k8sSnapshot,
		accountSnapshot{ID: creds.AccountID, Username: creds.Username},
		authProvenance{ProviderID: grant.ProviderID, AuthEpoch: grant.AuthEpoch,
			AuthMethod: grant.AuthMethod, CredEpoch: grant.CredEpoch}, false)
	if sess == nil {
		conn.Close()
		log.Printf("[SSHProxy] session 記錄建立失敗，連線已拒 (userID=%d assetID=%d)", userID, assetID)
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

	// 6b. 帳號新來源位址：session 主鍵已得（fail-close 已過）才觀察——
	// 告警列以 session_id 為自然鍵，先觀察就沒有可綁的會話。
	// 失敗只記 log 不阻連線，且交易整筆回滾，下次自同位址建線補發
	h.observeSourceIP(c, sess, userID, assetID)

	// 7. 升級 WebSocket
	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[SSHProxy] WebSocket 升級失敗: %v", err)
		conn.Close()
		h.closeSession(sess, "")
		return
	}

	// 8. 雙向轉發，掛載指令審計旁路（session 建立失敗時無歸屬主鍵，跳過審計）
	bridge := newBridge(ws, conn, sess, h.SessionService, h.RecordingPath, userID, assetID)

	if sess != nil {
		// Registry 登記關閉回呼：通知經 bridge 寫鎖＋文字協議，取代裸 conn 直寫；
		// 登記於 bridge 建立後、下方 CheckUserConnectable 複查前——REVOKE-1 窗口語義不變
		h.Registry.Register(sess.ID, bridge.terminate)
		// 已標記終止的 session SHALL NOT 啟動 proxy（design 行 268）。
		// 序列化保證「停用在前 → 兌換必被世代閘拒」與「兌換在前 → 停用必掃到本列」，
		// 但後者的鎖外收線可能早於此處的 Registry 登記完成（那時 Close 是 no-op），
		// 本複查即該殘留窗口的封口——必須在登記之後，否則兩者仍可交錯
		if h.SessionService.IsTerminated(sess.ID) {
			log.Printf("[SSHProxy] session 於建立後即被收線，拒絕啟動 proxy (SessionID=%d)", sess.ID)
			h.Registry.Close(sess.ID)
			conn.Close()
			ws.Close()
			return
		}
		// 系統指標採集需 SSH channel，資料庫 CLI 會話無此能力
		if sshClient != nil {
			h.statsClients.Store(sess.ID, sshClient)
		}
	}
	// 會話閒置/最大時長自動斷線（session-timeout）：政策優先、env 退路，0=停用。
	// SSH/k8s/DB 三協議共用本 handler，一處設定全協議生效
	idleTimeout, maxDuration := h.sessionTimeouts()
	bridge.setTimeouts(idleTimeout, maxDuration)

	var store *CommandStore
	var tap *auditTap
	var recTap *recordingTap
	if sess != nil {
		// asciicast 錄製：啟動失敗不斷線（fail-close 只掛簽發點），
		// 但須標記＋告警不得沉默
		var recErr error
		if recTap, recErr = newRecordingTap(h.RecordingPath, sess.ID, cols, rows); recErr != nil {
			session.ReportSessionRecordingFailure(sess.ID, model.MechanismRecordingText,
				model.CauseRecordingStartFailed,
				map[string]string{model.CauseParamDetail: recErr.Error()})
		} else {
			sid := sess.ID
			recTap.SetOnFailure(func(causeCode string, params map[string]string) {
				session.ReportSessionRecordingFailure(sid, model.MechanismRecordingText, causeCode, params)
			})
			bridge.attachRecording(recTap)
			// 錄影的時間原點：asciicast 的 elapsed=0
			// 是**此刻**，不是 sess.StartTime（會話建檔早於認證與 PTY 就緒）。
			// 不釘住這個時刻，回放深連結只能直接 seek(t)，落點會**偏晚**該段耗時、
			// 衝過目標指令——文字終端正是受害最重的一側。
			// 寫入失敗只記 log——回放體驗欄位不回壓已建立的連線
			if err := h.SessionService.SetRecordingStartedAt(sess.ID, recTap.startTime); err != nil {
				log.Printf("[SSHProxy] 錄影起始時刻寫入失敗 (SessionID=%d): %v", sess.ID, err)
			}
			if failure := audit.GetAuditFailure(); failure != nil {
				failure.Resolve(model.MechanismRecordingText)
			}
			log.Printf("[SSHProxy] 錄製已啟用 (SessionID=%d)", sess.ID)
		}

		// 即時監看 room：會話結束時於下方 CloseRoom
		bridge.attachMonitor(h.Monitor.OpenRoom(sess.ID, cols, rows))

		// 指令審計與阻斷：K8s logs 唯讀模態跳過（k8s-exec：logs 無指令、無注入）
		if !k8sLogsMode {
			aid := assetID
			store = NewCommandStore(database.DB, sess.ID, userID, &aid, string(assetRow.Protocol))
			// 降級告警的落地面：與阻斷路徑共用同一個 AlertSink，
			// 通知與 syslog 離機轉發因此自動接上，不重演「只入庫不 tee」
			store.SetAlertSink(h.AlertSink)
			if k8sSnapshot != nil {
				store.SetK8s(k8sSnapshot.Pod, k8sSnapshot.Container)
			}
			// DB CLI（mysql/postgres/mssql）多行語句累積：跨續行收成單一語句，
			// 審計完整且告警比對看得到完整語句（redis 為逐行，不啟用）。
			// mssql 另承認 GO 為批次終止符——模式由協議在 NewCommandParser 內推導
			parser := NewCommandParser(store.Enqueue, string(assetRow.Protocol))
			// 降級／限定紀錄的落地：
			// 無法可信重組的輪次改記為明確標記的降級列，不再是零紀錄
			parser.SetRecordSink(store.Record)
			tap = newAuditTap(parser)
			bridge.attachAudit(tap)
			log.Printf("[SSHProxy] 指令審計已啟用 (SessionID=%d)", sess.ID)

			// 指令阻斷（command-blocking）：matcher 未初始化時為 nil＝直通；
			// protocol 用於規則分流（shell 規則不掃 SQL、SQL 規則不掃 shell）
			bridge.attachBlocker(newCommandBlocker(audit.GetAlertMatcher(), h.AlertSink, sess.ID, userID, assetID, string(assetRow.Protocol)))
		}
	}

	// 轉發啟動前最後一次複查：
	// 收緊「連線授權通過後、bridge 掛上 Registry 前」窗口——會話列以 active 寫入 DB 早於
	// Register，若 admin 停用或撤銷即斷線恰落此窗，Terminate 的 registry.Close 會 no-op、
	// 讓已收線者逃過即時終斷。兩道閘：(1) 帳號可連線；(2) session 仍 active（撤銷/停用
	// 收線已 CAS 成 disconnected 即攔下）。任一失敗即停，對會話建立做成事實原子
	if err := h.AuthService.CheckUserConnectable(userID); err != nil {
		log.Printf("[SSHProxy] bridge 啟動前複查拒絕連線 (userID=%d, assetID=%d): %v", userID, assetID, err)
		bridge.writeErrorMessage(apierror.CodeAccountDisabled)
		bridge.stop() // 關 conn+ws；下方清理照常執行
	} else if sess != nil && !h.SessionService.IsActive(sess.ID) {
		log.Printf("[SSHProxy] bridge 啟動前複查：會話已被收線 (SessionID=%d)——撤銷/停用落窗", sess.ID)
		bridge.writeErrorMessage(apierror.CodeSessionTerminated)
		bridge.stop()
	} else {
		bridge.Run()
	}

	// bridge 已結束（sinks 不再被呼叫）：結算 pending 指令、drain 入庫佇列、收尾錄製
	endReason := bridge.EndReason()
	if tap != nil {
		tap.Flush()
	}
	if store != nil {
		store.Close()
	}
	if recTap != nil {
		recTap.Close(h.SessionService, sess.ID)
	}

	// 9. 清理
	if sess != nil {
		h.Monitor.CloseRoom(sess.ID)
		h.Registry.Unregister(sess.ID)
		h.statsClients.Delete(sess.ID)
		h.Shares.Revoke(sess.ID)
	}
	h.closeSession(sess, endReason)
	log.Printf("[SSHProxy] 連線已結束: assetID=%d reason=%s", assetID, endReason)
}

// 預設閒置 30 分鐘（合規安全基線）、最大時長不限（session-timeout）
const (
	defaultIdleTimeoutMinutes = 30
	defaultMaxSessionMinutes  = 0
)

// sessionTimeouts 會話超時來源分派：政策注入優先，未注入退回環境變數
func (h *Handler) sessionTimeouts() (idle, max time.Duration) {
	if h.TimeoutPolicy != nil {
		return h.TimeoutPolicy()
	}
	return sessionTimeoutsFromEnv()
}

// sessionTimeoutsFromEnv 自環境變數讀會話超時（分鐘）：
// SSH_IDLE_TIMEOUT_MINUTES（預設 30）、SSH_MAX_SESSION_MINUTES（預設 0=不限）；
// 0 = 停用該檢查，非法值回退預設。此為政策未注入時的退路
func sessionTimeoutsFromEnv() (idle, max time.Duration) {
	parse := func(key string, def int) time.Duration {
		v := def
		if s := os.Getenv(key); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n >= 0 {
				v = n
			}
		}
		return time.Duration(v) * time.Minute
	}
	return parse("SSH_IDLE_TIMEOUT_MINUTES", defaultIdleTimeoutMinutes),
		parse("SSH_MAX_SESSION_MINUTES", defaultMaxSessionMinutes)
}

// HandleMonitor 處理 GET /api/v1/sessions/:id/monitor 的唯讀監看連線
//
// 監看是稽核職能：僅 admin/auditor 角色，不走資產授權。
// 觀察者輸入一律忽略（僅回應 ping），斷線不影響被監看會話。
func (h *Handler) HandleMonitor(c *gin.Context) {
	observerID, role, ok := h.authenticate(c)
	if !ok {
		return
	}
	if role != model.RoleAdmin && role != model.RoleAuditor {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeMonitorRoleRequired, nil)
		return
	}

	sessionIDU64, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || sessionIDU64 == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
		return
	}
	sessionID := uint(sessionIDU64)

	sess, err := h.SessionService.GetByID(sessionID)
	if err != nil {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
		return
	}
	if !sess.Protocol.IsTextTerminal() || sess.Status != model.SessionStatusActive {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSessionMonitorNotActive, nil)
		return
	}

	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[Monitor] WebSocket 升級失敗: %v", err)
		return
	}

	// 觀察者自身的認證脈絡：撤銷判定依觀察者是誰、經哪個 provider 認證，
	// 與被監看會話的來源無關（被監看的可能是本地帳號建立的會話）
	authCtx := middleware.GetAuthContext(c)
	obs := ObserverContext{
		UserID: observerID, ProviderID: authCtx.ProviderID,
		AuthEpoch: authCtx.AuthEpoch, CredEpoch: authCtx.CredEpoch,
	}
	// 訂閱建立走序列化閘（3.8b）：providerID != 0 時持 provider 鎖、一律持 user 鎖，
	// 於鎖內重讀世代後才 Join——否則「通過檢查後暫停 → 停用並掃完既有訂閱 → 才 Join」
	// 的訂閱會錯過掃描，且訂閱建立後不再重驗 token
	joined, guardErr := session.JoinWithGenerationGuard(authCtx, observerID, func() bool {
		return h.Monitor.Join(sessionID, ws, obs)
	})
	if guardErr != nil {
		log.Printf("[Monitor] 訂閱建立點世代複查拒絕: userID=%d providerID=%d err=%v",
			observerID, authCtx.ProviderID, guardErr)
		if raw, encErr := EncodeCodedErrorMessage(apierror.CodeMonitorRevoked); encErr == nil {
			_ = ws.WriteMessage(websocket.TextMessage, raw)
		}
		ws.Close()
		return
	}
	if !joined {
		// room 已關閉（會話剛結束的競態）：通知後關閉
		if raw, encErr := EncodeCodedErrorMessage(apierror.CodeSessionEnded); encErr == nil {
			_ = ws.WriteMessage(websocket.TextMessage, raw)
		}
		ws.Close()
		return
	}
	// 監看加入留痕（session-monitor spec）：
	// 記於 Join 成功之後——「訂閱真的建立了」才是稽核要回答的事實，
	// 世代複查拒絕與 room 已關閉兩條路徑沒有任何畫面外流
	h.auditObserverJoin(c, observerJoinAudit{
		userID: observerID, sessionID: sessionID, assetID: sess.AssetID,
		targetUserID: sess.UserID, via: observerViaMonitor,
		status: model.StatusSuccess, statusCode: http.StatusSwitchingProtocols,
	})
	log.Printf("[Monitor] 觀察者加入: SessionID=%d", sessionID)

	// 唯讀讀取迴圈：觀察者訊息一律忽略（監看為唯讀），讀錯誤即離場。
	// 不回 pong——廣播 goroutine 已是此 ws 的唯一寫入者（gorilla 單寫者限制），
	// 觀察者送出的 ping 流量本身即足以維持中間層連線
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			break
		}
	}

	h.Monitor.Leave(sessionID, ws)
	ws.Close()
	log.Printf("[Monitor] 觀察者離開: SessionID=%d", sessionID)
}

// authenticate 解析使用者身分與角色；失敗時已寫入 HTTP 回應。
//
// **同時把認證脈絡寫入 gin context**：
// /monitor、/share/:code/ws、/ssh、/connect 四條路由都不掛 AuthMiddleware
// （手動處理認證以支援 WebSocket query token），故 `?token=` 分支上**本函式是
// authContext 的唯一寫入者**。不寫則下游的 middleware.GetAuthContext(c) 恆回零值，
// 造成兩個後果：ObserverContext.ProviderID=0 使 provider 停用收線一筆都匹配不到
// （OIDC 使用者的監看／分享訂閱在其 IdP 已停用後仍讀得到他人終端內容），
// 且 CredEpoch=0 會讓 JoinWithGenerationGuard 對 credential_epoch > 0 的使用者恆拒。
func (h *Handler) authenticate(c *gin.Context) (uint, string, bool) {
	if id, exists := middleware.GetCurrentUserID(c); exists {
		role, _ := c.Get("role")
		roleStr, _ := role.(string)
		// AuthMiddleware 已跑過（它同時寫入 userID 與 authContext）：
		// 此處不得再寫，否則會把中介層自 claims 解出的脈絡覆蓋掉
		return id, roleStr, true
	}

	tokenStr := c.Query("token")
	if tokenStr == "" {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return 0, "", false
	}

	// 連線端點統一認證：scoped token deny-by-default、
	// 重載用戶拒停用/鎖定中——與一般 API middleware 同一邊界，堵 ?token= 旁路。
	// **只經 gatewayapi.SessionVerifier 介面消費**：判定本體不變
	// （VerifySession 即 ValidateConnectionToken ＋欄位對映，不新增亦不放寬判定）
	var verifier gatewayapi.SessionVerifier = h.AuthService
	p, err := verifier.VerifySession(c.Request.Context(), tokenStr)
	if err != nil {
		log.Printf("[SSHProxy] 連線 token 驗證失敗: %v", err)
		respondConnectionAuthError(c, err)
		return 0, "", false
	}
	// 認證脈絡與 AuthMiddleware 寫入的是同一型別、同一 key，下游 GetAuthContext
	// 的呼叫點不必分辨自己走的是哪條認證路徑。四欄逐欄取自 Principal，
	// 與收口前的 claims.AuthContext 逐位相同
	c.Set("authContext", crypto.AuthContext{
		AuthMethod: p.AuthMethod, ProviderID: p.ProviderID,
		AuthEpoch: p.AuthEpoch, CredEpoch: p.CredEpoch,
	})
	// username 供 handler 自寫的審計列填實：
	// 審計表的 username 是稽核第一眼要看的欄，只有 user_id 得再查一次使用者表，
	// 且帳號刪除後就查不回來了。
	//
	// **只寫 username、刻意不寫 userID**：`AuditLogMiddleware` 以兩鍵皆存在為
	// 記錄條件，補上 userID 會讓這幾條 WebSocket 路由同時由中介層與 handler
	// 各寫一列（重複計數），而中介層那一列反而缺少會話與資產脈絡
	c.Set("username", p.Username)
	// **Role 是登入當下的角色快照，SHALL NOT 作為授權判定依據**：
	// 連線閘序的角色一律由 CurrentConnectRole 現查（G-I2／G-S3／G-G4）
	return p.UserID, p.Role, true
}

// connectionAuthError 連線認證錯誤映射：僅 sentinel 各配一碼，其餘泛化
// （原回傳散文 msg，改回傳碼——碼的 ZhFallback 與 sentinel 文案逐字相同）
func connectionAuthError(err error) (int, apierror.ErrCode) {
	switch {
	case errors.Is(err, identity.ErrAccountLocked):
		return http.StatusLocked, apierror.CodeAccountLocked
	case errors.Is(err, identity.ErrUserInactive):
		return http.StatusForbidden, apierror.CodeUserInactive
	case errors.Is(err, identity.ErrConnectionNotAuthorized):
		return http.StatusUnauthorized, apierror.CodeConnectionNotAuthorized
	default:
		return http.StatusUnauthorized, apierror.CodeTokenInvalid
	}
}

// respondConnectionAuthError 以映射後的狀態＋碼寫出回應
func respondConnectionAuthError(c *gin.Context, err error) {
	status, code := connectionAuthError(err)
	apierror.Respond(c, status, code, nil)
}

// authorizationContext 帶角色的授權判定 context（CheckPermission 與
// AuthorizeConnectAccount 共用同一 role key 慣例；role 為空即不注入，
// 由服務層落一般授權查詢）
func authorizationContext(c *gin.Context, role string) context.Context {
	ctx := c.Request.Context()
	if role != "" {
		ctx = context.WithValue(ctx, "role", role) //nolint:staticcheck // 沿用既有 CheckPermission 的 string key 慣例
	}
	return ctx
}

// checkPermission 檢查連線授權；失敗時已寫入 HTTP 回應
//
// role 經 context 傳入：CheckPermission 對 admin 角色自動放行；auditor 為稽核
// 唯讀，connect 不自動放行，須有顯式授權——與 guacd 路徑一致
func (h *Handler) checkPermission(c *gin.Context, userID uint, role string, assetID uint) bool {
	if out := h.connectPermissionOutcome(c, userID, role, assetID); out != nil {
		h.writeOutcome(c, out)
		return false
	}
	return true
}

// connectPermissionOutcome 連線授權判定的**不寫回應**版本（兩階段骨架用）：
// 判定與回應寫出分離，使同一道閘能以 connectgate.Gate 的形式登記進閘序表。
// 判定邏輯與回應語義與 checkPermission 完全同源——後者即以本函式實作，
// 兩條路徑不可能分化
func (h *Handler) connectPermissionOutcome(c *gin.Context, userID uint, role string, assetID uint) *connectgate.Outcome {
	ctx := authorizationContext(c, role)
	hasPermission, err := h.AuthorizationService.CheckPermission(ctx, userID, assetID, model.PermissionConnect)
	if err != nil {
		log.Printf("[SSHProxy] 權限檢查失敗: userID=%d, assetID=%d, err=%v", userID, assetID, err)
		return connectgate.DenyInternal(http.StatusInternalServerError,
			string(apierror.CodeInternalPermissionCheck), err)
	}
	if !hasPermission {
		return connectgate.Deny(http.StatusForbidden, string(apierror.CodeAssetConnectDenied), nil)
	}
	return nil
}

// writeOutcome 把閘序判定結果寫成 HTTP 回應。
//
// **唯一的回應出口**：Internal 非 nil 走 RespondInternal（伺服端記原始成因、
// 對外只回碼），其餘走 apierror.Write（Meta 平鋪回封套 top-level，前端 connect.js
// 依 reason／policy／risks 分支的機器欄語義不變）
func (h *Handler) writeOutcome(c *gin.Context, out *connectgate.Outcome) {
	code := apierror.ErrCode(out.Decision.Code)
	if out.Internal != nil {
		apierror.RespondInternal(c, out.Status, code, out.Internal)
		return
	}
	apierror.Write(c, out.Status, apierror.ErrorResponse{Code: code, Meta: out.Meta})
}

// writeRedeemOutcome **兌換側**閘序的唯一出口：回應照 writeOutcome 原樣寫出，
// 另為該次拒絕留痕。
//
// **為何不把留痕放進 writeOutcome**：後者同時服務簽發端點
// （`POST /api/v1/connect-tokens`，掛 AuthMiddleware）。在那裡留痕會與
// `AuditLogMiddleware` 已寫的列重複計數——同一次拒絕變兩列，稽核報表的
// 「被擋下幾次」當場翻倍。兌換側則相反：路由不掛認證中介層，中介層恆整筆跳過。
//
// **回應與留痕綁在同一個出口**是刻意的：閘序表（connect_gates.go 的 G-S3…G-S13）
// 往後只會增列，若留痕散在各閘的 Eval 裡，新增一道閘忘了寫審計不會有任何東西轉紅。
// st 提供主體與客體（票證所帶的 userID／assetID）；前置階段的閘拒絕時 st.creds
// 尚未解封，grant 的兩個鍵仍成立。
// via＝呼叫端所屬的兌換入口（`proxy.Via*`）。由呼叫端給值而不在此推斷：
// 這裡看不到請求是從哪一支路由進來的，猜錯的後果是一整條入口的拒絕被算進另一條。
func (h *Handler) writeRedeemOutcome(c *gin.Context, out *connectgate.Outcome,
	st *redeemState, via string) {
	h.auditRedeemDenied(c, proxy.ConnectDenial{
		UserID: st.grant.UserID, AssetID: st.grant.AssetID,
		Reason: out.Decision.Code, HTTPStatus: out.Status, Cause: st.sourceDenyCause,
	}, via)
	h.writeOutcome(c, out)
}

// auditRedeemDenied 本包各兌換入口的拒絕留痕，入口標記由呼叫端指定。
//
// 寫入實作與 `/connect` 共用（`proxy.AuditConnectDenied`，manifest AP-69）——
// spec 的「兌換拒絕留痕」沒有端點限定，兩包各寫一份就會各自演化欄位集，而
// 「某一側少填來源位址」不會讓任何測試轉紅。狀態值的 401→failure／其餘→denied
// 分流、asset_id 的 NULL 語義、來源位址取法全在該函式，見其檔頭。
//
// **入口標記不寫死**：本包現在有兩支路由（`GET /api/v1/ssh` 與
// `GET /api/v1/db-console`），沿用同一個值會讓稽核以 `via` 分流時，
// 其中一支的拒絕全部落到另一支名下。
func (h *Handler) auditRedeemDenied(c *gin.Context, ev proxy.ConnectDenial, via string) {
	ev.Via = via
	proxy.AuditConnectDenied(h.AuditService, c, ev)
}

// accountSnapshot 連線當下的帳號雙快照：
// ID 與 username 一併釘住，帳號日後改名或刪除都不影響已完成會話的審計語義
type accountSnapshot struct {
	ID       uint
	Username string
}

// authProvenance 建立會話的認證溯源：
// 由 connect grant 原樣帶入（脈絡只有簽發階段知道），**禁止在此查外部身分表反推
// provider**——混合帳號（同時有本地密碼與外部身分）會被誤標，導致停用某 provider
// 時連帶砍掉該帳號以本地密碼建立的會話。ProviderID 0 表本地／LDAP 登入
type authProvenance struct {
	ProviderID uint
	AuthEpoch  int
	// AuthMethod／CredEpoch 供「兌換建 session」的鎖內世代複查（3.8b）——
	// 序列化的三步「重查前提 → 讀世代 → 建立」需要完整脈絡，只帶 provider 維度
	// 會漏掉使用者維度（解綁外部身分／改為僅外部登入後的 connect grant）
	AuthMethod string
	CredEpoch  int
}

// createSession 建立會話記錄；失敗回傳 nil，由呼叫點 fail-close 拒連
// dbConsole 為真時於同一次 INSERT 標記本會話為查詢主控台會話——
// 事後 UPDATE 會產生一段「已建立但未標記」的窗口，而會話列表與監看在那段時間
// 會把它呈現成命令列會話
func (h *Handler) createSession(userID, assetID uint, protocol model.ProtocolType, clientIP string, k8sSnap *k8sproxy.PodSnapshot, acct accountSnapshot, prov authProvenance, dbConsole bool) *model.Session {
	id := assetID
	sess := &model.Session{
		DBConsole: dbConsole,
		UserID:   userID,
		AssetID:  &id,
		Protocol: protocol,
		ClientIP: clientIP,
		Status:   model.SessionStatusActive,
		// 帳號雙快照：與 session 建立原子寫入，之後永不更新
		AccountID:       acct.ID,
		AccountUsername: acct.Username,
	}
	// 認證溯源（1.9）：僅快照，授權仍現查。0 寫 NULL 以區分「本地登入」
	//（與 guacd 路徑 proxy/handler.go 同語義）
	if prov.ProviderID != 0 {
		pid := prov.ProviderID
		sess.AuthProviderID = &pid
	}
	sess.AuthEpoch = prov.AuthEpoch
	// K8s 不可變 pod 快照：與 session 建立原子寫入
	if k8sSnap != nil {
		sess.K8sNamespace = k8sSnap.Namespace
		sess.K8sPod = k8sSnap.Pod
		sess.K8sPodUID = k8sSnap.UID
		sess.K8sContainer = k8sSnap.Container
		sess.K8sImage = k8sSnap.Image
		sess.K8sNode = k8sSnap.Node
	}
	// 序列化建立（3.8b）：「重查前提 → 讀世代 → 建立 session」三步於 provider＋user
	// 鎖內完成。單純的「先查後插」擋不住 design 行 266 的序列——兌換讀到舊 epoch →
	// 停用推進世代並掃完既有會話 → 兌換才插入帶舊 epoch 的 session，該連線既不在
	// 掃描集合內、建立後又不再出示憑證，於是永久存活
	if err := h.SessionService.CreateWithGenerationGuard(crypto.AuthContext{
		AuthMethod: prov.AuthMethod, ProviderID: prov.ProviderID,
		AuthEpoch: prov.AuthEpoch, CredEpoch: prov.CredEpoch,
	}, sess); err != nil {
		log.Printf("[SSHProxy] 創建 Session 失敗: %v（呼叫點將 fail-close 拒連）", err)
		return nil
	}
	return sess
}

func (h *Handler) closeSession(sess *model.Session, reason string) {
	if sess == nil {
		return
	}
	if err := h.SessionService.CloseWithReason(sess.ID, reason); err != nil {
		log.Printf("[SSHProxy] 關閉 Session 失敗: ID=%d, err=%v", sess.ID, err)
	}
}

// HandleStats 處理 GET /api/v1/ssh/sessions/:id/stats（session-stats）：
// 對活躍會話的既有 SSH 連線開 channel 採集 /proc 指標；
// 授權：會話本人或 admin/auditor；非活躍回 404
func (h *Handler) HandleStats(c *gin.Context) {
	userID, role, ok := h.authenticate(c)
	if !ok {
		return
	}

	sessionID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
		return
	}

	sess, err := h.SessionService.GetByID(uint(sessionID))
	if err != nil {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
		return
	}
	if sess.UserID != userID && role != model.RoleAdmin && role != model.RoleAuditor {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeSessionStatsDenied, nil)
		return
	}

	clientVal, ok := h.statsClients.Load(uint(sessionID))
	if !ok {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotOnline, nil)
		return
	}

	stats, err := CollectStats(clientVal.(*ssh.Client))
	if err != nil {
		log.Printf("[SSHProxy] 指標採集失敗: sessionID=%d err=%v", sessionID, err)
		apierror.Respond(c, http.StatusBadGateway, apierror.CodeStatsUnsupported, nil)
		return
	}
	c.JSON(http.StatusOK, stats)
}

// HandleCreateShare 處理 POST /api/v1/sessions/:id/share（session-share）：
// 會話本人建立分享碼；再建立即覆蓋舊碼
func (h *Handler) HandleCreateShare(c *gin.Context) {
	userID, _, ok := h.authenticate(c)
	if !ok {
		return
	}
	sessionID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
		return
	}
	sess, err := h.SessionService.GetByID(uint(sessionID))
	if err != nil {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
		return
	}
	if sess.UserID != userID {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeSessionShareOwnerOnly, nil)
		return
	}
	if sess.Status != model.SessionStatusActive {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSessionShareNotActive, nil)
		return
	}

	var req struct {
		TTLMinutes int `json:"ttl_minutes"`
	}
	_ = c.ShouldBindJSON(&req)
	if req.TTLMinutes < 1 || req.TTLMinutes > 60 {
		req.TTLMinutes = 10
	}

	code, expires, err := h.Shares.Create(uint(sessionID), userID, time.Duration(req.TTLMinutes)*time.Minute)
	if err != nil {
		log.Printf("[Share] 產生分享碼失敗: %v", err)
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSessionShareCreate, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code":       code,
		"share_path": "/share/" + code,
		"expires_at": expires,
	})
}

// HandleRevokeShare 處理 DELETE /api/v1/sessions/:id/share
func (h *Handler) HandleRevokeShare(c *gin.Context) {
	userID, _, ok := h.authenticate(c)
	if !ok {
		return
	}
	sessionID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
		return
	}
	sess, err := h.SessionService.GetByID(uint(sessionID))
	if err != nil {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
		return
	}
	if sess.UserID != userID {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeSessionShareOwnerOnly, nil)
		return
	}
	if !h.Shares.Revoke(uint(sessionID)) {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeShareNotFound, nil)
		return
	}
	// 成功回應不帶 UI 文案（前端 ShareDialog 以 $t 自有成功訊息呈現）
	c.JSON(http.StatusOK, gin.H{"revoked": true})
}

// HandleShareJoin 處理 GET /api/v1/sessions/share/:code/ws（session-share）：
// 任何已登入用戶持有效碼加入唯讀觀看。
//
// **加入由本 handler 自寫審計，成功與拒絕兩路皆然**（AP-70）。
// 中介層在此路徑幫不上忙：本路由註冊於 `v1`
// 群組且不掛 AuthMiddleware（理由見 `authenticate` 檔頭：WebSocket 只能以 query
// token 認證），而 `authenticate` 的 `?token=` 分支只寫 `authContext`，不寫
// `userID`／`username`；`AuditLogMiddleware` 缺這兩個鍵時整筆跳過
//（`middleware/audit_log.go`），故中介層側恆為零列。
//
// 修法與 `/recordings/stream` 同型（handler 自寫，身分取自 `authenticate` 的回傳）：
// 成功加入走 `auditObserverJoin`（`via=share`），無效／失效分享碼走同一個寫入點
// 並記 `status=denied`。
//
// **註解曾與實況相反**：留痕補上之後，這裡仍留著「加入不入審計＝已知缺口」的
// 舊文字。註解不是判準（沒有測試會因它轉紅），但它是下一輪稽核的起點——寫錯會讓
// 人去補一個已經存在的東西，或反過來相信一個已消失的缺口還在。
func (h *Handler) HandleShareJoin(c *gin.Context) {
	userID, _, ok := h.authenticate(c)
	if !ok {
		return
	}

	code := c.Param("code")
	sessionID, valid := h.Shares.Resolve(code)
	if !valid {
		// 無效／失效分享碼的拒絕亦留痕（session-share spec 第二個 scenario）：
		// 反覆試碼是猜測攻擊的訊號，不留痕即與「沒有人試過」無從分辨。
		// **不記碼本身**——路徑以 FullPath 樣板寫入，稽核要的是來源與時刻
		h.auditObserverJoin(c, observerJoinAudit{
			userID: userID, via: observerViaShare,
			status: model.StatusDenied, statusCode: http.StatusNotFound,
			errMsg: string(apierror.CodeShareNotFound),
		})
		apierror.Respond(c, http.StatusNotFound, apierror.CodeShareNotFound, nil)
		return
	}

	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[Share] WebSocket 升級失敗: %v", err)
		return
	}

	// 分享觀看與監看走同一個 hub，**撤銷治理必須一致**（spec 4.14e）：
	// 只在監看端接脈絡，分享連結就成了繞過撤銷的旁路
	shareCtx := middleware.GetAuthContext(c)
	shareObs := ObserverContext{
		UserID: userID, ProviderID: shareCtx.ProviderID,
		AuthEpoch: shareCtx.AuthEpoch, CredEpoch: shareCtx.CredEpoch,
	}
	// 分享觀看與監看走同一個序列化閘（spec 4.14e：撤銷治理必須一致）
	shareJoined, shareGuardErr := session.JoinWithGenerationGuard(shareCtx, userID, func() bool {
		return h.Monitor.Join(sessionID, ws, shareObs)
	})
	if shareGuardErr != nil {
		log.Printf("[Share] 訂閱建立點世代複查拒絕: userID=%d providerID=%d err=%v",
			userID, shareCtx.ProviderID, shareGuardErr)
		if raw, encErr := EncodeCodedErrorMessage(apierror.CodeMonitorRevoked); encErr == nil {
			_ = ws.WriteMessage(websocket.TextMessage, raw)
		}
		ws.Close()
		return
	}
	if !shareJoined {
		if raw, encErr := EncodeCodedErrorMessage(apierror.CodeSessionEnded); encErr == nil {
			_ = ws.WriteMessage(websocket.TextMessage, raw)
		}
		ws.Close()
		return
	}
	// 分享加入留痕（session-share spec）：與監看同一
	// 個 hub、同一份留痕形狀，`via` 區分兩者。目標會話與資產另查一次——加入不在
	// 熱路徑上（每次觀看一次），而缺了資產鍵就答不出「他看的是哪台機器」
	shareTarget, shareErr := h.SessionService.GetByID(sessionID)
	shareEvent := observerJoinAudit{
		userID: userID, sessionID: sessionID, via: observerViaShare,
		status: model.StatusSuccess, statusCode: http.StatusSwitchingProtocols,
	}
	if shareErr == nil {
		shareEvent.assetID = shareTarget.AssetID
		shareEvent.targetUserID = shareTarget.UserID
	}
	h.auditObserverJoin(c, shareEvent)
	log.Printf("[Share] 分享觀看者加入: SessionID=%d userID=%d", sessionID, userID)

	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			break
		}
	}

	h.Monitor.Leave(sessionID, ws)
	ws.Close()
	log.Printf("[Share] 分享觀看者離開: SessionID=%d userID=%d", sessionID, userID)
}

// 唯讀觀看的兩條入口（審計 Details 的 `via` 值，機器可篩）
const (
	observerViaMonitor = "monitor"
	observerViaShare   = "share"
)

// observerJoinAudit 唯讀觀看加入事件的審計輸入
type observerJoinAudit struct {
	userID uint
	// sessionID 目標會話；0＝分享碼解析不出目標（拒絕路徑）
	sessionID uint
	// assetID 被觀看會話的資產；未知時 nil
	assetID *uint
	// targetUserID 被觀看會話的擁有者，即「誰被看了」；未知時 0
	targetUserID uint
	via          string
	status       model.AuditStatus
	statusCode   int
	errMsg       string
}

// auditObserverJoin 為「加入他人會話的唯讀觀看」寫審計列。
//
// # 為何由 handler 自寫
//
// `/sessions/:id/monitor` 與 `/sessions/share/:code/ws` 兩條路由不掛
// AuthMiddleware（WebSocket 只能以 query token 認證，見 `authenticate` 檔頭），
// `authenticate` 的 `?token=` 分支只寫 `authContext` 與 `username`、不寫 `userID`，
// 而 `AuditLogMiddleware` 缺 `userID` 即整筆跳過。故中介層在這兩條路徑上恆為零列，
// 身分只在 handler 手上。
//
// # 為何這是最敏感的一列
//
// PAM 產品裡「誰即時旁觀了誰的操作」無痕，等於管理員可以看遍所有人的終端而
// 無從課責。故本列必須答得出四件事：觀察者是誰、何時、看的是哪一場會話、
// 那場會話跑在哪台資產上——後兩者即 ResourceID 與 AssetID 兩欄。
//
// # AssetID 填實而非留白
//
// 與 AP-68（錄影取證）不同：那一列的主體是「錄影檔本體」，資產樞紐由
// `sessions.asset_id` 承擔即足。監看的稽核問題本身就是「誰看了這台機器上的操作」，
// 缺資產鍵時資產樞紐上看不到任何旁觀事實，與「沒有人看過」不可分辨。
//
// # 注入缺席不得靜默
//
// 這條路由沒有中介層兜底，審計服務缺席即等於回到零留痕的缺陷態，故記 log
// （形狀比照 `RecordingHandler.auditRecordingRetrieval`）。
func (h *Handler) auditObserverJoin(c *gin.Context, ev observerJoinAudit) {
	if h.AuditService == nil {
		log.Printf("[Monitor] 審計服務未注入，%s 的觀看加入未留痕（via=%s sessionID=%d）",
			c.Request.URL.Path, ev.via, ev.sessionID)
		return
	}
	username, _ := middleware.GetCurrentUsername(c)
	var resourceID *uint
	if ev.sessionID != 0 {
		id := ev.sessionID
		resourceID = &id
	}
	// 路徑取路由樣板而非原始 URL：分享碼是短期憑證，不該落進長期保存的審計表
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	h.AuditService.Log(&audit.AuditLogEntry{
		UserID:     ev.userID,
		Username:   username,
		Action:     model.ActionRead,
		Resource:   model.ResourceSession,
		ResourceID: resourceID,
		AssetID:    ev.assetID,
		Status:     ev.status,
		Method:     c.Request.Method,
		Path:       path,
		ClientIP:   sourceip.Of(c),
		StatusCode: ev.statusCode,
		RequestID:  c.GetString("request_id"),
		ErrorMsg:   ev.errMsg,
		Details: fmt.Sprintf(`{"session_id":%d,"via":%q,"target_user_id":%d}`,
			ev.sessionID, ev.via, ev.targetUserID),
	})
}

// mergeAuditDetails 合併寫入 audit_details（多道閘皆可能標記豁免，不互相覆蓋）
func mergeAuditDetails(c *gin.Context, kv map[string]string) {
	m := map[string]string{}
	if existing, ok := c.Get("audit_details"); ok {
		if em, ok := existing.(map[string]string); ok && em != nil {
			m = em
		}
	}
	for k, v := range kv {
		m[k] = v
	}
	c.Set("audit_details", m)
}

// parseSizeOutcome 解析初始終端尺寸的**不寫回應**版本（兩階段骨架用）：
// 回傳非 nil 即解析失敗。判定與碼與 parseSize 同源（後者以本函式實作）
func parseSizeOutcome(c *gin.Context) (int, int, *connectgate.Outcome) {
	cols, err := strconv.Atoi(c.Query("cols"))
	if err != nil || cols < 1 || cols > maxCols {
		return 0, 0, connectgate.Deny(http.StatusBadRequest,
			string(apierror.CodeTerminalColsInvalid), nil)
	}
	rows, err := strconv.Atoi(c.Query("rows"))
	if err != nil || rows < 1 || rows > maxRows {
		return 0, 0, connectgate.Deny(http.StatusBadRequest,
			string(apierror.CodeTerminalRowsInvalid), nil)
	}
	return cols, rows, nil
}

// HandleCreateConnectToken 處理 POST /api/v1/connect-tokens：
// JWT 認證＋授權檢查後簽發一次性 token，WS 端憑 token 直接建線
func (h *Handler) HandleCreateConnectToken(c *gin.Context) {
	userID, claimedRole, ok := h.authenticate(c)
	if !ok {
		return
	}

	// 兩階段閘序：AuthorizePreResolve → 帳號身分解析 → AuthorizeResolvedAccount。
	// 閘序表在 connect_gates.go，順序即該表的列序（G-I* 編號的定義亦在該檔）。
	// **簽發側的「解析」不解封憑證**——只解析 username（ResolveAccountIdentity 與
	// GetWithCredentialsForAccount 共用 resolveAssetAccount，故 fail-close 語義一致）
	st := &issueState{}
	// 主體：ClaimedRole＝**呼叫端自陳的**角色（JWT／middleware 的角色快照）。
	// 它僅供溯源，SHALL NOT 作判定依據——閘序用的角色一律是 G-I2 由
	// CurrentConnectRole 現查後寫進 st.role 的那一份。
	issueAuthCtx := middleware.GetAuthContext(c)
	subj := gatewayapi.ConnectSubject{
		UserID:      userID,
		ClaimedRole: claimedRole,
		AuthMethod:  issueAuthCtx.EffectiveMethod(),
		ProviderID:  issueAuthCtx.ProviderID,
		AuthEpoch:   issueAuthCtx.AuthEpoch,
		CredEpoch:   issueAuthCtx.CredEpoch,
		ClientIP:    sourceip.Of(c),
	}
	var gate gatewayapi.PolicyGate = connectgate.NewSequence(
		func(s gatewayapi.ConnectSubject) []connectgate.Gate {
			return h.issuePreResolveGates(c, s, st)
		},
		func(s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject) []connectgate.Gate {
			return h.issueResolvedAccountGates(c, s, o, st)
		},
	)
	reqCtx := c.Request.Context()
	if out := gate.AuthorizePreResolve(reqCtx, subj, gatewayapi.StageIssue); out != nil {
		h.writeOutcome(c, out)
		return
	}
	req := st.req

	identity, idErr := h.AssetService.ResolveAccountIdentity(req.AssetID, req.AccountID)
	if idErr != nil {
		if errors.Is(idErr, asset.ErrAssetAccountNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetAccountNotFound, nil)
			return
		}
		log.Printf("[ConnectToken] 解析連線帳號失敗: assetID=%d accountID=%d err=%v", req.AssetID, req.AccountID, idErr)
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetAccountResolve, idErr)
		return
	}
	st.identity = identity

	// 已解析客體：AccountID 為請求帶的選擇器（0＝預設帳號），
	// Username 為 ResolveAccountIdentity 解析出的帳號名，即 G-I10 的判定對象
	resolved := st.contractObject()
	if out := gate.AuthorizeResolvedAccount(reqCtx, subj, resolved,
		gatewayapi.StageIssue); out != nil {
		h.writeOutcome(c, out)
		return
	}
	// 認證脈絡於簽發階段取得（1.9）：兌換點只剩 grant，屆時已無從得知
	// 「當初經哪個 provider 認證」，而那正是停用時要按 provider 收線的依據。
	// 與 subj 同源（issueAuthCtx），故票證所帶脈絡與判定所見主體逐欄相同
	token, err := h.ConnectTokens.IssueConnectToken(reqCtx, proxy.ConnectGrant{
		UserID: userID, AssetID: req.AssetID, AccountID: req.AccountID,
		AuthMethod: subj.AuthMethod, ProviderID: subj.ProviderID,
		AuthEpoch: subj.AuthEpoch, CredEpoch: subj.CredEpoch,
	})
	if err != nil {
		// 容量拒絕與內部故障分開處置：前者是可預期的暫時性狀態（503／稍後再試），
		// 混進 500 會讓「有人在灌未兌換 token」淹沒在一般故障告警裡
		if errors.Is(err, proxy.ErrConnectTokenCapacity) {
			log.Printf("[ConnectToken] 容量拒發: userID=%d %v", userID, err)
			apierror.Respond(c, http.StatusServiceUnavailable, apierror.CodeConnectTokenCapacity, nil)
			return
		}
		log.Printf("[ConnectToken] 簽發失敗: %v", err)
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalConnectTokenIssue, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"connect_token": token, "expires_in": 60})
}

// HandleCreateTransmissionConsent 處理 POST /api/v1/transmission-consents
// 使用者對資產的傳輸風險立據。
// 與簽發同一授權邊界（authenticate＋checkPermission）；body 帶使用者
// 實際看到的風險項 key，與當下不符即 409 要求重新確認
func (h *Handler) HandleCreateTransmissionConsent(c *gin.Context) {
	userID, role, ok := h.authenticate(c)
	if !ok {
		return
	}
	if err := h.AuthService.CheckUserConnectable(userID); err != nil {
		respondConnectionAuthError(c, err)
		return
	}

	var req struct {
		AssetID  uint     `json:"asset_id" binding:"required"`
		RiskKeys []string `json:"risk_keys" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	assetRow, err := h.AssetService.GetByID(req.AssetID)
	if err != nil {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
		return
	}
	if !h.checkPermission(c, userID, role, req.AssetID) {
		return
	}
	if h.TransmissionConsent == nil {
		apierror.Respond(c, http.StatusServiceUnavailable, apierror.CodeTransmissionUnavailable, nil)
		return
	}

	consent, err := h.TransmissionConsent.Record(userID, assetRow, req.RiskKeys, sourceip.Of(c))
	switch {
	case err == nil:
		c.JSON(http.StatusOK, gin.H{"consented_at": consent.ConsentedAt})
	case errors.Is(err, policy.ErrConsentRisksChanged):
		apierror.Respond(c, http.StatusConflict, apierror.CodeConsentRisksChanged, nil)
	case errors.Is(err, policy.ErrConsentNoRisks):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeConsentNoRisks, nil)
	case errors.Is(err, policy.ErrConsentNotApplicable):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeConsentNotApplicable, nil)
	default:
		log.Printf("[TransmissionConsent] 立據失敗: %v", err)
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalConsentRecord, err)
	}
}
