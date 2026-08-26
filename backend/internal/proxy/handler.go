package proxy

import (
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/recorder"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// 允許所有來源（開發環境）
		// 生產環境應該檢查 Origin
		return true
	},
	// 支援 Guacamole WebSocket 子協議
	Subprotocols: []string{"guacamole"},
}

// ConnectRequest 連線請求
type ConnectRequest struct {
	Protocol string            `json:"protocol" binding:"required"` // ssh, rdp, vnc
	Hostname string            `json:"hostname" binding:"required"`
	Port     int               `json:"port"`
	Username string            `json:"username"`
	Password string            `json:"password"`
	Width    int               `json:"width"`
	Height   int               `json:"height"`
	Params   map[string]string `json:"params"`
}

// ConnectionHandler 處理連線請求
type ConnectionHandler struct {
	GuacdHost            string
	GuacdPort            int
	SessionService       *session.SessionService
	AssetService         *asset.AssetService
	AuthService          *identity.AuthService
	AuthorizationService *authz.AssetAuthorizationService // 授權服務
	// AccessPolicy 兌換點存取政策重查：nil 時不啟用（既有測試路徑）
	AccessPolicy *policy.AccessPolicyService
	// dataTransfer 資料傳輸有效能力解析（data-transfer-control）：決定連線參數
	// 的 disable-copy／disable-paste／disable-*load，並注入 FileTap 供逐次判定。
	// nil＝既有測試路徑（不注入任何 disable 參數，行為與改動前一致）。
	//
	// **刻意未匯出，只經 SetDataTransfer 注入**：原本是裸欄位賦值，因而落在
	// `lifecycle_manifest_guard_test.go` 的注入登記射程外——把組裝根那一行換成
	// `_ = dataTransferService`，guacd 連線參數、tunnel/file_tap 攔截、會話能力
	// 快照三處同時靜默失效而全樹測試仍綠。改為 setter 後該注入與
	// assetHandler／sftpHandler 兩處同構，未登記即由登記表守衛擋下
	dataTransfer *policy.DataTransferService
	Registry     *ConnectionRegistry // 連線註冊表
	// ConnectTokens 一次性連線 token：與 sshproxy 共用實例
	ConnectTokens *ConnectTokenManager
	// TimeoutPolicy 會話閒置/最大時長來源：組裝端注入安全政策讀取；
	// nil 時不啟用逾時檢查（既有測試路徑）
	TimeoutPolicy func() (idle, max time.Duration)
	// AuditSink 檔案上傳審計的投遞面（AP-28）：交給每條連線的 FileTap。
	// nil＝既有測試路徑（FileTap 取不到投遞面時記 log 不寫，維持「不回壓會話」）
	AuditSink gatewayapi.AsyncSink
	// AuditService 兌換拒絕的留痕出口。
	//
	// **與 AuditSink 分立不是重複**：AuditSink 是連線建立**之後**的事件投遞面
	//（檔案傳輸、能力快照），拒絕發生在那之前——此刻既無 session 也無 tunnel。
	// 組裝端一律注入；nil 僅限既有測試路徑，該情形下 `auditConnectDenied`
	// 記 log，SHALL NOT 靜默略過
	AuditService *audit.AuditLogService
	// SourceIPBaseline 帳號 × 來源位址的「已見」基準與新來源位址告警。
	//
	// 建線成功、session 主鍵已得之後觀察一次（與文字終端路徑同語義）；首次自該
	// 位址建線者在同一交易內得到一筆告警列。**失敗不阻連線**但一律記 log；
	// 交易失敗即整筆回滾，下次自同位址建線補發。nil 僅限既有測試路徑
	SourceIPBaseline *audit.SourceIPBaseline
	// ClipboardEncrypt 剪貼簿內容加密器，
	// 交給每條連線的 ClipboardTap。走建構子注入（同 auditService 的理由）：
	// 剪貼簿落庫即密文是安全紅線，缺線的後果是全部剪貼簿事件退化為缺口紀錄
	// ——fail-visible（缺口態）而非明文降級，但仍屬組裝錯誤，建構子參數使
	// 「漏接」成為編譯錯誤。nil 僅限既有測試路徑
	ClipboardEncrypt ClipboardEncryptor
}

// NewConnectionHandler 建立連線處理器。
//
// auditService 走建構子而非組裝根的裸欄位注入：
// 兌換拒絕留痕是安全紅線，缺席即整條探測路徑不可見；建構子參數使「漏接」成為
// 編譯錯誤，比登記表更早一步。既有測試路徑傳 nil，該情形下記 log 不靜默。
func NewConnectionHandler(guacdHost string, guacdPort int, sessionService *session.SessionService, assetService *asset.AssetService, authService *identity.AuthService, authorizationService *authz.AssetAuthorizationService, auditService *audit.AuditLogService, clipboardEncrypt ClipboardEncryptor) *ConnectionHandler {
	return &ConnectionHandler{
		GuacdHost:            guacdHost,
		GuacdPort:            guacdPort,
		SessionService:       sessionService,
		AssetService:         assetService,
		AuthService:          authService,
		AuthorizationService: authorizationService,
		AuditService:         auditService,
		ClipboardEncrypt:     clipboardEncrypt,
		Registry:             NewConnectionRegistry(),
	}
}

// SetDataTransfer 注入資料傳輸閘（組裝端呼叫）。
//
// 與 `AssetHandler.SetDataTransfer`／`SFTPHandler.SetDataTransfer` 同構：
// 三處共用同一 `*policy.DataTransferService` 實例，且三處注入皆須登記於
// `openspec/changes/archive/2026-08-11-modular-architecture/research/manifest-lifecycle.md`（隨公開快照出門的 lifecycle manifest）。**漏注入＝guacd 連線參數不帶 disable-*、
// tunnel 的 file_tap 不攔截、會話能力快照落空**，且症狀與「政策設為允許」
// 不可分辨——與另兩處同屬安全紅線類別
func (h *ConnectionHandler) SetDataTransfer(dt *policy.DataTransferService) {
	h.dataTransfer = dt
}

// HandleConnect 處理 WebSocket 連線請求（RDP/VNC 圖形協議）
//
// 連線收口：只收 token + asset_id，
// 目標主機與憑證由後端從資產庫解析並在記憶體解密注入 guacd 握手，
// 前端與 URL 全程不出現 hostname/username/password。
// 流程：認證 → 授權 → 取憑證 → guacd 握手 → 升級 WebSocket。
func (h *ConnectionHandler) HandleConnect(c *gin.Context) {
	// 1-3. 認證與授權：connect_token 一次性簽發即焚，
	// 唯一連線入口——授權與傳輸政策閘都在簽發時完成。舊 query-JWT 直連與
	// middleware context 回退已收口（繞過簽發閘＝繞過傳輸政策）
	// 連線收口防呆：URL 帶目標/憑證參數直接拒——
	// 即使參數會被忽略，憑證出現在 URL 就會落 access log，必須顯式擋下
	if c.Query("hostname") != "" || c.Query("password") != "" {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeConnectTargetParamsRejected, nil)
		return
	}
	ct := c.Query("connect_token")
	// 清理 guacamole-js tunnel 可能附加的 ?undefined 污染
	if idx := strings.Index(ct, "?"); idx != -1 {
		ct = ct[:idx]
	}
	if ct == "" {
		// 兌換拒絕留痕（connection-gating spec）
		h.auditConnectDenied(c, ConnectDenial{
			Reason: string(RedeemDenyMissing), HTTPStatus: http.StatusUnauthorized})
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeConnectTokenMissing, nil)
		return
	}
	// 拒絕原因取內部版本：對外仍是同一則「token 無效」（不給票證存在性探測面），
	// 審計則分得出偽造票與過期票——前者是探測訊號，後者多半只是慢了一步
	grant, denyReason := h.ConnectTokens.RedeemConnectTokenWithReason(c.Request.Context(), ct)
	if denyReason != RedeemDenyNone {
		h.auditConnectDenied(c, ConnectDenial{
			Reason: string(denyReason), HTTPStatus: http.StatusUnauthorized})
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeConnectTokenInvalid, nil)
		return
	}
	// 兩階段閘序：AuthorizePreResolve → 憑證解封 → AuthorizeResolvedAccount。
	// 閘序表在 connect_gates.go，順序即該表的列序（G-G* 編號的定義亦在該檔）
	st := &graphicsRedeemState{grant: grant}
	// 主體＝票證所帶的溯源脈絡。**ClaimedRole 留空是實質**：grant 刻意不攜帶角色
	// （見 connect_token.go），兌換側的角色一律由 G-G4 現查
	subj := st.contractSubject(sourceip.Of(c))
	var gate gatewayapi.PolicyGate = connectgate.NewSequence(
		func(s gatewayapi.ConnectSubject) []connectgate.Gate {
			return h.redeemPreResolveGates(s, st)
		},
		func(s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject) []connectgate.Gate {
			return h.redeemResolvedAccountGates(s, o, st)
		},
	)
	reqCtx := c.Request.Context()
	if out := gate.AuthorizePreResolve(reqCtx, subj, gatewayapi.StageRedeemGraphical); out != nil {
		h.writeOutcome(c, out, st)
		return
	}

	userID, assetIDUint := grant.UserID, grant.AssetID

	// 4. 取資產與憑證（記憶體內解密，永不出後端）——**兩階段之間的唯一解封點**。
	// 以 grant 所帶帳號取憑證（0＝預設帳號）。
	// 帳號於簽發後被刪除／改隸他資產者在此 fail-close 拒絕——**絕不靜默退回
	// 預設帳號**（那等於以另一組憑證建線，且跨資產注入即可拿到目標預設憑證）
	creds, err := h.AssetService.GetWithCredentialsForAccount(assetIDUint, grant.AccountID)
	if err != nil {
		log.Printf("[Handler] 取得資產憑證失敗: assetID=%d, accountID=%d, err=%v", assetIDUint, grant.AccountID, err)
		if errors.Is(err, asset.ErrAssetAccountNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetAccountNotFound, nil)
			return
		}
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetCredentialUnavailable, nil)
		return
	}
	st.creds = creds
	// role key 慣例沿用既有 CheckPermission（兩道 authz 閘共用同一 ctx）
	st.authzCtx = context.WithValue(c.Request.Context(), "role", st.currentRole) //nolint:staticcheck // 沿用既有 CheckPermission 的 string key 慣例
	// 已解析客體：AccountID 維持 grant 帶的**選擇器**值（0＝預設帳號），
	// Username 為解封後實際會用的帳號名——後者正是帳號範圍閘的輸入
	resolved := st.contractObject()
	if out := gate.AuthorizeResolvedAccount(reqCtx, subj, resolved,
		gatewayapi.StageRedeemGraphical); out != nil {
		h.writeOutcome(c, out, st)
		return
	}
	assetRow, password := creds.Asset, creds.Password
	protocol := string(assetRow.Protocol)

	log.Printf("[Handler] 收到連線請求: userID=%d, assetID=%d, protocol=%s", userID, assetIDUint, protocol)

	// 5. 獲取客戶端 IP
	clientIP := sourceip.Of(c)

	// 6. 準備連線參數（目標與憑證均來自資產庫）
	params := make(map[string]string)
	params["protocol"] = protocol
	params["hostname"] = assetRow.Host
	params["port"] = strconv.Itoa(assetRow.Port)
	// username 與密碼同取自同一帳號；不再讀 assetRow.Username
	params["username"] = creds.Username
	params["password"] = password

	// 初始顯示尺寸：前端實測容器尺寸，供 guacd 握手 size instruction 使用
	if w := c.Query("width"); w != "" {
		params["width"] = w
	}
	if h := c.Query("height"); h != "" {
		params["height"] = h
	}

	// 為 RDP/VNC 連線產生唯一的錄製檔名（使用時間戳，之後會重命名）
	var recordingName string
	if protocol == "rdp" || protocol == "vnc" {
		recordingName = fmt.Sprintf("%s-%d", protocol, time.Now().UnixNano())
		params["recording-name-temp"] = recordingName // 暫存，供後續使用
	}

	// RDP 檔案傳輸：啟用磁碟重導（enable-drive 預設 off，不設則 guacd 不建磁碟、
	// 前端 onfilesystem 永不觸發、上傳無處可去）。Windows 端顯示為「Shared」磁碟。
	// 每連線獨立 drive-path，避免跨會話檔案互見（連線隔離）。
	// 凍畫面根因（傳完後檔案 handle 未關）已在前端 oncomplete 補 stream.sendEnd() 修復。
	if protocol == "rdp" {
		params["enable-drive"] = "true"
		params["drive-name"] = "Shared"
		// 扁平路徑：父層 /tmp 必存在（create-drive-path 只建葉目錄、不遞迴建父）
		params["drive-path"] = "/tmp/guacdrive-" + recordingName
		params["create-drive-path"] = "true"

		// RDP 傳輸安全參數：由資產欄位經
		// 單一事實源注入；空欄位的最終值與 fillDefaults 原預設完全一致（零影響）
		security, ignoreCert := assetRow.EffectiveRDPParams()
		params["security"] = security
		params["ignore-cert"] = strconv.FormatBool(ignoreCert)
	}

	// VNC 檔案傳輸（vnc-file-transfer）：RFB 無檔案通道，經 guacd SFTP 側車。
	// sftp-hostname 固定取資產 host（不可由前端改指，防繞收口）；憑證僅此處
	// 記憶體內解密注入。解密失敗僅停用檔案傳輸，不中斷 VNC 連線本體。
	if protocol == "vnc" && assetRow.SftpEnabled {
		sftpPwd, sftpErr := h.AssetService.GetSftpPassword(assetRow)
		if sftpErr != nil {
			log.Printf("[Handler] SFTP 憑證解密失敗（停用檔案傳輸續連）: assetID=%d", assetIDUint)
		} else {
			params["enable-sftp"] = "true"
			params["sftp-hostname"] = assetRow.Host
			params["sftp-port"] = strconv.Itoa(assetRow.SftpPort)
			params["sftp-username"] = assetRow.SftpUsername
			params["sftp-password"] = sftpPwd
			// sftp-root-directory 決定前端上傳落地根：libguac 以此為前綴，
			// 一般帳號無權寫伺服器根 /，故預設對到帳號家目錄（v1；自訂路徑列 backlog）
			params["sftp-root-directory"] = sftpRootForUser(assetRow.SftpUsername)
		}
	}

	// 資料傳輸管控（data-transfer-control）：解析五項有效能力，注入 guacd 連線
	// 參數並供 FileTap 逐次判定。解析失敗 fail-close（零值＝全禁）——傳輸控制的
	// 失敗方向必須是擋住而非放行
	var transferCaps policy.TransferCapabilities
	if h.dataTransfer != nil {
		var capErr error
		transferCaps, capErr = h.dataTransfer.EffectiveTransfer(reqCtx, userID, assetIDUint, policy.TransferChannelWeb)
		if capErr != nil {
			log.Printf("[Handler] 傳輸能力解析失敗（fail-close 全禁）: userID=%d, assetID=%d, err=%v", userID, assetIDUint, capErr)
			transferCaps = policy.TransferCapabilities{}
		}
		applyTransferParams(params, protocol, transferCaps)
	}

	// 添加默認參數
	params = fillDefaults(params, protocol)

	log.Printf("[Handler] 連線參數已準備: %+v", maskSensitiveParams(params))

	// 5. 創建 Connection 並執行握手
	conn := NewConnection(protocol, params)
	if err := conn.Connect(h.GuacdHost, h.GuacdPort); err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeGuacdHandshake, err)
		return
	}
	// 錄影的時間原點：guacd 一握手成功即開始寫
	// .guac，而 SessionRecording 的 t=0 是檔內第一個 sync 幀。此刻**早於**下方的
	// 會話建檔，故圖形路徑未校正的深連結落點偏「早」（與文字終端方向相反，見
	// model.Session.RecordingStartedAt 的說明）。於此擷取，隨會話一併寫入
	recordingStartedAt := time.Now()

	log.Printf("[Handler] 握手成功，準備升級 WebSocket")

	// 7. 創建 Session 記錄
	assetID := &assetIDUint
	sess := &model.Session{
		UserID:   userID,
		AssetID:  assetID,
		Protocol: model.ProtocolType(protocol),
		ClientIP: clientIP,
		Status:   model.SessionStatusActive,
		// 帳號雙快照（assetRow-multi-account）：連線當下的帳號 ID 與 username
		// 一併釘住，帳號日後改名／刪除都不改寫已完成會話的審計語義
		AccountID:       creds.AccountID,
		AccountUsername: creds.Username,
	}
	// 只有實際會產生錄影的協議才釘原點；未錄製時留 NULL，前端據此不作定位宣稱
	if recordingName != "" {
		sess.RecordingStartedAt = &recordingStartedAt
	}
	// 認證溯源（1.9）：僅快照，授權仍現查。0 寫 NULL 以區分「本地登入」
	if grant.ProviderID != 0 {
		pid := grant.ProviderID
		sess.AuthProviderID = &pid
	}
	sess.AuthEpoch = grant.AuthEpoch

	// 序列化建立：與文字終端路徑（sshproxy/handler.go
	// createSession）同語義——「重查前提 → 讀世代 → 建立」三步於 provider＋user 鎖內
	// 完成，堵住「兌換讀到舊 epoch → 停用推進並掃完 → 兌換才插入」的 TOCTOU
	if err := h.SessionService.CreateWithGenerationGuard(crypto.AuthContext{
		AuthMethod: grant.AuthMethod, ProviderID: grant.ProviderID,
		AuthEpoch: grant.AuthEpoch, CredEpoch: grant.CredEpoch,
	}, sess); err != nil {
		// session 記錄 fail-close：無審計歸屬一律拒連，admin 亦不豁免
		//（與文字終端路徑對稱；能走到此步證明 DB 讀正常＝部分故障）
		conn.Close()
		log.Printf("[Handler] session 記錄建立失敗，連線已拒: %v", err)
		if failure := audit.GetAuditFailure(); failure != nil {
			failure.Report(model.MechanismSessionRecord, model.CauseSessionRecordCreateFailed,
				map[string]string{
					"user_id":  strconv.FormatUint(uint64(userID), 10),
					"asset_id": strconv.FormatUint(uint64(assetIDUint), 10),
				})
		}
		apierror.Write(c, http.StatusForbidden, apierror.ErrorResponse{
			Code: apierror.CodeSessionRecordFailed,
			Meta: map[string]any{"reason": "session_unavailable"},
		})
		return
	}
	log.Printf("[Handler] Session 已創建: ID=%d", sess.ID)

	// 帳號新來源位址：session 主鍵已得（fail-close 已過）才觀察——告警列以
	// session_id 為自然鍵，先觀察就沒有可綁的會話。失敗只記 log 不阻連線，
	// 且交易整筆回滾，下次自同位址建線補發
	if h.SourceIPBaseline != nil {
		if _, err := h.SourceIPBaseline.ObserveSession(reqCtx, userID, clientIP,
			sess.ID, assetID, time.Now()); err != nil {
			audit.LogObserveError(audit.ObserveSiteGraphics, userID, err)
		}
	}

	// 連線建立時的有效傳輸能力快照（data-transfer-control）：使事後可回答
	// 「那次連線當時允許什麼」。政策可在連線後被改，只查政策現值答不出這個問題。
	// 失敗只記 log——留痕失敗不回壓連線（與 FileTap 同處置）
	if h.dataTransfer != nil && h.AuditSink != nil {
		if err := h.AuditSink.Submit(reqCtx, gatewayapi.AuditEvent{
			Action:     string(model.ActionCreate),
			Resource:   string(model.ResourceSession),
			ResourceID: &sess.ID,
			Status:     string(model.StatusSuccess),
			Actor:      gatewayapi.Actor{UserID: userID},
			Details: fmt.Sprintf(
				`{"session_id":%d,"asset_id":%d,"protocol":%q,"transfer_capabilities":`+
					`{"clipboard_send":%t,"clipboard_recv":%t,"file_upload":%t,"file_download":%t,"file_delete":%t}}`,
				sess.ID, assetIDUint, protocol,
				transferCaps.ClipboardSend, transferCaps.ClipboardRecv,
				transferCaps.FileUpload, transferCaps.FileDownload, transferCaps.FileDelete),
		}); err != nil {
			log.Printf("[Handler] 傳輸能力快照留存失敗: session=%d err=%v", sess.ID, err)
		}
	}

	// 8. 握手成功後才升級 WebSocket
	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[Handler] WebSocket 升級失敗: %v", err)
		conn.Close()
		// 如果 WebSocket 升級失敗，關閉 Session
		if sess != nil {
			h.SessionService.Close(sess.ID)
		}
		return
	}

	log.Println("[Handler] WebSocket 連線已建立")

	// 9. 創建簡化版 Tunnel（只做資料轉發）
	// SSH 已退出 guacd 路徑：指令審計與 asciicast 錄製由 internal/sshproxy 負責
	// 剪貼簿審計旁路（clipboard-audit）：session 建立失敗時無主鍵，跳過留存
	var sendTap, recvTap *ClipboardTap
	var fileTap *FileTap
	if sess != nil {
		sendTap = NewClipboardTap(database.DB, h.ClipboardEncrypt, sess.ID, "send")
		recvTap = NewClipboardTap(database.DB, h.ClipboardEncrypt, sess.ID, "recv")
		// 檔案上傳審計（vnc-file-transfer）：RDP 磁碟＋VNC SFTP 同一路徑補齊
		fileTap = NewFileTap(database.DB, h.AuditSink, sess.ID, userID, &assetIDUint, protocol)
		// 資料傳輸管控（data-transfer-control 5.1/5.6）：**逐次判定**，不是連線
		// 建立時的一次性快照——每個 put／get 重解析一次，政策改動經 30 秒政策
		// 快取窗口後即對進行中連線生效（即時層）
		if h.dataTransfer != nil {
			dtSvc, uid, aid := h.dataTransfer, userID, assetIDUint
			fileTap.SetDecider(func(action string) bool {
				ok, err := dtSvc.AllowsAction(context.Background(), uid, aid, policy.TransferChannelWeb, action)
				if err != nil {
					log.Printf("[Handler] 傳輸能力逐次判定失敗（fail-close 拒絕）: action=%s err=%v", action, err)
					return false
				}
				return ok
			})
		}
	}
	tunnel := NewTunnel(ws, conn, sendTap, recvTap, fileTap)

	// 10. 註冊關閉回呼到 Registry：disconnect 指令經 tunnel 寫鎖送出，
	// 取代裸 conn 直寫；登記於 tunnel 建立後、下方複查前——REVOKE-1 窗口語義不變
	if sess != nil {
		h.Registry.Register(sess.ID, tunnel.Disconnect)
		log.Printf("[Handler] 關閉回呼已註冊到 Registry: SessionID=%d", sess.ID)
		// 已標記終止的 session SHALL NOT 啟動 proxy（design 行 268）：
		// 鎖外收線可能早於此處的登記完成（那時 Close 是 no-op），本複查封該窗口
		if h.SessionService.IsTerminated(sess.ID) {
			log.Printf("[Handler] session 於建立後即被收線，拒絕啟動 proxy: SessionID=%d", sess.ID)
			h.Registry.Close(sess.ID)
			conn.Close()
			ws.Close()
			return
		}
	}
	// 會話閒置/最大時長自動斷線：以客戶端輸入 opcode 計閒置。
	// TimeoutPolicy 未注入時退回安全預設而非零逾時——
	// 與 sshproxy nil→env 退路對稱，避免注入被回歸/誤刪時 RDP/VNC 靜默永不逾時（fail-open）
	idleTimeout, maxDuration := defaultTunnelIdleTimeout, time.Duration(0)
	if h.TimeoutPolicy != nil {
		idleTimeout, maxDuration = h.TimeoutPolicy()
	}
	tunnel.SetTimeouts(idleTimeout, maxDuration)

	// 轉發啟動前最後一次複查：
	// 與 sshproxy 對稱，收緊「連線授權通過後、tunnel 掛上 Registry 前」窗口——兩道閘：
	// (1) 帳號可連線；(2) session 仍 active（撤銷/停用收線已 CAS 成 disconnected 即攔下）
	if err := h.AuthService.CheckUserConnectable(userID); err != nil {
		log.Printf("[Handler] tunnel 啟動前複查拒絕連線 (userID=%d): %v", userID, err)
		tunnel.Close()
	} else if sess != nil && !h.SessionService.IsActive(sess.ID) {
		log.Printf("[Handler] tunnel 啟動前複查：會話已被收線 (SessionID=%d)——撤銷/停用落窗", sess.ID)
		tunnel.Close()
	} else if err := tunnel.Start(); err != nil {
		// 11. 啟動雙向轉發
		log.Printf("[Handler] 隧道錯誤: %v", err)
	}

	log.Println("[Handler] 連線已結束")

	// 11.3 處理 Guacamole RDP/VNC 錄製檔案。
	// 落地鏈本體抽到 finalizeGraphicsRecording（graphics_recording.go）：行為逐字不變，
	// 只把 metadata 寫入、失效通報與 Resolve 三個外部作用參數化，使四條路徑
	// （缺檔／更名失敗／取大小失敗／metadata 更新失敗）可在不起 WebSocket handler 的
	// 情況下被測試覆蓋
	if (protocol == "rdp" || protocol == "vnc") && sess != nil && recordingName != "" {
		finalizeGraphicsRecording(sess.ID, "", recordingName, graphicsRecordingDeps{
			stat:            os.Stat,
			rename:          os.Rename,
			updateRecording: h.SessionService.UpdateRecording,
			reportFailure: func(sessionID uint, cause string, params map[string]string) {
				session.ReportSessionRecordingFailure(sessionID, model.MechanismRecordingGraphics, cause, params)
			},
			resolve: func() {
				if failure := audit.GetAuditFailure(); failure != nil {
					failure.Resolve(model.MechanismRecordingGraphics)
				}
			},
		})
	}

	// 12. 從 Registry 註銷連線
	if sess != nil {
		h.Registry.Unregister(sess.ID)
		log.Printf("[Handler] WebSocket 已從 Registry 註銷: SessionID=%d", sess.ID)
	}

	// 13. 連線結束後更新 Session 狀態（逾時斷線記入 end_reason，沿用 session-timeout 審計語義）
	if sess != nil {
		var err error
		if reason := tunnel.EndReason(); reason != "" {
			err = h.SessionService.CloseWithReason(sess.ID, reason)
		} else {
			err = h.SessionService.Close(sess.ID)
		}
		if err != nil {
			log.Printf("[Handler] 更新 Session 狀態失敗: %v", err)
		} else {
			log.Printf("[Handler] Session 已關閉: ID=%d", sess.ID)
		}
	}
}

// connectionAuthCode 兌換點認證錯誤映射：sentinel 各配一碼，其餘泛化為
// 「無效或過期的 token」。與 sshproxy 的同名映射語義一致（該側另處理
// ErrConnectionNotAuthorized——guacd 路徑不走 scoped token 驗證，故不涉及）。
// 碼的 ZhFallback 與 sentinel 文案逐字相同，遷移前後 error 欄不變。
func connectionAuthCode(err error) (int, apierror.ErrCode) {
	switch {
	case errors.Is(err, identity.ErrAccountLocked):
		return http.StatusLocked, apierror.CodeAccountLocked
	case errors.Is(err, identity.ErrUserInactive):
		return http.StatusForbidden, apierror.CodeUserInactive
	default:
		return http.StatusUnauthorized, apierror.CodeTokenInvalid
	}
}

// sftpRootForUser 依 SSH 帳號推定 SFTP 上傳落地根目錄（vnc-file-transfer v1）：
// root→/root，其餘→/home/<username>。涵蓋主流帳號家目錄；非標準家目錄自訂列 backlog。
func sftpRootForUser(username string) string {
	if username == "root" {
		return "/root"
	}
	return "/home/" + username
}

// maskSensitiveParams 日誌用參數遮罩（密鑰絕不落日誌）
func maskSensitiveParams(params map[string]string) map[string]string {
	masked := make(map[string]string, len(params))
	for k, v := range params {
		if k == "password" || k == "sftp-password" || k == "private-key" {
			if v != "" {
				masked[k] = "***MASKED***"
			} else {
				masked[k] = ""
			}
			continue
		}
		masked[k] = v
	}
	return masked
}

// fillDefaults 填充默認參數
func fillDefaults(params map[string]string, protocol string) map[string]string {
	result := make(map[string]string)
	for k, v := range params {
		result[k] = v
	}

	switch protocol {
	case "rdp":
		// 安全設定
		if result["security"] == "" {
			result["security"] = "any" // 自動協商最佳安全模式
		}
		if result["ignore-cert"] == "" {
			result["ignore-cert"] = "true" // 開發環境忽略憑證
		}

		// 顯示設定 - 修復黑屏問題
		if result["color-depth"] == "" {
			result["color-depth"] = "24" // 24-bit真彩色 (更好的顯示效果)
		}

		// 禁用 RDP Graphics Pipeline (rdpgfx)
		// 原因：rdpgfx 與 xrdp + Xfce 環境不兼容，會導致黑畫面
		// 禁用後將使用傳統的 Bitmap 渲染模式
		if result["disable-gfx"] == "" {
			result["disable-gfx"] = "true"
		}

		if result["resize-method"] == "" {
			result["resize-method"] = "display-update" // RDP 8.1+ 推薦模式
		}

		// 鍵盤設定
		if result["server-layout"] == "" {
			result["server-layout"] = "en-us-qwerty" // 預設美式鍵盤
		}

		// 視覺效果 - 啟用桌布修復黑屏
		if result["enable-wallpaper"] == "" {
			result["enable-wallpaper"] = "true" // 啟用桌布（修復黑屏問題）
		}
		if result["enable-theming"] == "" {
			result["enable-theming"] = "true" // 啟用主題（更好的視覺效果）
		}
		if result["enable-font-smoothing"] == "" {
			result["enable-font-smoothing"] = "true" // 啟用字體平滑
		}

		// 效能與相容性
		if result["enable-desktop-composition"] == "" {
			result["enable-desktop-composition"] = "true" // 啟用桌面合成
		}
		if result["enable-menu-animations"] == "" {
			result["enable-menu-animations"] = "false" // 停用選單動畫（節省頻寬）
		}

		// RDP 錄製設定（Guacamole 內建支援）
		// 參考：https://guacamole.apache.org/doc/gug/configuring-guacamole.html#rdp-recording
		if result["recording-path"] == "" {
			// 與更名端（會後 os.Rename）共用同一個正規化過的根，否則 guacd 寫在 A、
			// 後端到 B 找檔
			result["recording-path"] = recorder.ResolveBasePath("")
		}
		if result["recording-name"] == "" {
			// 使用從 params 傳入的臨時檔名
			if tempName, ok := result["recording-name-temp"]; ok && tempName != "" {
				result["recording-name"] = tempName
				delete(result, "recording-name-temp") // 移除臨時 key
			} else {
				// 回退：使用時間戳
				result["recording-name"] = fmt.Sprintf("rdp-%d", time.Now().UnixNano())
			}
		}
		if result["create-recording-path"] == "" {
			result["create-recording-path"] = "true" // 自動創建錄製目錄
		}

	case "vnc":
		// VNC 僅使用密碼認證，無 username 概念
		delete(result, "username")

		// 顯示設定
		if result["color-depth"] == "" {
			result["color-depth"] = "24"
		}

		// 剪貼簿參數**刻意不在此設預設**（data-transfer-control 3.1）：原本硬寫
		// disable-copy／disable-paste = "false" 會在政策解析缺席時把「允許」寫死，
		// 且與 applyTransferParams 的政策值形成兩個寫入者。政策值由
		// applyTransferParams 於 fillDefaults 之前寫入；未注入 DataTransfer 的
		// 測試路徑則兩個參數皆不出現，guacd 吃自身預設（＝允許），與改動前一致。

		// Guacamole 原生錄製（與 RDP 同機制，回放共用 GuacamolePlayer）
		if result["recording-path"] == "" {
			result["recording-path"] = recorder.ResolveBasePath("")
		}
		if result["recording-name"] == "" {
			if tempName, ok := result["recording-name-temp"]; ok && tempName != "" {
				result["recording-name"] = tempName
				delete(result, "recording-name-temp")
			} else {
				result["recording-name"] = fmt.Sprintf("vnc-%d", time.Now().UnixNano())
			}
		}
		if result["create-recording-path"] == "" {
			result["create-recording-path"] = "true"
		}
	}

	return result
}
