package sshproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/dbproxy"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/sshmaterial"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"golang.org/x/crypto/ssh"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// establishRequest carries request facts and side-effect adapters, never an HTTP
// writer. Gate factories bind the existing single gate table at the HTTP boundary.
// The client address is read from the current request, never from the ticket.
type establishRequest struct {
	Redeemed          func(proxy.ConnectGrant)
	ConsoleAudit      func(uint, uint) *consoleAuditContext
	ConsolePreResolve func(gatewayapi.ConnectSubject, *redeemState) []connectgate.Gate
	ConsoleResolved   func(gatewayapi.ConnectSubject, gatewayapi.ResolvedConnectObject, *redeemState, *consoleAuditContext, *func()) []connectgate.Gate
	Context           context.Context
	Token, ClientIP   string
	Query             func(string) string
	PreResolve        func(gatewayapi.ConnectSubject, *redeemState) []connectgate.Gate
	Resolved          func(gatewayapi.ConnectSubject, gatewayapi.ResolvedConnectObject, *redeemState) []connectgate.Gate
	Deny              func(proxy.ConnectDenial)
	DenyOutcome       func(*connectgate.Outcome, *redeemState)
}

// EstablishFailure preserves the existing HTTP/WS response mapping.
type EstablishFailure struct {
	DBError *dbconsole.DBError
	Outcome *connectgate.Outcome
	Dial    bool
	Message string
	Silent  bool
}

func responseFailure(status int, code apierror.ErrCode) *EstablishFailure {
	return outcomeFailure(connectgate.Deny(status, string(code), nil))
}
func outcomeFailure(out *connectgate.Outcome) *EstablishFailure {
	return &EstablishFailure{Outcome: out}
}
func dialFailure(code apierror.ErrCode, message string) *EstablishFailure {
	f := responseFailure(http.StatusBadGateway, code)
	f.Dial = true
	f.Message = message
	return f
}
func sessionFailure() *EstablishFailure {
	return outcomeFailure(connectgate.Deny(http.StatusForbidden, string(apierror.CodeSessionRecordFailed), map[string]any{"reason": "session_unavailable"}))
}

// EstablishedTerminal owns the target connection and persistent session.
type EstablishedTerminal struct {
	Session     *model.Session
	conn        TerminalConn
	grant       proxy.ConnectGrant
	asset       *model.Asset
	cols, rows  int
	sshClient   *ssh.Client
	k8sSnapshot *k8sproxy.PodSnapshot
	k8sLogsMode bool
}

func (h *Handler) establishTerminal(req establishRequest) (*EstablishedTerminal, *EstablishFailure) {
	// 1-3. 身分與授權：connect_token 一次性簽發即焚，
	// 唯一連線入口——授權與傳輸政策閘都在簽發時完成。舊 query-JWT 直連
	// 模式已收口（繞過簽發閘＝繞過傳輸政策）
	ct := req.Token
	if ct == "" {
		// 兌換拒絕留痕（connection-gating spec）：
		// 與 `/connect` 共用 `proxy.AuditConnectDenied` 這一個寫入點
		req.Deny(proxy.ConnectDenial{
			Reason: string(proxy.RedeemDenyMissing), HTTPStatus: http.StatusUnauthorized})
		return nil, responseFailure(http.StatusUnauthorized, apierror.CodeConnectTokenMissing)
	}
	// 拒絕原因取內部版本：對外仍是同一則「token 無效」（不給票證存在性探測面），
	// 審計則分得出偽造票與過期票——前者是探測訊號，後者多半只是慢了一步
	grant, denyReason := h.ConnectTokens.RedeemConnectTokenWithReason(req.Context, ct)
	if denyReason != proxy.RedeemDenyNone {
		req.Deny(proxy.ConnectDenial{
			Reason: string(denyReason), HTTPStatus: http.StatusUnauthorized})
		return nil, responseFailure(http.StatusUnauthorized, apierror.CodeConnectTokenInvalid)
	}

	// 兩階段閘序：AuthorizePreResolve → 憑證解封 → AuthorizeResolvedAccount。
	// 閘序表在 connect_gates.go，順序即該表的列序（G-S* 編號的定義亦在該檔）
	if req.Redeemed != nil {
		req.Redeemed(grant)
	}
	st := &redeemState{grant: grant}
	// 主體＝票證所帶的溯源脈絡。**ClaimedRole 留空是實質**：grant 刻意不攜帶角色
	// （見 proxy/connect_token.go），兌換側的角色一律由 G-S3 現查
	subj := st.contractSubject(req.ClientIP)
	var gate gatewayapi.PolicyGate = connectgate.NewSequence(
		func(s gatewayapi.ConnectSubject) []connectgate.Gate {
			return req.PreResolve(s, st)
		},
		func(s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject) []connectgate.Gate {
			return req.Resolved(s, o, st)
		},
	)
	reqCtx := req.Context
	if out := gate.AuthorizePreResolve(reqCtx, subj, gatewayapi.StageRedeemTerminal); out != nil {
		req.DenyOutcome(out, st)
		return nil, outcomeFailure(out)
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
			return nil, responseFailure(http.StatusNotFound, apierror.CodeAssetAccountNotFound)
		}
		return nil, responseFailure(http.StatusNotFound, apierror.CodeAssetCredentialUnavailable)
	}
	defer creds.Destroy()
	st.creds = creds
	// 已解析客體：AccountID 維持 grant 帶的**選擇器**值（0＝預設帳號，K8s 閘 G-S12
	// 判的正是這個請求值）；Username 為解封後實際會用的帳號名，即 G-S13 的判定對象
	resolved := st.contractObject()
	if out := gate.AuthorizeResolvedAccount(reqCtx, subj, resolved,
		gatewayapi.StageRedeemTerminal); out != nil {
		req.DenyOutcome(out, st)
		return nil, outcomeFailure(out)
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
			Context: reqCtx, Host: assetRow.Host, Port: assetRow.Port, Username: creds.Username,
			Password: sshmaterial.NewPassword(password), PrivateKey: privateKey,
			Cols: cols, Rows: rows, HostKey: h.HostKeys.Callback(assetID),
		})
		if err != nil {
			log.Printf("[SSHProxy] SSH 連線失敗: assetID=%d, err=%v", assetID, err)
			// Dial 已分類為使用者語言（逾時/認證/不可達）；
			// 僅「解析私鑰失敗: %w」帶庫原文，截斷至動作描述避免洩漏
			msg := err.Error()
			if idx := strings.Index(msg, ": "); idx > 0 {
				msg = msg[:idx]
			}
			return nil, dialFailure(dialErrorCode(err), msg)
		}
		conn = sshConn
		sshClient = sshConn.Client()
	} else if assetRow.Protocol == model.ProtocolK8s {
		// 連線時選 pod：namespace 取自資產（server-trusted），pod/container/模態由前端帶入
		// The Kubernetes SDK retains an immutable token; its copies are not erased.
		target, tokenErr := material.Use(password, func(raw []byte) (k8sproxy.Target, error) {
			return k8sproxy.Target{
				Server:    fmt.Sprintf("https://%s:%d", assetRow.Host, assetRow.Port),
				Token:     string(raw),
				Namespace: assetRow.K8sNamespace,
				Pod:       req.Query("k8s_pod"),
				Container: req.Query("k8s_container"),
				CACert:    assetRow.K8sCACert,
				Insecure:  assetRow.K8sInsecureSkipTLS,
				Mode:      k8sproxy.Mode(req.Query("k8s_mode")),
			}, nil
		})
		if tokenErr != nil {
			return nil, responseFailure(http.StatusNotFound, apierror.CodeAssetCredentialUnavailable)
		}
		// one-shot 單指令尚未實裝 argv 側指令審計與阻斷（列 v1.1）：在此一律拒絕，
		// 避免單指令繞過指令阻斷器（只看 PTY 串流）與審計（security review HIGH）。
		if target.Mode == k8sproxy.ModeOneShot || req.Query("k8s_command") != "" {
			return nil, responseFailure(http.StatusBadRequest, apierror.CodeK8sOneShotDisabled)
		}
		if target.Pod == "" {
			return nil, responseFailure(http.StatusBadRequest, apierror.CodeK8sPodRequired)
		}
		// 釘 session 快照（同時驗證 pod 存在/可達/權限），錯誤已分類為六類（各配一碼）
		snap, gerr := k8sproxy.GetPod(req.Context, target)
		if gerr != nil {
			log.Printf("[K8sProxy] GetPod 失敗: assetID=%d, pod=%s, err=%v", assetID, target.Pod, gerr)
			return nil, dialFailure(k8sDialCode(gerr), gerr.Error())
		}
		target.Container = snap.Container // 解析後的實際容器（default annotation/第一個）
		k8sConn, err := k8sproxy.Start(target, cols, rows)
		if err != nil {
			log.Printf("[K8sProxy] kubectl 啟動失敗: assetID=%d, err=%v", assetID, err)
			return nil, dialFailure(apierror.CodeK8sStartFailed, zhFallbackOf(apierror.CodeK8sStartFailed))
		}
		conn = k8sConn
		k8sSnapshot = snap
		k8sLogsMode = target.Mode == k8sproxy.ModeLogs
	} else {
		// Transfer ownership until prompt injection or connection closure.
		dbPassword, err := material.Move(password)
		if err != nil {
			return nil, &EstablishFailure{Silent: true}
		}
		dbConn, err := dbproxy.Start(dbproxy.Target{
			Protocol: string(assetRow.Protocol),
			Host:     assetRow.Host,
			Port:     assetRow.Port,
			// username 與憑證同取自同一帳號；不再讀 assetRow.Username
			Username: creds.Username,
			Password: dbPassword,
			DBName:   assetRow.DBName,
			TLSMode:  assetRow.DBTLSMode,
			CACert:   assetRow.DBCACert,
		}, cols, rows)
		if err != nil {
			// Start 僅在程式缺失/PTY 失敗時出錯（不含目標連線失敗），記詳情回泛化訊息
			log.Printf("[DBProxy] CLI 啟動失敗: assetID=%d, err=%v", assetID, err)
			return nil, dialFailure(apierror.CodeDBClientStartFailed, zhFallbackOf(apierror.CodeDBClientStartFailed))
		}
		conn = dbConn
	}

	creds.Destroy()
	// 6. Session 記錄 fail-close：能走到此步證明 DB 讀正常（前置
	// CheckUserConnectable/GetWithCredentials 皆已過），故 session INSERT 失敗＝
	// 部分故障。無 session 主鍵即無 registry/錄影/指令審計/監看，一律拒連——admin
	// 亦不豁免（完全無審計歸屬，與錄影 fail-close 的 admin 例外刻意不同）
	// 帳號雙快照：帶入連線當下實際使用的帳號 ID 與 username
	// 認證溯源（1.9）：provider/世代自 grant 原樣帶入，SSH/K8s/DB 三協議共此一路徑
	sess := h.createSession(userID, assetID, assetRow.Protocol, req.ClientIP, k8sSnapshot,
		accountSnapshot{ID: creds.AccountID, Username: creds.Username},
		authProvenance{AgentTokenID: grant.AgentTokenID, AccessRequestID: grant.AccessRequestID, ProviderID: grant.ProviderID, AuthEpoch: grant.AuthEpoch,
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
		return nil, sessionFailure()
	}

	// 6b. 帳號新來源位址：session 主鍵已得（fail-close 已過）才觀察——
	// 告警列以 session_id 為自然鍵，先觀察就沒有可綁的會話。
	// 失敗只記 log 不阻連線，且交易整筆回滾，下次自同位址建線補發

	return &EstablishedTerminal{Session: sess, conn: conn, grant: grant, asset: assetRow, cols: cols, rows: rows, sshClient: sshClient, k8sSnapshot: k8sSnapshot, k8sLogsMode: k8sLogsMode}, nil
}

type establishedConsole struct {
	Session  *model.Session
	dialect  dbconsole.Dialect
	protocol dbconsole.Protocol
	grant    proxy.ConnectGrant
	auditCtx *consoleAuditContext
	release  func()
}

func (h *Handler) establishConsole(req establishRequest) (*establishedConsole, *EstablishFailure) {
	ct := req.Token
	if ct == "" {
		req.Deny(proxy.ConnectDenial{
			Reason: string(proxy.RedeemDenyMissing), HTTPStatus: http.StatusUnauthorized})
		return nil, responseFailure(http.StatusUnauthorized, apierror.CodeConnectTokenMissing)
	}
	grant, denyReason := h.ConnectTokens.RedeemConnectTokenWithReason(req.Context, ct)
	if denyReason != proxy.RedeemDenyNone {
		req.Deny(proxy.ConnectDenial{
			Reason: string(denyReason), HTTPStatus: http.StatusUnauthorized})
		return nil, responseFailure(http.StatusUnauthorized, apierror.CodeConnectTokenInvalid)
	}

	if req.Redeemed != nil {
		req.Redeemed(grant)
	}
	st := &redeemState{grant: grant}
	subj := st.contractSubject(req.ClientIP)
	auditCtx := req.ConsoleAudit(grant.UserID, grant.AssetID)

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
			return req.ConsolePreResolve(s, st)
		},
		func(s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject) []connectgate.Gate {
			return req.ConsoleResolved(s, o, st, auditCtx, &releaseAdmission)
		},
	)
	reqCtx := req.Context
	if out := gate.AuthorizePreResolve(reqCtx, subj, gatewayapi.StageRedeemTerminal); out != nil {
		req.DenyOutcome(out, st)
		return nil, outcomeFailure(out)
	}
	userID, assetID := grant.UserID, grant.AssetID

	// 唯一解封點：與 `/ssh` 共用同一個呼叫，帳號於簽發後被刪除或改隸他資產者
	// 在此 fail-close，絕不靜默退回預設帳號
	creds, err := h.AssetService.GetWithCredentialsForAccount(assetID, grant.AccountID)
	if err != nil {
		log.Printf("[DBConsole] 取得資產憑證失敗: assetID=%d, accountID=%d, err=%v",
			assetID, grant.AccountID, err)
		return nil, responseFailure(http.StatusNotFound, apierror.CodeAssetCredentialUnavailable)
	}
	defer creds.Destroy()
	st.creds = creds
	resolved := st.contractObject()
	if out := gate.AuthorizeResolvedAccount(reqCtx, subj, resolved,
		gatewayapi.StageRedeemTerminal); out != nil {
		req.DenyOutcome(out, st)
		return nil, outcomeFailure(out)
	}

	assetRow := creds.Asset
	protocol := dbconsole.Protocol(assetRow.Protocol)

	// 建立目標連線。密碼的所有權移交 dbconsole：Open 返回時我方副本已清零
	dialCtx, cancelDial := context.WithTimeout(context.Background(), dbconsole.ConnectTimeout)
	dialect, err := material.Use(creds.Password, func(raw []byte) (dbconsole.Dialect, error) {
		return dbconsole.Open(dialCtx, dbconsole.Config{
			Protocol: protocol,
			Host:     assetRow.Host,
			Port:     assetRow.Port,
			Username: creds.Username,
			Password: bytes.Clone(raw),
			Database: assetRow.DBName,
			TLSMode:  assetRow.DBTLSMode,
			CACert:   assetRow.DBCACert,
		})
	})
	creds.Destroy()
	cancelDial()
	if err != nil {
		// 起始連線失敗一律泛化：連線階段的錯誤字串含主機、埠、憑證主體與
		// 主機端規則，那些是我們的拓撲不是使用者的產品內容。**不建立會話列**
		class := dbconsole.ClassifyConnect(protocol, err)
		log.Printf("[DBConsole] 目標連線失敗: assetID=%d class=%s err=%v", assetID, class, err)
		auditCtx.auditConnectFailure(string(class))
		f := dialFailure(consoleConnectCode(class), "")
		f.DBError = dbconsole.DBErrorOf(protocol, err, false)
		return nil, f
	}

	// 會話記錄 fail-close：無 session 主鍵即無註冊表、錄影、語句審計與監看，
	// 一律拒連——admin 亦不豁免
	sess := h.createSession(userID, assetID, assetRow.Protocol, req.ClientIP, nil,
		accountSnapshot{ID: creds.AccountID, Username: creds.Username},
		authProvenance{AgentTokenID: grant.AgentTokenID, AccessRequestID: grant.AccessRequestID, ProviderID: grant.ProviderID, AuthEpoch: grant.AuthEpoch,
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
		return nil, sessionFailure()
	}
	auditCtx.sessionID = sess.ID

	keep = true
	return &establishedConsole{Session: sess, dialect: dialect, protocol: protocol, grant: grant, auditCtx: auditCtx, release: releaseAdmission}, nil
}
